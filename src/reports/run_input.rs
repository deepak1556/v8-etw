use super::workloads::{number, read_json, text};
use crate::Result;
use serde::Deserialize;
use serde_json::{Value, json};
use std::collections::BTreeSet;
use std::fs;
use std::path::{Component, Path, PathBuf};

pub(super) enum LogEvent {
    Activity(Value),
    Complete(Value),
}

// Translate old capture-wrapper names only at the input boundary.
pub(super) fn log_event(line: &str) -> Result<Option<LogEvent>> {
    if !line.starts_with('{') {
        return Ok(None);
    }
    let value: Value = serde_json::from_str(line).map_err(|e| e.to_string())?;
    if value.get("activity").is_some() {
        return Ok(Some(LogEvent::Activity(value)));
    }
    if value.get("runComplete").is_some() {
        return Ok(Some(LogEvent::Complete(value)));
    }
    if value.get("memoryBenchmark").is_some() {
        return Ok(Some(LogEvent::Activity(json!({
            "activity":text(&value,"memoryBenchmark")?,
            "phase":text(&value,"phase")?,
            "timestampMs":number(&value,"timestampMs")?
        }))));
    }
    if value.get("memoryPassComplete").is_some() {
        return Ok(Some(LogEvent::Complete(json!({
            "runComplete":value["memoryPassComplete"],"results":value["results"]
        }))));
    }
    Ok(None)
}

#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Pair {
    pub id: String,
    pub control: PathBuf,
    pub candidate: PathBuf,
    #[serde(skip)]
    pub legacy_seed: Option<u64>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Pairs {
    pub performance: Vec<Pair>,
    #[serde(default)]
    pub latency: Vec<Pair>,
}

pub(super) fn load_pairs(directory: &Path) -> Result<Pairs> {
    let manifest = directory.join("pairs.json");
    if manifest.exists() {
        let pairs: Pairs = serde_json::from_value(read_json(&manifest)?)
            .map_err(|e| format!("Invalid pairs.json: {e}"))?;
        for group in [&pairs.performance, &pairs.latency] {
            let mut ids = BTreeSet::new();
            for pair in group {
                if pair.id.trim().is_empty() || !ids.insert(&pair.id) {
                    return Err("Pair IDs must be nonempty and unique within each group.".into());
                }
                for path in [&pair.control, &pair.candidate] {
                    if path.as_os_str().is_empty()
                        || path
                            .components()
                            .any(|part| !matches!(part, Component::Normal(_)))
                    {
                        return Err("Pair paths must be relative child directories.".into());
                    }
                }
                if pair.control == pair.candidate {
                    return Err("A pair must reference different run directories.".into());
                }
            }
        }
        if pairs.performance.is_empty() {
            return Err("At least one performance pair is required.".into());
        }
        return Ok(pairs);
    }
    legacy_pairs(directory)
}

fn legacy_pairs(directory: &Path) -> Result<Pairs> {
    let mut controls = BTreeSet::new();
    let mut candidates = BTreeSet::new();
    for entry in fs::read_dir(directory).map_err(|e| e.to_string())? {
        let entry = entry.map_err(|e| e.to_string())?;
        if !entry.file_type().map_err(|e| e.to_string())?.is_dir() {
            continue;
        }
        let name = entry.file_name();
        let name = name.to_str().ok_or("Run directory name is not UTF-8.")?;
        for (prefix, seeds) in [
            ("perf-control-seed", &mut controls),
            ("perf-candidate-seed", &mut candidates),
        ] {
            if let Some(seed) = name.strip_prefix(prefix) {
                seeds.insert(seed.parse::<u64>().map_err(|e| e.to_string())?);
            }
        }
    }
    if controls.is_empty() || controls != candidates {
        return Err("Provide pairs.json or complete legacy performance pairs.".into());
    }
    let mut latency = Vec::new();
    let performance = controls
        .into_iter()
        .map(|seed| {
            let pair = |prefix| Pair {
                id: seed.to_string(),
                control: format!("{prefix}-control-seed{seed}").into(),
                candidate: format!("{prefix}-candidate-seed{seed}").into(),
                legacy_seed: Some(seed),
            };
            let timing = pair("latency");
            if directory.join(&timing.control).is_dir()
                || directory.join(&timing.candidate).is_dir()
            {
                latency.push(timing);
            }
            pair("perf")
        })
        .collect();
    Ok(Pairs {
        performance,
        latency,
    })
}

pub(super) fn validate_legacy_seed(metadata: &Value, seed: Option<u64>) -> Result<()> {
    let Some(seed) = seed else {
        return Ok(());
    };
    let expected = format!("--random-seed={seed}");
    let args = metadata["Arguments"]
        .as_array()
        .ok_or("Runtime arguments missing.")?;
    if args
        .iter()
        .filter(|x| x.as_str().is_some_and(|s| s.starts_with("--random-seed=")))
        .count()
        != 1
        || !args.iter().any(|x| x.as_str() == Some(&expected))
    {
        return Err("Legacy run directory seed does not match its runtime argument.".into());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn generic_and_legacy_markers_normalize_at_input_boundary() {
        let canonical = r#"{"activity":"startup","phase":"begin","timestampMs":10}"#;
        let legacy = r#"{"memoryBenchmark":"startup","phase":"begin","timestampMs":10}"#;
        let activity = |line| match log_event(line).unwrap().unwrap() {
            LogEvent::Activity(value) => value,
            _ => panic!("expected activity"),
        };
        assert_eq!(activity(canonical), activity(legacy));
        assert!(log_event("ordinary application log").unwrap().is_none());
        assert!(log_event(r#"{"activity":"broken""#).is_err());
    }
    #[test]
    fn explicit_manifest_does_not_require_seed_flags() {
        let metadata = json!({"Arguments":["app.js"]});
        assert!(validate_legacy_seed(&metadata, None).is_ok());
        assert!(validate_legacy_seed(&metadata, Some(11)).is_err());
        let metadata = json!({"Arguments":["--random-seed=11","app.js"]});
        assert!(validate_legacy_seed(&metadata, Some(11)).is_ok());
        assert!(validate_legacy_seed(&metadata, Some(29)).is_err());
    }
}
