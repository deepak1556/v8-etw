use super::composition::activity_windows;
use super::workloads::{number, read_json, text, write_json};
use crate::Result;
use crate::symbols::attribution::function_key;
use serde_json::{Value, json};
use std::collections::{BTreeMap, BTreeSet};
use std::fs::File;
use std::io::{BufRead, BufReader};
use std::path::Path;

#[derive(Default)]
struct Counts {
    leaf: BTreeMap<String, u64>,
    inclusive: BTreeMap<String, u64>,
    samples: u64,
    unknown_leaf: u64,
}

fn ranked(counts: &BTreeMap<String, u64>) -> Vec<Value> {
    let mut rows: Vec<_> = counts.iter().collect();
    rows.sort_by(|a, b| b.1.cmp(a.1).then_with(|| a.0.cmp(b.0)));
    rows.truncate(100);
    rows.into_iter()
        .map(|(name, count)| json!({"function":name,"samples":count}))
        .collect()
}

pub(crate) fn run(input: &Path, output: &Path) -> Result<()> {
    if output.exists() {
        return Err("Hotspot report exists; refusing overwrite.".into());
    }
    let directory = if input.join("summary.json").is_file() {
        input.to_owned()
    } else {
        input.join("analysis")
    };
    let attribution = read_json(&directory.join("attribution.json"))?;
    if !attribution["required_pdb_failures"]
        .as_array()
        .is_some_and(|x| x.is_empty())
    {
        return Err("Hotspot report requires successful requested PDB validation.".into());
    }
    let windows = activity_windows(&directory)?;
    let mut counts: BTreeMap<String, Counts> = windows
        .iter()
        .map(|x| (x.name.clone(), Counts::default()))
        .collect();
    let mut seen = BTreeSet::new();
    for line in BufReader::with_capacity(
        1024 * 1024,
        File::open(directory.join("symbolized.jsonl")).map_err(|e| e.to_string())?,
    )
    .lines()
    {
        let line = line.map_err(|e| e.to_string())?;
        if !line.contains("\"kind\":\"stack\"") {
            continue;
        }
        let event: Value = serde_json::from_str(&line).map_err(|e| e.to_string())?;
        let related = event["related_event_kinds"].as_array();
        if !related.is_some_and(|kinds| kinds.iter().any(|x| x == "cpu_sample")) {
            continue;
        }
        let timestamp = text(&event, "timestamp_raw")?
            .parse::<u64>()
            .map_err(|e| e.to_string())?;
        let tid = number(&event, "tid")?;
        if !seen.insert((timestamp, tid)) {
            continue;
        }
        let index = windows.partition_point(|x| x.begin <= timestamp);
        if index == 0 || timestamp > windows[index - 1].end {
            continue;
        }
        let frames = event["frames"]
            .as_array()
            .ok_or("CPU stack frames missing.")?;
        let row = counts
            .get_mut(&windows[index - 1].name)
            .ok_or("Missing CPU plan.")?;
        row.samples += 1;
        if let Some(frame) = frames.first().filter(|x| x["function"].is_string()) {
            *row.leaf.entry(function_key(frame)).or_default() += 1;
        } else {
            row.unknown_leaf += 1;
        }
        let functions: BTreeSet<_> = frames
            .iter()
            .filter(|x| x["function"].is_string())
            .map(function_key)
            .collect();
        for function in functions {
            *row.inclusive.entry(function).or_default() += 1;
        }
    }
    if counts.values().all(|x| x.samples == 0) {
        return Err("No CPU stacks correlated to activity windows; report is unavailable.".into());
    }
    let result = json!({"schema_version":1,"plans":counts.into_iter().map(|(name,c)|(
        name,json!({"cpu_stack_samples":c.samples,"unresolved_leaf_samples":c.unknown_leaf,
        "leaf_functions":ranked(&c.leaf),"inclusive_functions":ranked(&c.inclusive),
        "leaf_function_count":c.leaf.len(),"inclusive_function_count":c.inclusive.len(),
        "lists_truncated":c.leaf.len()>100||c.inclusive.len()>100})
    )).collect::<BTreeMap<_,_>>(),
    "symbol_modules":attribution["modules"],"frame_coverage":attribution["frame_coverage"],
    "limitations":["CPU stacks are assigned by activity time, not causal worker-job ownership.",
        "Samples include all process threads; inclusive frame counts overlap and cannot be summed as CPU time.",
        "Only stacks correlated to CPU samples are counted; short work and unresolved frames can be missed.",
        "Each function list is bounded to the top 100; original symbolized stacks remain available.",
        "CPU sampling can suggest first-touch/OS work but does not measure page-fault latency directly."]});
    write_json(output, &result)?;
    eprintln!("Activity CPU hotspots: {}", output.display());
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn ranking_is_bounded_and_deterministic() {
        let counts: BTreeMap<_, _> = (0..150).map(|i| (format!("f{i:03}"), i as u64)).collect();
        let rows = ranked(&counts);
        assert_eq!(rows.len(), 100);
        assert_eq!(rows[0]["function"], "f149");
        assert_eq!(rows[0]["samples"], 149);
    }
}
