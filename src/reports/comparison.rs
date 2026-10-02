use super::run_input::{load_pairs, validate_legacy_seed};
use super::workloads::{WorkloadRun, load_run, percentile, write_json};
use crate::Result;
use serde_json::{Value, json};
use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

fn matching(control: &WorkloadRun, candidate: &WorkloadRun, ignored: &[String]) -> Result<()> {
    if control.plans.keys().ne(candidate.plans.keys()) {
        return Err("Paired activity sets differ.".into());
    }
    if control.scores.keys().ne(candidate.scores.keys()) {
        return Err("Paired scored activity sets differ.".into());
    }
    for key in ["V8Revision", "ProfileInputs"] {
        if control.metadata.get(key) != candidate.metadata.get(key) {
            return Err(format!("Paired {key} differs."));
        }
    }
    let args = |run: &WorkloadRun| -> Result<Vec<String>> {
        run.metadata["Arguments"]
            .as_array()
            .ok_or("Runtime arguments missing.")?
            .iter()
            .map(|v| {
                v.as_str()
                    .map(str::to_owned)
                    .ok_or("Invalid runtime argument.".into())
            })
            .collect::<Result<Vec<_>>>()
            .map(|items| items.into_iter().filter(|x| !ignored.contains(x)).collect())
    };
    if args(control)? != args(candidate)? {
        return Err("Uncontrolled paired runtime arguments.".into());
    }
    Ok(())
}

fn latency(
    gc: &BTreeMap<String, BTreeMap<String, Vec<f64>>>,
    records: usize,
) -> Result<BTreeMap<String, Value>> {
    if records == 0 {
        return Err("No native GC timing records decoded from latency run.".into());
    }
    Ok(gc
        .iter()
        .map(|(name, groups)| {
            let values: BTreeMap<_, _> = groups
                .iter()
                .map(|(kind, values)| {
                    (
                        kind,
                        json!({"count":values.len(),"total_ms":values.iter().sum::<f64>(),
                "p50_ms":percentile(values,0.5),"p95_ms":percentile(values,0.95),
                "max_ms":values.iter().copied().max_by(f64::total_cmp)}),
                    )
                })
                .collect();
            (name.clone(), json!(values))
        })
        .collect())
}

fn percent_change(before: Option<u64>, after: Option<u64>) -> Option<f64> {
    match (before, after) {
        (Some(before), Some(after)) if before > 0 => {
            Some((after as f64 / before as f64 - 1.0) * 100.0)
        }
        _ => None,
    }
}

fn scope_duration_field(key: &str) -> bool {
    if key == "mark.js_global_proxies" || key.ends_with("_count") || key.ends_with(".steps_count") {
        return false;
    }
    matches!(
        key,
        "time_to_safepoint"
            | "prologue"
            | "epilogue"
            | "weakness_handling"
            | "conservative_stack_scanning"
            | "incremental_longest_step"
            | "incremental_wrapper_tracing_longest_step"
            | "incremental_walltime_duration"
            | "incremental.steps_took"
    ) || [
        "heap",
        "clear",
        "complete",
        "evacuate",
        "finish",
        "mark",
        "sweep",
        "scavenge",
        "minor_ms",
        "incremental",
        "background",
    ]
    .iter()
    .any(|prefix| {
        key == *prefix
            || key
                .strip_prefix(prefix)
                .is_some_and(|tail| tail.starts_with('.'))
    })
}

fn gc_phase_stats(records: &[Value]) -> Result<Value> {
    let mut scopes = BTreeMap::<String, BTreeMap<String, Vec<f64>>>::new();
    for record in records {
        let kind = record["gc"]
            .as_str()
            .ok_or("GC kind missing in detailed record.")?;
        for (key, value) in record
            .as_object()
            .ok_or("GC detailed record is not an object.")?
        {
            if !scope_duration_field(key) {
                continue;
            }
            let duration = value
                .as_f64()
                .filter(|x| x.is_finite() && *x >= 0.0)
                .ok_or_else(|| format!("Invalid duration for GC scope {key}."))?;
            scopes
                .entry(kind.to_owned())
                .or_default()
                .entry(key.clone())
                .or_default()
                .push(duration);
        }
    }
    let mut longest: Vec<_> = records
        .iter()
        .map(|record| {
            record["pause"]
                .as_f64()
                .filter(|x| x.is_finite() && *x >= 0.0)
                .map(|pause| (pause, record))
                .ok_or_else(|| "Invalid detailed GC pause.".to_owned())
        })
        .collect::<Result<_>>()?;
    longest.sort_by(|a, b| b.0.total_cmp(&a.0));
    longest.truncate(5);
    Ok(json!({
        "json_record_count":records.len(),"longest_collections":longest.into_iter().map(|(_,record)|record).collect::<Vec<_>>(),
        "scopes_by_collector":scopes.into_iter().map(|(kind,fields)|(
            kind,fields.into_iter().map(|(scope,v)|(scope,json!({
                "count":v.len(),"total_ms":v.iter().sum::<f64>(),
                "p50_ms":percentile(&v,0.5),"p95_ms":percentile(&v,0.95),
                "max_ms":v.iter().copied().max_by(f64::total_cmp)
            }))).collect::<BTreeMap<_,_>>()
        )).collect::<BTreeMap<_,_>>(),
        "limitations":["Nested scope timings and background worker timings overlap; do not add them into pause time.",
            "Scope observations describe changed GC work, not automatically the cause of a regression.",
            "Legacy GC logs without JSON scope fields retain pauses but cannot provide this breakdown."]
    }))
}

pub(crate) fn run(
    directory: &Path,
    output: &Path,
    ignored: &[String],
    excluded: &[String],
    exclusion_reason: Option<&str>,
) -> Result<()> {
    if output.exists() {
        return Err("Comparison output exists; refusing overwrite.".into());
    }
    let mut pairs = load_pairs(directory)?;
    if excluded.is_empty() != exclusion_reason.is_none() {
        return Err(
            "Pair exclusions require a nonempty --exclusion-reason; a reason requires exclusions."
                .into(),
        );
    }
    let mut unique_exclusions = BTreeSet::new();
    for id in excluded {
        if !unique_exclusions.insert(id.clone()) || !pairs.performance.iter().any(|p| p.id == *id) {
            return Err("Excluded pair is duplicate or not in the paired run set.".into());
        }
    }
    pairs
        .performance
        .retain(|p| !unique_exclusions.contains(&p.id));
    pairs.latency.retain(|p| !unique_exclusions.contains(&p.id));
    if pairs.performance.is_empty() {
        return Err("Cannot exclude every paired observation.".into());
    }
    let mut plans = BTreeMap::<String, Value>::new();
    let mut scored_activities = None;
    let mut ratios = Vec::new();
    for pair in &pairs.performance {
        let before = load_run(&directory.join(&pair.control))?;
        let after = load_run(&directory.join(&pair.candidate))?;
        matching(&before, &after, ignored)?;
        validate_legacy_seed(&before.metadata, pair.legacy_seed)?;
        validate_legacy_seed(&after.metadata, pair.legacy_seed)?;
        let scored: BTreeSet<_> = before.scores.keys().cloned().collect();
        if scored_activities
            .as_ref()
            .is_some_and(|previous| *previous != scored)
        {
            return Err("Scored activity sets differ between performance pairs.".into());
        }
        scored_activities = Some(scored);
        if !plans.is_empty() && before.plans.keys().ne(plans.keys()) {
            return Err("Plan sets differ between seeds.".into());
        }
        let mut logs = Vec::new();
        for (name, control) in &before.plans {
            let candidate = after.plans.get(name).ok_or("Candidate plan missing.")?;
            let ratio = before
                .scores
                .get(name)
                .zip(after.scores.get(name))
                .map(|(a, b)| b / a);
            if let Some(ratio) = ratio {
                logs.push(ratio.ln());
            }
            let delta = match (
                candidate.sampled_private_peak_bytes,
                control.sampled_private_peak_bytes,
            ) {
                (Some(a), Some(b)) => Some(a as i128 - b as i128),
                _ => None,
            };
            let row = plans
                .entry(name.clone())
                .or_insert_with(|| json!({"paired_runs":[]}));
            row["paired_runs"]
                .as_array_mut()
                .ok_or("Invalid paired-run array.")?
                .push(json!({
                    "pair_id":pair.id,"seed":pair.legacy_seed,"control":control,"candidate":candidate,
                    "control_score":before.scores.get(name),"candidate_score":after.scores.get(name),
                    "score_change_percent":ratio.map(|r|(r-1.0)*100.0),"private_peak_change_bytes":delta,
                    "private_peak_change_percent":percent_change(control.sampled_private_peak_bytes,candidate.sampled_private_peak_bytes),
                    "working_set_peak_change_percent":percent_change(control.sampled_working_set_peak_bytes,candidate.sampled_working_set_peak_bytes),
                    "end_private_change_percent":percent_change(control.sampled_end_private_bytes,candidate.sampled_end_private_bytes),
                    "sampled_cpu_change_percent":percent_change(control.sampled_cpu_ms,candidate.sampled_cpu_ms)
                }));
        }
        if !logs.is_empty() {
            ratios.push((logs.iter().sum::<f64>() / logs.len() as f64).exp());
        }
    }
    let mut gc_before = BTreeMap::<String, BTreeMap<String, Vec<f64>>>::new();
    let mut gc_after = gc_before.clone();
    let mut count_before = 0;
    let mut count_after = 0;
    let mut detail_before = BTreeMap::<String, Vec<Value>>::new();
    let mut detail_after = BTreeMap::<String, Vec<Value>>::new();
    for pair in &pairs.latency {
        let before = load_run(&directory.join(&pair.control))?;
        let after = load_run(&directory.join(&pair.candidate))?;
        matching(&before, &after, ignored)?;
        validate_legacy_seed(&before.metadata, pair.legacy_seed)?;
        validate_legacy_seed(&after.metadata, pair.legacy_seed)?;
        if before.plans.keys().ne(plans.keys()) {
            return Err("Latency/performance plan sets differ.".into());
        }
        count_before += before.gc_records;
        count_after += after.gc_records;
        for (source, dest) in [
            (&before.gc_details, &mut detail_before),
            (&after.gc_details, &mut detail_after),
        ] {
            for (name, records) in source {
                dest.entry(name.clone())
                    .or_default()
                    .extend(records.iter().cloned());
            }
        }
        let seed_before = latency(&before.gc, before.gc_records)?;
        let seed_after = latency(&after.gc, after.gc_records)?;
        for (name, row) in &mut plans {
            if row.get("gc_latency_pairs").is_none() {
                row["gc_latency_pairs"] = json!([]);
            }
            row["gc_latency_pairs"]
                .as_array_mut()
                .ok_or("Invalid GC pairs.")?
                .push(json!({
                    "pair_id":pair.id,"seed":pair.legacy_seed,"control":seed_before.get(name).ok_or("GC control plan missing.")?,
                    "candidate":seed_after.get(name).ok_or("GC candidate plan missing.")?
                }));
        }
        for (source, dest) in [(&before.gc, &mut gc_before), (&after.gc, &mut gc_after)] {
            for (name, groups) in source {
                for (kind, values) in groups {
                    dest.entry(name.clone())
                        .or_default()
                        .entry(kind.clone())
                        .or_default()
                        .extend(values);
                }
            }
        }
    }
    let gc_before = if pairs.latency.is_empty() {
        None
    } else {
        Some(latency(&gc_before, count_before)?)
    };
    let gc_after = if pairs.latency.is_empty() {
        None
    } else {
        Some(latency(&gc_after, count_after)?)
    };
    for (name, row) in &mut plans {
        let changes: Vec<_> = row["paired_runs"]
            .as_array()
            .ok_or("Paired runs missing.")?
            .iter()
            .filter_map(|x| x["score_change_percent"].as_f64())
            .collect();
        row["median_score_change_percent"] = json!(percentile(&changes, 0.5));
        let pairs = row["paired_runs"]
            .as_array()
            .ok_or("Paired runs missing.")?;
        let mut summaries = BTreeMap::new();
        for key in [
            "private_peak_change_bytes",
            "private_peak_change_percent",
            "working_set_peak_change_percent",
            "end_private_change_percent",
            "sampled_cpu_change_percent",
        ] {
            let values: Vec<_> = pairs.iter().filter_map(|x| x[key].as_f64()).collect();
            summaries.insert(
                key,
                json!({
                    "observed_pairs":values.len(),"missing_pairs":pairs.len()-values.len(),
                    "median":percentile(&values,0.5),
                    "minimum":values.iter().copied().min_by(f64::total_cmp),
                    "maximum":values.iter().copied().max_by(f64::total_cmp)
                }),
            );
        }
        row["paired_metric_summary"] = json!(summaries);
        row["gc_latency_available"] = json!(gc_before.is_some());
        row["gc_latency_control"] = json!(gc_before.as_ref().and_then(|gc| gc.get(name)));
        row["gc_latency_candidate"] = json!(gc_after.as_ref().and_then(|gc| gc.get(name)));
        row["gc_phases_control"] =
            gc_phase_stats(detail_before.get(name).map_or(&[], Vec::as_slice))?;
        row["gc_phases_candidate"] =
            gc_phase_stats(detail_after.get(name).map_or(&[], Vec::as_slice))?;
    }
    let report = json!({"schema_version":1,"plans":plans,
    "suite_score_geomean_ratios_by_seed":ratios,
    "median_suite_score_change_percent":percentile(&ratios,0.5).map(|v|(v-1.0)*100.0),
    "pair_ids":pairs.performance.iter().map(|p|&p.id).collect::<Vec<_>>(),
    "latency_pair_ids":pairs.latency.iter().map(|p|&p.id).collect::<Vec<_>>(),
    "seeds":pairs.performance.iter().filter_map(|p|p.legacy_seed).collect::<Vec<_>>(),
    "latency_seeds":pairs.latency.iter().filter_map(|p|p.legacy_seed).collect::<Vec<_>>(),
    "allowed_argument_differences":ignored,
    "excluded_pair_ids":unique_exclusions,"exclusion_reason":exclusion_reason,
    "score_available":!ratios.is_empty(),"gc_latency_available":gc_before.is_some(),
    "limitations":[
        "Compare matching activities within each pair, not peaks of unrelated activities.",
        "Repeated scores are not a significance test or universal performance claim.",
        "GC latency is from separate matched GC-tracing runs, not throughput runs.",
        "Low-count tails and varying collection schedules need more repetitions.",
        "Sampled CPU/peaks can miss short windows; missing observations remain null."
        ,"Negative memory/CPU changes mean reductions; zero denominators yield null percentages."
    ]});
    write_json(output, &report)?;
    eprintln!("Paired performance/latency: {}", output.display());
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::super::workloads::ProcessSamples;
    use super::*;
    #[test]
    fn manifest_comparison_needs_no_scores_gc_seeds_or_v8_metadata() {
        let directory =
            std::env::temp_dir().join(format!("v8-generic-pair-test-{}", std::process::id()));
        std::fs::create_dir(&directory).unwrap();
        for name in ["before", "after"] {
            let path = directory.join(name);
            std::fs::create_dir(&path).unwrap();
            std::fs::write(
                path.join("run.json"),
                json!({
                    "ExitCode":0,"TimedOut":false,"StartedUtc":"1970-01-01T00:00:00Z",
                    "Arguments":["application.js"]
                })
                .to_string(),
            )
            .unwrap();
            std::fs::write(
                path.join("stdout.log"),
                concat!(
                    "{\"activity\":\"startup\",\"phase\":\"begin\",\"timestampMs\":10}\n",
                    "{\"activity\":\"startup\",\"phase\":\"end\",\"timestampMs\":20}\n",
                    "{\"runComplete\":true,\"results\":[{\"name\":\"startup\"}]}\n"
                ),
            )
            .unwrap();
            let private = if name == "before" { 200 } else { 100 };
            std::fs::write(path.join("process-memory.csv"),format!(
                "ElapsedMs,PrivateBytes,WorkingSetBytes,CpuMs\n10,{private},80,1\n20,{private},90,3\n"
            )).unwrap();
        }
        let manifest =
            json!({"performance":[{"id":"repeat-a","control":"before","candidate":"after"}]});
        std::fs::write(directory.join("pairs.json"), manifest.to_string()).unwrap();
        let output = directory.join("report.json");
        run(&directory, &output, &[], &[], None).unwrap();
        let report = super::super::workloads::read_json(&output).unwrap();
        assert_eq!(report["pair_ids"], json!(["repeat-a"]));
        assert_eq!(report["score_available"], false);
        assert_eq!(report["gc_latency_available"], false);
        assert!(report["median_suite_score_change_percent"].is_null());
        assert_eq!(
            report["plans"]["startup"]["paired_metric_summary"]["private_peak_change_percent"]["median"],
            -50.0
        );
        assert!(report["plans"]["startup"]["gc_latency_control"].is_null());
        assert!(run(&directory, &output, &[], &[], None).is_err());
        std::fs::remove_file(&output).unwrap();
        let timing = json!({
            "performance":[{"id":"repeat-a","control":"before","candidate":"after"}],
            "latency":[{"id":"timing-a","control":"before","candidate":"after"}]
        });
        std::fs::write(directory.join("pairs.json"), timing.to_string()).unwrap();
        assert!(run(&directory, &output, &[], &[], None).is_err());
        assert!(!output.exists());
        let mut invalid = manifest;
        invalid["performance"][0]["control"] = json!("..\\outside");
        std::fs::write(directory.join("pairs.json"), invalid.to_string()).unwrap();
        assert!(run(&directory, &output, &[], &[], None).is_err());
        assert!(!output.exists());
        for name in ["before", "after"] {
            for file in ["run.json", "stdout.log", "process-memory.csv"] {
                std::fs::remove_file(directory.join(name).join(file)).unwrap();
            }
            std::fs::remove_dir(directory.join(name)).unwrap();
        }
        std::fs::remove_file(directory.join("pairs.json")).unwrap();
        std::fs::remove_dir(directory).unwrap();
    }
    #[test]
    fn paired_changes_preserve_direction_and_missing_observations() {
        assert_eq!(percent_change(Some(200), Some(100)), Some(-50.0));
        assert_eq!(percent_change(Some(100), Some(200)), Some(100.0));
        assert_eq!(percent_change(Some(0), Some(1)), None);
        assert_eq!(percent_change(None, Some(1)), None);
    }
    #[test]
    fn scope_breakdown_excludes_counters_and_preserves_collector_details() {
        let records = vec![json!({"pause":7.0,"gc":"mc","mark":3.0,"sweep":2.0,
            "mark.js_global_proxies":99,"incremental.steps_count":123,"start_object_size":1024})];
        let report = gc_phase_stats(&records).unwrap();
        assert_eq!(report["scopes_by_collector"]["mc"]["mark"]["p50_ms"], 3.0);
        assert!(
            report["scopes_by_collector"]["mc"]
                .get("mark.js_global_proxies")
                .is_none()
        );
        assert_eq!(report["longest_collections"][0]["start_object_size"], 1024);
    }
    #[test]
    fn gc_categories_are_not_combined_or_silently_missing() {
        let run = WorkloadRun {
            metadata: Value::Null,
            plans: BTreeMap::<String, ProcessSamples>::new(),
            scores: BTreeMap::new(),
            gc: BTreeMap::from([(
                "A".into(),
                BTreeMap::from([("all".into(), vec![2.0, 4.0]), ("major".into(), vec![4.0])]),
            )]),
            gc_records: 2,
            gc_details: BTreeMap::new(),
        };
        let value = latency(&run.gc, run.gc_records).unwrap();
        assert_eq!(value["A"]["all"]["p50_ms"], 3.0);
        assert_eq!(value["A"]["major"]["count"], 1);
        let mut empty = run;
        empty.gc_records = 0;
        assert!(latency(&empty.gc, empty.gc_records).is_err());
    }
}
