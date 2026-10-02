use super::workloads::{load_run, number, percentile, text, write_json};
use crate::{Result, validated_decode_summary};
use serde::Serialize;
use serde_json::{Value, json};
use std::collections::BTreeMap;
use std::fs::{File, OpenOptions};
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};

#[derive(Serialize)]
struct Snapshot {
    id: u64,
    reason: String,
    scope_id: u64,
    gc_epoch: u64,
    gc_type: u64,
    isolate: String,
    begin: u64,
    end: u64,
    duration_us: u64,
    metrics: BTreeMap<String, [u64; 3]>,
    native_heap_errors: Vec<[u64; 3]>,
}

pub(super) struct Window {
    pub name: String,
    isolate: String,
    pub begin: u64,
    pub end: u64,
}
struct Operation {
    time: u64,
    isolate: String,
    kind: String,
    bytes: u64,
    ns: u64,
    success: bool,
    address: String,
}

fn components(snapshot: &Snapshot) -> Value {
    let metrics = &snapshot.metrics;
    let [committed, used, physical] = metrics["heap"];
    let [native_committed, native_allocated, native_reserved] = metrics["windows-heaps"];
    let coverage = metrics["windows-heap-coverage"];
    let native_complete =
        coverage[0] > 0 && coverage[1] == 0 && snapshot.native_heap_errors.is_empty();
    let spaces: BTreeMap<_, _> = metrics
        .iter()
        .filter_map(|(name, values)| {
            name.strip_prefix("space/").map(|space| {
                (
                    space.to_owned(),
                    json!({
                        "committed":values[0], "accounted_used":values[1],
                        "physical_accounting":values[2],
                        "available":metrics.get(&format!("available/{space}")).map(|v|v[0])
                    }),
                )
            })
        })
        .collect();
    json!({
        "snapshot_id":snapshot.id,"reason":snapshot.reason,
        "process_private_bytes":metrics["process"][0],
        "process_working_set_bytes":metrics["process"][1],
        "v8_heap_committed_bytes":committed,"v8_heap_accounted_used_bytes":used,
        "v8_heap_physical_accounting_bytes":physical,
        "v8_heap_unoccupied_accounting_bytes":committed.checked_sub(used),
        "heap_accounting_consistent":used<=committed,
        "v8_external_counter_bytes":metrics["heap-external"][0],
        "v8_backing_store_counter_bytes":metrics["heap-external"][1],
        "windows_heaps_committed_bytes":native_committed,
        "windows_heaps_allocated_bytes":native_allocated,
        "windows_heaps_reserved_bytes":native_reserved,
        "windows_heap_coverage_complete":native_complete,
        "windows_heap_unallocated_backing_bytes":if native_complete {native_committed.checked_sub(native_allocated)} else {None},
        "spaces":spaces,
        "main_thread_lab_tails":metrics.iter().filter_map(|(n,v)|n.strip_prefix("lab/").map(|s|(s.to_owned(),v[0]))).collect::<BTreeMap<_,_>>(),
        "wasm_process":metrics.get("wasm-process"),
        "v8_page_pool_backing":metrics.get("v8-page-pool"),
        "v8_page_pool_commit":metrics.get("v8-page-pool-commit"),
        "partition_alloc":metrics.iter().filter_map(|(n,v)|n.strip_prefix("partition/").map(|s|(s.to_owned(),*v))).collect::<BTreeMap<_,_>>()
    })
}

struct DecodedComposition {
    snapshots: Vec<Snapshot>,
    windows: Vec<Window>,
    operations: Vec<Operation>,
    frequency: u64,
}

fn parse(directory: &Path) -> Result<DecodedComposition> {
    let summary = validated_decode_summary(directory)?;
    for key in ["metadata_errors", "property_errors"] {
        if !summary[key].as_object().is_some_and(|x| x.is_empty()) {
            return Err(format!("Composition requires empty {key}."));
        }
    }
    let frequency = number(&summary, "performance_frequency")?;
    if frequency == 0 {
        return Err("Invalid ETW clock frequency.".into());
    }
    let mut pending = BTreeMap::<u64, Snapshot>::new();
    let mut snapshots = Vec::new();
    let mut windows = Vec::new();
    let mut current = None::<Window>;
    let mut operations = Vec::new();
    let mut previous = 0;
    for line in BufReader::with_capacity(
        1024 * 1024,
        File::open(directory.join("events.jsonl")).map_err(|e| e.to_string())?,
    )
    .lines()
    {
        let line = line.map_err(|e| e.to_string())?;
        if !line.contains("\"kind\":\"zone_probe\"") {
            continue;
        }
        if line.len() > 1024 * 1024 {
            return Err("Composition event exceeds bounded record size.".into());
        }
        let event: Value = serde_json::from_str(&line).map_err(|e| e.to_string())?;
        let fields = &event["properties"];
        let sequence = number(fields, "Sequence")?;
        if sequence != previous + 1 || number(fields, "FailedWrites")? != 0 {
            return Err("Probe sequence gap or SDK write failure.".into());
        }
        previous = sequence;
        let timestamp = text(&event, "timestamp_raw")?
            .parse::<u64>()
            .map_err(|e| e.to_string())?;
        let kind = number(fields, "Kind")?;
        let name = text(fields, "ZoneName")?;
        let isolate = text(fields, "Zone")?;
        let values = [
            number(fields, "CapacityBytes")?,
            number(fields, "UsedBytes")?,
            number(fields, "ExpansionRequestBytes")?,
        ];
        if kind == 10 {
            match values[1] {
                1 if current.is_none() => {
                    current = Some(Window {
                        name: name.into(),
                        isolate: isolate.into(),
                        begin: timestamp,
                        end: 0,
                    })
                }
                2 => {
                    let mut window = current.take().ok_or("Activity end without begin.")?;
                    if window.name != name || window.isolate != isolate || timestamp < window.begin
                    {
                        return Err("Activity marker mismatch.".into());
                    }
                    window.end = timestamp;
                    windows.push(window);
                }
                _ => return Err("Invalid/overlapping activity marker.".into()),
            }
        } else if kind == 14 {
            if !matches!(
                name,
                "decommit" | "recommit" | "pool-get" | "pool-put" | "pool-select" | "pool-schedule"
            ) || values[2] > 1
            {
                return Err("Invalid pool operation record.".into());
            }
            operations.push(Operation {
                time: timestamp,
                isolate: isolate.into(),
                kind: name.into(),
                bytes: values[0],
                ns: values[1],
                success: values[2] == 1,
                address: text(fields, "Segment")?.to_owned(),
            });
        } else if kind == 13 {
            let id = number(fields, "SnapshotId")?;
            if let Some(reason) = name.strip_prefix("snapshot-begin/") {
                if pending
                    .insert(
                        id,
                        Snapshot {
                            id,
                            reason: reason.into(),
                            scope_id: values[0],
                            gc_epoch: values[1],
                            gc_type: values[2],
                            isolate: isolate.into(),
                            begin: timestamp,
                            end: 0,
                            duration_us: 0,
                            metrics: BTreeMap::new(),
                            native_heap_errors: Vec::new(),
                        },
                    )
                    .is_some()
                {
                    return Err("Duplicate snapshot begin.".into());
                }
            } else {
                let snapshot = pending
                    .get_mut(&id)
                    .ok_or("Snapshot metric without begin.")?;
                if snapshot.isolate != isolate {
                    return Err("Snapshot isolate changed.".into());
                }
                if name == "snapshot-end" {
                    for key in [
                        "process",
                        "heap",
                        "heap-external",
                        "heap-aux",
                        "sampling",
                        "windows-heaps",
                        "windows-heap-coverage",
                    ] {
                        if !snapshot.metrics.contains_key(key) {
                            return Err(format!("Missing snapshot metric {key}."));
                        }
                        for key in snapshot
                            .metrics
                            .keys()
                            .filter_map(|x| x.strip_prefix("space/"))
                        {
                            if !snapshot.metrics.contains_key(&format!("available/{key}")) {
                                return Err(format!("Missing availability metric for {key}."));
                            }
                        }
                    }
                    if timestamp < snapshot.begin {
                        return Err("Snapshot clock went backwards.".into());
                    }
                    snapshot.end = timestamp;
                    snapshot.duration_us = values[0];
                    snapshots.push(pending.remove(&id).ok_or("Missing completed snapshot.")?);
                } else if name == "windows-heap-error" {
                    snapshot.native_heap_errors.push(values);
                } else if snapshot.metrics.insert(name.into(), values).is_some() {
                    return Err("Duplicate snapshot metric.".into());
                }
            }
        }
    }
    if current.is_some() || !pending.is_empty() || windows.is_empty() || snapshots.is_empty() {
        return Err("Incomplete snapshot/activity capture.".into());
    }
    snapshots.sort_by_key(|x| x.begin);
    Ok(DecodedComposition {
        snapshots,
        windows,
        operations,
        frequency,
    })
}

pub(super) fn activity_windows(directory: &Path) -> Result<Vec<Window>> {
    Ok(parse(directory)?.windows)
}

fn operation_stats(group: &[&Operation], kind: &str) -> Value {
    let durations: Vec<_> = group.iter().map(|x| x.ns as f64 / 1000.0).collect();
    json!({"count":group.len(),"bytes":group.iter().map(|x|x.bytes as u128).sum::<u128>(),
        "failures":if kind=="pool-get" {0} else {group.iter().filter(|x|!x.success).count()},
        "cache_misses":if kind=="pool-get" {group.iter().filter(|x|!x.success).count()} else {0},
        "total_duration_ms":durations.iter().sum::<f64>()/1000.0,
        "p50_duration_us":percentile(&durations,0.5),
        "p95_duration_us":percentile(&durations,0.95),
        "max_duration_us":durations.iter().copied().max_by(f64::total_cmp)})
}

fn reuse_intervals(operations: &[Operation], frequency: u64) -> Result<Vec<(u64, f64)>> {
    if frequency == 0 {
        return Err("Invalid pool reuse clock frequency.".into());
    }
    let mut decommitted = BTreeMap::<String, u64>::new();
    let mut intervals = Vec::new();
    for operation in operations {
        if !operation.success {
            continue;
        }
        if operation.kind == "decommit" {
            decommitted.insert(operation.address.clone(), operation.time);
        } else if operation.kind == "recommit"
            && let Some(start) = decommitted.remove(&operation.address)
        {
            let ticks = operation
                .time
                .checked_sub(start)
                .ok_or("Pool reuse clock went backwards.")?;
            intervals.push((operation.time, ticks as f64 * 1000.0 / frequency as f64));
        }
    }
    Ok(intervals)
}

pub(crate) fn run(input: &Path, baselines: &[PathBuf], output: &Path) -> Result<()> {
    let decoded = if input.join("summary.json").exists() {
        input.to_owned()
    } else {
        input.join("analysis")
    };
    let samples = output.with_file_name(format!(
        "{}-samples.jsonl",
        output
            .file_stem()
            .and_then(|x| x.to_str())
            .ok_or("Invalid output name.")?
    ));
    if output.exists() || samples.exists() {
        return Err("Composition output already exists; refusing overwrite.".into());
    }
    let DecodedComposition {
        snapshots,
        windows,
        operations,
        frequency,
    } = parse(&decoded)?;
    let mut plans = BTreeMap::new();
    let reuse_intervals = reuse_intervals(&operations, frequency)?;
    for window in &windows {
        let rows: Vec<_> = snapshots
            .iter()
            .filter(|x| {
                x.isolate == window.isolate && x.begin >= window.begin && x.end <= window.end
            })
            .collect();
        let peak = rows
            .iter()
            .copied()
            .max_by_key(|x| {
                (
                    x.metrics["process"][0],
                    std::cmp::Reverse(x.begin),
                    std::cmp::Reverse(x.id),
                )
            })
            .ok_or_else(|| format!("No main-isolate snapshots for {}.", window.name))?;
        let major: Vec<_> = rows
            .iter()
            .filter(|x| x.reason == "gc-after" && x.gc_type & 4 != 0)
            .collect();
        let own_ops: Vec<_> = operations
            .iter()
            .filter(|x| {
                (x.isolate == window.isolate || x.isolate == "0x0")
                    && x.time >= window.begin
                    && x.time <= window.end
            })
            .collect();
        let ops: BTreeMap<_, _> = [
            "decommit",
            "recommit",
            "pool-get",
            "pool-put",
            "pool-select",
            "pool-schedule",
        ]
        .into_iter()
        .map(|kind| {
            let group: Vec<_> = own_ops.iter().copied().filter(|x| x.kind == kind).collect();
            (kind, operation_stats(&group, kind))
        })
        .collect();
        let mut hypotheses = Vec::new();
        if let Some(pool) = peak
            .metrics
            .get("v8-page-pool")
            .filter(|x| x.iter().any(|n| *n > 0))
        {
            hypotheses.push(json!({"kind":"retained-v8-page-backing",
                "normal_backing_at_own_peak_bytes":pool[0],"large_backing_at_own_peak_bytes":pool[1],"zone_backing_at_own_peak_bytes":pool[2],
                "interpretation":"Cached reservations are not live workload data; verify commitment, reuse and latency before selecting a policy."}));
        }
        let reclaim: BTreeMap<_, _> = peak
            .metrics
            .iter()
            .filter(|(n, v)| {
                n.starts_with("partition/") && n.ends_with("/reclaimable") && (v[0] > 0 || v[1] > 0)
            })
            .collect();
        if !reclaim.is_empty() {
            hypotheses.push(json!({"kind":"partition-reclaimable-backing","decommittable_discardable_by_root":reclaim}));
        }
        let value = json!({
            "snapshot_count":rows.len(),
            "max_observed_snapshot_gap_ms":rows.windows(2).map(|p|(p[1].begin-p[0].begin)as f64*1000.0/frequency as f64).max_by(f64::total_cmp),
            "snapshot_peak":components(peak),"entry":components(rows.first().ok_or("Missing entry.")?),"end":components(rows.last().ok_or("Missing end.")?),
            "natural_major_gc_epilogue_count":major.len(),"natural_major_gc_epilogues":major.iter().rev().take(100).rev().map(|x|components(x)).collect::<Vec<_>>(),
            "major_gc_list_truncated":major.len()>100,
            "native_heap_partial_snapshots":rows.iter().filter(|x|x.metrics["windows-heap-coverage"][1]>0).count(),
            "allocator_hypotheses":hypotheses,"pool_operations":ops,"within_plan_baseline_runs":[]
        });
        let intervals: Vec<_> = reuse_intervals
            .iter()
            .filter(|(time, _)| *time >= window.begin && *time <= window.end)
            .map(|(_, ms)| *ms)
            .collect();
        let mut value = value;
        value["recommit_reuse_intervals"] = json!({
            "matched_count":intervals.len(),"p50_ms":percentile(&intervals,0.5),
            "p95_ms":percentile(&intervals,0.95),
            "completed_within_ms": ([1_u64,10,50,100,250,1000].into_iter().map(|ms|(
                ms.to_string(),intervals.iter().filter(|x|**x<=ms as f64).count()
            )).collect::<BTreeMap<_,_>>()),
            "limitations":["Intervals are decommit-to-recommit event completion times, not exact idle lifetimes.",
                "Unreused/released pages are censored; this distribution describes only observed successful reuse."]
        });
        if plans.insert(window.name.clone(), value).is_some() {
            return Err("Duplicate activity name.".into());
        }
    }
    let capture = input.join("capture");
    let measured = if capture.join("run.json").exists() {
        Some(load_run(&capture)?)
    } else {
        None
    };
    if let Some(run) = &measured {
        if run.plans.keys().ne(plans.keys()) {
            return Err("ETW/workload plan sets differ.".into());
        }
        for (name, row) in &run.plans {
            plans.get_mut(name).ok_or("Missing plan.")?["process_sampler"] =
                serde_json::to_value(row).map_err(|e| e.to_string())?;
        }
    }
    for baseline in baselines {
        let run = load_run(baseline)?;
        if run.plans.keys().ne(plans.keys()) {
            return Err("Baseline/diagnostic plan sets differ.".into());
        }
        if let Some(measured) = &measured {
            for key in ["V8Revision", "ProfileInputs"] {
                if run.metadata.get(key) != measured.metadata.get(key) {
                    return Err(format!("Baseline {key} differs."));
                }
            }
        } else {
            return Err("Baseline comparison requires capture/run.json metadata.".into());
        }
        for (name, row) in run.plans {
            plans.get_mut(&name).ok_or("Missing plan.")?["within_plan_baseline_runs"]
                .as_array_mut()
                .ok_or("Invalid baseline list.")?
                .push(serde_json::to_value(row).map_err(|e| e.to_string())?);
        }
    }
    let result = json!({"schema_version":1,"plans":plans,"snapshot_count":snapshots.len(),
    "isolate_scopes":snapshots.iter().map(|x|x.scope_id).collect::<std::collections::BTreeSet<_>>(),
    "no_cross_plan_peak_comparison":true,
    "limitations":[
        "Compare each plan only with the same plan; prior plans can carry state forward.",
        "Short sequential snapshots are not atomic and delayed interrupts can miss true peaks.",
        "Accounted-used is not exact live memory; LAB reservations and pending sweeping matter.",
        "Heap/code/backing-store/Windows/PartitionAlloc gauges overlap and must not be summed.",
        "V8 physical accounting is not OS working set; reservations are not resident memory.",
        "Unused capacity includes GC workspace, metadata, rounding and useful headroom.",
        "Shared/worker/process-wide metrics must not be summed across isolate scopes.",
        "Pool operation latency is instrumented, separate from uninstrumented throughput."
    ]});
    let mut history = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&samples)
        .map_err(|e| e.to_string())?;
    for snapshot in &snapshots {
        serde_json::to_writer(&mut history, snapshot).map_err(|e| e.to_string())?;
        history.write_all(b"\n").map_err(|e| e.to_string())?;
    }
    write_json(output, &result)?;
    eprintln!("Activity composition: {}", output.display());
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn reuse_pairs_ignore_failed_operations_and_use_latest_decommit() {
        let op = |time, kind: &str, success| Operation {
            time,
            isolate: "0x1".into(),
            kind: kind.into(),
            bytes: 262144,
            ns: 1000,
            success,
            address: "0x100".into(),
        };
        let operations = vec![
            op(1, "decommit", true),
            op(2, "decommit", true),
            op(3, "recommit", false),
            op(5, "recommit", true),
        ];
        assert_eq!(reuse_intervals(&operations, 1000).unwrap(), vec![(5, 3.0)]);
        assert!(reuse_intervals(&operations, 0).is_err());
        assert!(
            reuse_intervals(&[op(10, "decommit", true), op(9, "recommit", true)], 1000).is_err()
        );
    }
    #[test]
    fn operation_latency_does_not_mix_plans_or_gc_masks() {
        let op = Operation {
            time: 10,
            isolate: "0x1".into(),
            kind: "recommit".into(),
            bytes: 262144,
            ns: 50000,
            success: true,
            address: "0x100".into(),
        };
        let value = operation_stats(&[&op], "recommit");
        assert_eq!(value["bytes"], 262144);
        assert_eq!(value["max_duration_us"], 50.0);
        assert_eq!(value["failures"], 0);
        let miss = Operation {
            success: false,
            ..op
        };
        let value = operation_stats(&[&miss], "pool-get");
        assert_eq!(value["failures"], 0);
        assert_eq!(value["cache_misses"], 1);
    }

    #[test]
    fn incomplete_transport_and_snapshot_records_fail_before_output() {
        let directory =
            std::env::temp_dir().join(format!("v8-composition-test-{}", std::process::id()));
        std::fs::create_dir(&directory).unwrap();
        let summary = json!({"complete":true,"events_lost":0,"buffers_lost":0,
            "target_events":1,"performance_frequency":1000,"metadata_errors":{},"property_errors":{}});
        std::fs::write(directory.join("summary.json"), summary.to_string()).unwrap();
        let event = json!({"kind":"zone_probe","timestamp_raw":"1","properties":{
            "Sequence":1,"FailedWrites":0,"Kind":13,"ZoneName":"snapshot-begin/periodic",
            "Zone":"0x1","SnapshotId":1,"CapacityBytes":1,"UsedBytes":0,"ExpansionRequestBytes":0
        }});
        std::fs::write(directory.join("events.jsonl"), event.to_string()).unwrap();
        assert!(parse(&directory).err().unwrap().contains("Incomplete"));
        let mut bad_summary = summary;
        bad_summary["events_lost"] = json!(1);
        std::fs::write(directory.join("summary.json"), bad_summary.to_string()).unwrap();
        assert!(parse(&directory).is_err());
        for name in ["summary.json", "events.jsonl"] {
            std::fs::remove_file(directory.join(name)).unwrap();
        }
        std::fs::remove_dir(directory).unwrap();
    }
}
