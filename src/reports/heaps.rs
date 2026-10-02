use crate::Result;
use serde_json::{Value, json};
use std::collections::BTreeMap;
use std::fs::{self, File};
use std::io::{BufRead, BufReader};
use std::path::Path;

pub fn stack_frames(hex: &str) -> Result<Value> {
    if !hex.len().is_multiple_of(16) || hex.len() > 48 * 16 {
        return Err("Invalid native allocation stack length.".into());
    }
    let mut frames = Vec::new();
    for chunk in hex.as_bytes().as_chunks::<16>().0 {
        let mut bytes = [0; 8];
        for (index, pair) in chunk.as_chunks::<2>().0.iter().enumerate() {
            bytes[index] =
                u8::from_str_radix(std::str::from_utf8(pair).map_err(|e| e.to_string())?, 16)
                    .map_err(|e| e.to_string())?;
        }
        frames.push(format!("0x{:x}", u64::from_le_bytes(bytes)));
    }
    Ok(json!(frames))
}

fn field(event: &Value, name: &str) -> Result<u64> {
    event["properties"][name]
        .as_u64()
        .ok_or_else(|| format!("Missing probe field {name}"))
}

pub fn run(output: &Path) -> Result<()> {
    let mut samples: BTreeMap<String, (u64, u64, String)> = BTreeMap::new();
    let mut checkpoints: BTreeMap<u64, Value> = BTreeMap::new();
    let mut added = 0u64;
    let mut removed = 0u64;
    let mut unknown_frees = 0u64;
    let mut errors = Vec::new();
    let mut interval = 0u64;
    let mut native_interval = None;
    let mut stopped = false;
    let mut workload_markers = Vec::new();
    for line in BufReader::with_capacity(
        1024 * 1024,
        File::open(output.join("events.jsonl")).map_err(|e| e.to_string())?,
    )
    .lines()
    {
        let line = line.map_err(|e| e.to_string())?;
        // Decoder-owned compact JSONL: exact lifetime traffic is reconciled
        // separately and need not be materialized for checkpoint census.
        if !line.contains("\"kind\":\"heap_probe\"")
            || line.contains("\"event_name\":\"CppgcLifetime\"")
            || line.contains("\"event_name\":\"CppgcAllocationTraffic\"")
        {
            continue;
        }
        let event: Value = serde_json::from_str(&line).map_err(|e| e.to_string())?;
        if event["kind"] != "heap_probe" {
            continue;
        }
        let name = event["event_name"]
            .as_str()
            .ok_or("Memory probe event has no name.")?;
        match name {
            "WorkloadMarker" => {
                workload_markers.push(json!({
                    "timestamp_raw": event["timestamp_raw"],
                    "phase": event["properties"]["Phase"],
                    "suite": event["properties"]["Suite"],
                    "iteration": field(&event, "Iteration")?,
                    "isolate": event["properties"]["Isolate"]
                }));
            }
            "ProbeStarted" => {
                stopped = false;
                if field(&event, "SchemaVersion")? != 1 {
                    return Err("Unsupported probe schema.".into());
                }
                interval = field(&event, "SamplingInterval")?;
                native_interval = event["properties"]["NativeSamplingInterval"].as_u64();
                samples.clear();
            }
            "NativeSampleAdded" => {
                if samples.len() >= 1_000_000 {
                    return Err("Native sample map exceeds one million entries.".into());
                }
                let address = event["properties"]["Address"]
                    .as_str()
                    .ok_or("Missing sample address.")?
                    .to_owned();
                if samples
                    .insert(
                        address,
                        (
                            field(&event, "RequestedBytes")?,
                            field(&event, "EstimatedBytes")?,
                            event["properties"]["Heap"]
                                .as_str()
                                .ok_or("Native sample has no heap identity.")?
                                .to_owned(),
                        ),
                    )
                    .is_some()
                {
                    errors.push("Duplicate live native sample address.".to_owned());
                }
                added += 1;
            }
            "NativeSampleRemoved" => {
                let address = event["properties"]["Address"]
                    .as_str()
                    .ok_or("Missing free address.")?;
                if samples.remove(address).is_some() {
                    removed += 1;
                } else {
                    unknown_frees += 1;
                }
            }
            "CppgcAllocationTraffic" | "CppgcLifetime" => {}
            "ProbeStopped" => {
                stopped = true;
                if field(&event, "FailedWrites")? != 0 {
                    errors.push("Probe stopped with failed writes.".into());
                }
            }
            "CheckpointBegin" => {
                let id = field(&event, "Checkpoint")?;
                if checkpoints.contains_key(&id) {
                    return Err("Duplicate checkpoint ID.".into());
                }
                let bytes: u64 = samples.values().map(|sample| sample.0).sum();
                let estimated: u64 = samples.values().map(|sample| sample.1).sum();
                let mut by_heap: BTreeMap<String, (u64, u64, u64)> = BTreeMap::new();
                for (requested, estimated, heap) in samples.values() {
                    let entry = by_heap.entry(heap.clone()).or_default();
                    entry.0 += 1;
                    entry.1 += requested;
                    entry.2 += estimated;
                }
                checkpoints.insert(id, json!({
                    "checkpoint": id, "phase": event["properties"]["Phase"],
                    "isolate": event["properties"]["Isolate"], "complete": false,
                    "cppgc_allocated_traffic_bytes": event["properties"]["CppgcAllocatedTrafficBytes"],
                    "cppgc_allocation_count": event["properties"]["CppgcAllocationCount"],
                    "native_live_sample_count": samples.len(),
                    "native_sampled_requested_bytes": bytes,
                    "native_estimated_live_bytes": estimated,
                    "native_samples_by_heap": by_heap.into_iter().map(|(heap, (count, requested, estimated))| {
                        (heap, json!({
                            "live_sample_count": count,
                            "sampled_requested_bytes": requested,
                            "estimated_live_bytes": estimated
                        }))
                    }).collect::<BTreeMap<_, _>>(),
                    "records": [],
                }));
            }
            "CheckpointEnd" => {
                let id = field(&event, "Checkpoint")?;
                let checkpoint = checkpoints
                    .get_mut(&id)
                    .ok_or("Checkpoint end without begin.")?;
                let failed = field(&event, "FailedWrites")?;
                checkpoint["failed_native_writes"] = json!(failed);
                checkpoint["complete"] = json!(failed == 0);
                if failed != 0 {
                    errors.push(format!(
                        "Checkpoint {id}: {failed} failed native event writes."
                    ));
                }
            }
            _ => {
                if let Some(id) = event["properties"]["Checkpoint"].as_u64() {
                    let checkpoint = checkpoints
                        .get_mut(&id)
                        .ok_or("Probe data outside checkpoint.")?;
                    checkpoint["records"]
                        .as_array_mut()
                        .ok_or("Invalid checkpoint record array.")?
                        .push(json!({"event": name, "properties": event["properties"]}));
                } else {
                    errors.push(format!("Unrecognized memory probe event: {name}"));
                }
            }
        }
    }
    for checkpoint in checkpoints.values_mut() {
        let records = checkpoint["records"]
            .as_array()
            .ok_or("Invalid checkpoint records.")?;
        let mut census = json!({
            "partition_roots": {}, "partition_buckets": [],
            "v8_spaces": {}, "cppgc_spaces": {}, "cppgc_types_by_space": {}
        });
        for record in records {
            let properties = &record["properties"];
            match record["event"]
                .as_str()
                .ok_or("Invalid checkpoint event name.")?
            {
                "PartitionTotals" | "V8Space" | "CppgcSpace" => {
                    let field = match record["event"].as_str() {
                        Some("PartitionTotals") => "partition_roots",
                        Some("V8Space") => "v8_spaces",
                        _ => "cppgc_spaces",
                    };
                    let heap = properties["Heap"].as_str().ok_or("Missing heap name.")?;
                    census[field][heap] = properties.clone();
                }
                "PartitionBucket" => census["partition_buckets"]
                    .as_array_mut()
                    .ok_or("Invalid partition bucket list.")?
                    .push(properties.clone()),
                "V8HeapTotals" => census["v8_totals"] = properties.clone(),
                "CppgcTotals" => census["cppgc_totals"] = properties.clone(),
                "CppgcType" => {
                    let heap = properties["Heap"].as_str().ok_or("Missing cppgc heap.")?;
                    let name = properties["Type"].as_str().ok_or("Missing cppgc type.")?;
                    let key = format!("{heap}/{name}");
                    let previous = &census["cppgc_types_by_space"][&key];
                    let count = properties["ObjectCount"]
                        .as_u64()
                        .ok_or("Invalid cppgc count.")?;
                    let bytes = properties["AllocatedBytes"]
                        .as_u64()
                        .ok_or("Invalid cppgc bytes.")?;
                    let old_count = if previous.is_null() {
                        0
                    } else {
                        previous["object_count"]
                            .as_u64()
                            .ok_or("Invalid prior cppgc count.")?
                    };
                    let old_bytes = if previous.is_null() {
                        0
                    } else {
                        previous["allocated_bytes"]
                            .as_u64()
                            .ok_or("Invalid prior cppgc bytes.")?
                    };
                    census["cppgc_types_by_space"][key] = json!({
                        "object_count": old_count.checked_add(count).ok_or("Cppgc count overflow.")?,
                        "allocated_bytes": old_bytes.checked_add(bytes).ok_or("Cppgc bytes overflow.")?,
                    });
                }
                _ => {}
            }
        }
        let mut nodes: BTreeMap<u64, (u64, String)> = BTreeMap::new();
        for record in records {
            if record["event"] != "V8AllocationNode" {
                continue;
            }
            let properties = &record["properties"];
            let id = properties["Node"].as_u64().ok_or("Invalid V8 node ID.")?;
            let parent = properties["Parent"]
                .as_u64()
                .ok_or("Invalid V8 parent ID.")?;
            let function = properties["Function"]
                .as_str()
                .ok_or("Invalid V8 function.")?;
            let script = properties["Script"].as_str().ok_or("Invalid V8 script.")?;
            nodes.insert(
                id,
                (
                    parent,
                    format!(
                        "{function}@{script}:{}:{}",
                        properties["Line"], properties["Column"]
                    ),
                ),
            );
        }
        let mut paths: BTreeMap<String, (u64, u64)> = BTreeMap::new();
        for record in records {
            if record["event"] != "V8AllocationSample" {
                continue;
            }
            let properties = &record["properties"];
            if properties["Live"].as_u64() != Some(1) {
                continue;
            }
            let mut id = properties["Node"]
                .as_u64()
                .ok_or("Invalid V8 sample node.")?;
            let mut frames = Vec::new();
            while id != 0 {
                if frames.len() >= 128 {
                    return Err("V8 allocation graph is cyclic or too deep.".into());
                }
                let (parent, frame) = nodes
                    .get(&id)
                    .ok_or("V8 allocation sample references absent node.")?;
                frames.push(frame.clone());
                id = *parent;
            }
            frames.reverse();
            let count = properties["EstimatedCount"]
                .as_u64()
                .ok_or("Invalid V8 sample count.")?;
            let size = properties["ObjectBytes"]
                .as_u64()
                .ok_or("Invalid V8 sample size.")?;
            let bytes = count
                .checked_mul(size)
                .ok_or("V8 allocation estimate overflow.")?;
            let entry = paths.entry(frames.join(" -> ")).or_default();
            entry.0 = entry.0.checked_add(count).ok_or("V8 count overflow.")?;
            entry.1 = entry.1.checked_add(bytes).ok_or("V8 bytes overflow.")?;
        }
        checkpoint["v8_live_allocation_estimates_by_path"] = json!(
            paths
                .into_iter()
                .map(|(path, (count, bytes))| {
                    (
                        path,
                        json!({"estimated_object_count": count, "estimated_live_bytes": bytes}),
                    )
                })
                .collect::<BTreeMap<_, _>>()
        );
        checkpoint["heap_census"] = census;
        if checkpoint["complete"] != true {
            errors.push(format!(
                "Incomplete checkpoint {}",
                checkpoint["checkpoint"]
            ));
        }
    }
    let report = json!({
        "schema_version": 1,
        "sampling_interval": interval,
        "native_sampling_interval": native_interval,
        "native_samples_added": added, "native_samples_removed": removed,
        "unmatched_native_sample_frees": unknown_frees,
        "checkpoints": checkpoints.values().collect::<Vec<_>>(),
        "workload_markers": workload_markers,
        "errors": errors,
        "limitations": [
            "Native allocation/free events are Poisson samples, not a census; EstimatedBytes are sampler weights.",
            "Unknown sample frees can refer to samples created before the session; never infer missing allocation sizes.",
            "Partition root/bucket dumps are non-atomic snapshots across roots, not additive with V8/cppgc totals.",
            "V8 samples are live allocation estimates attributed to JS call paths; use heap-space totals for census.",
            "Cppgc stacks are Poisson allocation-traffic samples; not sampled live lifetimes.",
            "Snapshots do not force GC; dead-but-unswept objects remain included until collection.",
            "Native sampling covers Chromium dispatcher allocators, not arbitrary third-party allocators.",
            "Instrumentation allocations and explicit checkpoints have overhead; compare uninstrumented runs separately."
        ]
    });
    fs::write(
        output.join("heap-report.json"),
        serde_json::to_string_pretty(&report).map_err(|e| e.to_string())?,
    )
    .map_err(|e| e.to_string())?;
    if interval == 0 {
        return Err("ProbeStarted missing; allocation capture is left-truncated.".into());
    }
    if !stopped {
        return Err("ProbeStopped missing; heap capture is right-truncated.".into());
    }
    if !errors.is_empty() {
        return Err("Heap probe capture is incomplete; inspect heap-report.json.".into());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn native_binary_stacks_decode_little_endian_without_precision_loss() {
        assert_eq!(
            stack_frames("3412000000000000ffffffffffffffff").unwrap(),
            json!(["0x1234", "0xffffffffffffffff"])
        );
        assert!(stack_frames("01").is_err());
        assert!(stack_frames("gg00000000000000").is_err());
    }

    #[test]
    fn heap_checkpoints_reconcile_samples_and_reject_truncated_sessions() {
        let directory =
            std::env::temp_dir().join(format!("v8-etw-heap-test-{}", std::process::id()));
        fs::create_dir(&directory).unwrap();
        let event = |name: &str, properties: Value| {
            json!({"kind": "heap_probe", "event_name": name, "properties": properties}).to_string()
                + "\n"
        };
        let mut input = event(
            "ProbeStarted",
            json!({"SchemaVersion": 1, "SamplingInterval": 4096}),
        );
        input += &event(
            "NativeSampleAdded",
            json!({
                "Address": "0x1234", "Heap": "root-a", "RequestedBytes": 64, "EstimatedBytes": 4096
            }),
        );
        input += &event(
            "CheckpointBegin",
            json!({"Checkpoint": 1, "Phase": "retained", "Isolate": 42}),
        );
        input += &event(
            "V8AllocationNode",
            json!({
                "Checkpoint": 1, "Node": 1, "Parent": 0,
                "Function": "allocate", "Script": "bench.js", "Line": 1, "Column": 1
            }),
        );
        input += &event(
            "V8AllocationSample",
            json!({
                "Checkpoint": 1, "Node": 1, "ObjectBytes": 16, "EstimatedCount": 128, "Live": 1
            }),
        );
        for count in [2, 3] {
            input += &event(
                "CppgcType",
                json!({
                    "Checkpoint": 1, "Heap": "Normal", "Type": "Node",
                    "ObjectCount": count, "AllocatedBytes": count * 16
                }),
            );
        }
        input += &event("CheckpointEnd", json!({"Checkpoint": 1, "FailedWrites": 0}));
        input += &event("NativeSampleRemoved", json!({"Address": "0x1234"}));
        fs::write(directory.join("events.jsonl"), &input).unwrap();
        assert!(run(&directory).unwrap_err().contains("right-truncated"));
        input += &event("ProbeStopped", json!({"FailedWrites": 0}));
        fs::write(directory.join("events.jsonl"), &input).unwrap();
        run(&directory).unwrap();
        let report: Value =
            serde_json::from_slice(&fs::read(directory.join("heap-report.json")).unwrap()).unwrap();
        assert_eq!(report["native_samples_removed"], 1);
        assert_eq!(
            report["checkpoints"][0]["native_estimated_live_bytes"],
            4096
        );
        assert_eq!(
            report["checkpoints"][0]["native_samples_by_heap"]["root-a"],
            json!({"live_sample_count": 1, "sampled_requested_bytes": 64, "estimated_live_bytes": 4096})
        );
        assert_eq!(
            report["checkpoints"][0]["heap_census"]["cppgc_types_by_space"]["Normal/Node"],
            json!({"object_count": 5, "allocated_bytes": 80})
        );
        assert_eq!(
            report["checkpoints"][0]["v8_live_allocation_estimates_by_path"]["allocate@bench.js:1:1"],
            json!({"estimated_object_count": 128, "estimated_live_bytes": 2048})
        );
        fs::remove_file(directory.join("events.jsonl")).unwrap();
        fs::remove_file(directory.join("heap-report.json")).unwrap();
        fs::remove_dir(directory).unwrap();
    }
}
