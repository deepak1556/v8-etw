use crate::Result;
use serde_json::{Value, json};
use std::collections::{BTreeMap, HashMap};
use std::fs::{self, File};
use std::io::{BufRead, BufReader};
use std::path::Path;

pub fn decode(bytes: &[u8]) -> Result<BTreeMap<String, Value>> {
    const HEADER_BYTES: usize = (12 + 24) * 8;
    if bytes.len() <= HEADER_BYTES {
        return Err("Truncated Zone ETW record.".into());
    }
    let mut words = [0u64; 36];
    for (word, data) in words
        .iter_mut()
        .zip(bytes[..HEADER_BYTES].as_chunks::<8>().0)
    {
        *word = u64::from_le_bytes(*data);
    }
    if words[0] != 1 || !(1..=14).contains(&words[2]) || words[11] > 24 {
        return Err("Unsupported Zone ETW schema/kind/stack depth.".into());
    }
    let label = &bytes[HEADER_BYTES..];
    if label.last() != Some(&0) || label[..label.len() - 1].contains(&0) {
        return Err("Invalid Zone name terminator.".into());
    }
    let name = std::str::from_utf8(&label[..label.len() - 1]).map_err(|e| e.to_string())?;
    let keys = [
        "SchemaVersion",
        "Sequence",
        "Kind",
        "Zone",
        "Allocator",
        "Segment",
        "CapacityBytes",
        "UsedBytes",
        "ExpansionRequestBytes",
        "Managed",
        "FailedWrites",
        "StackDepth",
    ];
    let mut fields = BTreeMap::new();
    for (index, key) in keys.iter().enumerate() {
        let value = if matches!(index, 3..=5) {
            json!(format!("0x{:x}", words[index]))
        } else {
            json!(words[index])
        };
        fields.insert((*key).to_owned(), value);
    }
    fields.insert("ZoneName".into(), json!(name));
    if words[2] == 11 {
        fields.insert("TypeInstanceSize".into(), json!(words[5]));
    }
    if words[2] == 13 {
        fields.insert("SnapshotId".into(), json!(words[5]));
    }
    fields.insert(
        "NativeStack".into(),
        json!(
            words[12..12 + words[11] as usize]
                .iter()
                .map(|address| format!("0x{address:x}"))
                .collect::<Vec<_>>()
        ),
    );
    Ok(fields)
}

#[derive(Default)]
struct Zone {
    name: String,
    allocator: String,
    created_sequence: u64,
    segment_count: u64,
    capacity: u64,
    peak_capacity: u64,
    peak_used_observed: u64,
    end_used: Option<u64>,
    end_capacity: Option<u64>,
    resets: u64,
    restores: u64,
    destroyed: bool,
    segments_returned: u64,
}

pub fn run(directory: &Path) -> Result<()> {
    let mut zones = Vec::<Zone>::new();
    let mut active = HashMap::<String, usize>::new();
    let mut segments = HashMap::<String, (usize, u64)>::new();
    let mut previous = 0u64;
    let mut lifecycle_events = 0u64;
    let mut owned_bytes = 0u64;
    let mut peak_owned_bytes = 0u64;
    let mut peak_sequence = 0;
    let mut peak_zones = Vec::new();
    let mut active_capacity_by_name = BTreeMap::<String, u64>::new();
    let mut warnings = Vec::new();
    let mut warning_count = 0u64;
    let mut benchmark_markers = Vec::new();
    let mut type_stats = BTreeMap::<String, BTreeMap<String, Value>>::new();
    let mut phase_stats = BTreeMap::<String, Value>::new();
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
        let event: Value = serde_json::from_str(&line).map_err(|e| e.to_string())?;
        let fields = &event["properties"];
        let number = |key: &str| {
            fields[key]
                .as_u64()
                .ok_or_else(|| format!("Missing Zone field {key}"))
        };
        let text = |key: &str| {
            fields[key]
                .as_str()
                .ok_or_else(|| format!("Missing Zone field {key}"))
        };
        let sequence = number("Sequence")?;
        if sequence != previous + 1 || number("FailedWrites")? != 0 {
            return Err("Zone ETW sequence gap or provider write failure.".into());
        }
        previous = sequence;
        let kind = number("Kind")?;
        if matches!(kind, 13 | 14) {
            continue;
        }
        if kind <= 9 {
            lifecycle_events += 1;
        }
        if kind == 10 {
            benchmark_markers.push(json!({
                "name":text("ZoneName")?,"phase":if number("UsedBytes")?==1{"begin"}else{"end"},
                "sequence":sequence,"timestamp_raw":event["timestamp_raw"],
                "owned_segment_bytes":owned_bytes
            }));
            continue;
        }
        let pointer = text("Zone")?.to_owned();
        if kind == 8 {
            continue;
        }
        if kind == 1 {
            if active
                .get(&pointer)
                .is_some_and(|index| !zones[*index].destroyed)
            {
                return Err("Zone address reused before destruction.".into());
            }
            active.insert(pointer, zones.len());
            zones.push(Zone {
                name: text("ZoneName")?.into(),
                allocator: text("Allocator")?.into(),
                created_sequence: sequence,
                ..Default::default()
            });
            continue;
        }
        let Some(index) = active.get(&pointer).copied() else {
            warning_count += 1;
            if warnings.len() < 16 {
                warnings.push(format!(
                    "Pre-existing/unobserved Zone {pointer} at {sequence}."
                ));
            }
            continue;
        };
        let zone = &mut zones[index];
        let capacity = number("CapacityBytes")?;
        let used = number("UsedBytes")?;
        if kind == 11 {
            let instance_size = number("TypeInstanceSize")?;
            let row = type_stats
                .entry(zone.name.clone())
                .or_default()
                .entry(text("ZoneName")?.to_owned())
                .or_insert_with(|| {
                    json!({
                        "allocated_bytes":0,"deleted_bytes":0,"allocation_count":0,
                        "instance_size_bytes":instance_size
                    })
                });
            if row["instance_size_bytes"].as_u64() != Some(instance_size) {
                return Err("Inconsistent Zone type size.".into());
            }
            for (key, value) in [
                ("allocated_bytes", capacity),
                ("deleted_bytes", used),
                ("allocation_count", number("ExpansionRequestBytes")?),
            ] {
                row[key] = json!(
                    row[key]
                        .as_u64()
                        .ok_or("Invalid type aggregate.")?
                        .checked_add(value)
                        .ok_or("Type aggregate overflow.")?
                );
            }
            continue;
        }
        if kind == 12 {
            let row = phase_stats
                .entry(text("ZoneName")?.to_owned())
                .or_insert_with(|| {
                    json!({
                        "count":0,"summed_allocated_bytes":0,"max_absolute_allocated_bytes":0
                    })
                });
            row["count"] = json!(row["count"].as_u64().ok_or("Invalid phase count.")? + 1);
            row["summed_allocated_bytes"] = json!(
                row["summed_allocated_bytes"]
                    .as_u64()
                    .ok_or("Invalid phase aggregate.")?
                    .checked_add(capacity)
                    .ok_or("Phase aggregate overflow.")?
            );
            row["max_absolute_allocated_bytes"] = json!(
                row["max_absolute_allocated_bytes"]
                    .as_u64()
                    .ok_or("Invalid phase peak.")?
                    .max(number("ExpansionRequestBytes")?)
            );
            continue;
        }
        if kind == 2 {
            let segment = text("Segment")?.to_owned();
            if segments.insert(segment, (index, capacity)).is_some() {
                return Err("Segment allocated twice without return.".into());
            }
            zone.segment_count += 1;
            zone.capacity = zone
                .capacity
                .checked_add(capacity)
                .ok_or("Zone capacity overflow.")?;
            owned_bytes = owned_bytes
                .checked_add(capacity)
                .ok_or("Total Zone capacity overflow.")?;
            *active_capacity_by_name
                .entry(zone.name.clone())
                .or_default() += capacity;
            zone.peak_used_observed = zone.peak_used_observed.max(used);
        } else if kind == 3 {
            let segment = text("Segment")?;
            let (owner, size) = segments
                .remove(segment)
                .ok_or("Segment returned without observed allocation.")?;
            if owner != index || size != capacity {
                return Err("Segment owner/size mismatch.".into());
            }
            zone.capacity = zone
                .capacity
                .checked_sub(size)
                .ok_or("Zone capacity underflow.")?;
            owned_bytes = owned_bytes
                .checked_sub(size)
                .ok_or("Total Zone capacity underflow.")?;
            let named = active_capacity_by_name
                .get_mut(&zone.name)
                .ok_or("Missing named Zone capacity.")?;
            *named = named
                .checked_sub(size)
                .ok_or("Named Zone capacity underflow.")?;
            zone.segments_returned += 1;
        } else {
            if used > capacity {
                return Err("Zone used bytes exceed capacity.".into());
            }
            zone.peak_used_observed = zone.peak_used_observed.max(used);
            match kind {
                4 => {}
                5 => zone.resets += 1,
                6 => zone.restores += 1,
                7 => {
                    zone.destroyed = true;
                    zone.end_used = Some(used);
                    zone.end_capacity = Some(capacity);
                }
                9 => {}
                _ => return Err("Unknown Zone kind.".into()),
            }
        }
        zone.peak_capacity = zone.peak_capacity.max(zone.capacity);
        if owned_bytes > peak_owned_bytes {
            peak_owned_bytes = owned_bytes;
            peak_sequence = sequence;
            peak_zones = active_capacity_by_name
                .iter()
                .filter(|(_, bytes)| **bytes > 0)
                .map(|(name, bytes)| json!({"zone_name":name,"capacity_bytes":bytes}))
                .collect();
        }
    }
    if previous == 0 {
        return Err("Zone provider missing from capture.".into());
    }
    let mut grouped = BTreeMap::<String, Value>::new();
    let mut closed_frontier_buckets = BTreeMap::<String, BTreeMap<u64, (u64, u64, u64)>>::new();
    for zone in &zones {
        let row = grouped.entry(zone.name.clone()).or_insert_with(|| {
            json!({
                "instances":0,"segments_allocated":0,"segments_returned":0,
                "summed_peak_capacity_bytes":0,"summed_observed_peak_used_bytes":0,
                "peak_instance_capacity_bytes":0,"closed_capacity_bytes":0,
                "closed_used_bytes":0,"closed_slack_bytes":0,
                "reset_count":0,"snapshot_restore_count":0,"live_instances":0
            })
        });
        for (key, value) in [
            ("instances", 1),
            ("segments_allocated", zone.segment_count),
            ("segments_returned", zone.segments_returned),
            ("summed_peak_capacity_bytes", zone.peak_capacity),
            ("summed_observed_peak_used_bytes", zone.peak_used_observed),
            ("reset_count", zone.resets),
            ("snapshot_restore_count", zone.restores),
            ("live_instances", u64::from(!zone.destroyed)),
        ] {
            let old = row[key].as_u64().ok_or("Invalid Zone aggregation field.")?;
            row[key] = json!(old.checked_add(value).ok_or("Zone aggregate overflow.")?);
        }
        row["peak_instance_capacity_bytes"] = json!(
            row["peak_instance_capacity_bytes"]
                .as_u64()
                .ok_or("Invalid Zone peak.")?
                .max(zone.peak_capacity)
        );
        if let (Some(capacity), Some(used)) = (zone.end_capacity, zone.end_used) {
            let upper = [0u64, 256, 1024, 4096, 8192, 32768, 1048576, u64::MAX]
                .into_iter()
                .find(|upper| used <= *upper)
                .ok_or("Missing Zone frontier bucket.")?;
            let bin = closed_frontier_buckets
                .entry(zone.name.clone())
                .or_default()
                .entry(upper)
                .or_default();
            bin.0 += 1;
            bin.1 += capacity;
            bin.2 += used;
            for (key, value) in [
                ("closed_capacity_bytes", capacity),
                ("closed_used_bytes", used),
                ("closed_slack_bytes", capacity - used),
            ] {
                row[key] = json!(row[key].as_u64().ok_or("Invalid Zone aggregate.")? + value);
            }
        }
    }
    let mut largest_instances: Vec<_> = zones.iter().collect();
    largest_instances.sort_by_key(|zone| std::cmp::Reverse(zone.peak_capacity));
    largest_instances.truncate(1000);
    let instances:Vec<_>=largest_instances.into_iter().map(|zone|json!({
        "zone_name":zone.name,"allocator":zone.allocator,"created_sequence":zone.created_sequence,
        "peak_capacity_bytes":zone.peak_capacity,"peak_used_observed_bytes":zone.peak_used_observed,
        "end_capacity_bytes":zone.end_capacity,"end_used_bytes":zone.end_used,
        "destroyed":zone.destroyed,"remaining_segment_capacity_bytes":zone.capacity
    })).collect();
    fs::write(directory.join("zone-report.json"),serde_json::to_vec_pretty(&json!({
        "schema_version":1,"sequence_complete":true,
        "coverage_complete":warning_count==0 && lifecycle_events>0,
        "zone_lifecycle_present":lifecycle_events>0,
        "events":previous,"peak_simultaneous_owned_segment_bytes":peak_owned_bytes,
        "peak_sequence":peak_sequence,"peak_contributing_zones":peak_zones,
        "remaining_owned_segment_bytes":owned_bytes,"warning_count":warning_count,
        "warnings":warnings,"zone_names":grouped,"instances":instances,
        "total_zone_instances":zones.len(),"instance_list_truncated":zones.len()>1000,
        "benchmark_markers":benchmark_markers,
        "type_stats_by_zone":type_stats,"compiler_phase_stats":phase_stats,
        "closed_frontier_buckets":closed_frontier_buckets.into_iter().map(|(name,bins)|(
            name,bins.into_iter().map(|(upper,(count,capacity,used))|json!({
                "upper_used_bytes":upper,"instances":count,
                "capacity_bytes":capacity,"used_bytes":used
            })).collect::<Vec<_>>())).collect::<BTreeMap<_,_>>(),
        "limitations":[
            "Capacity is Zone-owned segment memory, not process RSS or total allocator pool retention.",
            "Used bytes are aligned bump-allocation frontiers observed at expansion/reset/restore/destruction, not all-time type-level live demand.",
            "Closed capacity minus used includes segment headers, padding and slack; it is not all reclaimable.",
            "Zone names include parser/compiler/other runtime arenas; attribute by name and native stacks before calling them compiler cost.",
            "Pre-existing Zones without observed creation are explicitly excluded and reported.",
            "Sum of per-instance peaks is traffic-like, not simultaneous peak."
        ]
    })).map_err(|e|e.to_string())?).map_err(|e|e.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn fixed_protocol_checks_version_stack_bounds_and_utf8_name() {
        let mut words = [0u64; 36];
        words[0] = 1;
        words[1] = 1;
        words[2] = 2;
        words[11] = 1;
        words[12] = 0xffffffffffffffff;
        let mut bytes = words
            .iter()
            .flat_map(|word| word.to_le_bytes())
            .collect::<Vec<_>>();
        bytes.extend_from_slice(b"compiler\0");
        let fields = decode(&bytes).unwrap();
        assert_eq!(fields["NativeStack"], json!(["0xffffffffffffffff"]));
        assert_eq!(fields["ZoneName"], "compiler");
        bytes[16] = 11;
        bytes[40] = 16;
        assert_eq!(decode(&bytes).unwrap()["TypeInstanceSize"], 16);
        bytes[16] = 13;
        assert_eq!(decode(&bytes).unwrap()["SnapshotId"], 16);
        bytes[0] = 2;
        assert!(decode(&bytes).is_err());
        assert!(decode(&bytes[..20]).is_err());
    }

    #[test]
    fn plain_allocator_zone_balances_segments_reset_and_restore() {
        let dir = std::env::temp_dir().join(format!("v8-zone-report-test-{}", std::process::id()));
        fs::create_dir(&dir).unwrap();
        let mut records = String::new();
        for (sequence, kind, segment, capacity, used) in [
            (1, 1, "0x0", 0, 0),
            (2, 2, "0x100", 8192, 0),
            (3, 2, "0x200", 16384, 4096),
            (4, 9, "0x0", 24576, 20000),
            (5, 3, "0x200", 16384, 0),
            (6, 6, "0x0", 8192, 1024),
            (7, 5, "0x100", 8192, 0),
            (8, 11, "0x10", 8192, 1024),
            (9, 12, "0x0", 4096, 2048),
            (10, 7, "0x0", 8192, 2048),
            (11, 4, "0x0", 8192, 2048),
            (12, 3, "0x100", 8192, 0),
        ] {
            records += &(json!({"kind":"zone_probe","properties":{
                "Sequence":sequence,"Kind":kind,"Zone":"0x10","Allocator":"0x20",
                "Segment":segment,"CapacityBytes":capacity,"UsedBytes":used,
                "ZoneName":"compiler","FailedWrites":0,"TypeInstanceSize":16,
                "ExpansionRequestBytes":if kind==11{3}else{0}
            }})
            .to_string()
                + "\n");
        }
        fs::write(dir.join("events.jsonl"), &records).unwrap();
        run(&dir).unwrap();
        let report: Value =
            serde_json::from_slice(&fs::read(dir.join("zone-report.json")).unwrap()).unwrap();
        assert_eq!(report["coverage_complete"], true);
        assert_eq!(report["peak_simultaneous_owned_segment_bytes"], 24576);
        assert_eq!(report["remaining_owned_segment_bytes"], 0);
        assert_eq!(report["zone_names"]["compiler"]["closed_slack_bytes"], 6144);
        assert_eq!(report["total_zone_instances"], 1);
        assert_eq!(report["instance_list_truncated"], false);
        assert_eq!(
            report["type_stats_by_zone"]["compiler"]["compiler"],
            json!({"allocated_bytes":8192,"deleted_bytes":1024,
                   "allocation_count":3,"instance_size_bytes":16})
        );
        assert_eq!(
            report["compiler_phase_stats"]["compiler"]["summed_allocated_bytes"],
            4096
        );
        assert_eq!(
            report["closed_frontier_buckets"]["compiler"],
            json!([{"upper_used_bytes":4096,"instances":1,"capacity_bytes":8192,"used_bytes":2048}])
        );
        assert_eq!(
            report["zone_names"]["compiler"]["snapshot_restore_count"],
            1
        );
        fs::remove_file(dir.join("zone-report.json")).unwrap();
        fs::remove_file(dir.join("events.jsonl")).unwrap();
        fs::remove_dir(dir).unwrap();
    }
}
