use crate::Result;
use serde_json::{Value, json};
use std::collections::{BTreeMap, HashMap};
use std::fs::{self, File};
use std::io::{BufRead, BufReader, BufWriter, Write};
use std::path::Path;
use std::time::Instant;

#[derive(Clone)]
struct Object {
    id: u64,
    bytes: u64,
    gc_info: u64,
    birth_major: u64,
    seeded: bool,
    requested_bytes: Option<u64>,
}

#[derive(Default)]
struct Heap {
    id: String,
    initial_known: bool,
    seed_open: bool,
    destroyed: bool,
    allocations: u64,
    seeds: u64,
    frees: u64,
    moves: u64,
    resizes: u64,
    teardown_objects: u64,
    completed_major: u64,
    gc: Option<(u64, bool)>,
    live: HashMap<String, Object>,
    problems: Vec<String>,
    problem_count: u64,
    header_bytes: Option<u64>,
    major_gc_history: Vec<Value>,
}

impl Heap {
    fn warn(&mut self, message: String) {
        self.problem_count += 1;
        if self.problems.len() < 16 {
            self.problems.push(message);
        }
    }
}
#[derive(Default)]
struct History {
    heaps: Vec<Heap>,
    current: HashMap<String, usize>,
    names: HashMap<u64, String>,
    ended: bool,
    sequence_errors: Vec<String>,
}

fn number(event: &Value, name: &str) -> Result<u64> {
    event["properties"][name]
        .as_u64()
        .ok_or_else(|| format!("Lifetime event missing {name}"))
}
fn text<'a>(event: &'a Value, name: &str) -> Result<&'a str> {
    event["properties"][name]
        .as_str()
        .ok_or_else(|| format!("Lifetime event missing {name}"))
}

impl History {
    fn apply(&mut self, event: &Value) -> Result<Value> {
        let kind = number(event, "Kind")?;
        let sequence = number(event, "Sequence")?;
        let raw_heap = text(event, "HeapId")?.to_owned();
        if kind == 12 {
            self.ended = true;
            return Ok(json!({"sequence": sequence, "kind": "capture_end"}));
        }
        if self.ended {
            return Err("Lifetime event after capture end.".into());
        }
        if kind == 0
            && self
                .current
                .get(&raw_heap)
                .is_some_and(|index| !self.heaps[*index].destroyed)
        {
            return Err("Heap-created event overlaps an active heap identity.".into());
        }
        let index = if kind == 0 || !self.current.contains_key(&raw_heap) {
            let index = self.heaps.len();
            self.heaps.push(Heap {
                id: format!("{raw_heap}#{index}"),
                initial_known: kind == 0,
                ..Default::default()
            });
            self.current.insert(raw_heap.clone(), index);
            index
        } else {
            self.current[&raw_heap]
        };
        let heap = &mut self.heaps[index];
        let address = text(event, "Address")?.to_owned();
        let bytes = number(event, "AllocatedBytes")?;
        let gc_info = number(event, "GCInfo")?;
        let epoch = number(event, "GcEpoch")?;
        if matches!(kind, 4 | 7) && event["properties"]["RequestedKnown"] == 1 {
            let requested = number(event, "RequestedBytes")?;
            if let Some(header) = heap.header_bytes
                && requested
                    .checked_add(header)
                    .is_none_or(|total| total > bytes)
            {
                return Err("Requested payload/header exceeds allocation capacity.".into());
            }
        }
        let mut allocation_id = None;
        match kind {
            0 => heap.header_bytes = Some(bytes),
            1 => {
                if heap.initial_known || heap.seed_open {
                    return Err("Duplicate seed start.".into());
                }
                heap.seed_open = true;
                heap.header_bytes = Some(bytes);
            }
            2 | 4 => {
                if heap.destroyed {
                    return Err("Allocation on destroyed heap.".into());
                }
                if kind == 2 && !heap.seed_open {
                    return Err("Seed object outside inventory.".into());
                }
                if bytes == 0 || address == "0x0" {
                    return Err("Invalid zero-sized/null allocation.".into());
                }
                if heap.live.contains_key(&address) {
                    heap.warn(format!(
                        "Address {address} allocated twice without a free/move."
                    ));
                }
                let birth_major =
                    heap.completed_major + u64::from(heap.gc.is_some_and(|(_, major)| major));
                heap.live.insert(
                    address.clone(),
                    Object {
                        id: sequence,
                        bytes,
                        gc_info,
                        birth_major,
                        seeded: kind == 2,
                        requested_bytes: if event["properties"]["RequestedKnown"] == 1 {
                            Some(number(event, "RequestedBytes")?)
                        } else {
                            None
                        },
                    },
                );
                allocation_id = Some(sequence);
                if kind == 2 {
                    heap.seeds += 1;
                } else {
                    heap.allocations += 1;
                }
            }
            3 => {
                if !heap.seed_open {
                    return Err("Seed end without begin.".into());
                }
                heap.seed_open = false;
                heap.initial_known = true;
            }
            5 => {
                if let Some(object) = heap.live.remove(&address) {
                    allocation_id = Some(object.id);
                    if object.bytes != bytes || object.gc_info != gc_info {
                        heap.warn(format!(
                            "Free metadata mismatch for allocation {}.",
                            object.id
                        ));
                    }
                    heap.frees += 1;
                } else {
                    heap.warn(format!("Free without known allocation: {address}."));
                }
            }
            6 => {
                let target = text(event, "OtherAddress")?.to_owned();
                if target == "0x0" || target == address {
                    return Err("Invalid relocation target.".into());
                }
                if let Some(object) = heap.live.remove(&address) {
                    allocation_id = Some(object.id);
                    if object.bytes != bytes || object.gc_info != gc_info {
                        heap.warn(format!(
                            "Move metadata mismatch for allocation {}.",
                            object.id
                        ));
                    }
                    if heap.live.insert(target, object).is_some() {
                        heap.warn("Relocation overwrote another live object.".into());
                    }
                    heap.moves += 1;
                } else {
                    heap.warn(format!("Move from unknown object: {address}."));
                }
            }
            7 => {
                if bytes == 0 {
                    return Err("Zero-sized resize.".into());
                }
                if let Some(object) = heap.live.get_mut(&address) {
                    allocation_id = Some(object.id);
                    object.bytes = bytes;
                    object.requested_bytes = if event["properties"]["RequestedKnown"] == 1 {
                        Some(number(event, "RequestedBytes")?)
                    } else {
                        None
                    };
                    if object.gc_info != gc_info {
                        heap.warn("Resize changed GC type.".into());
                    }
                    heap.resizes += 1;
                } else {
                    heap.warn(format!("Resize of unknown object: {address}."));
                }
            }
            8 => {
                if heap.gc.is_some() {
                    heap.warn("GC begin while previous cycle is unfinished.".into());
                }
                heap.gc = Some((epoch, number(event, "MajorGC")? == 1));
            }
            9 => match heap.gc.take() {
                Some((start, major)) if start == epoch => {
                    if major {
                        heap.completed_major += 1;
                        let mut by_type: BTreeMap<u64, (u64, u64)> = BTreeMap::new();
                        for object in heap.live.values() {
                            let entry = by_type.entry(object.gc_info).or_default();
                            entry.0 += 1;
                            entry.1 += object.bytes;
                        }
                        heap.major_gc_history.push(json!({
                            "gc_epoch": epoch, "sequence": sequence,
                            "live_objects": heap.live.len(),
                            "live_bytes": heap.live.values().map(|object| object.bytes).sum::<u64>(),
                            "live_types_by_gc_info": by_type
                        }));
                    }
                }
                _ => heap.warn(format!("GC end {epoch} has no matching begin.")),
            },
            10 => {
                let name = text(event, "TypeName")?;
                if !name.is_empty() {
                    self.names.entry(gc_info).or_insert_with(|| name.to_owned());
                }
            }
            11 => {
                heap.teardown_objects += heap.live.len() as u64;
                heap.live.clear();
                heap.destroyed = true;
            }
            _ => return Err(format!("Unknown lifetime kind: {kind}")),
        }
        Ok(json!({
            "sequence": sequence, "heap_id": heap.id, "kind": kind,
            "allocation_id": allocation_id, "address": address,
            "other_address": event["properties"]["OtherAddress"], "allocated_bytes": bytes,
            "gc_info": gc_info, "gc_epoch": epoch, "timestamp_raw": event["timestamp_raw"],
            "native_stack": event["properties"]["NativeStack"],
            "type_name": event["properties"]["TypeName"],
        }))
    }

    fn report(&self) -> Value {
        let transport_complete = self.ended && self.sequence_errors.is_empty();
        let heaps: Vec<Value> = self.heaps.iter().map(|heap| {
            let complete = transport_complete && heap.initial_known && !heap.seed_open && heap.problems.is_empty();
            let mut types: BTreeMap<String, (u64, u64, u64, u64)> = BTreeMap::new();
            let mut candidates: BTreeMap<(u64, u64), Value> = BTreeMap::new();
            let mut candidate_count = 0u64;
            let mut known_requested = 0u64;
            let mut known_padding = 0u64;
            let mut unknown_requested_objects = 0u64;
            for (address, object) in &heap.live {
                if let (Some(requested), Some(header)) = (object.requested_bytes, heap.header_bytes) {
                    known_requested += requested;
                    let payload_with_header = requested + header;
                    known_padding += object.bytes.saturating_sub(payload_with_header);
                } else { unknown_requested_objects += 1; }
                let name = self.names.get(&object.gc_info).cloned()
                    .unwrap_or_else(|| format!("GCInfo {} (type name not observed)", object.gc_info));
                let survived = heap.completed_major.saturating_sub(object.birth_major);
                let entry = types.entry(name.clone()).or_default();
                entry.0 += 1;
                entry.1 += object.bytes;
                entry.2 = entry.2.max(survived);
                entry.3 = entry.3.max(u64::from(object.seeded));
                if complete && survived >= 2 {
                    candidate_count += 1;
                    candidates.insert((object.bytes, object.id), json!({
                        "allocation_id": object.id, "address": address,
                        "type_name": name, "bytes": object.bytes,
                        "completed_major_cycles_survived": survived,
                        "seeded_before_capture": object.seeded,
                    }));
                    if candidates.len() > 1000 { candidates.pop_first(); }
                }
            }
            let by_type: Vec<Value> = types.into_iter().map(|(name, (count, bytes, age, seeded))| json!({
                "type_name": name, "object_count": count, "bytes": bytes,
                "oldest_gc_epoch": age, "includes_pre_capture_objects": seeded != 0
            })).collect();
            json!({
                "heap_id": heap.id, "complete": complete, "initial_inventory_known": heap.initial_known,
                "allocations": heap.allocations, "seeded_objects": heap.seeds,
                "frees": heap.frees, "moves": heap.moves, "resizes": heap.resizes,
                "heap_teardown_releases": heap.teardown_objects,
                "live_objects": heap.live.len(),
                "live_bytes": heap.live.values().map(|object| object.bytes).sum::<u64>(),
                "object_header_bytes": heap.header_bytes.map(|bytes| bytes * heap.live.len() as u64),
                "known_requested_payload_bytes": known_requested,
                "known_rounding_or_retained_capacity_bytes": known_padding,
                "objects_with_unknown_requested_size": unknown_requested_objects,
                "completed_major_gcs": heap.completed_major,
                "major_gc_history": heap.major_gc_history,
                "gc_in_progress_at_end": heap.gc.is_some(), "destroyed": heap.destroyed,
                "survivors_by_type": by_type,
                "retention_candidate_count": candidate_count,
                "retention_candidates_truncated": candidate_count > 1000,
                "retention_candidates": candidates.into_iter().rev().map(|(_, candidate)| candidate).collect::<Vec<_>>(),
                "warning_count": heap.problem_count, "warnings": heap.problems,
            })
        }).collect();
        json!({
            "schema_version": 1, "complete": transport_complete && heaps.iter().all(|heap| heap["complete"] == true),
            "capture_end_observed": self.ended, "heaps": heaps, "warnings": self.sequence_errors,
            "type_catalog_by_gc_info": self.names,
            "limitations": [
                "Stable allocation IDs derive from allocation sequence; moves/resizes preserve IDs, reused addresses do not.",
                "Frees denote logical reclamation before deferred destructors/backing reuse, not physical page release.",
                "Unseeded pre-existing worker heaps are incomplete; newly created worker heaps have complete initial state.",
                "Retention after completed major cycles is a candidate, not a proven leak; establish unintended roots and growth.",
                "Major-GC checkpoint trends distinguish accumulating cohorts from stable legitimate long-lived runtime objects.",
                "Native allocation paths are present for full-stack captures or separately sampled allocation sequences.",
                "Requested payload includes application data and runtime fields; structural header/rounding costs are separate, not application-ownership attribution.",
                "Seeded objects lack original requested sizes; unknown decomposition remains explicit.",
                "Heap destruction ends all remaining storage lifetimes without implying that all destructors ran."
            ]
        })
    }
}

pub fn run(directory: &Path) -> Result<()> {
    let mut history = History::default();
    let mut pending = BTreeMap::new();
    let mut expected = 1u64;
    let mut found = false;
    let started = Instant::now();
    let mut last_progress = Instant::now();
    let mut records = 0u64;
    let mut output = BufWriter::new(
        File::create(directory.join("cppgc-lifetimes.jsonl")).map_err(|e| e.to_string())?,
    );
    for line in BufReader::with_capacity(
        1024 * 1024,
        File::open(directory.join("events.jsonl")).map_err(|e| e.to_string())?,
    )
    .lines()
    {
        let line = line.map_err(|e| e.to_string())?;
        if !line.contains("\"event_name\":\"CppgcLifetime\"") {
            continue;
        }
        let event: Value = serde_json::from_str(&line).map_err(|e| e.to_string())?;
        if event["kind"] != "heap_probe" || event["event_name"] != "CppgcLifetime" {
            continue;
        }
        found = true;
        records += 1;
        if records.is_multiple_of(100_000) && last_progress.elapsed().as_secs() >= 10 {
            eprintln!(
                "cppgc history: {records} lifecycle records, {} heaps, {:.1}s",
                history.heaps.len(),
                started.elapsed().as_secs_f64()
            );
            last_progress = Instant::now();
        }
        let seq = number(&event, "Sequence")?;
        if seq < expected || pending.insert(seq, event).is_some() {
            return Err("Duplicate/retrograde cppgc lifetime sequence.".into());
        }
        if pending.len() > 65536 {
            let next = *pending
                .first_key_value()
                .ok_or("Missing pending lifetime event.")?
                .0;
            history
                .sequence_errors
                .push(format!("Missing sequence {expected} before {next}."));
            expected = next;
        }
        while let Some(event) = pending.remove(&expected) {
            let record = history.apply(&event)?;
            serde_json::to_writer(&mut output, &record).map_err(|e| e.to_string())?;
            output.write_all(b"\n").map_err(|e| e.to_string())?;
            expected += 1;
        }
    }
    if !found {
        return Ok(());
    }
    for (seq, event) in pending {
        if seq != expected {
            history
                .sequence_errors
                .push(format!("Missing sequence {expected} before {seq}."));
        }
        let record = history.apply(&event)?;
        serde_json::to_writer(&mut output, &record).map_err(|e| e.to_string())?;
        output.write_all(b"\n").map_err(|e| e.to_string())?;
        expected = seq + 1;
    }
    output.flush().map_err(|e| e.to_string())?;
    let report = history.report();
    fs::write(
        directory.join("cppgc-history.json"),
        serde_json::to_string_pretty(&report).map_err(|e| e.to_string())?,
    )
    .map_err(|e| e.to_string())?;
    if !history.ended || !history.sequence_errors.is_empty() {
        return Err("Incomplete cppgc lifetime stream; leak claims are disabled.".into());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    fn event(seq: u64, kind: u64, address: &str, other: &str, bytes: u64, epoch: u64) -> Value {
        json!({"properties": {
            "Sequence":seq, "Kind":kind, "HeapId":"0x10", "Address":address,
            "OtherAddress":other, "AllocatedBytes":bytes, "GCInfo":1, "GcEpoch":epoch,
            "MajorGC":1, "TypeName":"TestNode"
        }})
    }
    #[test]
    fn moves_resizes_and_address_reuse_preserve_correct_identity() {
        let mut history = History::default();
        history.apply(&event(1, 0, "0x0", "0x0", 0, 0)).unwrap();
        history.apply(&event(2, 4, "0x100", "0x0", 16, 0)).unwrap();
        assert_eq!(
            history
                .apply(&event(3, 6, "0x100", "0x200", 16, 0))
                .unwrap()["allocation_id"],
            2
        );
        history.apply(&event(4, 7, "0x200", "0x0", 32, 0)).unwrap();
        assert_eq!(
            history.apply(&event(5, 5, "0x200", "0x0", 32, 0)).unwrap()["allocation_id"],
            2
        );
        assert_eq!(
            history.apply(&event(6, 4, "0x100", "0x0", 16, 0)).unwrap()["allocation_id"],
            6
        );
        history.apply(&event(7, 12, "0x0", "0x0", 0, 0)).unwrap();
        let report = history.report();
        assert_eq!(report["heaps"][0]["live_bytes"], 16);
        assert_eq!(report["heaps"][0]["frees"], 1);
        assert_eq!(report["heaps"][0]["moves"], 1);
        assert_eq!(report["heaps"][0]["resizes"], 1);
    }
    #[test]
    fn retention_requires_completed_major_cycles_and_complete_capture() {
        let mut history = History::default();
        history.apply(&event(1, 0, "0x0", "0x0", 0, 0)).unwrap();
        history.apply(&event(2, 4, "0x100", "0x0", 16, 0)).unwrap();
        for (seq, epoch) in [(3, 1), (5, 2)] {
            history
                .apply(&event(seq, 8, "0x0", "0x0", 0, epoch))
                .unwrap();
            history
                .apply(&event(seq + 1, 9, "0x0", "0x0", 0, epoch))
                .unwrap();
        }
        assert!(
            history.report()["heaps"][0]["retention_candidates"]
                .as_array()
                .unwrap()
                .is_empty()
        );
        history.apply(&event(7, 12, "0x0", "0x0", 0, 2)).unwrap();
        assert_eq!(
            history.report()["heaps"][0]["retention_candidates"]
                .as_array()
                .unwrap()
                .len(),
            1
        );
    }
    #[test]
    fn missing_initial_state_never_becomes_a_proven_leak() {
        let mut history = History::default();
        history.apply(&event(1, 4, "0x100", "0x0", 16, 0)).unwrap();
        history.apply(&event(2, 12, "0x0", "0x0", 0, 0)).unwrap();
        assert_eq!(history.report()["heaps"][0]["complete"], false);
    }
}
