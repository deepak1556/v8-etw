use crate::Result;
use serde::Deserialize;
use serde_json::json;
use std::collections::{BTreeMap, HashMap};
use std::fs::{self, File};
use std::io::{BufRead, BufReader};
use std::path::Path;
use std::time::Instant;

#[derive(Deserialize)]
#[serde(untagged)]
enum Kind {
    Number(u64),
    Text(String),
}

#[derive(Deserialize)]
struct Event {
    sequence: u64,
    kind: Kind,
    heap_id: Option<String>,
    allocation_id: Option<u64>,
    allocated_bytes: Option<u64>,
    gc_info: Option<u64>,
    timestamp_raw: Option<String>,
}

#[derive(Clone)]
struct Object {
    bytes: u64,
    gc_info: u64,
    allocated_at: u64,
    seeded: bool,
}

#[derive(Default)]
struct Heap {
    live: HashMap<u64, Object>,
    live_bytes: u64,
    large_live_bytes: u64,
    peak_live_bytes: u64,
    peak_large_live_bytes: u64,
    peak_large_sequence: u64,
    large_allocations: u64,
    large_frees: u64,
    large_traffic_bytes: u64,
    resize_growth_bytes: u64,
    resize_shrink_bytes: u64,
    buckets: BTreeMap<u64, (u64, u64)>,
    top_allocations: BTreeMap<(u64, u64), serde_json::Value>,
    peak_large_types: BTreeMap<u64, (u64, u64)>,
    large_types: BTreeMap<u64, (u64, u64)>,
    top_by_id: HashMap<u64, (u64, u64)>,
}

const HISTOGRAM_BOUNDS: [u64; 13] = [
    16,
    32,
    64,
    128,
    256,
    512,
    1024,
    4096,
    16384,
    65536,
    1048576,
    16777216,
    u64::MAX,
];

impl Heap {
    fn apply(&mut self, event: &Event, threshold: u64) -> Result<()> {
        let Kind::Number(kind) = event.kind else {
            return Ok(());
        };
        if !matches!(kind, 2 | 4 | 5 | 7 | 11) {
            return Ok(());
        }
        if kind == 11 {
            self.live.clear();
            self.live_bytes = 0;
            self.large_live_bytes = 0;
            self.large_types.clear();
            return Ok(());
        }
        let id = event
            .allocation_id
            .ok_or("Object event lacks stable allocation ID.")?;
        let bytes = event
            .allocated_bytes
            .ok_or("Object event lacks capacity.")?;
        if kind == 2 || kind == 4 {
            let gc_info = event.gc_info.ok_or("Object lacks GC type.")?;
            if self
                .live
                .insert(
                    id,
                    Object {
                        bytes,
                        gc_info,
                        allocated_at: event
                            .timestamp_raw
                            .as_ref()
                            .ok_or("Object lacks timestamp.")?
                            .parse::<u64>()
                            .map_err(|e| e.to_string())?,
                        seeded: kind == 2,
                    },
                )
                .is_some()
            {
                return Err("Duplicate stable allocation ID.".into());
            }
            self.live_bytes = self
                .live_bytes
                .checked_add(bytes)
                .ok_or("Live-byte overflow.")?;
            if bytes >= threshold {
                self.large_live_bytes = self
                    .large_live_bytes
                    .checked_add(bytes)
                    .ok_or("Large live-byte overflow.")?;
                let entry = self.large_types.entry(gc_info).or_default();
                entry.0 += 1;
                entry.1 += bytes;
            }
            if kind == 4 {
                let upper = *HISTOGRAM_BOUNDS
                    .iter()
                    .find(|upper| bytes <= **upper)
                    .ok_or("Missing histogram bound.")?;
                let bucket = self.buckets.entry(upper).or_default();
                bucket.0 += 1;
                bucket.1 = bucket
                    .1
                    .checked_add(bytes)
                    .ok_or("Allocation traffic overflow.")?;
                if bytes >= threshold {
                    self.large_allocations += 1;
                    self.large_traffic_bytes = self
                        .large_traffic_bytes
                        .checked_add(bytes)
                        .ok_or("Large traffic overflow.")?;
                    self.top_allocations.insert(
                        (bytes, id),
                        json!({
                            "allocation_id": id, "bytes": bytes, "gc_info": gc_info,
                            "allocated_at": event.timestamp_raw,
                        }),
                    );
                    self.top_by_id.insert(id, (bytes, id));
                    if self.top_allocations.len() > 100
                        && let Some(((_, id), _)) = self.top_allocations.pop_first()
                    {
                        self.top_by_id.remove(&id);
                    }
                }
            }
        } else {
            let old = self
                .live
                .get(&id)
                .ok_or("Free/resize references unknown allocation ID.")?
                .clone();
            self.live_bytes = self
                .live_bytes
                .checked_sub(old.bytes)
                .ok_or("Live-byte underflow.")?;
            if old.bytes >= threshold {
                self.large_live_bytes = self
                    .large_live_bytes
                    .checked_sub(old.bytes)
                    .ok_or("Large live-byte underflow.")?;
                let entry = self
                    .large_types
                    .get_mut(&old.gc_info)
                    .ok_or("Missing large type balance.")?;
                entry.0 = entry
                    .0
                    .checked_sub(1)
                    .ok_or("Large object-count underflow.")?;
                entry.1 = entry
                    .1
                    .checked_sub(old.bytes)
                    .ok_or("Large type-byte underflow.")?;
                if entry.0 == 0 {
                    self.large_types.remove(&old.gc_info);
                }
            }
            if kind == 5 {
                if old.bytes != bytes {
                    return Err("Free capacity differs from live object.".into());
                }
                self.live.remove(&id);
                if old.bytes >= threshold {
                    self.large_frees += 1;
                }
                if let Some(key) = self.top_by_id.get(&id) {
                    let record = self
                        .top_allocations
                        .get_mut(key)
                        .ok_or("Largest allocation index mismatch.")?;
                    record["freed_at"] = json!(event.timestamp_raw);
                }
            } else {
                if bytes >= old.bytes {
                    self.resize_growth_bytes += bytes - old.bytes;
                } else {
                    self.resize_shrink_bytes += old.bytes - bytes;
                }
                self.live.get_mut(&id).ok_or("Resize lost object.")?.bytes = bytes;
                self.live_bytes = self
                    .live_bytes
                    .checked_add(bytes)
                    .ok_or("Resize live-byte overflow.")?;
                if bytes >= threshold {
                    self.large_live_bytes += bytes;
                    let entry = self.large_types.entry(old.gc_info).or_default();
                    entry.0 += 1;
                    entry.1 += bytes;
                }
            }
        }
        self.peak_live_bytes = self.peak_live_bytes.max(self.live_bytes);
        if self.large_live_bytes > self.peak_large_live_bytes {
            self.peak_large_live_bytes = self.large_live_bytes;
            self.peak_large_sequence = event.sequence;
            self.peak_large_types.clone_from(&self.large_types);
        }
        Ok(())
    }
}

pub fn run(directory: &Path, threshold: u64) -> Result<()> {
    if threshold == 0 {
        return Err("Large-allocation threshold must be positive.".into());
    }
    let output = directory.join("large-allocation-report.json");
    if output.exists() {
        return Err("Large-allocation report already exists.".into());
    }
    let history: serde_json::Value = serde_json::from_slice(
        &fs::read(directory.join("cppgc-history.json")).map_err(|e| e.to_string())?,
    )
    .map_err(|e| e.to_string())?;
    if history["complete"] != true {
        return Err("Large-allocation analysis requires complete cppgc history.".into());
    }
    let mut heaps: HashMap<String, Heap> = HashMap::new();
    let clock = Instant::now();
    let mut progress = Instant::now();
    let mut count = 0u64;
    for line in BufReader::with_capacity(
        1024 * 1024,
        File::open(directory.join("cppgc-lifetimes.jsonl")).map_err(|e| e.to_string())?,
    )
    .lines()
    {
        let event: Event =
            serde_json::from_str(&line.map_err(|e| e.to_string())?).map_err(|e| e.to_string())?;
        if let Kind::Text(ref kind) = event.kind {
            if kind != "capture_end" {
                return Err("Unknown text lifetime event kind.".into());
            }
            continue;
        }
        count += 1;
        let name = event
            .heap_id
            .as_ref()
            .ok_or("Lifetime event lacks heap identity.")?;
        heaps
            .entry(name.clone())
            .or_default()
            .apply(&event, threshold)?;
        if count.is_multiple_of(100000) && progress.elapsed().as_secs() >= 10 {
            eprintln!(
                "Large allocations: {count} records, {:.1}s",
                clock.elapsed().as_secs_f64()
            );
            progress = Instant::now();
        }
    }
    let type_name = |gc_info: u64| {
        history["type_catalog_by_gc_info"][gc_info.to_string()]
            .as_str()
            .map(str::to_owned)
            .unwrap_or_else(|| format!("GCInfo {gc_info}: name not observed"))
    };
    let mut report_heaps = BTreeMap::new();
    for (name, heap) in heaps {
        let original = history["heaps"]
            .as_array()
            .ok_or("Missing lifetime heap summaries.")?
            .iter()
            .find(|record| record["heap_id"].as_str() == Some(&name))
            .ok_or("Large-allocation heap absent from lifetime summary.")?;
        if original["live_bytes"].as_u64() != Some(heap.live_bytes)
            || original["live_objects"].as_u64() != Some(heap.live.len() as u64)
        {
            return Err(
                "Large-allocation analysis does not reconcile with exact lifetime totals.".into(),
            );
        }
        let mut largest: Vec<_> = heap
            .top_allocations
            .into_iter()
            .rev()
            .map(|(_, mut record)| {
                if let Some(gc_info) = record["gc_info"].as_u64() {
                    record["type_name"] = json!(type_name(gc_info));
                }
                record
            })
            .collect();
        largest.truncate(100);
        report_heaps.insert(name, json!({
            "large_threshold_bytes": threshold,
            "large_allocations": heap.large_allocations, "large_frees": heap.large_frees,
            "large_allocation_traffic_bytes": heap.large_traffic_bytes,
            "peak_all_live_capacity_bytes": heap.peak_live_bytes,
            "peak_simultaneous_large_capacity_bytes": heap.peak_large_live_bytes,
            "peak_large_sequence": heap.peak_large_sequence,
            "peak_large_types": heap.peak_large_types.iter().map(|(gc_info,(count,bytes))|
                json!({"type_name":type_name(*gc_info),"object_count":count,"bytes":bytes})).collect::<Vec<_>>(),
            "resize_growth_bytes": heap.resize_growth_bytes,
            "resize_shrink_bytes": heap.resize_shrink_bytes,
            "allocation_size_histogram": heap.buckets.into_iter().map(|(upper,(count,bytes))|
                json!({"upper_bound_bytes":upper,"allocation_count":count,"traffic_bytes":bytes})).collect::<Vec<_>>(),
            "largest_allocations": largest,
            "final_live_objects":heap.live.len(), "final_live_bytes":heap.live_bytes,
            "final_seeded_objects":heap.live.values().filter(|object|object.seeded).count(),
            "oldest_observed_live_allocation_timestamp":heap.live.values()
                .filter(|object|!object.seeded).map(|object| object.allocated_at).min()
                .map(|timestamp|timestamp.to_string()),
        }));
    }
    fs::write(output,serde_json::to_vec_pretty(&json!({
        "schema_version":1,"complete":true,"analysis_elapsed_ms":clock.elapsed().as_millis(),
        "lifetime_records":count,"heaps":report_heaps,
        "limitations":[
            "Capacities include cppgc headers/alignment; these peaks are not process RSS/private commit.",
            "Seeded allocations have unknown pre-capture birth times.",
            "Native/OS large allocations need separate sample/VirtualAlloc analysis; this is exact cppgc only.",
            "Large allocation/churn or long lifetime does not imply a leak.",
            "Largest-allocation list is bounded to100; histogram and peak accounting cover all events."
        ]
    })).map_err(|e| e.to_string())?).map_err(|e| e.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    fn event(sequence: u64, kind: u64, id: u64, bytes: u64) -> Event {
        Event {
            sequence,
            kind: Kind::Number(kind),
            heap_id: Some("heap".into()),
            allocation_id: Some(id),
            allocated_bytes: Some(bytes),
            gc_info: Some(1),
            timestamp_raw: Some(sequence.to_string()),
        }
    }
    #[test]
    fn counts_overlapping_large_objects_resizes_and_eventual_frees() {
        let mut heap = Heap::default();
        heap.apply(&event(1, 4, 1, 1024), 1024).unwrap();
        heap.apply(&event(2, 4, 2, 2048), 1024).unwrap();
        heap.apply(&event(3, 7, 1, 4096), 1024).unwrap();
        heap.apply(&event(4, 5, 2, 2048), 1024).unwrap();
        heap.apply(&event(5, 7, 1, 64), 1024).unwrap();
        heap.apply(&event(6, 5, 1, 64), 1024).unwrap();
        assert_eq!(heap.peak_large_live_bytes, 6144);
        assert_eq!(heap.large_allocations, 2);
        assert_eq!(heap.resize_growth_bytes, 3072);
        assert_eq!(heap.resize_shrink_bytes, 4032);
        assert_eq!(heap.live_bytes, 0);
    }
}
