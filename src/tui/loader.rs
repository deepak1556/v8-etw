use super::*;

pub(super) fn read_bounded(path: &Path, limit: u64) -> Result<Option<Vec<u8>>> {
    let file = match File::open(path) {
        Ok(file) => file,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(format!("{}: {error}", path.display())),
    };
    if file.metadata().map_err(|e| e.to_string())?.len() > limit {
        return Err(format!("{} exceeds {limit} byte limit", path.display()));
    }
    let mut bytes = Vec::new();
    file.take(limit + 1)
        .read_to_end(&mut bytes)
        .map_err(|e| format!("{}: {e}", path.display()))?;
    if bytes.len() as u64 > limit {
        return Err(format!("{} grew beyond {limit} byte limit", path.display()));
    }
    Ok(Some(bytes))
}

pub(super) fn report(directory: &Path, name: &str) -> Result<Option<Value>> {
    read_bounded(&directory.join(name), REPORT_LIMIT)?
        .map(|bytes| {
            let value: Value =
                serde_json::from_slice(&bytes).map_err(|e| format!("{name}: {e}"))?;
            if !value.is_object() {
                return Err(format!("{name}: expected JSON object"));
            }
            Ok(value)
        })
        .transpose()
}

pub(super) fn report_size(directory: &Path, name: &str) -> Result<Option<u64>> {
    match File::open(directory.join(name)) {
        Ok(file) => file
            .metadata()
            .map(|metadata| Some(metadata.len()))
            .map_err(|error| error.to_string()),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(format!("{}: {error}", directory.join(name).display())),
    }
}

pub(super) fn projection_candidates(directory: &Path, name: &str) -> Vec<std::path::PathBuf> {
    let mut candidates = vec![directory.join(name)];
    if let Some(parent) = directory.parent() {
        candidates.push(parent.join(name));
        if let Some(grandparent) = parent.parent() {
            candidates.push(grandparent.join(name));
            candidates.push(grandparent.join("speedometer-suite-pass").join(name));
        }
    }
    candidates
}

pub(super) fn projection(directory: &Path, name: &str) -> Result<Option<(Value, String)>> {
    for path in projection_candidates(directory, name) {
        if !path.is_file() {
            continue;
        }
        let parent = path.parent().ok_or("Projection path has no parent")?;
        let value = report(parent, name)?.ok_or("Projection disappeared while loading")?;
        return Ok(Some((value, path.display().to_string())));
    }
    Ok(None)
}

pub(super) fn load_projections(directory: &Path) -> Result<Projections> {
    let mut projections = Projections::default();
    for (name, target) in [
        (
            "runtime-cost-census-all-iterations.json",
            &mut projections.runtime,
        ),
        ("reader-performance-summary.json", &mut projections.reader),
        ("suite-cost-summary.json", &mut projections.suites),
        ("large-allocation-report.json", &mut projections.large),
    ] {
        if let Some((value, source)) = projection(directory, name)? {
            *target = Some(value);
            projections.sources.push(source);
        }
    }
    Ok(projections)
}

pub(super) fn mib(bytes: u64) -> f64 {
    bytes as f64 / (1024.0 * 1024.0)
}

pub(super) fn oversized_message(name: &str, bytes: u64) -> String {
    format!(
        "{name} is {:.1} MiB and exceeds the 32 MiB interactive canonical-report limit. \
Use a bounded UI projection (runtime-cost-census-all-iterations.json, \
suite-cost-summary.json, large-allocation-report.json, or \
reader-performance-summary.json); the limit is a conservative whole-JSON parse guard, \
not a measurement-derived memory threshold.",
        mib(bytes)
    )
}

pub(super) fn required<'a>(value: &'a Value, key: &str) -> Result<&'a Value> {
    value
        .get(key)
        .ok_or_else(|| format!("Required field missing (case-sensitive): {key}"))
}

pub(super) fn unsigned(value: &Value, key: &str) -> Result<u64> {
    required(value, key)?
        .as_u64()
        .ok_or_else(|| format!("{key}: expected unsigned integer"))
}

pub(super) fn boolean(value: &Value, key: &str) -> Result<bool> {
    required(value, key)?
        .as_bool()
        .ok_or_else(|| format!("{key}: expected boolean"))
}

pub(super) fn array<'a>(value: &'a Value, key: &str) -> Result<&'a Vec<Value>> {
    required(value, key)?
        .as_array()
        .ok_or_else(|| format!("{key}: expected array"))
}

pub(super) fn object<'a>(
    value: &'a Value,
    key: &str,
) -> Result<&'a serde_json::Map<String, Value>> {
    required(value, key)?
        .as_object()
        .ok_or_else(|| format!("{key}: expected object"))
}

pub(super) fn display(value: Option<&Value>) -> String {
    match value {
        None | Some(Value::Null) => "unavailable".into(),
        Some(Value::String(text)) => text.clone(),
        Some(value) => value.to_string(),
    }
}

pub(super) fn fields(lines: &mut Vec<String>, title: &str, value: Option<&Value>) {
    lines.push(title.into());
    match value {
        Some(Value::Object(values)) => {
            for (key, value) in values {
                lines.push(format!("  {key}: {}", display(Some(value))));
            }
        }
        _ => lines.push(format!("  {}", display(value))),
    }
}

pub(super) fn metrics(
    lines: &mut Vec<String>,
    title: &str,
    value: Option<&Value>,
    keys: &[&str],
) -> Result<()> {
    lines.push(title.into());
    let Some(value) = value else {
        lines.push("  unavailable".into());
        return Ok(());
    };
    for key in keys {
        lines.push(format!("  {key}: {}", unsigned(value, key)?));
    }
    Ok(())
}

pub(super) fn messages(lines: &mut Vec<String>, value: &Value, key: &str) -> Result<()> {
    for message in array(value, key)? {
        lines.push(format!("{key}: {}", display(Some(message))));
    }
    Ok(())
}

pub(super) fn ranked(
    lines: &mut Vec<String>,
    title: &str,
    value: Option<&Value>,
    metric: &str,
) -> Result<()> {
    lines.push(title.into());
    let Some(value) = value else {
        lines.push("  unavailable".into());
        return Ok(());
    };
    let values = value
        .as_object()
        .ok_or_else(|| format!("{title}: expected object"))?;
    let mut rows = values
        .iter()
        .map(|(name, row)| Ok((unsigned(row, metric)?, name, row)))
        .collect::<Result<Vec<_>>>()?;
    rows.sort_by(|a, b| b.0.cmp(&a.0).then_with(|| a.1.cmp(b.1)));
    if rows.is_empty() {
        lines.push("  no entries recorded".into());
    }
    for (_, name, row) in rows {
        fields(lines, name, Some(row));
    }
    Ok(())
}

pub(super) fn native_paths(directory: &Path) -> Result<Vec<String>> {
    let path = directory.join("symbolized.jsonl");
    let file = match File::open(&path) {
        Ok(file) => file,
        Err(e) if e.kind() == io::ErrorKind::NotFound => {
            return Ok(vec![
                "Native allocation call paths: unavailable (symbolized.jsonl missing)".into(),
            ]);
        }
        Err(e) => return Err(format!("{}: {e}", path.display())),
    };
    let mut bytes = Vec::new();
    file.take(STACK_LIMIT + 1)
        .read_to_end(&mut bytes)
        .map_err(|e| format!("{}: {e}", path.display()))?;
    let truncated = bytes.len() as u64 > STACK_LIMIT;
    if truncated {
        bytes.truncate(STACK_LIMIT as usize);
        let end = bytes
            .iter()
            .rposition(|b| *b == b'\n')
            .ok_or("symbolized.jsonl: first record exceeds bounded stack scan")?;
        bytes.truncate(end + 1);
    }
    let mut lines = vec![
        "Native/cppgc allocation call paths: trace-wide samples, NOT checkpoint live bytes".into(),
        format!(
            "Bounded preview: first 8 MiB, at most {STACK_SAMPLES} allocation stacks; not exhaustive"
        ),
    ];
    let mut samples = 0;
    for (index, line) in bytes.split(|b| *b == b'\n').enumerate() {
        if line.iter().all(u8::is_ascii_whitespace) {
            continue;
        }
        let record: Value = serde_json::from_slice(line)
            .map_err(|e| format!("symbolized.jsonl record {}: {e}", index + 1))?;
        if !matches!(
            record.get("event_name").and_then(Value::as_str),
            Some("NativeSampleAdded" | "CppgcAllocationTraffic")
        ) {
            continue;
        }
        lines.push(format!(
            "{} timestamp={} tid={}",
            display(record.get("event_name")),
            display(record.get("timestamp_raw")),
            display(record.get("tid"))
        ));
        fields(
            &mut lines,
            "Sample weights (traffic, not census)",
            record.get("allocation_properties"),
        );
        for frame in array(&record, "frames")? {
            lines.push(format!(
                "  -> {} [{}] {}",
                display(frame.get("function").or_else(|| frame.get("address"))),
                display(frame.get("status")),
                display(frame.get("source_file").or_else(|| frame.get("module")))
            ));
        }
        samples += 1;
        if samples == STACK_SAMPLES {
            break;
        }
    }
    lines.push(format!(
        "Displayed {samples} allocation stacks; scan byte limit reached: {truncated}"
    ));
    Ok(lines)
}

pub(super) fn frame_label(frame: &Value) -> String {
    let function = frame
        .get("function")
        .and_then(Value::as_str)
        .or_else(|| frame.get("address").and_then(Value::as_str))
        .unwrap_or("<unresolved>");
    match frame.get("module").and_then(Value::as_str) {
        Some(module) => format!("{module}!{function}"),
        None => function.to_owned(),
    }
}

pub(super) fn frame_source(frame: &Value) -> String {
    let Some(file) = frame.get("source_file").and_then(Value::as_str) else {
        return display(frame.get("status"));
    };
    match frame.get("source_line").and_then(Value::as_u64) {
        Some(line) => format!("{file}:{line}"),
        None => file.to_owned(),
    }
}

pub(super) fn add_stat<K: Ord + Clone>(
    values: &mut BTreeMap<K, AllocationStat>,
    key: K,
    weight: u64,
) {
    let stat = values.entry(key).or_default();
    stat.samples += 1;
    stat.weight = stat.weight.saturating_add(weight);
    if values.len() > 8
        && let Some(key) = values
            .iter()
            .min_by_key(|(_, stat)| stat.weight)
            .map(|(key, _)| key.clone())
    {
        values.remove(&key);
    }
}

impl AllocationBreakdown {
    fn add(&mut self, observation: &AllocationObservation, weight: u64) {
        self.observed_bytes = self
            .observed_bytes
            .saturating_add(observation.observed_bytes);
        self.requested_bytes = self
            .requested_bytes
            .saturating_add(observation.requested_bytes);
        add_stat(&mut self.kinds, observation.kind.clone(), weight);
        if let Some(heap) = &observation.heap {
            add_stat(&mut self.heaps, heap.clone(), weight);
        }
        if let Some(id) = observation.allocation_id {
            add_stat(&mut self.allocation_ids, id, weight);
        }
    }
}

pub(super) fn allocator_subsystem(value: u64) -> String {
    match value {
        1 => "PartitionAllocator".into(),
        2 => "Allocator shim".into(),
        3 => "Manual/testing allocation".into(),
        _ => format!("Native subsystem {value}"),
    }
}

pub(super) fn insert_stack(
    root: &mut StackNode,
    frames: &[Value],
    weight: u64,
    observation: &AllocationObservation,
) {
    root.inclusive = root.inclusive.saturating_add(weight);
    root.samples += 1;
    root.allocation.add(observation, weight);
    let mut node = root;
    for frame in frames.iter().rev() {
        let label = frame_label(frame);
        node = node
            .children
            .entry(label.clone())
            .or_insert_with(|| StackNode {
                label,
                source: frame_source(frame),
                ..Default::default()
            });
        node.inclusive = node.inclusive.saturating_add(weight);
        node.samples += 1;
        node.allocation.add(observation, weight);
    }
    node.self_weight = node.self_weight.saturating_add(weight);
}

pub(super) fn load_stack_domains(directory: &Path) -> Result<(Vec<StackDomain>, bool)> {
    let mut domains = vec![
        StackDomain {
            title: "Native allocation",
            badge: "SAMPLED TRAFFIC",
            exact: false,
            root: StackNode::default(),
        },
        StackDomain {
            title: "Cppgc allocation",
            badge: "SAMPLED TRAFFIC",
            exact: false,
            root: StackNode::default(),
        },
        StackDomain {
            title: "Cppgc lifecycle",
            badge: "EXACT ALLOCATIONS",
            exact: true,
            root: StackNode::default(),
        },
    ];
    let path = directory.join("symbolized.jsonl");
    let file = match File::open(&path) {
        Ok(file) => file,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok((domains, false)),
        Err(error) => return Err(format!("{}: {error}", path.display())),
    };
    let file_size = file.metadata().map_err(|e| e.to_string())?.len();
    let mut reader = BufReader::new(file);
    let mut line = String::new();
    let mut consumed = 0u64;
    let mut samples = 0usize;
    while consumed < TREE_SCAN_LIMIT && samples < TREE_SAMPLE_LIMIT {
        line.clear();
        let bytes = reader.read_line(&mut line).map_err(|e| e.to_string())?;
        if bytes == 0 {
            break;
        }
        consumed = consumed.saturating_add(bytes as u64);
        if consumed > TREE_SCAN_LIMIT {
            break;
        }
        let record: Value =
            serde_json::from_str(&line).map_err(|e| format!("symbolized.jsonl: {e}"))?;
        let Some(frames) = record.get("frames").and_then(Value::as_array) else {
            continue;
        };
        if frames.is_empty() {
            continue;
        }
        let properties = record
            .get("allocation_properties")
            .ok_or("Allocation stack is missing allocation_properties")?;
        let (domain, weight, observation) = match record.get("event_name").and_then(Value::as_str) {
            Some("NativeSampleAdded") => {
                let subsystem = properties
                    .get("AllocatorSubsystem")
                    .and_then(Value::as_u64)
                    .map_or_else(|| "Native allocator".into(), allocator_subsystem);
                let context = properties
                    .get("AllocationContext")
                    .and_then(Value::as_str)
                    .filter(|value| !value.is_empty());
                (
                    0,
                    properties.get("EstimatedBytes").and_then(Value::as_u64),
                    AllocationObservation {
                        observed_bytes: properties
                            .get("RequestedBytes")
                            .and_then(Value::as_u64)
                            .unwrap_or(0),
                        requested_bytes: properties
                            .get("RequestedBytes")
                            .and_then(Value::as_u64)
                            .unwrap_or(0),
                        kind: context.map_or(subsystem.clone(), |context| {
                            format!("{subsystem} / {context}")
                        }),
                        heap: properties
                            .get("Heap")
                            .and_then(Value::as_str)
                            .map(str::to_owned),
                        allocation_id: None,
                    },
                )
            }
            Some("CppgcAllocationTraffic") => (
                1,
                properties
                    .get("EstimatedTrafficBytes")
                    .and_then(Value::as_u64),
                AllocationObservation {
                    observed_bytes: properties
                        .get("AllocatedBytes")
                        .and_then(Value::as_u64)
                        .unwrap_or(0),
                    requested_bytes: 0,
                    kind: "cppgc sampled allocation".into(),
                    heap: properties
                        .get("HeapId")
                        .and_then(Value::as_str)
                        .map(str::to_owned),
                    allocation_id: properties
                        .get("LifetimeAllocationSequence")
                        .and_then(Value::as_u64)
                        .filter(|id| *id != 0),
                },
            ),
            Some("CppgcLifetime") if properties.get("Kind").and_then(Value::as_u64) == Some(4) => {
                let gc_info = properties
                    .get("GCInfo")
                    .and_then(Value::as_u64)
                    .unwrap_or(0);
                let type_name = properties
                    .get("TypeName")
                    .and_then(Value::as_str)
                    .filter(|name| !name.is_empty())
                    .map_or_else(|| format!("cppgc GCInfo {gc_info}"), str::to_owned);
                (
                    2,
                    properties.get("AllocatedBytes").and_then(Value::as_u64),
                    AllocationObservation {
                        observed_bytes: properties
                            .get("AllocatedBytes")
                            .and_then(Value::as_u64)
                            .unwrap_or(0),
                        requested_bytes: if properties.get("RequestedKnown").and_then(Value::as_u64)
                            == Some(1)
                        {
                            properties
                                .get("RequestedBytes")
                                .and_then(Value::as_u64)
                                .unwrap_or(0)
                        } else {
                            0
                        },
                        kind: type_name,
                        heap: properties
                            .get("HeapId")
                            .and_then(Value::as_str)
                            .map(str::to_owned),
                        allocation_id: properties.get("Sequence").and_then(Value::as_u64),
                    },
                )
            }
            _ => continue,
        };
        let weight = weight.ok_or("Allocation stack is missing its weight")?;
        insert_stack(&mut domains[domain].root, frames, weight, &observation);
        samples += 1;
    }
    Ok((
        domains,
        consumed < file_size || samples == TREE_SAMPLE_LIMIT,
    ))
}

pub(super) fn load_lifetime_events(directory: &Path) -> Result<Vec<Value>> {
    let path = directory.join("cppgc-lifetimes.jsonl");
    let Some(bytes) = read_bounded(&path, LIFETIME_LIMIT)? else {
        return Ok(Vec::new());
    };
    bytes
        .split(|byte| *byte == b'\n')
        .filter(|line| !line.iter().all(u8::is_ascii_whitespace))
        .enumerate()
        .map(|(index, line)| {
            serde_json::from_slice(line)
                .map_err(|e| format!("cppgc-lifetimes.jsonl record {}: {e}", index + 1))
        })
        .collect()
}

pub(super) fn load_lifecycle(
    history: Option<&Value>,
    directory: &Path,
) -> Result<Option<Lifecycle>> {
    let Some(history) = history else {
        return Ok(None);
    };
    let heap = history
        .get("heaps")
        .and_then(Value::as_array)
        .and_then(|heaps| heaps.first())
        .ok_or("cppgc-history.json: no heap records")?;
    let type_names = history
        .get("type_catalog_by_gc_info")
        .and_then(Value::as_object)
        .into_iter()
        .flatten()
        .filter_map(|(key, value)| {
            Some((
                key.parse().ok()?,
                value.as_str().unwrap_or("<unknown type>").to_owned(),
            ))
        })
        .collect();
    let mut objects = BTreeMap::<u64, LifeObject>::new();
    let mut major_sequences = Vec::new();
    let mut capture_start_sequence = u64::MAX;
    let mut inventory_end_sequence = 0;
    let mut capture_end_sequence = 0;
    for record in load_lifetime_events(directory)? {
        let sequence = record.get("sequence").and_then(Value::as_u64).unwrap_or(0);
        capture_start_sequence = capture_start_sequence.min(sequence);
        capture_end_sequence = capture_end_sequence.max(sequence);
        let kind = match record.get("kind") {
            Some(Value::String(kind)) => kind.clone(),
            Some(kind) => kind.to_string(),
            None => "unknown".into(),
        };
        if kind == "3" {
            inventory_end_sequence = sequence;
        }
        if kind == "9" {
            major_sequences.push((
                sequence,
                record.get("gc_epoch").and_then(Value::as_u64).unwrap_or(0),
            ));
        }
        let Some(id) = record.get("allocation_id").and_then(Value::as_u64) else {
            continue;
        };
        let object = objects.entry(id).or_insert_with(|| LifeObject {
            id,
            bytes: record
                .get("allocated_bytes")
                .and_then(Value::as_u64)
                .unwrap_or(0),
            gc_info: record.get("gc_info").and_then(Value::as_u64).unwrap_or(0),
            seeded: kind == "2",
            events: Vec::new(),
        });
        object.events.push(LifeEvent {
            sequence,
            kind,
            gc_epoch: record.get("gc_epoch").and_then(Value::as_u64).unwrap_or(0),
            bytes: record
                .get("allocated_bytes")
                .and_then(Value::as_u64)
                .unwrap_or(0),
        });
    }
    let major_live_bytes = heap
        .get("major_gc_history")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(|row| row.get("live_bytes").and_then(Value::as_u64))
        .collect();
    let mut objects = objects.into_values().collect::<Vec<_>>();
    objects.sort_by(|a, b| b.bytes.cmp(&a.bytes).then_with(|| a.id.cmp(&b.id)));
    Ok(Some(Lifecycle {
        complete: history.get("complete").and_then(Value::as_bool) == Some(true),
        heap_id: display(heap.get("heap_id")),
        live_objects: heap
            .get("live_objects")
            .and_then(Value::as_u64)
            .unwrap_or(0),
        live_bytes: heap.get("live_bytes").and_then(Value::as_u64).unwrap_or(0),
        header_bytes: heap.get("object_header_bytes").and_then(Value::as_u64),
        known_payload_bytes: heap
            .get("known_requested_payload_bytes")
            .and_then(Value::as_u64)
            .unwrap_or(0),
        known_padding_bytes: heap
            .get("known_rounding_or_retained_capacity_bytes")
            .and_then(Value::as_u64)
            .unwrap_or(0),
        unknown_requested_objects: heap
            .get("objects_with_unknown_requested_size")
            .and_then(Value::as_u64)
            .unwrap_or(0),
        major_live_bytes,
        major_sequences,
        capture_start_sequence: if capture_start_sequence == u64::MAX {
            0
        } else {
            capture_start_sequence
        },
        inventory_end_sequence,
        capture_end_sequence,
        objects,
        type_names,
    }))
}

impl Reports {
    pub(super) fn load(directory: &Path) -> Result<Self> {
        let activities = activities::ActivityReports::load(directory)?;
        let directory = if directory.is_file() {
            directory
                .parent()
                .ok_or("Activity report has no parent directory.")?
        } else {
            directory
        };
        let projections = load_projections(directory)?;
        let mut skipped_oversized = Vec::new();
        let heap = match report_size(directory, "heap-report.json")? {
            Some(size) if size > REPORT_LIMIT => {
                if projections.runtime.is_none() {
                    return Err(oversized_message("heap-report.json", size));
                }
                skipped_oversized.push(oversized_message("heap-report.json", size));
                None
            }
            _ => report(directory, "heap-report.json")?,
        };
        let summary = report(directory, "summary.json")?;
        let attribution = match report_size(directory, "attribution.json")? {
            Some(size) if size > REPORT_LIMIT => {
                if projections.reader.is_none() {
                    return Err(oversized_message("attribution.json", size));
                }
                skipped_oversized.push(oversized_message("attribution.json", size));
                None
            }
            _ => report(directory, "attribution.json")?,
        };
        let history = report(directory, "cppgc-history.json")?;
        if heap.is_none()
            && summary.is_none()
            && attribution.is_none()
            && history.is_none()
            && projections.sources.is_empty()
            && activities.is_empty()
        {
            return Err("No supported reports found in directory".into());
        }
        let mut health = vec!["Trace health (missing metrics are NOT zero)".into()];
        if let Some(summary) = &summary {
            unsigned(summary, "schema_version")?;
            boolean(summary, "complete")?;
            unsigned(summary, "events_lost")?;
            unsigned(summary, "buffers_lost")?;
            object(summary, "metadata_errors")?;
            object(summary, "property_errors")?;
            for key in [
                "schema_version",
                "target_pid",
                "complete",
                "events_lost",
                "buffers_lost",
                "total_events",
                "selected_events",
                "metadata_errors",
                "property_errors",
            ] {
                health.push(format!("{key}: {}", display(summary.get(key))));
            }
            messages(&mut health, summary, "limitations")?;
        } else {
            health.push("Trace health: unavailable (summary.json missing)".into());
        }
        for message in &skipped_oversized {
            health.push(format!("Projection mode: {message}"));
        }
        for source in &projections.sources {
            health.push(format!("Loaded UI projection: {source}"));
        }
        if let Some(heap) = &heap {
            unsigned(heap, "schema_version")?;
            messages(&mut health, heap, "errors")?;
            messages(&mut health, heap, "limitations")?;
            for key in [
                "sampling_interval",
                "native_sampling_interval",
                "native_samples_added",
                "native_samples_removed",
                "unmatched_native_sample_frees",
            ] {
                health.push(format!("{key}: {}", display(heap.get(key))));
            }
        } else {
            health.push("Heap checkpoints: unavailable (heap-report.json missing)".into());
        }
        let mut paths = native_paths(directory)?;
        if let Some(attribution) = &attribution {
            fields(
                &mut health,
                "Symbol frame coverage",
                attribution.get("frame_coverage"),
            );
            fields(
                &mut health,
                "Required PDB failures",
                attribution.get("required_pdb_failures"),
            );
            paths.push(
                "Trace-wide inclusive function traffic: NOT live bytes; functions overlap".into(),
            );
            ranked(
                &mut paths,
                "Sampled native/cppgc functions",
                attribution.get("allocation_function_traffic"),
                "samples",
            )?;
        } else {
            health.push("Symbol attribution: unavailable (attribution.json missing)".into());
        }
        let mut lifecycle = vec![
            "Retained survivors are candidates, NOT proven leaks.".into(),
            "Exact lifecycle fidelity only when complete=true; absent fields are unavailable."
                .into(),
        ];
        if let Some(history) = &history {
            for key in ["schema_version", "complete", "warnings"] {
                lifecycle.push(format!("{key}: {}", display(history.get(key))));
            }
            lifecycle.push(match history.get("complete").and_then(Value::as_bool) {
                Some(true) => "Lifecycle fidelity: complete capture".into(),
                _ => "Lifecycle fidelity: incomplete/unavailable; NOT exact".into(),
            });
            match history.get("heaps") {
                Some(Value::Array(heaps)) => {
                    for heap in heaps {
                        for key in [
                            "heap_id",
                            "allocations",
                            "frees",
                            "moves",
                            "live_objects",
                            "live_bytes",
                        ] {
                            lifecycle.push(format!("{key}: {}", display(heap.get(key))));
                        }
                        match heap.get("survivors_by_type") {
                            Some(Value::Array(types)) => {
                                for row in types {
                                    lifecycle.push(format!(
                                        "Candidate: {} objects={} bytes={} oldest_gc_epoch={}",
                                        display(row.get("type_name")),
                                        display(row.get("object_count")),
                                        display(row.get("bytes")),
                                        display(row.get("oldest_gc_epoch"))
                                    ));
                                }
                            }
                            other => fields(&mut lifecycle, "survivors_by_type", other),
                        }
                    }
                }
                other => fields(&mut lifecycle, "heaps", other),
            }
        } else {
            lifecycle.push("Lifecycle: unavailable (cppgc-history.json missing)".into());
        }
        let checkpoints = heap.as_ref().map(|v| array(v, "checkpoints")).transpose()?;
        let mut phases = Vec::new();
        let mut pages = Vec::new();
        if let Some(checkpoints) = checkpoints {
            for checkpoint in checkpoints {
                let id = unsigned(checkpoint, "checkpoint")?;
                let complete = boolean(checkpoint, "complete")?;
                let phase = required(checkpoint, "phase")?
                    .as_str()
                    .ok_or("phase: expected string")?;
                phases.push(format!("Checkpoint {id}: {phase} (complete={complete})"));
                let mut local_health = health.clone();
                local_health.push(format!("Checkpoint complete: {complete}"));
                local_health.push(format!(
                    "failed_native_writes: {}",
                    display(checkpoint.get("failed_native_writes"))
                ));
                let census = object(checkpoint, "heap_census")?;
                let mut layers = vec![
                    "NON-ADDITIVE memory layers: NEVER grand summed; overlapping ownership.".into(),
                    "Process OS footprint (RSS/private bytes): unavailable; VirtualAlloc traffic is not RSS.".into(),
                    "All sizes below are bytes; requested/used, committed, reserved differ.".into(),
                ];
                metrics(
                    &mut layers,
                    "V8 heap census",
                    census.get("v8_totals"),
                    &[
                        "HeapBytes",
                        "UsedBytes",
                        "PhysicalBytes",
                        "ExternalBytes",
                        "MallocedBytes",
                    ],
                )?;
                metrics(
                    &mut layers,
                    "Cppgc heap census",
                    census.get("cppgc_totals"),
                    &[
                        "UsedBytes",
                        "CommittedBytes",
                        "ResidentBytes",
                        "PooledBytes",
                    ],
                )?;
                layers.push("Native Poisson samples: overlapping allocator ownership, NOT another additive layer".into());
                for key in [
                    "native_live_sample_count",
                    "native_sampled_requested_bytes",
                    "native_estimated_live_bytes",
                    "cppgc_allocated_traffic_bytes",
                    "cppgc_allocation_count",
                ] {
                    layers.push(format!("{key}: {}", display(checkpoint.get(key))));
                }
                layers.push(
                    "PartitionAlloc roots: non-atomic snapshots, overlap V8/cppgc/native samples"
                        .into(),
                );
                if let Some(roots) = census.get("partition_roots") {
                    let roots = roots
                        .as_object()
                        .ok_or("partition_roots: expected object")?;
                    for (name, row) in roots {
                        fields(&mut layers, name, Some(row));
                    }
                } else {
                    layers.push("PartitionAlloc roots: unavailable".into());
                }
                let mut types = vec![
                    "Cppgc type footprint by space (dead-but-unswept objects may remain)".into(),
                ];
                ranked(
                    &mut types,
                    "Types sorted by allocated_bytes",
                    census.get("cppgc_types_by_space"),
                    "allocated_bytes",
                )?;
                let mut allocator = vec![
                    "Allocator buckets: same-root fragmentation only; no cross-layer sums.".into(),
                    "ProvisionedBytes - ActiveBytes is slack, NOT proven reclaimable memory."
                        .into(),
                ];
                fields(
                    &mut allocator,
                    "Native sampled estimates by heap (NOT census)",
                    checkpoint.get("native_samples_by_heap"),
                );
                match census.get("partition_buckets") {
                    Some(Value::Array(buckets)) => {
                        for row in buckets {
                            let provisioned = unsigned(row, "ProvisionedBytes")?;
                            let active = unsigned(row, "ActiveBytes")?;
                            fields(&mut allocator, "Partition bucket", Some(row));
                            allocator.push(match provisioned.checked_sub(active) {
                                Some(slack) => format!("  provisioned slack bytes: {slack}"),
                                None => "  provisioned slack: unavailable (ActiveBytes exceeds ProvisionedBytes; non-atomic snapshot)".into(),
                            });
                        }
                    }
                    None => allocator.push("Partition buckets: unavailable".into()),
                    _ => return Err("partition_buckets: expected array".into()),
                }
                let mut local_paths = vec![
                    "V8 sampled LIVE allocation estimates by JS call path (NOT a census)".into(),
                ];
                ranked(
                    &mut local_paths,
                    "V8 paths sorted by estimated_live_bytes",
                    checkpoint.get("v8_live_allocation_estimates_by_path"),
                    "estimated_live_bytes",
                )?;
                local_paths.extend(paths.clone());
                pages.push(vec![
                    local_health,
                    layers,
                    types,
                    allocator,
                    local_paths,
                    lifecycle.clone(),
                ]);
            }
        }
        if phases.is_empty()
            && let Some(iterations) = projections
                .runtime
                .as_ref()
                .and_then(|value| value.get("iteration_memory"))
                .and_then(Value::as_array)
        {
            for (index, iteration) in iterations.iter().enumerate() {
                phases.push(format!(
                    "Iteration {}: {} [PROJECTED]",
                    index + 1,
                    display(iteration.get("phase"))
                ));
                pages.push(vec![
                    health.clone(),
                    vec!["Projection-backed iteration memory".into()],
                    vec!["Projection-backed cppgc type ranking".into()],
                    vec!["Projection-backed allocator slack".into()],
                    paths.clone(),
                    lifecycle.clone(),
                ]);
            }
        }
        if phases.is_empty() {
            phases.push("No checkpoints or iteration projections available".into());
            pages.push(vec![
                health,
                vec!["Memory layers: unavailable (no checkpoints)".into()],
                vec!["Cppgc types: unavailable".into()],
                vec!["Allocator: unavailable".into()],
                paths,
                lifecycle,
            ]);
        }
        let target_pid = summary
            .as_ref()
            .and_then(|value| value.get("target_pid"))
            .and_then(Value::as_u64);
        let trace_complete = summary
            .as_ref()
            .and_then(|value| value.get("complete"))
            .and_then(Value::as_bool);
        let events_lost = summary
            .as_ref()
            .and_then(|value| value.get("events_lost"))
            .and_then(Value::as_u64);
        let required_pdb_failures = attribution
            .as_ref()
            .and_then(|value| value.get("required_pdb_failures"))
            .and_then(Value::as_array)
            .map_or(0, Vec::len);
        let (stack_domains, stack_scan_truncated) = load_stack_domains(directory)?;
        let lifecycle = match report_size(directory, "cppgc-lifetimes.jsonl")? {
            Some(size) if size > LIFETIME_LIMIT && projections.runtime.is_some() => {
                skipped_oversized.push(format!(
                    "cppgc-lifetimes.jsonl is {:.1} MiB; Object Inspector is disabled in projection mode.",
                    mib(size)
                ));
                None
            }
            _ => load_lifecycle(history.as_ref(), directory)?,
        };
        for page in &mut pages {
            page.push(vec!["Activity composition and paired comparison".into()]);
        }
        Ok(Self {
            phases,
            pages,
            target_pid,
            trace_complete,
            events_lost,
            required_pdb_failures,
            stack_domains,
            stack_scan_truncated,
            lifecycle,
            projections,
            skipped_oversized,
            activities,
        })
    }
}
