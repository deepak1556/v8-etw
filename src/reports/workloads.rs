use super::run_input::{LogEvent, log_event};
use crate::Result;
use serde::Serialize;
use serde_json::Value;
use std::collections::BTreeMap;
use std::fs::{self, File, OpenOptions};
use std::io::{BufRead, BufReader, Write};
use std::path::Path;

pub(super) fn read_json(path: &Path) -> Result<Value> {
    if fs::metadata(path)
        .map_err(|e| format!("{}: {e}", path.display()))?
        .len()
        > 32 * 1024 * 1024
    {
        return Err(format!("Report exceeds metadata limit: {}", path.display()));
    }
    serde_json::from_slice(&fs::read(path).map_err(|e| e.to_string())?)
        .map_err(|e| format!("{}: {e}", path.display()))
}

pub(super) fn write_json(path: &Path, value: &impl Serialize) -> Result<()> {
    let bytes = serde_json::to_vec_pretty(value).map_err(|e| e.to_string())?;
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .map_err(|e| {
            format!(
                "Refusing existing/unwritable output {}: {e}",
                path.display()
            )
        })?;
    file.write_all(&bytes).map_err(|e| e.to_string())
}

pub(super) fn number(value: &Value, key: &str) -> Result<u64> {
    value[key]
        .as_u64()
        .ok_or_else(|| format!("Missing/invalid numeric field {key}"))
}

pub(super) fn text<'a>(value: &'a Value, key: &str) -> Result<&'a str> {
    value[key]
        .as_str()
        .ok_or_else(|| format!("Missing/invalid text field {key}"))
}

pub(super) fn percentile(values: &[f64], fraction: f64) -> Option<f64> {
    if values.is_empty() {
        return None;
    }
    let mut sorted = values.to_vec();
    sorted.sort_by(f64::total_cmp);
    let index = (sorted.len() - 1) as f64 * fraction;
    let low = index.floor() as usize;
    let high = index.ceil() as usize;
    Some(sorted[low] + (sorted[high] - sorted[low]) * (index - low as f64))
}

pub(super) fn utc_millis(value: &str) -> Result<f64> {
    let value = value
        .strip_suffix('Z')
        .or_else(|| value.strip_suffix("+00:00"))
        .ok_or("StartedUtc must be an explicit UTC timestamp.")?;
    let (date, time) = value.split_once('T').ok_or("Invalid UTC timestamp.")?;
    let date: Vec<i64> = date
        .split('-')
        .map(|x| x.parse::<i64>())
        .collect::<std::result::Result<_, _>>()
        .map_err(|e| e.to_string())?;
    let time: Vec<f64> = time
        .split(':')
        .map(|x| x.parse::<f64>())
        .collect::<std::result::Result<_, _>>()
        .map_err(|e| e.to_string())?;
    if date.len() != 3 || time.len() != 3 {
        return Err("Invalid UTC timestamp.".into());
    }
    let (year, month, day) = (date[0], date[1], date[2]);
    let leap = year % 4 == 0 && (year % 100 != 0 || year % 400 == 0);
    let days = [
        31,
        if leap { 29 } else { 28 },
        31,
        30,
        31,
        30,
        31,
        31,
        30,
        31,
        30,
        31,
    ];
    if !(1..=9999).contains(&year)
        || !(1..=12).contains(&month)
        || day < 1
        || day > days[(month - 1) as usize]
        || !time.iter().all(|x| x.is_finite())
        || !(0.0..24.0).contains(&time[0])
        || time[0].fract() != 0.0
        || !(0.0..60.0).contains(&time[1])
        || time[1].fract() != 0.0
        || !(0.0..60.0).contains(&time[2])
    {
        return Err("UTC timestamp components out of range.".into());
    }
    let y = year - i64::from(month <= 2);
    let era = y.div_euclid(400);
    let yoe = y - era * 400;
    let m = month + if month > 2 { -3 } else { 9 };
    let doy = (153 * m + 2) / 5 + day - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    let civil_days = era * 146097 + doe - 719468;
    Ok(civil_days as f64 * 86400000.0 + time[0] * 3600000.0 + time[1] * 60000.0 + time[2] * 1000.0)
}

#[derive(Clone, Serialize)]
pub(super) struct ProcessSamples {
    pub duration_ms: f64,
    pub sample_count: usize,
    pub sampled_private_peak_bytes: Option<u64>,
    pub sampled_working_set_peak_bytes: Option<u64>,
    pub sampled_entry_private_bytes: Option<u64>,
    pub sampled_end_private_bytes: Option<u64>,
    pub sampled_cpu_ms: Option<u64>,
}

pub(super) struct WorkloadRun {
    pub metadata: Value,
    pub plans: BTreeMap<String, ProcessSamples>,
    pub scores: BTreeMap<String, f64>,
    pub gc: BTreeMap<String, BTreeMap<String, Vec<f64>>>,
    pub gc_records: usize,
    pub gc_details: BTreeMap<String, Vec<Value>>,
}

pub(super) fn load_run(directory: &Path) -> Result<WorkloadRun> {
    let metadata = read_json(&directory.join("run.json"))?;
    if metadata["ExitCode"].as_i64() != Some(0) || metadata["TimedOut"] != false {
        return Err(format!(
            "Workload failed/incomplete: {}",
            directory.display()
        ));
    }
    let start = utc_millis(text(&metadata, "StartedUtc")?)?;
    let mut markers = Vec::<Value>::new();
    let mut completions = Vec::new();
    let mut active = None::<String>;
    let mut gc = BTreeMap::<String, BTreeMap<String, Vec<f64>>>::new();
    let mut gc_records = 0;
    let mut gc_details = BTreeMap::<String, Vec<Value>>::new();
    let mut previous_marker_time = None;
    for line in
        BufReader::new(File::open(directory.join("stdout.log")).map_err(|e| e.to_string())?).lines()
    {
        let line = line.map_err(|e| e.to_string())?;
        let parsed = log_event(&line)?;
        if let Some(LogEvent::Activity(marker)) = parsed {
            let name = text(&marker, "activity")?.to_owned();
            if name.trim().is_empty() {
                return Err("Activity name must not be empty.".into());
            }
            let timestamp = number(&marker, "timestampMs")?;
            if previous_marker_time.is_some_and(|previous| timestamp < previous) {
                return Err("Activity marker clock went backwards.".into());
            }
            previous_marker_time = Some(timestamp);
            match text(&marker, "phase")? {
                "begin" if active.is_none() => {
                    active = Some(name.clone());
                    if gc
                        .insert(
                            name,
                            BTreeMap::from([
                                ("all".into(), Vec::new()),
                                ("major".into(), Vec::new()),
                            ]),
                        )
                        .is_some()
                    {
                        return Err("Duplicate activity window.".into());
                    }
                }
                "end" if active.as_deref() == Some(&name) => {
                    active = None;
                }
                _ => return Err("Unmatched/overlapping workload markers.".into()),
            }
            markers.push(marker);
        } else if let Some(LogEvent::Complete(value)) = parsed {
            completions.push(value);
        } else if let Some(name) = &active {
            let pause = if let Some((_, data)) = line.split_once("GC: ") {
                let value: Value = serde_json::from_str(data).map_err(|e| e.to_string())?;
                gc_details
                    .entry(name.clone())
                    .or_default()
                    .push(value.clone());
                Some((
                    value["pause"].as_f64().ok_or("GC pause missing.")?,
                    text(&value, "gc")?.to_owned(),
                ))
            } else if line.contains("pause=") && line.contains(" gc=") {
                let fields: BTreeMap<_, _> = line
                    .split_whitespace()
                    .filter_map(|x| x.split_once('='))
                    .collect();
                Some((
                    fields
                        .get("pause")
                        .ok_or("GC pause missing.")?
                        .parse::<f64>()
                        .map_err(|e| e.to_string())?,
                    fields.get("gc").ok_or("GC kind missing.")?.to_string(),
                ))
            } else {
                None
            };
            if let Some((pause, kind)) = pause {
                if !pause.is_finite() || pause < 0.0 {
                    return Err("Invalid GC pause.".into());
                }
                let groups = gc.get_mut(name).ok_or("Missing GC window.")?;
                groups
                    .get_mut("all")
                    .ok_or("Missing GC category.")?
                    .push(pause);
                if kind == "mc" {
                    groups
                        .get_mut("major")
                        .ok_or("Missing GC category.")?
                        .push(pause);
                }
                gc_records += 1;
            }
        }
    }
    if active.is_some() || completions.len() != 1 || completions[0]["runComplete"] != true {
        return Err("Missing/incomplete workload completion.".into());
    }
    let results = completions[0]["results"]
        .as_array()
        .ok_or("Completion scores missing.")?;
    let mut scores = BTreeMap::new();
    for result in results {
        if result.get("score").is_none() {
            continue;
        }
        let score = result["score"]
            .as_f64()
            .filter(|x| x.is_finite() && *x > 0.0)
            .ok_or("Invalid activity score.")?;
        if scores
            .insert(text(result, "name")?.to_owned(), score)
            .is_some()
        {
            return Err("Duplicate activity score.".into());
        }
    }
    let mut completed_names = std::collections::BTreeSet::new();
    for result in results {
        if !completed_names.insert(text(result, "name")?.to_owned()) {
            return Err("Duplicate completed activity.".into());
        }
    }
    if markers.len() != completed_names.len() * 2 {
        return Err("Incomplete activity markers.".into());
    }
    let mut lines = BufReader::new(
        File::open(directory.join("process-memory.csv")).map_err(|e| e.to_string())?,
    )
    .lines();
    let header = lines
        .next()
        .ok_or("Empty process-memory CSV.")?
        .map_err(|e| e.to_string())?;
    let columns: Vec<_> = header.split(',').collect();
    let index = |name: &str| {
        columns
            .iter()
            .position(|x| *x == name)
            .ok_or_else(|| format!("CSV field {name} missing."))
    };
    let (elapsed, private, working, cpu) = (
        index("ElapsedMs")?,
        index("PrivateBytes")?,
        index("WorkingSetBytes")?,
        index("CpuMs")?,
    );
    let mut samples = Vec::new();
    for line in lines {
        let line = line.map_err(|e| e.to_string())?;
        let fields: Vec<_> = line.split(',').collect();
        if fields.len() != columns.len() {
            return Err("Malformed process CSV row.".into());
        }
        let time = fields[elapsed].parse::<f64>().map_err(|e| e.to_string())?;
        if !time.is_finite()
            || time < 0.0
            || samples
                .last()
                .is_some_and(|x: &(f64, u64, u64, u64)| x.0 > time)
        {
            return Err("Invalid/nonmonotonic process sample time.".into());
        }
        samples.push((
            time,
            fields[private].parse::<u64>().map_err(|e| e.to_string())?,
            fields[working].parse::<u64>().map_err(|e| e.to_string())?,
            fields[cpu].parse::<u64>().map_err(|e| e.to_string())?,
        ));
    }
    if samples.is_empty() {
        return Err("No process samples.".into());
    }
    let mut plans = BTreeMap::new();
    for pair in markers.as_chunks::<2>().0 {
        let name = text(&pair[0], "activity")?.to_owned();
        let begin = number(&pair[0], "timestampMs")? as f64 - start;
        let end = number(&pair[1], "timestampMs")? as f64 - start;
        if end < begin || !completed_names.contains(&name) {
            return Err("Invalid plan window.".into());
        }
        let rows = &samples
            [samples.partition_point(|x| x.0 < begin)..samples.partition_point(|x| x.0 <= end)];
        let cpu_ms = match (rows.first(), rows.last()) {
            (Some(a), Some(b)) => Some(
                b.3.checked_sub(a.3)
                    .ok_or("CPU sample counter went backwards.")?,
            ),
            _ => None,
        };
        plans.insert(
            name,
            ProcessSamples {
                duration_ms: end - begin,
                sample_count: rows.len(),
                sampled_private_peak_bytes: rows.iter().map(|x| x.1).max(),
                sampled_working_set_peak_bytes: rows.iter().map(|x| x.2).max(),
                sampled_entry_private_bytes: rows.first().map(|x| x.1),
                sampled_end_private_bytes: rows.last().map(|x| x.1),
                sampled_cpu_ms: cpu_ms,
            },
        );
    }
    Ok(WorkloadRun {
        metadata,
        plans,
        scores,
        gc,
        gc_records,
        gc_details,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use std::sync::atomic::{AtomicU64, Ordering};
    static NEXT_TEST: AtomicU64 = AtomicU64::new(0);

    #[test]
    fn workload_parser_keeps_gc_and_process_samples_within_their_plan() {
        let directory = std::env::temp_dir().join(format!(
            "v8-workload-test-{}-{}",
            std::process::id(),
            NEXT_TEST.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&directory).unwrap();
        fs::write(
            directory.join("run.json"),
            json!({
                "ExitCode":0,"TimedOut":false,"StartedUtc":"1970-01-01T00:00:00Z"
            })
            .to_string(),
        )
        .unwrap();
        let log = concat!(
            "{\"activity\":\"A\",\"phase\":\"begin\",\"timestampMs\":10}\n",
            "GC: {\"pause\":4.0,\"gc\":\"mc\"}\n",
            "{\"activity\":\"A\",\"phase\":\"end\",\"timestampMs\":20}\n",
            "{\"activity\":\"B\",\"phase\":\"begin\",\"timestampMs\":30}\n",
            "pause=9.0 gc=mms\n",
            "{\"activity\":\"B\",\"phase\":\"end\",\"timestampMs\":40}\n",
            "{\"runComplete\":true,\"results\":[{\"name\":\"A\",\"score\":1.0},{\"name\":\"B\",\"score\":2.0}]}\n"
        );
        fs::write(directory.join("stdout.log"), log).unwrap();
        fs::write(
            directory.join("process-memory.csv"),
            concat!(
                "ElapsedMs,PrivateBytes,WorkingSetBytes,CpuMs\n",
                "10,100,80,1\n20,200,160,3\n30,900,400,4\n40,800,300,5\n"
            ),
        )
        .unwrap();
        let run = load_run(&directory).unwrap();
        assert_eq!(run.plans["A"].sampled_private_peak_bytes, Some(200));
        assert_eq!(run.plans["B"].sampled_private_peak_bytes, Some(900));
        assert_eq!(run.plans["A"].sampled_cpu_ms, Some(2));
        assert_eq!(run.gc["A"]["major"], vec![4.0]);
        assert!(run.gc["B"]["major"].is_empty());
        assert_eq!(run.gc_records, 2);
        fs::write(
            directory.join("stdout.log"),
            log.replace("\"score\":2.0", "\"score\":0.0"),
        )
        .unwrap();
        assert!(load_run(&directory).is_err());
        for name in ["run.json", "stdout.log", "process-memory.csv"] {
            fs::remove_file(directory.join(name)).unwrap();
        }
        fs::remove_dir(directory).unwrap();
    }
    #[test]
    fn timestamp_and_percentiles_preserve_precision() {
        assert_eq!(utc_millis("1970-01-01T00:00:00Z").unwrap(), 0.0);
        assert_eq!(
            utc_millis("2024-02-29T12:00:00.125Z").unwrap(),
            1709208000125.0
        );
        assert!(utc_millis("2023-02-29T00:00:00Z").is_err());
        assert!(utc_millis("2024-01-01T00:00:NaNZ").is_err());
        assert_eq!(percentile(&[1., 2., 3., 4.], 0.5), Some(2.5));
        assert_eq!(percentile(&[], 0.95), None);
    }
}
