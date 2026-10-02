use super::{
    Result, analyze, build_reports, large_allocations, tui, validated_decode_summary, zones,
};
use crate::reports::{comparison, composition, hotspots};
use std::ffi::OsString;
use std::path::{Path, PathBuf};

const HELP: &str = "\
v8-etw TRACE.etl --pid PID --output NEW_DIRECTORY [--allow-loss] [--tdh-probe] [--symbols-dir LOCAL_DIRECTORY] [--require-pdb MODULE.exe]
v8-etw reports DECODED_DIRECTORY [--symbols-dir LOCAL_DIRECTORY] [--require-pdb MODULE.exe]
v8-etw symbols DECODED_DIRECTORY --symbols-dir LOCAL_DIRECTORY [--require-pdb MODULE.exe]
v8-etw zones DECODED_DIRECTORY
v8-etw composition RUN_OR_DECODED_DIRECTORY --output NEW_JSON [--baseline RUN_DIRECTORY]...
v8-etw hotspots RUN_OR_DECODED_DIRECTORY --output NEW_JSON
v8-etw compare PAIRED_RUNS_DIRECTORY --output NEW_JSON [--allow-arg-difference FLAG]...
  [--exclude-pair ID]... [--exclusion-reason TEXT]
v8-etw large REPORT_DIRECTORY [THRESHOLD_BYTES]
v8-etw tui REPORT_DIRECTORY_OR_ACTIVITY_JSON
v8-etw render REPORT_DIRECTORY_OR_ACTIVITY_JSON NEW_TEXT_FILE";

pub(super) struct DecodeOptions {
    pub(super) trace: PathBuf,
    pub(super) output: PathBuf,
    pub(super) pid: u32,
    pub(super) allow_loss: bool,
    pub(super) symbol_dirs: Vec<PathBuf>,
    pub(super) required_pdbs: Vec<String>,
    pub(super) tdh_probe: bool,
}

fn decode_options(args: &[OsString]) -> Result<DecodeOptions> {
    let mut args = args.iter();
    let trace = args.next().ok_or("Missing ETL path.")?;
    let mut pid = None;
    let mut output = None;
    let mut allow_loss = false;
    let mut symbol_dirs = Vec::new();
    let mut required_pdbs = Vec::new();
    let mut tdh_probe = false;
    while let Some(argument) = args.next() {
        match argument.to_str() {
            Some("--pid") => {
                pid = Some(
                    args.next()
                        .and_then(|value| value.to_str()?.parse::<u32>().ok())
                        .filter(|value| *value != 0)
                        .ok_or("--pid requires a nonzero process ID.")?,
                );
            }
            Some("--output") => {
                output = Some(PathBuf::from(args.next().ok_or("Missing output path.")?))
            }
            Some("--allow-loss") => allow_loss = true,
            Some("--tdh-probe") => tdh_probe = true,
            Some("--symbols-dir") => symbol_dirs.push(PathBuf::from(
                args.next().ok_or("Missing --symbols-dir path.")?,
            )),
            Some("--require-pdb") => required_pdbs.push(
                args.next()
                    .and_then(|value| value.to_str())
                    .ok_or("Missing --require-pdb module name.")?
                    .to_owned(),
            ),
            _ => return Err(format!("Unknown argument: {}", argument.to_string_lossy())),
        }
    }
    Ok(DecodeOptions {
        trace: PathBuf::from(trace),
        output: output.ok_or("Missing --output directory.")?,
        pid: pid
            .ok_or("Missing --pid; system-wide events must not be mistaken for the workload.")?,
        allow_loss,
        symbol_dirs,
        required_pdbs,
        tdh_probe,
    })
}

fn resume_reports(args: &[OsString]) -> Result<()> {
    let directory = PathBuf::from(args.get(1).ok_or("Missing reports directory.")?);
    let symbols_only = args.first().and_then(|arg| arg.to_str()) == Some("symbols");
    let outputs: &[&str] = if symbols_only {
        &[
            "attribution.json",
            "symbolized.jsonl",
            "analysis-timings.json",
        ]
    } else {
        &[
            "heap-report.json",
            "zone-report.json",
            "cppgc-history.json",
            "cppgc-lifetimes.jsonl",
            "attribution.json",
            "symbolized.jsonl",
            "analysis-timings.json",
        ]
    };
    for name in outputs {
        if directory.join(name).exists() {
            return Err(format!(
                "Report output {name} already exists; refusing to overwrite."
            ));
        }
    }
    let summary = validated_decode_summary(&directory)?;
    let mut symbols = Vec::new();
    let mut required = Vec::new();
    let mut index = 2;
    while index < args.len() {
        let value = args.get(index + 1).ok_or("Report option needs a value.")?;
        match args[index].to_str() {
            Some("--symbols-dir") => symbols.push(PathBuf::from(value)),
            Some("--require-pdb") => {
                required.push(value.to_str().ok_or("Invalid module name.")?.to_owned())
            }
            _ => return Err("Unknown report option.".into()),
        }
        index += 2;
    }
    if !directory.join("events.jsonl").is_file() {
        return Err("Decoded events.jsonl missing.".into());
    }
    if symbols_only && symbols.is_empty() {
        return Err("Symbol-only resume needs at least one --symbols-dir.".into());
    }
    build_reports(
        &directory,
        &symbols,
        &required,
        !symbols_only
            && summary["selected_by_kind"]["heap_probe"]
                .as_u64()
                .is_some_and(|count| count > 0),
    )
}

fn analysis_options(args: &[OsString]) -> Result<()> {
    let input = Path::new(args.get(1).ok_or("Analysis input directory missing.")?);
    let mut output = None;
    let mut baselines = Vec::new();
    let mut ignored = Vec::new();
    let mut excluded = Vec::new();
    let mut exclusion_reason = None;
    let composition_command = args[0] == "composition";
    let hotspot_command = args[0] == "hotspots";
    let mut index = 2;
    while index < args.len() {
        let value = args
            .get(index + 1)
            .ok_or("Analysis option requires a value.")?;
        match args[index].to_str() {
            Some("--output") if output.is_none() => output = Some(PathBuf::from(value)),
            Some("--baseline") if composition_command => baselines.push(PathBuf::from(value)),
            Some("--allow-arg-difference") if !composition_command && !hotspot_command => {
                let argument = value
                    .to_str()
                    .filter(|x| x.starts_with("--") && x.len() > 2)
                    .ok_or("Allowed argument difference must be a full --flag.")?;
                ignored.push(argument.to_owned());
            }
            Some("--exclude-seed") if !composition_command && !hotspot_command => {
                excluded.push(
                    value
                        .to_str()
                        .ok_or("Seed must be UTF-8.")?
                        .parse::<u64>()
                        .map_err(|e| e.to_string())?
                        .to_string(),
                );
            }
            Some("--exclude-pair") if !composition_command && !hotspot_command => {
                excluded.push(
                    value
                        .to_str()
                        .filter(|s| !s.trim().is_empty())
                        .ok_or("Pair ID must not be empty.")?
                        .to_owned(),
                );
            }
            Some("--exclusion-reason")
                if !composition_command && !hotspot_command && exclusion_reason.is_none() =>
            {
                exclusion_reason = Some(
                    value
                        .to_str()
                        .filter(|s| !s.trim().is_empty())
                        .ok_or("Exclusion reason must not be empty.")?
                        .to_owned(),
                );
            }
            _ => return Err("Unknown/duplicate analysis option.".into()),
        }
        index += 2;
    }
    let output = output.ok_or("Analysis requires --output NEW_JSON.")?;
    if composition_command {
        composition::run(input, &baselines, &output)
    } else if hotspot_command {
        hotspots::run(input, &output)
    } else {
        comparison::run(
            input,
            &output,
            &ignored,
            &excluded,
            exclusion_reason.as_deref(),
        )
    }
}

fn dispatch(args: &[OsString]) -> Result<()> {
    match args.first().and_then(|argument| argument.to_str()) {
        Some("composition" | "compare" | "hotspots") => analysis_options(args),
        Some("zones") if args.len() == 2 => {
            let directory = Path::new(&args[1]);
            if directory.join("zone-report.json").exists() {
                Err("Zone report already exists; refusing to overwrite.".into())
            } else {
                validated_decode_summary(directory).and_then(|_| zones::run(directory))
            }
        }
        Some("zones") => Err("Usage: v8-etw zones DECODED_DIRECTORY".into()),
        Some("large") if args.len() == 2 || args.len() == 3 => {
            let threshold = if let Some(value) = args.get(2) {
                value
                    .to_str()
                    .and_then(|value| value.parse::<u64>().ok())
                    .ok_or_else(|| "Invalid large allocation threshold.".to_owned())
            } else {
                Ok(65536)
            };
            threshold.and_then(|threshold| large_allocations::run(Path::new(&args[1]), threshold))
        }
        Some("large") => Err("Usage: v8-etw large REPORT_DIRECTORY [THRESHOLD_BYTES]".into()),
        Some("reports" | "symbols") => resume_reports(args),
        Some("tui") if args.len() == 2 => tui::run(Path::new(&args[1])),
        Some("render") if args.len() == 3 => {
            tui::render_once(Path::new(&args[1]), Path::new(&args[2]))
        }
        Some("tui" | "render") => {
            Err("Usage: v8-etw tui REPORT_DIRECTORY_OR_ACTIVITY_JSON | render REPORT_DIRECTORY_OR_ACTIVITY_JSON NEW_TEXT_FILE".into())
        }
        _ => decode_options(args).and_then(analyze),
    }
}

pub(super) fn run() {
    let args: Vec<_> = std::env::args_os().skip(1).collect();
    if args.first().is_some_and(|argument| argument == "--help") {
        println!("{HELP}");
        return;
    }
    if let Err(error) = dispatch(&args) {
        eprintln!("v8-etw: {error}");
        std::process::exit(1);
    }
}
