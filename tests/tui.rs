type Result<T> = std::result::Result<T, String>;

use serde_json::json;
use std::{
    fs,
    path::PathBuf,
    sync::atomic::{AtomicU64, Ordering},
};
use v8_etw::tui;

static NEXT: AtomicU64 = AtomicU64::new(0);

fn composition_point(private: u64) -> serde_json::Value {
    json!({"process_private_bytes":private,"process_working_set_bytes":0,
        "v8_heap_committed_bytes":4096,"v8_heap_accounted_used_bytes":2048,
        "v8_backing_store_counter_bytes":null,
        "spaces":{"old_space":{"committed":4096,"accounted_used":2048}},
        "main_thread_lab_tails":{"old":0}})
}

#[test]
fn activity_dashboard_renders_composition_comparison_and_all_details() {
    let directory = Directory::new();
    directory.write("composition.json",json!({"schema_version":1,"snapshot_count":6,
        "plans":{
            "build-records":{"entry":composition_point(1000),"snapshot_peak":composition_point(2000),
                "end":composition_point(1500),"max_observed_snapshot_gap_ms":25,
                "natural_major_gc_epilogues":[{"process_private_bytes":1200}],
                "within_plan_baseline_runs":[{"sampled_private_peak_bytes":1800}],
                "pool_operations":{"recommit":{"count":0,"p95_duration_us":null}}},
            "use-records":{"entry":composition_point(1500),"snapshot_peak":composition_point(3000),
                "end":composition_point(1500),"snapshot_count":3}},
        "limitations":["NON-ADDITIVE activity fixture"]}));
    directory.write(
        "comparison.json",
        json!({"schema_version":1,"pair_ids":["repeat-a"],
        "score_available":false,"gc_latency_available":true,
        "plans":{"use-records":{"paired_runs":[{"pair_id":"repeat-a",
            "control":{"sampled_private_peak_bytes":4000},
            "candidate":{"sampled_private_peak_bytes":3000}}],
            "median_score_change_percent":null,
            "paired_metric_summary":{"private_peak_change_percent":{"median":-25.0,
                "observed_pairs":1,"missing_pairs":0}},
            "gc_latency_control":{"all":{"p95_ms":5.0,"count":2}},
            "gc_latency_candidate":{"all":{"p95_ms":7.0,"count":2}},
            "gc_latency_pairs":[{"pair_id":"repeat-a","candidate":{"major":{"max_ms":8.0}}}]}},
        "exclusion_reason":null,"limitations":["Low-count tails require more observations"]}),
    );
    let output = directory.0.join("activity.txt");
    tui::render_once(&directory.0, &output).unwrap();
    let text = fs::read_to_string(&output).unwrap();
    for expected in [
        "Activities",
        "build-records",
        "use-records",
        "Entry",
        "Own peak",
        "Median paired change",
        "-25.00%",
        "unavailable",
        "snapshot_peak.spaces.old_space",
        "max_observed_snapshot_gap_ms",
        "natural_major_gc_epilogues",
        "within_plan_baseline_runs",
        "gc_latency_pairs",
        "gc_latency_candidate.all.p95_ms",
        "paired_runs[0].pair_id: repeat-a",
        "NON-ADDITIVE activity fixture",
        "Low-count tails require more observations",
    ] {
        assert!(text.contains(expected), "missing {expected}");
    }
}

#[test]
fn activity_report_file_supports_custom_names_and_rejects_invalid_metrics() {
    let directory = Directory::new();
    let name = "my-run-results.json";
    let mut report = json!({"schema_version":1,"pair_ids":["a"],"plans":{"startup":{
        "paired_runs":[],"median_score_change_percent":null,
        "paired_metric_summary":{"private_peak_change_percent":{"median":0.0}}}}});
    directory.write(name, report.clone());
    let output = directory.0.join("custom.txt");
    tui::render_once(&directory.0.join(name), &output).unwrap();
    assert!(fs::read_to_string(&output).unwrap().contains("+0.00%"));
    report["plans"]["startup"]["paired_metric_summary"]["private_peak_change_percent"]["median"] =
        json!("bad");
    directory.write(name, report);
    let invalid = directory.0.join("invalid.txt");
    assert!(
        tui::render_once(&directory.0.join(name), &invalid)
            .unwrap_err()
            .contains("numeric measurement")
    );
    assert!(!invalid.exists());
    directory.write(name, json!({"schema_version":99,"plans":{}}));
    assert!(
        tui::render_once(&directory.0.join(name), &invalid)
            .unwrap_err()
            .contains("schema")
    );
    let file = fs::File::create(directory.0.join(name)).unwrap();
    file.set_len(32 * 1024 * 1024 + 1).unwrap();
    assert!(
        tui::render_once(&directory.0.join(name), &invalid)
            .unwrap_err()
            .contains("byte limit")
    );
    assert!(!invalid.exists());
}

struct Directory(PathBuf);
impl Directory {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!(
            "v8-etw-tui-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&path).unwrap();
        Self(path)
    }
    fn write(&self, name: &str, value: serde_json::Value) {
        fs::write(self.0.join(name), value.to_string()).unwrap();
    }
}
impl Drop for Directory {
    fn drop(&mut self) {
        fs::remove_dir_all(&self.0).unwrap();
    }
}

fn heap() -> serde_json::Value {
    json!({
        "schema_version": 1, "errors": [], "limitations": [],
        "checkpoints": [{
            "checkpoint": 7, "phase": "after GC", "complete": true,
            "heap_census": {
                "v8_totals": {"UsedBytes": 12345, "HeapBytes": 20000, "PhysicalBytes": 20000,
                    "ExternalBytes": 32, "MallocedBytes": 16},
                "cppgc_totals": {"UsedBytes": 456, "CommittedBytes": 1024, "ResidentBytes": 1024, "PooledBytes": 0},
                "cppgc_types_by_space": {"blink::Node": {"allocated_bytes": 456, "object_count": 3}},
                "partition_roots": {"root-A": {"ActiveBytes": 100}},
                "partition_buckets": [{"SlotBytes": 16, "ActiveBytes": 100, "ProvisionedBytes": 256}]
            },
            "v8_live_allocation_estimates_by_path": {
                "root -> allocate@fixture.js": {"estimated_live_bytes": 4096, "estimated_object_count": 8}
            }
        }]
    })
}

#[test]
fn headless_snapshot_has_layers_paths_fragmentation_and_lifecycle() {
    let directory = Directory::new();
    directory.write("heap-report.json", heap());
    directory.write("cppgc-history.json", json!({
        "schema_version": 1, "complete": false, "warnings": ["lost lifecycle events"],
        "heaps": [{"heap_id": 8, "survivors_by_type": [{"type_name": "blink::Node", "bytes": 64}]}]
    }));
    let output = directory.0.join("snapshot.txt");
    tui::render_once(&directory.0, &output).unwrap();
    let snapshot = fs::read_to_string(&output).unwrap();
    for text in [
        "after GC",
        "NON-ADDITIVE",
        "NEVER grand summed",
        "OS footprint",
        "UsedBytes: 12345",
        "blink::Node",
        "slack bytes: 156",
        "allocate@fixture.js",
        "NOT proven leaks",
        "NOT exact",
        "objects=unavailable",
        "lost lifecycle events",
        "summary.json missing",
        "symbolized.jsonl missing",
    ] {
        assert!(snapshot.contains(text), "missing {text}");
    }
    assert!(tui::render_once(&directory.0, &output).is_err());
    assert_eq!(fs::read_to_string(output).unwrap(), snapshot);
}

#[test]
fn malformed_case_sensitive_and_oversized_reports_fail_explicitly() {
    let directory = Directory::new();
    let mut value = heap();
    value["checkpoints"][0]["heap_census"]["cppgc_types_by_space"]["blink::Node"] =
        json!({"Allocated_Bytes": 456});
    directory.write("heap-report.json", value);
    let output = directory.0.join("snapshot.txt");
    assert!(
        tui::render_once(&directory.0, &output)
            .unwrap_err()
            .contains("allocated_bytes")
    );
    assert!(!output.exists());
    fs::write(directory.0.join("heap-report.json"), "{").unwrap();
    assert!(
        tui::render_once(&directory.0, &output)
            .unwrap_err()
            .contains("heap-report.json")
    );
    let file = fs::File::create(directory.0.join("heap-report.json")).unwrap();
    file.set_len(32 * 1024 * 1024 + 1).unwrap();
    assert!(
        tui::render_once(&directory.0, &output)
            .unwrap_err()
            .contains("32 MiB interactive canonical-report limit")
    );
}

#[test]
fn oversized_canonical_report_uses_bounded_ui_projections() {
    let directory = Directory::new();
    let heap = fs::File::create(directory.0.join("heap-report.json")).unwrap();
    heap.set_len(32 * 1024 * 1024 + 1).unwrap();
    directory.write(
        "runtime-cost-census-all-iterations.json",
        json!({
            "workload": "fixture",
            "target_pid": 7,
            "cppgc_types_by_median_iteration_footprint": [{
                "type": "blink::ProjectedType", "present_iterations": 1,
                "median_allocated_bytes": 4096.0, "min_allocated_bytes": 2048,
                "max_allocated_bytes": 8192, "median_object_count": 3.0
            }],
            "iteration_memory": [{
                "phase": "iteration-1", "v8_used_bytes": 10000,
                "cppgc_used_bytes": 4096, "cppgc_allocation_count": 3,
                "cppgc_allocation_traffic_bytes": 8192,
                "native_estimated_live_bytes": 16384
            }],
            "largest_bucket_slack_observations": [{
                "phase": "iteration-1", "root": "root-projected", "slot_bytes": 64,
                "active_bytes": 4096, "provisioned_bytes": 8192,
                "provisioned_slack_bytes": 4096, "active_count": 4,
                "empty_spans": 1, "direct_map": 0
            }],
            "lifetime_heaps": [{
                "heap_id": "heap-projected", "complete": true, "allocations": 4,
                "frees": 1, "moves": 0, "resizes": 1, "seeded_objects": 2,
                "live_objects": 5, "live_bytes": 65536, "completed_major_gcs": 2,
                "object_header_bytes": 40, "known_requested_payload_bytes": 16,
                "known_rounding_or_retained_capacity_bytes": 8,
                "objects_with_unknown_requested_size": 2,
                "retention_candidate_count": 1, "major_gc_history": []
            }],
            "limitations": []
        }),
    );
    directory.write(
        "reader-performance-summary.json",
        json!({
            "etl_bytes": 100, "total_events": 10, "selected_events": 8,
            "decode_elapsed_ms": 2, "schema_queries": 1,
            "symbol_attribution_ms": 3, "frame_occurrences": 6,
            "frame_coverage": {"pdb": 4, "jit": 1, "module_only": 1,
                "no_image_or_jit_range": 0, "unresolved": 0},
            "lifetime_complete": true, "losses": {"events": 0, "buffers": 0},
            "validation": [], "limitations": []
        }),
    );
    directory.write(
        "suite-cost-summary.json",
        json!({
            "complete": true, "full_enabled_suites": 20, "iterations": 10,
            "workload_markers": 400, "detailed_suite_count": 1,
            "ranked_suite_costs": [{
                "suite": "ProjectedSuite", "observed_iterations": 10,
                "median_allocation_traffic_bytes": 1000.0,
                "median_allocation_count": 2.0,
                "median_cppgc_after_bytes": 3000.0, "iterations": []
            }],
            "limitations": []
        }),
    );
    directory.write(
        "large-allocation-report.json",
        json!({
            "schema_version": 1, "complete": true, "lifetime_records": 10,
            "analysis_elapsed_ms": 1, "heaps": {
                "heap-projected": {
                    "largest_allocations": [{
                        "allocation_id": 9, "type_name": "ProjectedLarge",
                        "bytes": 65536, "gc_info": 4, "freed_at": null
                    }]
                }
            }, "limitations": []
        }),
    );
    let output = directory.0.join("projection-snapshot.txt");
    tui::render_once(&directory.0, &output).unwrap();
    let snapshot = fs::read_to_string(output).unwrap();
    for text in [
        "Projection mode",
        "Iteration memory lenses",
        "ProjectedSuite",
        "blink::ProjectedType",
        "root-projected",
        "Lifecycle projection",
        "ProjectedLarge",
        "32 MiB interactive canonical-report limit",
    ] {
        assert!(snapshot.contains(text), "missing {text}");
    }
}

#[test]
fn preserves_case_distinct_symbols_and_unknown_frames() {
    let directory = Directory::new();
    directory.write("heap-report.json", heap());
    directory.write(
        "attribution.json",
        json!({
            "allocation_function_traffic": {
                "SkPath::Make": {"samples": 2}, "SkPath::make": {"samples": 1}
            }
        }),
    );
    fs::write(
        directory.0.join("symbolized.jsonl"),
        json!({
            "event_name": "NativeSampleAdded", "timestamp_raw": "123", "tid": 1,
            "allocation_properties": {"EstimatedBytes": 4096},
            "frames": [{"function": "nativeAllocate", "status": "pdb"},
                {"address": "0x1234", "status": "no_image_or_jit_range"}]
        })
        .to_string()
            + "\n",
    )
    .unwrap();
    let output = directory.0.join("snapshot.txt");
    tui::render_once(&directory.0, &output).unwrap();
    let snapshot = fs::read_to_string(output).unwrap();
    for text in [
        "SkPath::Make",
        "SkPath::make",
        "nativeAllocate",
        "0x1234",
        "trace-wide samples",
    ] {
        assert!(snapshot.contains(text));
    }
}

#[test]
fn renders_actual_reports_when_requested() {
    let Some(path) = std::env::var_os("V8_ETW_REPORT_DIR") else {
        return;
    };
    let directory = Directory::new();
    let output = directory.0.join("actual-snapshot.txt");
    tui::render_once(&PathBuf::from(path), &output).unwrap();
    let snapshot = fs::read_to_string(output).unwrap();
    for text in [
        "NON-ADDITIVE",
        "Cppgc heap census",
        "Partition bucket",
        "V8 paths",
        "events_lost: 0",
    ] {
        assert!(snapshot.contains(text), "missing {text}");
    }
}

#[test]
fn run_signature_matches_cli_contract() {
    let _: fn(&std::path::Path) -> Result<()> = tui::run;
}
