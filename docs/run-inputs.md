# Generate run inputs

The CLI accepts ordinary ETW traces for decoding and symbols. Composition and
comparisons also need named intervals and process samples.

## Which files come from where?

| Input | Producer | When you need it |
|---|---|---|
| `run.json`, `stdout.log`, `stderr.log`, `process-memory.csv` | `scripts/measure.ps1` | Compare runs or attach process samples to composition |
| The same files plus `capture.etl` | Elevated `scripts/capture.ps1` | Diagnose CPU, symbols and allocation events |
| `analysis/summary.json`, `analysis/events.jsonl`, optional symbol reports | Native CLI decoding an ETL | Compose runtime-probe snapshots or find CPU hotspots |
| Activity markers and completion inside `stdout.log` | Your application, or the example below | Select the same intervals across runs |
| `pairs.json` | You describe the control/candidate directories | Compare the runs, without naming conventions |

You do not need to create metadata or CSV files by hand.

## Record your application

From this repository in PowerShell 7:

```powershell
$work = (Resolve-Path .\docs\example-workload.js).Path
.\scripts\measure.ps1 -Executable C:\build\d8.exe `
  -RuntimeArguments @($work) -OutputDirectory C:\captures\before-a
```

The helper runs a fresh process, captures both logs, samples process counters
and writes its exit/timeout status. It refuses existing directories. A failed
child raises an error but retains its logs and metadata. No elevation is needed.
Use `-WorkingDirectory` for workloads with relative resources, and
`-SampleIntervalMs` / `-TimeoutSeconds` when appropriate.

Optional build identity can be supplied as `-Metadata @{ V8Revision = '...' }`.
Supply accurate profile/build identity for reproducibility; the helper does
not infer a checkout or clone your source. Measurement scripts must be finished
before building another binary used by the same recordings.

To also generate ETW, use `capture.ps1` in an elevated terminal:

```powershell
.\scripts\capture.ps1 -Executable C:\build\d8.exe `
  -RuntimeArguments @('--enable-etw-stack-walking',
    '--no-enable-etw-by-custom-filter-only', $work) `
  -OutputDirectory C:\captures\diagnostic-run\capture
$run = Get-Content C:\captures\diagnostic-run\capture\run.json -Raw |
  ConvertFrom-Json
v8-etw C:\captures\diagnostic-run\capture\capture.etl `
  --pid $run.ProcessId --output C:\captures\diagnostic-run\analysis `
  --symbols-dir C:\captures\matching-build --require-pdb d8.exe
```

For detailed composition, first build the [optional V8 probes](../patches/README.md)
and add `--trace-process-memory-etw` to the capture arguments. Neither the
recorder nor CLI installs runtime probes automatically.

## A recorded run

```text
run/
  run.json
  stdout.log
  process-memory.csv
```

`run.json` identifies the process start and invocation:

```json
{
  "StartedUtc": "2026-01-01T00:00:00Z",
  "ExitCode": 0,
  "TimedOut": false,
  "Arguments": ["workload.js"]
}
```

Optional `V8Revision` and `ProfileInputs` fields are compared when present.
Supplying either in just one run of a pair is an error. Arguments must match
except for explicitly allowed differences.

The numeric CSV columns are:

```csv
ElapsedMs,PrivateBytes,WorkingSetBytes,CpuMs
0,1000000,800000,0
20,2000000,1500000,10
```

Time is milliseconds since process start; memory is bytes and CPU is cumulative
process CPU milliseconds. A short interval may have no samples, which produces
null measurements rather than invented peaks.

The application emits JSON lines among its ordinary output. In d8:

```javascript
print(JSON.stringify({ activity: 'startup', phase: 'begin', timestampMs: Date.now() }));
if (typeof d8.zoneMemoryMarker === 'function') d8.zoneMemoryMarker('startup', true);
// Run the existing application work here.
if (typeof d8.zoneMemoryMarker === 'function') d8.zoneMemoryMarker('startup', false);
print(JSON.stringify({ activity: 'startup', phase: 'end', timestampMs: Date.now() }));
print(JSON.stringify({ runComplete: true, results: [{ name: 'startup' }] }));
```

The JSON markers support process comparisons. The optional d8 call supplies
ETW interval markers for composition/hotspots. Emitting JSON alone does not
insert interval events into an ETL. The bundled [example](example-workload.js)
works with stock d8 for comparisons and uses the marker API when patched.

For example, the log lines look like:

```json
{"activity":"startup","phase":"begin","timestampMs":1767225600000}
{"activity":"startup","phase":"end","timestampMs":1767225600020}
{"runComplete":true,"results":[{"name":"startup"}]}
```

V8 GC JSON (`GC: {...}`) or legacy `pause=... gc=...` lines are read within those
intervals. They are optional for performance only comparisons.

## Pair the runs you recorded

A comparison directory contains `pairs.json` plus its run directories:

Record `before-a` and `after-a` with `measure.ps1`, changing only the intended
implementation/flag. Repeat for `before-b` and `after-b`, reversing order.
Write this manifest beside those directories (replace paths with yours):

```json
{
  "performance": [
    {"id":"repeat-a","control":"before-a","candidate":"after-a"},
    {"id":"repeat-b","control":"before-b","candidate":"after-b"}
  ],
  "latency": [
    {"id":"timing-a","control":"before-timing","candidate":"after-timing"}
  ]
}
```

For example, save it as `C:\captures\paired-runs\pairs.json` using your editor,
then run `v8-etw compare C:\captures\paired-runs --output C:\reports\comparison.json`.

Paths are relative child directories. Pair IDs are unique within each group.
`latency` is optional; without it, GC latency is reported as unavailable.
When supplied, both timing runs must contain decoded GC observations.
No seed naming or V8 random-seed flag is required for this format.

For GC latency, use `measure.ps1` again with `--trace-gc-nvp` in both runs and
put those directories in `latency`. Preserve the same activities and other
runtime arguments. Keep GC tracing out of the performance pairs. If no latency
runs were recorded, omit `latency`; the report says latency is unavailable.

## Adding decoded ETW

For composition with process samples, use:

```text
diagnostic-run/
  analysis/
    summary.json
    events.jsonl
  capture/
    run.json
    stdout.log
    process-memory.csv
```

Pass `diagnostic-run` to `composition`, or pass `analysis` directly for ETW-only
composition. Its versioned memory probes must include interval markers and
complete snapshots. The tool does not install probes in the runtime.
