# Optional runtime memory probes

This directory contains optional runtime instrumentation patches for detailed
ETW memory reports (`composition`, `heap-report.json`, and `cppgc` lifetime
history). Ordinary V8/Chromium ETW traces (`VirtualAllocation`, `SampledProfile`,
and `V8.js`) work without these patches.

| Patch | Target repository | Base commit | Purpose |
|---|---|---|---|
| [v8-memory-probes.patch](v8-memory-probes.patch) | `v8` (`src/v8`) | `9066f6647a115e2eab402fda8d764e57190b682f` | Standalone `d8` probes for activity CPU attribution, process composition, V8 page-pool backing, and Zone accounting |
| [v8-cppgc-lifetime-probes.patch](v8-cppgc-lifetime-probes.patch) | `v8` (`src/v8`) | `9066f6647a115e2eab402fda8d764e57190b682f` | `CppHeap` allocation-traffic sampling (`SetAllocationObserverForTesting`) and process-wide `cppgc` object lifetime stream (`StartLifetimeObserverForTesting`) |
| [chromium-partition-alloc-probes.patch](chromium-partition-alloc-probes.patch) | `chromium` (`src`) | `dfe95e2247ebea04d3ef31c953ec27e3581b2089` | `PartitionRoot::DumpAllStatsForTesting` and `GetRootFromAddress` hooks for PartitionAlloc root and bucket statistics |
| [electron-memory-probes.patch](electron-memory-probes.patch) | `electron` (`src/electron`) | `03703aea6a3f11c45030f8b60909066416be9a73` | `Electron.Memory` ETW provider (`9EEB8A39-89E8-4C86-9F88-33083799F7D9`) and `--memory-etw-probe` `v8Util` bridge (`startMemoryProbe`, `memoryCheckpoint`, `memoryMarker`, `stopMemoryProbe`) |

## 1. Standalone `d8` probes (`v8-memory-probes.patch`)

The patch targets V8 commit `9066f6647a115e2eab402fda8d764e57190b682f` on
Windows x64. Its `d8` target depends on Chromium's PartitionAlloc target.

### Apply and build

From the V8 repository:

```powershell
git rev-parse HEAD
git status --short
git apply --check C:\tools\v8-etw\patches\v8-memory-probes.patch
git apply C:\tools\v8-etw\patches\v8-memory-probes.patch
```

Use the checkout's existing GN/Ninja build workflow to rebuild `d8`. Keep a
production like optimized configuration for process memory diagnosis. The patch
does not require RTTI or precise per-type Zone statistics. Preserve the rebuilt
`d8.exe`, matching PDB, and snapshot file before recording.

### What it enables

- `--trace-process-memory-etw`: periodic, natural GC, and activity boundary
  snapshots of process, heap spaces, backing stores, LAB tails, V8 page-pool
  backing, and PartitionAlloc roots.
- `--trace-zone-etw`: Zone segment lifetime events and expansion stacks.
- `--turbo-stats --turbo-stats-wasm --maglev-stats`: existing compiler counters
  also exported through the diagnostic provider.
- `d8.zoneMemoryMarker(name, begin)`: emits an interval marker and, when enabled,
  memory snapshots at its boundaries. Use any activity name.

The flags default off. Snapshots read internal accounting without retiring LABs
or forcing GC; they still add overhead.

Periodic snapshots are requested every 20 ms on the isolate thread, with
additional observations at natural GC and activity boundaries. Long native work
can delay those requests, so a short-lived peak can be missed.

Follow the [walkthrough](../docs/analysis.md) to record and interpret a run.

## 2. Electron / Chromium / `cppgc` heap & lifetime probes

To record multi-layer Electron renderer/browser memory checkpoints (`V8HeapTotals`,
`V8Space`, `CppgcTotals`, `CppgcSpace`, `CppgcType`, `PartitionTotals`,
`PartitionBucket`) and optional exact `cppgc` object lifetime streams
(`CppgcLifetime`, `CppgcAllocationTraffic`), apply the three companion patches in
an Electron checkout:

```powershell
git -C src\v8 apply --check C:\tools\v8-etw\patches\v8-cppgc-lifetime-probes.patch
git -C src\v8 apply C:\tools\v8-etw\patches\v8-cppgc-lifetime-probes.patch

git -C src apply --check C:\tools\v8-etw\patches\chromium-partition-alloc-probes.patch
git -C src apply C:\tools\v8-etw\patches\chromium-partition-alloc-probes.patch

git -C src\electron apply --check C:\tools\v8-etw\patches\electron-memory-probes.patch
git -C src\electron apply C:\tools\v8-etw\patches\electron-memory-probes.patch
```

### What it enables

When launched with `--memory-etw-probe`, `process._linkedBinding('electron_common_v8_util')`
registers the `Electron.Memory` ETW provider (`GUID 9EEB8A39-89E8-4C86-9F88-33083799F7D9`,
keyword `0x1`, included in [profiles/v8-memory.wprp](../profiles/v8-memory.wprp))
and exposes:

- `startMemoryProbe(samplingIntervalBytes?, enableCppgcHistory?, fullCppgcStacks?)`:
  starts V8 heap sampling, PartitionAlloc Poisson sampling, `cppgc` allocation
  traffic sampling, and (when `enableCppgcHistory` is `true`) the process-wide
  `cppgc` object lifetime stream.
- `memoryCheckpoint(phaseName)`: emits a synchronized checkpoint snapshot across
  V8 heap spaces, `cppgc::HeapStatistics::kDetailed` spaces/types/pooled bytes,
  PartitionAlloc roots/buckets, and V8 allocation profile nodes.
- `memoryMarker(phase, iteration, suite)`: emits a workload boundary marker.
- `stopMemoryProbe()`: stops active observers and verifies zero failed ETW event
  writes (`ProbeStopped`).

Decode the resulting `.etl` trace with `v8-etw` to generate `heap-report.json`,
`cppgc-history.json`, and `cppgc-lifetimes.jsonl`, and inspect them with
`v8-etw tui <report-dir>` or `v8-etw render <report-dir> preview.txt`.

