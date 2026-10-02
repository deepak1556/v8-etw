# v8-etw

A Windows ETW analysis tool for V8. Decode traces, resolve local native and
JavaScript symbols, explore memory in a terminal UI, and compare recorded runs.

## Getting started

You need Windows and the Rust MSVC toolchain. Recording also requires the
Windows Performance Toolkit and an elevated terminal.

```powershell
cargo build --release --locked

.\target\release\v8-etw.exe trace.etl `
  --pid 1234 --output C:\reports\run-01 `
  --symbols-dir C:\build

.\target\release\v8-etw.exe tui C:\reports\run-01
```

If your linker environment is not configured, use the build helper:

```powershell
.\scripts\build.ps1 -ToolchainEnvironment C:\path\to\environment.x64
```

To record a workload, run this from an elevated PowerShell:

```powershell
.\scripts\capture.ps1 `
  -Executable C:\build\d8.exe `
  -RuntimeArguments @('--enable-etw-stack-walking', 'workload.js') `
  -OutputDirectory C:\captures\run-01
```

## Learn more

- [End-to-end analysis walkthrough](docs/analysis.md): record, interpret and
  compare using a real investigation.
- [Optional V8 instrumentation](patches/README.md): build the runtime probes
  for detailed memory reports.
- Run `v8-etw --help` for available commands.
- [Investigation records](investigations/loop-stack.md): the loop-stack experiment,
  [property-info ownership](investigations/property-info-ownership.md), and
  [empty-page caching](investigations/empty-page-cache.md).

Ordinary V8 traces support symbol and virtual allocation analysis. Detailed heap and allocator reports need additional runtime probe events.

Traces may contain script names, paths and unrelated machine activity. Keep them
local unless you have reviewed them for sharing.

## Development

```powershell
cargo test --locked
cargo clippy --locked --all-targets --all-features -- -D warnings
cargo fmt --all -- --check
```
