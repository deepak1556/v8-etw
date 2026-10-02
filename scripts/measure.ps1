#requires -Version 7.0
[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$Executable,
    [string[]]$RuntimeArguments = @(),
    [Parameter(Mandatory)][string]$OutputDirectory,
    [string]$WorkingDirectory,
    [ValidateRange(1, 1000)][int]$SampleIntervalMs = 20,
    [ValidateRange(1, 86400)][int]$TimeoutSeconds = 300,
    [hashtable]$Metadata = @{}
)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$Executable = (Resolve-Path -LiteralPath $Executable).Path
$info = [Diagnostics.ProcessStartInfo]::new($Executable)
$info.WorkingDirectory = if ($WorkingDirectory) {
    (Resolve-Path -LiteralPath $WorkingDirectory).Path
} else { Split-Path $Executable }
$info.UseShellExecute = $false
$info.RedirectStandardOutput = $true
$info.RedirectStandardError = $true
foreach ($argument in $RuntimeArguments) { $info.ArgumentList.Add($argument) }
$reserved = @('Executable','Arguments','WorkingDirectory','ProcessId','StartedUtc',
    'SampleIntervalMs','Samples','ElapsedMs','ExitCode','TimedOut')
foreach ($key in $Metadata.Keys) {
    if ($key -in $reserved) { throw "Metadata cannot replace recorded field '$key'." }
}
if (Test-Path -LiteralPath $OutputDirectory) {
    throw "Output directory already exists: $OutputDirectory"
}
$null = New-Item -ItemType Directory -Path $OutputDirectory
$process = [Diagnostics.Process]::new()
$process.StartInfo = $info
$stdout = [IO.File]::Create((Join-Path $OutputDirectory 'stdout.log'))
$stderr = [IO.File]::Create((Join-Path $OutputDirectory 'stderr.log'))
$csv = [IO.StreamWriter]::new((Join-Path $OutputDirectory 'process-memory.csv'))
$clock = [Diagnostics.Stopwatch]::new()
$samples = 0
$started = $false
$timedOut = $false
$stdoutCopy = $null
$stderrCopy = $null
try {
    $csv.WriteLine('ElapsedMs,ProcessId,PrivateBytes,WorkingSetBytes,CpuMs')
    $startedUtc = [DateTime]::UtcNow.ToString('o')
    $clock.Start()
    $started = $process.Start()
    if (-not $started) { throw 'Workload did not start.' }
    $stdoutCopy = $process.StandardOutput.BaseStream.CopyToAsync($stdout)
    $stderrCopy = $process.StandardError.BaseStream.CopyToAsync($stderr)
    while (-not $process.HasExited) {
        if ($clock.Elapsed.TotalSeconds -ge $TimeoutSeconds) {
            $timedOut = $true
            Stop-Process -Id $process.Id -Force
            break
        }
        try {
            $process.Refresh()
            $csv.WriteLine((@($clock.ElapsedMilliseconds,$process.Id,
                $process.PrivateMemorySize64,$process.WorkingSet64,
                [long]$process.TotalProcessorTime.TotalMilliseconds) -join ','))
            $samples++
        } catch [InvalidOperationException] {
            if (-not $process.HasExited) { throw }
            break
        }
        Start-Sleep -Milliseconds $SampleIntervalMs
    }
    $process.WaitForExit()
    $null = $stdoutCopy.GetAwaiter().GetResult()
    $null = $stderrCopy.GetAwaiter().GetResult()
    $clock.Stop()
    $result = [ordered]@{}
    foreach ($key in $Metadata.Keys) { $result[$key] = $Metadata[$key] }
    $result.Executable = $Executable
    $result.Arguments = $RuntimeArguments
    $result.WorkingDirectory = $info.WorkingDirectory
    $result.ProcessId = $process.Id
    $result.StartedUtc = $startedUtc
    $result.SampleIntervalMs = $SampleIntervalMs
    $result.Samples = $samples
    $result.ElapsedMs = $clock.ElapsedMilliseconds
    $result.ExitCode = $process.ExitCode
    $result.TimedOut = $timedOut
    $result | ConvertTo-Json -Depth 10 |
        Set-Content -LiteralPath (Join-Path $OutputDirectory 'run.json') -Encoding utf8
    if ($timedOut) { throw "Workload timed out. Logs: $OutputDirectory" }
    if ($process.ExitCode -ne 0) {
        throw "Workload exited with code $($process.ExitCode). Logs: $OutputDirectory"
    }
    if ($samples -eq 0) { throw 'Workload was too short to collect process samples.' }
    [pscustomobject]$result
} finally {
    if ($started -and -not $process.HasExited) {
        Stop-Process -Id $process.Id -Force
        $process.WaitForExit()
    }
    try {
        if ($null -ne $stdoutCopy) { $null = $stdoutCopy.GetAwaiter().GetResult() }
        if ($null -ne $stderrCopy) { $null = $stderrCopy.GetAwaiter().GetResult() }
    } finally {
        $csv.Dispose()
        $stdout.Dispose()
        $stderr.Dispose()
        $process.Dispose()
    }
}
