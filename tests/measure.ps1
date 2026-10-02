#requires -Version 7.0
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$measure = Join-Path $PSScriptRoot '..\scripts\measure.ps1'
$pwsh = (Get-Command pwsh).Source
$root = Join-Path ([IO.Path]::GetTempPath()) ('v8-etw-measure-' + [Guid]::NewGuid().ToString('N'))
$null = New-Item -ItemType Directory -Path $root
try {
    $success = Join-Path $root 'success with spaces'
    $run = & $measure -Executable $pwsh -RuntimeArguments @('-NoProfile','-Command',
        'Write-Output "argument with spaces"; Start-Sleep -Milliseconds 300') `
        -OutputDirectory $success -SampleIntervalMs 10 -Metadata @{V8Revision='fixture'}
    if ($run.Samples -le 0 -or $run.ExitCode -ne 0 -or $run.V8Revision -ne 'fixture') {
        throw 'Successful run metadata/samples failed.'
    }
    if ((Get-Content (Join-Path $success 'stdout.log') -Raw).Trim() -ne 'argument with spaces') {
        throw 'Argument quoting or log redirection failed.'
    }
    foreach ($name in @('failure','timeout')) {
        $args = if ($name -eq 'failure') {
            @('-NoProfile','-Command','Start-Sleep -Milliseconds 100; exit 7')
        } else { @('-NoProfile','-Command','Start-Sleep -Seconds 10') }
        $path = Join-Path $root $name
        $rejected = $false
        try {
            & $measure -Executable $pwsh -RuntimeArguments $args `
                -OutputDirectory $path -TimeoutSeconds 1 | Out-Null
        } catch {
            if (-not (Test-Path (Join-Path $path 'run.json'))) { throw }
            $rejected = $true
        }
        if (-not $rejected) { throw 'Failed or timed-out child was accepted.' }
        $metadata = Get-Content (Join-Path $path 'run.json') -Raw | ConvertFrom-Json
        if (($name -eq 'failure' -and $metadata.ExitCode -ne 7) -or
            ($name -eq 'timeout' -and -not $metadata.TimedOut)) {
            throw 'Failure/timeout metadata was not retained.'
        }
    }
    $rejected = $false
    try { & $measure -Executable $pwsh -OutputDirectory $success | Out-Null }
    catch { $rejected = $true }
    if (-not $rejected) { throw 'Existing recording was overwritten.' }
    Write-Output 'Recorder tests passed.'
} finally {
    foreach ($name in @('success with spaces','failure','timeout')) {
        $directory = Join-Path $root $name
        foreach ($file in @('run.json','stdout.log','stderr.log','process-memory.csv')) {
            $path = Join-Path $directory $file
            if (Test-Path -LiteralPath $path) { Remove-Item -LiteralPath $path }
        }
        if (Test-Path -LiteralPath $directory) { Remove-Item -LiteralPath $directory }
    }
    Remove-Item -LiteralPath $root
}
