#requires -Version 7.0
[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$Executable,
    [string[]]$RuntimeArguments = @(),
    [Parameter(Mandatory)][string]$OutputDirectory,
    [string]$WorkingDirectory,
    [ValidateRange(1, 1000)][int]$SampleIntervalMs = 20,
    [hashtable]$Metadata = @{},
    [ValidateRange(1, 86400)][int]$TimeoutSeconds = 300
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = [Security.Principal.WindowsPrincipal]::new($identity)
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'ETW recording requires an elevated PowerShell terminal.'
}

$Executable = (Resolve-Path -LiteralPath $Executable).Path
$profile = Join-Path $PSScriptRoot '..\profiles\v8-memory.wprp'
if (Test-Path -LiteralPath $OutputDirectory) {
    throw "Output directory already exists: $OutputDirectory"
}

$status = @(& wpr -status)
if ($LASTEXITCODE -ne 0) { throw 'Cannot query WPR recording state.' }
if (($status -join "`n") -notmatch 'WPR is not recording') {
    throw 'WPR may already be recording. Leave that recording untouched.'
}

$instance = 'V8Etw-' + [Guid]::NewGuid().ToString('N')
$recording = $false
try {
    & wpr -start "${profile}!V8Memory" -filemode -instancename $instance
    if ($LASTEXITCODE -ne 0) { throw 'WPR failed to start.' }
    $recording = $true

    $run = & (Join-Path $PSScriptRoot 'measure.ps1') -Executable $Executable `
        -RuntimeArguments $RuntimeArguments -OutputDirectory $OutputDirectory `
        -WorkingDirectory $WorkingDirectory -SampleIntervalMs $SampleIntervalMs `
        -TimeoutSeconds $TimeoutSeconds -Metadata $Metadata
    Set-Content -LiteralPath (Join-Path $OutputDirectory 'pid.txt') -Value $run.ProcessId
    Set-Content -LiteralPath (Join-Path $OutputDirectory 'exit-code.txt') `
        -Value $run.ExitCode
} finally {
    if ($recording) {
        if (-not (Test-Path -LiteralPath $OutputDirectory)) {
            $null = New-Item -ItemType Directory -Path $OutputDirectory
        }
        $etl = Join-Path $OutputDirectory 'capture.etl'
        & wpr -stop $etl -instancename $instance
        if ($LASTEXITCODE -ne 0) {
            throw "WPR stop failed for instance '$instance'."
        }
    }
}
