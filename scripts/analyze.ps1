#requires -Version 7.0
[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$Trace,
    [Parameter(Mandatory)][ValidateRange(1, 2147483647)][int]$ProcessId,
    [Parameter(Mandatory)][string]$OutputDirectory,
    [string[]]$SymbolDirectories = @(),
    [string[]]$RequirePdb = @(),
    [string]$ToolchainEnvironment,
    [switch]$AllowLoss,
    [switch]$NoBuild
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$Trace = (Resolve-Path -LiteralPath $Trace).Path
if (-not $NoBuild) {
    $null = & (Join-Path $PSScriptRoot 'build.ps1') `
        -ToolchainEnvironment $ToolchainEnvironment
}

$binary = Join-Path $PSScriptRoot '..\target\release\v8-etw.exe'
if (-not (Test-Path -LiteralPath $binary)) {
    throw 'Build the release analyzer first.'
}

$arguments = @($Trace, '--pid', "$ProcessId", '--output', $OutputDirectory)
if ($AllowLoss) { $arguments += '--allow-loss' }
foreach ($directory in $SymbolDirectories) {
    $arguments += @('--symbols-dir', (Resolve-Path -LiteralPath $directory).Path)
}
foreach ($module in $RequirePdb) {
    $arguments += @('--require-pdb', $module)
}

& $binary @arguments
if ($LASTEXITCODE -ne 0) {
    throw "ETL analysis failed. Inspect diagnostics in $OutputDirectory"
}
