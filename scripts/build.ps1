#requires -Version 7.0
[CmdletBinding()]
param([string]$ToolchainEnvironment)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$cargo = Get-Command cargo -ErrorAction SilentlyContinue
$cargoPath = if ($cargo) { $cargo.Source } else { Join-Path $HOME '.cargo\bin\cargo.exe' }
if (-not (Test-Path -LiteralPath $cargoPath)) {
    throw 'Rust is missing. Install the Rust MSVC toolchain first.'
}

$env:PATH = "$(Split-Path $cargoPath);$env:PATH"
if ($ToolchainEnvironment) {
    $environmentFile = (Resolve-Path -LiteralPath $ToolchainEnvironment).Path
    foreach ($entry in [IO.File]::ReadAllText($environmentFile).Split([char]0)) {
        $separator = $entry.IndexOf('=')
        if ($separator -le 0) { continue }
        $name = $entry.Substring(0, $separator)
        $value = $entry.Substring($separator + 1)
        if ($name -in @('INCLUDE', 'LIB', 'LIBPATH')) {
            [Environment]::SetEnvironmentVariable($name, $value, 'Process')
        } elseif ($name -eq 'PATH') {
            $env:PATH = "$(Split-Path $cargoPath);$value;$env:PATH"
        }
    }
}

$manifest = Join-Path $PSScriptRoot '..\Cargo.toml'
& $cargoPath build --release --locked --manifest-path $manifest
if ($LASTEXITCODE -ne 0) { throw 'v8-etw release build failed.' }

$binary = Join-Path $PSScriptRoot '..\target\release\v8-etw.exe'
if (-not (Test-Path -LiteralPath $binary)) {
    throw 'Cargo did not produce v8-etw.exe.'
}
(Resolve-Path -LiteralPath $binary).Path
