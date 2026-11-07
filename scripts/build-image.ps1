<#
.SYNOPSIS
Builds the m1r4g3-server image from this repository.

.EXAMPLE
pwsh -File scripts/build-image.ps1
pwsh -File scripts/build-image.ps1 -SaveTar 'C:\out\m1r4g3-server.tar'
#>
[CmdletBinding()]
param(
    [string]$Tag = 'm1r4g3-server:1',
    [string]$SaveTar = '',
    # How many rustc processes may run inside the builder. 0 = every core.
    [int]$Jobs = 0
)

$ErrorActionPreference = 'Stop'

$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
Write-Host "repo : $repoRoot"

# A native command that writes to stderr is NOT a failure. PowerShell turns
# every stderr line into an error record, and with $ErrorActionPreference =
# 'Stop' that would abort the script on docker build's FIRST progress line.
$ErrorActionPreference = 'Continue'

$buildArgs = @('build', '--file', (Join-Path $repoRoot 'Dockerfile'), '--tag', $Tag)
if ($Jobs -gt 0) { $buildArgs += @('--build-arg', "CARGO_BUILD_JOBS=$Jobs") }
$buildArgs += $repoRoot
& docker @buildArgs
$buildCode = $LASTEXITCODE
if ($buildCode -ne 0) { throw "docker build failed with $buildCode" }
if ($SaveTar) {
    $tarDir = Split-Path -Parent $SaveTar
    if ($tarDir -and -not (Test-Path $tarDir)) { New-Item -ItemType Directory -Path $tarDir -Force | Out-Null }
    Write-Host "saving $Tag -> $SaveTar"
    & docker save --output $SaveTar $Tag
    $saveCode = $LASTEXITCODE
    if ($saveCode -ne 0) { throw "docker save failed with $saveCode" }
}

Write-Host "done: $Tag"
