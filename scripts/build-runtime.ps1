param(
    [switch]$DryRun,
    [ValidateSet('windows-amd64', 'windows-arm64', 'linux-amd64', 'linux-arm64', 'darwin-amd64', 'darwin-arm64')]
    [string[]]$Target = @()
)

$ErrorActionPreference = 'Stop'
$runtimeScript = Join-Path $PSScriptRoot 'build-runtime.mjs'
$runtimeArgs = @($runtimeScript)
if ($DryRun) { $runtimeArgs += '--dry-run' }
foreach ($runtimeTarget in $Target) { $runtimeArgs += @('--target', $runtimeTarget) }

# All build environment overrides live in child processes in the Node script.
# No caller environment, current directory, global Go installation or VM changes.
$runtimeNode = (Get-Command node -ErrorAction Stop).Source
& $runtimeNode @runtimeArgs
if ($LASTEXITCODE -ne 0) { throw "Runtime build failed with exit code $LASTEXITCODE" }
