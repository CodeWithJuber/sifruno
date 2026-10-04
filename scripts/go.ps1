$ErrorActionPreference = 'Stop'
$taskRoot = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
$taskGo = Join-Path $taskRoot '.tools\go\bin\go.exe'
if (-not (Test-Path -LiteralPath $taskGo)) { throw 'Run scripts/bootstrap-tools.ps1 first.' }
$env:GOCACHE = Join-Path $taskRoot '.cache\go-build'
$env:GOMODCACHE = Join-Path $taskRoot '.cache\go-mod'
& $taskGo @args
exit $LASTEXITCODE
