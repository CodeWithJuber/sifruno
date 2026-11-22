$ErrorActionPreference = 'Stop'
$taskRoot = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
$taskTools = Join-Path $taskRoot '.tools'
New-Item -ItemType Directory -Force -Path $taskTools | Out-Null
$taskArchive = Join-Path $taskTools 'go1.27.1.windows-amd64.zip'
$taskExpectedHash = 'a3911b5e0e1b1053f25ed0675f4c1c6aad1e2bfcf253df2b9be4caabd2edd95d'
$taskGo = Join-Path $taskTools 'go\bin\go.exe'
if (-not (Test-Path -LiteralPath $taskGo)) {
    if (-not (Test-Path -LiteralPath $taskArchive)) {
        Invoke-WebRequest -Uri 'https://go.dev/dl/go1.27.1.windows-amd64.zip' -OutFile $taskArchive
    }
    if ((Get-FileHash -LiteralPath $taskArchive -Algorithm SHA256).Hash.ToLowerInvariant() -ne $taskExpectedHash) {
        throw 'Go download checksum mismatch; refusing to extract.'
    }
    Expand-Archive -LiteralPath $taskArchive -DestinationPath $taskTools
}
& $taskGo version
if ($LASTEXITCODE -ne 0) { throw 'Go toolchain validation failed.' }
$env:GOCACHE = Join-Path $taskRoot '.cache\go-build'
$env:GOMODCACHE = Join-Path $taskRoot '.cache\go-mod'
