$ErrorActionPreference = 'Stop'
$projectRoot = Split-Path $PSScriptRoot -Parent
$destination = Join-Path $projectRoot 'deliverables'
New-Item -ItemType Directory -Force -Path $destination | Out-Null
$paths = @(
  (Join-Path $projectRoot 'assets'),
  (Join-Path $projectRoot 'docs'),
  (Join-Path $projectRoot 'DESIGN.md')
)
Compress-Archive -LiteralPath $paths -DestinationPath (Join-Path $destination 'sifruno-brand-kit.zip') -Force
$zipPath = Join-Path $destination 'sifruno-brand-kit.zip'
$zipHash = (Get-FileHash -LiteralPath $zipPath -Algorithm SHA256).Hash.ToLowerInvariant()
$reviewRoot = Join-Path $projectRoot '.cache\brand-package-review'
$reviewDir = Join-Path $reviewRoot $zipHash.Substring(0,16)
New-Item -ItemType Directory -Force -Path $reviewDir | Out-Null
Expand-Archive -LiteralPath $zipPath -DestinationPath $reviewDir -Force
@{ path = $reviewDir; sha256 = $zipHash } | ConvertTo-Json | Set-Content -LiteralPath (Join-Path $reviewRoot 'current.json') -Encoding utf8
Get-Item (Join-Path $destination 'sifruno-brand-kit.zip') | Select-Object Name,Length
