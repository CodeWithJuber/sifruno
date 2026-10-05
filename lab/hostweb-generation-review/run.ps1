param(
    [Parameter(Mandatory=$true)][string]$SourceRoot,
    [Parameter(Mandatory=$true)][ValidateSet('hostaccounts','hostwebgeneration')][string]$Package,
    [switch]$CheckLayout
)
$ErrorActionPreference = 'Stop'
function Assert-PlainPath([string]$Path, [string]$Kind, [switch]$AllowMissing) {
    $absolute = [IO.Path]::GetFullPath($Path)
    if (-not $AllowMissing -and -not (Test-Path -LiteralPath $absolute -PathType $Kind)) { throw 'Required review path is missing or has the wrong type.' }
    $current = $absolute
    while ($current) {
        if (Test-Path -LiteralPath $current) {
            $info = Get-Item -LiteralPath $current -Force
            if ($info.Attributes -band [IO.FileAttributes]::ReparsePoint) { throw 'Review paths and their ancestors cannot be reparse points.' }
        }
        $parent = [IO.Path]::GetDirectoryName($current)
        if ($parent -eq $current) { break }
        $current = $parent
    }
}
function Assert-SifrunoRoot([string]$Path) {
    Assert-PlainPath $Path 'Container'
    $modulePath = Join-Path $Path 'go.mod'
    Assert-PlainPath $modulePath 'Leaf'
    if ((Get-Item -LiteralPath $modulePath).Length -gt 65536) { throw 'Review module identity exceeds its bound.' }
    $moduleText = [IO.File]::ReadAllText($modulePath)
    $moduleLines = @([regex]::Matches($moduleText, '(?m)^module[ \t]+([^\r\n]+)[ \t]*$'))
    if ($moduleLines.Count -ne 1 -or $moduleLines[0].Groups[1].Value.Trim() -cne 'sifruno') { throw 'Review root must have module sifruno identity.' }
}
$reviewRoot = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..\..'))
if ([IO.Path]::GetFullPath($PSScriptRoot) -ne (Join-Path $reviewRoot 'lab\hostweb-generation-review')) { throw 'Runner must use the fixed lab review layout.' }
Assert-PlainPath $PSScriptRoot 'Container'
$runnerParent = [IO.Path]::GetDirectoryName($reviewRoot)
if ([IO.Path]::GetFileName($runnerParent) -eq '.worktrees') {
    if ([IO.Path]::GetFileName($reviewRoot) -ne 'native-transfer-review') { throw 'Runner worktree must be native-transfer-review.' }
    $primaryRoot = [IO.Path]::GetDirectoryName($runnerParent)
} else {
    $primaryRoot = $reviewRoot
}
Assert-SifrunoRoot $primaryRoot
Assert-SifrunoRoot $reviewRoot
$goWrapper = Join-Path $primaryRoot 'scripts\go.ps1'
Assert-PlainPath $goWrapper 'Leaf'
Assert-PlainPath (Join-Path $primaryRoot 'scripts\bootstrap-tools.ps1') 'Leaf'
$sourcePath = [IO.Path]::GetFullPath($SourceRoot)
$allowedRoots = @($primaryRoot, (Join-Path $primaryRoot '.worktrees\native-transfer-ui'), (Join-Path $primaryRoot '.worktrees\native-transfer-cli'))
if ($sourcePath -notin $allowedRoots) { throw 'Source root is outside the fixed review allowlist.' }
Assert-SifrunoRoot $sourcePath
$packagePath = Join-Path $sourcePath ('internal\' + $Package)
Assert-PlainPath $packagePath 'Container'
$testPath = Join-Path $PSScriptRoot ('testdata\' + $Package + '_challenge_test.go')
Assert-PlainPath $testPath 'Leaf'
if ($CheckLayout) {
    [ordered]@{ mode = 'layout_admission_only'; primary_root = $primaryRoot; runner_root = $reviewRoot; source_root = $sourcePath; package = $Package; execution = $false } | ConvertTo-Json
    exit 0
}
$goExecutable = Join-Path $primaryRoot '.tools\go\bin\go.exe'
if (-not (Test-Path -LiteralPath $goExecutable -PathType Leaf)) { throw 'Run scripts/bootstrap-tools.ps1 in the primary checkout first.' }
Assert-PlainPath $goExecutable 'Leaf'
$sourceFiles = @('hostaccounts','hostweb','hostwebgeneration','securestate') | ForEach-Object {
    $directory = Join-Path $sourcePath ('internal\' + $_)
    if (Test-Path -LiteralPath $directory -PathType Container) {
        Assert-PlainPath $directory 'Container'
        Get-ChildItem -LiteralPath $directory -File -Filter '*.go'
    }
}
function Get-Pins {
    @($sourceFiles | Sort-Object FullName | ForEach-Object {
        Assert-PlainPath $_.FullName 'Leaf'
        [ordered]@{ path = $_.FullName.Substring($sourcePath.Length + 1); sha256 = (Get-FileHash -LiteralPath $_.FullName -Algorithm SHA256).Hash.ToLowerInvariant() }
    })
}
$beforePins = Get-Pins
$runId = [DateTime]::UtcNow.ToString('yyyyMMddTHHmmssfff') + '-' + [Guid]::NewGuid().ToString('N').Substring(0,8)
$resultDir = Join-Path $reviewRoot ('artifacts\hostweb-generation-review\' + $runId + '-' + $Package)
Assert-PlainPath $resultDir 'Container' -AllowMissing
New-Item -ItemType Directory -Path $resultDir | Out-Null
$overlayPath = Join-Path $resultDir 'overlay.json'
$mapping = @{}
$mapping[(Join-Path $packagePath 'independent_review_challenge_test.go')] = $testPath
$compilerPath = Join-Path $primaryRoot 'internal\hostweb\compiler.go'
Assert-PlainPath $compilerPath 'Leaf'
$compilerHashBefore = (Get-FileHash -LiteralPath $compilerPath -Algorithm SHA256).Hash.ToLowerInvariant()
$canonicalInputs = @()
if ($sourcePath -ne $primaryRoot) {
    $mapping[(Join-Path $sourcePath 'internal\hostweb\compiler.go')] = $compilerPath
    if ($Package -eq 'hostwebgeneration') {
        foreach ($dependency in @('hostaccounts','securestate')) {
            Assert-PlainPath (Join-Path $primaryRoot ('internal\' + $dependency)) 'Container'
            $canonicalInputs += @(Get-ChildItem -LiteralPath (Join-Path $primaryRoot ('internal\' + $dependency)) -File -Filter '*.go')
        }
        foreach ($inputFile in $canonicalInputs) {
            Assert-PlainPath $inputFile.FullName 'Leaf'
            $relativePath = $inputFile.FullName.Substring($primaryRoot.Length + 1)
            $mapping[(Join-Path $sourcePath $relativePath)] = $inputFile.FullName
        }
    }
}
function Get-CanonicalPins {
    @($canonicalInputs | Sort-Object FullName | ForEach-Object {
        [ordered]@{ path = $_.FullName.Substring($primaryRoot.Length + 1); sha256 = (Get-FileHash -LiteralPath $_.FullName -Algorithm SHA256).Hash.ToLowerInvariant() }
    })
}
$canonicalBefore = Get-CanonicalPins
[IO.File]::WriteAllText($overlayPath, (@{Replace=$mapping} | ConvertTo-Json -Depth 4), [Text.UTF8Encoding]::new($false))
$arguments = @('test','-overlay',$overlayPath,'-count=1','-timeout=40s','-run','^TestReview','-v',('./internal/' + $Package))
$output = @()
$exitCode = -1
Push-Location -LiteralPath $sourcePath
try {
    $output = @(& $goWrapper @arguments 2>&1)
    $exitCode = $LASTEXITCODE
} finally { Pop-Location }
$output | Set-Content -LiteralPath (Join-Path $resultDir 'test-output.txt') -Encoding utf8
$afterPins = Get-Pins
$pinsEqual = ($beforePins | ConvertTo-Json -Depth 4 -Compress) -ceq ($afterPins | ConvertTo-Json -Depth 4 -Compress)
$compilerHashAfter = (Get-FileHash -LiteralPath $compilerPath -Algorithm SHA256).Hash.ToLowerInvariant()
$pinsEqual = $pinsEqual -and $compilerHashBefore -ceq $compilerHashAfter
$pinsEqual = $pinsEqual -and (($canonicalBefore | ConvertTo-Json -Depth 4 -Compress) -ceq ((Get-CanonicalPins) | ConvertTo-Json -Depth 4 -Compress))
$testCount = @($output | Where-Object { $_.ToString() -match '^--- PASS: TestReview' }).Count
$report = [ordered]@{
    schema_version = 1; run_id = $runId; package = $Package; source_root = $sourcePath; primary_root = $primaryRoot; runner_root = $reviewRoot
    command = ('scripts/go.ps1 ' + ($arguments -join ' ')); exit_code = $exitCode
    passed = ($exitCode -eq 0 -and $pinsEqual -and $testCount -gt 0)
    top_level_passed_tests = $testCount; source_unchanged = $pinsEqual; source_pins = $beforePins
    canonical_compiler_path = $compilerPath; canonical_compiler_sha256 = $compilerHashBefore
    canonical_dependency_pins = $canonicalBefore
    challenge_sha256 = (Get-FileHash -LiteralPath $testPath -Algorithm SHA256).Hash.ToLowerInvariant()
    evidence_boundary = 'Isolated protocol/persistence tests with injected native and executor doubles; no daemon isolation, native activation, broker integration, or root-owner qualification.'
}
$reportPath = Join-Path $resultDir 'report.json'
$report | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $reportPath -Encoding utf8
$output | ForEach-Object { Write-Output $_ }
Write-Output ('REPORT ' + $reportPath)
if (-not $report.passed) { exit 1 }
exit 0
