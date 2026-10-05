param([string]$SourceRoot, [switch]$CheckLayout, [switch]$SkipLinuxCompile)
$ErrorActionPreference = 'Stop'
function Assert-Plain([string]$Path, [string]$Kind, [switch]$Missing) {
    $absolute = [IO.Path]::GetFullPath($Path)
    if (-not $Missing -and -not (Test-Path -LiteralPath $absolute -PathType $Kind)) { throw 'Required review input is missing.' }
    $current = $absolute
    while ($current) {
        if (Test-Path -LiteralPath $current) {
            if ((Get-Item -LiteralPath $current -Force).Attributes -band [IO.FileAttributes]::ReparsePoint) { throw 'Review path contains a reparse point.' }
        }
        $parent = [IO.Path]::GetDirectoryName($current)
        if ($parent -eq $current) { break }; $current = $parent
    }
}
function Assert-SifrunoRoot([string]$Path) {
    Assert-Plain $Path 'Container'
    $modulePath = Join-Path $Path 'go.mod'
    Assert-Plain $modulePath 'Leaf'
    if ((Get-Item -LiteralPath $modulePath).Length -gt 65536) { throw 'Review module identity exceeds its bound.' }
    $moduleText = [IO.File]::ReadAllText($modulePath).Replace("`r`n","`n")
    $lines = @([regex]::Matches($moduleText, '(?m)^module[ \t]+([^\r\n]+)[ \t]*$'))
    if ($lines.Count -ne 1 -or $lines[0].Groups[1].Value.Trim() -cne 'sifruno') { throw 'Review root must have module sifruno identity.' }
}
function Get-ReviewLayout([string]$RunnerDirectory, [string]$RequestedSource) {
    $lab = [IO.Path]::GetFullPath($RunnerDirectory)
    $review = [IO.Path]::GetFullPath((Join-Path $lab '..\..'))
    if ($lab -ne (Join-Path $review 'lab\hostwebruntime-review')) { throw 'Runner must use the fixed lab review layout.' }
    Assert-Plain $lab 'Container'
    $parent = [IO.Path]::GetDirectoryName($review)
    $kind = 'canonical'
    if ([IO.Path]::GetFileName($parent) -eq '.worktrees') {
        if ([IO.Path]::GetFileName($review) -ne 'native-web-review-sol') { throw 'Runner worktree must be native-web-review-sol.' }
        $primary = [IO.Path]::GetDirectoryName($parent)
        $kind = 'assigned_worktree'
    } else { $primary = $review }
    Assert-SifrunoRoot $primary
    Assert-SifrunoRoot $review
    $source = $primary
    if ($RequestedSource) { $source = [IO.Path]::GetFullPath($RequestedSource) }
    if ($source -ne $primary) { throw 'Source root is outside the canonical source allowlist.' }
    Assert-SifrunoRoot $source
    foreach ($package in @('hostweb','hostaccounts','hostwebgeneration','securestate')) { Assert-Plain (Join-Path $source ('internal\' + $package)) 'Container' }
    [ordered]@{ runner_root=$review; primary_root=$primary; source_root=$source; layout=$kind; execution=$false }
}
$layout = Get-ReviewLayout $PSScriptRoot $SourceRoot
$reviewRoot = $layout.runner_root
$primaryRoot = $layout.primary_root
if ($CheckLayout) { $layout | ConvertTo-Json; exit 0 }
$goExecutable = Join-Path $primaryRoot '.tools\go\bin\go.exe'
Assert-Plain $goExecutable 'Leaf'
$manifestPath = Join-Path $PSScriptRoot 'testdata\candidate-manifest.json'
Assert-Plain $manifestPath 'Leaf'
$manifest = Get-Content -LiteralPath $manifestPath -Raw | ConvertFrom-Json
if ($manifest.schema_version -ne 1 -or $manifest.package -cne 'hostwebruntime' -or @($manifest.files).Count -lt 2 -or @($manifest.files).Count -gt 24) { throw 'Candidate freeze manifest is invalid.' }
$mapping = @{}
$pinPaths = [Collections.Generic.List[string]]::new()
foreach ($file in $manifest.files) {
    if ($file.name -cnotmatch '^(?:[a-z][a-z0-9_]*\.go|README\.md)$' -or $file.sha256 -cnotmatch '^[a-f0-9]{64}$') { throw 'Candidate file identity is invalid.' }
    $candidatePath = Join-Path $PSScriptRoot ('testdata\candidate\' + $file.name)
    Assert-Plain $candidatePath 'Leaf'
    if ((Get-FileHash -LiteralPath $candidatePath).Hash.ToLowerInvariant() -cne $file.sha256) { throw 'Candidate freeze hash differs.' }
    $pinPaths.Add($candidatePath)
    if ($file.name.EndsWith('.go')) { $mapping[(Join-Path $PSScriptRoot $file.name)] = $candidatePath }
}
foreach ($testFile in @(Get-ChildItem -LiteralPath (Join-Path $PSScriptRoot 'testdata') -File -Filter '*_test.go')) {
    Assert-Plain $testFile.FullName 'Leaf'
    $mapping[(Join-Path $PSScriptRoot ('independent_' + $testFile.Name))] = $testFile.FullName
    $pinPaths.Add($testFile.FullName)
}
if (@($mapping.Keys | Where-Object { $_ -match 'independent_.*_test.go$' }).Count -eq 0) { throw 'Independent challenge tests are absent.' }
# Read current canonical compiler/account/coordinator inputs, without copying or editing them.
foreach ($package in @('hostweb','hostaccounts','hostwebgeneration','securestate')) {
    $directory = Join-Path $primaryRoot ('internal\' + $package)
    Assert-Plain $directory 'Container'
    foreach ($inputFile in @(Get-ChildItem -LiteralPath $directory -File -Filter '*.go')) {
        Assert-Plain $inputFile.FullName 'Leaf'
        $mapping[(Join-Path $reviewRoot ('internal\' + $package + '\' + $inputFile.Name))] = $inputFile.FullName
        $pinPaths.Add($inputFile.FullName)
    }
}
foreach ($path in @($manifestPath, $PSCommandPath, (Join-Path $PSScriptRoot 'layout-challenge.ps1'), (Join-Path $reviewRoot 'go.mod'), (Join-Path $reviewRoot 'go.sum'), (Join-Path $primaryRoot 'go.mod'), (Join-Path $primaryRoot 'go.sum'))) { Assert-Plain $path 'Leaf'; $pinPaths.Add($path) }
if ([IO.File]::ReadAllText((Join-Path $reviewRoot 'go.mod')).Replace("`r`n","`n") -cne [IO.File]::ReadAllText((Join-Path $primaryRoot 'go.mod')).Replace("`r`n","`n") -or [IO.File]::ReadAllText((Join-Path $reviewRoot 'go.sum')).Replace("`r`n","`n") -cne [IO.File]::ReadAllText((Join-Path $primaryRoot 'go.sum')).Replace("`r`n","`n")) { throw 'Canonical dependency content differs from the review checkout (CRLF/LF only is allowed).' }
function Get-Pins {
    @($pinPaths | Sort-Object -Unique | ForEach-Object {
        if ($_.StartsWith($PSScriptRoot + '\', [StringComparison]::OrdinalIgnoreCase)) { $scope='lab'; $base=$PSScriptRoot }
        elseif ($reviewRoot -ne $primaryRoot -and $_.StartsWith($reviewRoot + '\', [StringComparison]::OrdinalIgnoreCase)) { $scope='review'; $base=$reviewRoot }
        else { $scope='canonical'; $base=$primaryRoot }
        [ordered]@{ scope=$scope; path=$_.Substring($base.Length+1).Replace('\','/'); sha256=(Get-FileHash -LiteralPath $_).Hash.ToLowerInvariant() }
    })
}
$before = Get-Pins
$runId = [DateTime]::UtcNow.ToString('yyyyMMddTHHmmssfff') + '-' + [Guid]::NewGuid().ToString('N').Substring(0,8)
$resultDir = Join-Path $PSScriptRoot ('artifacts\' + $runId)
Assert-Plain $resultDir 'Container' -Missing
New-Item -ItemType Directory -Path $resultDir | Out-Null
$overlayPath = Join-Path $resultDir 'overlay.json'
[IO.File]::WriteAllText($overlayPath, (@{ Replace = $mapping } | ConvertTo-Json -Depth 5), [Text.UTF8Encoding]::new($false))
$savedEnvironment = @{}
$environment = @{ GOCACHE=(Join-Path $PSScriptRoot '.cache\go-build'); GOMODCACHE=(Join-Path $primaryRoot '.cache\go-mod'); GOPROXY='off'; GOSUMDB='off'; GOTOOLCHAIN='local'; CGO_ENABLED='0'; GOOS='windows'; GOARCH='amd64' }
Assert-Plain $environment.GOCACHE 'Container' -Missing
Assert-Plain $environment.GOMODCACHE 'Container'
$checks = [Collections.Generic.List[object]]::new()
$passed = $false
function Invoke-Check([string]$Name, [string[]]$Arguments, [bool]$Executed) {
    $priorErrorPreference = $ErrorActionPreference
    $priorNativePreference = $PSNativeCommandUseErrorActionPreference
    try {
        $ErrorActionPreference = 'Continue'
        $PSNativeCommandUseErrorActionPreference = $false
        $result = @(& $goExecutable @Arguments 2>&1); $code = $LASTEXITCODE
    } finally {
        $ErrorActionPreference = $priorErrorPreference
        $PSNativeCommandUseErrorActionPreference = $priorNativePreference
    }
    $result | Set-Content -LiteralPath (Join-Path $resultDir ($Name + '.txt')) -Encoding utf8
    $checks.Add([ordered]@{ name=$Name; arguments=$Arguments; exit_code=$code; native_execution=$Executed })
    if ($code -ne 0) { throw ('Review check failed: ' + $Name) }
}
try {
    foreach ($name in $environment.Keys) { $savedEnvironment[$name] = [Environment]::GetEnvironmentVariable($name,'Process'); [Environment]::SetEnvironmentVariable($name,$environment[$name],'Process') }
    Push-Location -LiteralPath $reviewRoot
    try {
        Invoke-Check 'windows-challenges' @('test','-mod=readonly','-overlay',$overlayPath,'-count=1','-timeout=40s','-run','^TestReview','-v','./lab/hostwebruntime-review') $true
        Invoke-Check 'windows-vet' @('vet','-mod=readonly','-overlay',$overlayPath,'./lab/hostwebruntime-review') $false
        if (-not $SkipLinuxCompile) {
            $env:GOOS = 'linux'
            Invoke-Check 'linux-compile-only' @('test','-mod=readonly','-overlay',$overlayPath,'-c','-o',(Join-Path $resultDir 'hostwebruntime-linux-amd64.test'),'./lab/hostwebruntime-review') $false
            Invoke-Check 'linux-vet' @('vet','-mod=readonly','-overlay',$overlayPath,'./lab/hostwebruntime-review') $false
        }
    } finally { Pop-Location }
    $passed = $true
} catch { $failure = $_.Exception.Message }
finally {
    foreach ($name in $savedEnvironment.Keys) { [Environment]::SetEnvironmentVariable($name,$savedEnvironment[$name],'Process') }
    $after = Get-Pins
    $pinsEqual = ($before | ConvertTo-Json -Depth 4 -Compress) -ceq ($after | ConvertTo-Json -Depth 4 -Compress)
    $passed = $passed -and $pinsEqual
    $report = [ordered]@{ schema_version=2; run_id=$runId; passed=$passed; failure=$failure; layout=$layout.layout; source_pins_unchanged=$pinsEqual; source_pins=$before; checks=@($checks); evidence_kind='Windows unavailable and common pure protocol challenges; Linux compile only'; daemon_execution_qualified=$false; activation_performed=$false; root_or_git_mutated=$false }
    $reportPath = Join-Path $resultDir 'report.json'
    [IO.File]::WriteAllText($reportPath, ($report | ConvertTo-Json -Depth 8) + "`n", [Text.UTF8Encoding]::new($false))
    [ordered]@{passed=$passed;report=$reportPath;sha256=(Get-FileHash -LiteralPath $reportPath).Hash.ToLowerInvariant()} | ConvertTo-Json
}
if (-not $passed) { exit 1 }
