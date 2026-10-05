param()
$ErrorActionPreference = 'Stop'
$runner = Join-Path $PSScriptRoot 'run.ps1'
$runnerHash = (Get-FileHash -Algorithm SHA256 -LiteralPath $runner).Hash.ToLowerInvariant()
$tokens = $null; $errors = $null
$ast = [Management.Automation.Language.Parser]::ParseFile($runner, [ref]$tokens, [ref]$errors)
if (@($errors).Count) { throw 'Runner parser failed.' }
# Exercise the exact frozen admission functions without invoking Go or the runner body.
foreach ($name in @('Assert-Plain','Assert-SifrunoRoot','Get-ReviewLayout')) {
    $definitions = @($ast.FindAll({ param($node) $node -is [Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -eq $name }, $false))
    if ($definitions.Count -ne 1) { throw 'Runner layout function is missing or duplicated.' }
    . ([scriptblock]::Create($definitions[0].Extent.Text))
}
$runId = 'layout-' + [DateTime]::UtcNow.ToString('yyyyMMddTHHmmssfff') + '-' + [Guid]::NewGuid().ToString('N').Substring(0,8)
$resultDir = Join-Path $PSScriptRoot ('artifacts\' + $runId)
Assert-Plain $resultDir 'Container' -Missing
New-Item -ItemType Directory -Path $resultDir | Out-Null
$fixture = Join-Path $resultDir 'fixture'
New-Item -ItemType Directory -Path $fixture | Out-Null
$results = [Collections.Generic.List[object]]::new()
$junction = Join-Path $fixture 'linked-root'
function New-FixtureRoot([string]$Path) {
    New-Item -ItemType Directory -Path (Join-Path $Path 'lab\hostwebruntime-review') -Force | Out-Null
    [IO.File]::WriteAllText((Join-Path $Path 'go.mod'), "module sifruno`n", [Text.UTF8Encoding]::new($false))
    foreach ($package in @('hostweb','hostaccounts','hostwebgeneration','securestate')) { New-Item -ItemType Directory -Path (Join-Path $Path ('internal\' + $package)) -Force | Out-Null }
}
function Test-Layout([string]$Name, [string]$Directory, [string]$Source, [bool]$Reject, [string]$Kind) {
    $caught = $false; $layout = $null
    try { $layout = Get-ReviewLayout $Directory $Source } catch { $caught = $true }
    $passed = $caught -eq $Reject
    if (-not $Reject) { $passed = $passed -and $layout.layout -ceq $Kind -and $layout.execution -eq $false }
    $results.Add([ordered]@{ name=$Name; passed=$passed; rejected=$caught; execution=$false })
    if (-not $passed) { throw ('Layout challenge failed: ' + $Name) }
}
$passed = $false; $failure = $null; $cleaned = $false
try {
    $canonical = Join-Path $fixture 'canonical'
    New-FixtureRoot $canonical
    $assigned = Join-Path $canonical '.worktrees\native-web-review-sol'
    New-FixtureRoot $assigned
    [IO.File]::WriteAllText((Join-Path $assigned 'go.mod'), "module sifruno`r`n")
    Test-Layout 'canonical' (Join-Path $canonical 'lab\hostwebruntime-review') $canonical $false 'canonical'
    Test-Layout 'assigned-worktree' (Join-Path $assigned 'lab\hostwebruntime-review') $canonical $false 'assigned_worktree'
    [IO.File]::WriteAllText((Join-Path $canonical 'go.mod'), "module foreign`n")
    Test-Layout 'wrong-primary-module' (Join-Path $canonical 'lab\hostwebruntime-review') $canonical $true ''
    [IO.File]::WriteAllText((Join-Path $canonical 'go.mod'), "module sifruno`n")
    [IO.File]::WriteAllText((Join-Path $assigned 'go.mod'), "module foreign`n")
    Test-Layout 'wrong-worktree-module' (Join-Path $assigned 'lab\hostwebruntime-review') $canonical $true ''
    [IO.File]::WriteAllText((Join-Path $assigned 'go.mod'), "module sifruno`n")
    $outside = Join-Path $fixture 'outside'
    New-FixtureRoot $outside
    Test-Layout 'outside-source' (Join-Path $canonical 'lab\hostwebruntime-review') $outside $true ''
    $unapproved = Join-Path $canonical '.worktrees\other-worker'
    New-FixtureRoot $unapproved
    Test-Layout 'unapproved-worktree' (Join-Path $unapproved 'lab\hostwebruntime-review') $canonical $true ''
    New-Item -ItemType Directory -Path (Join-Path $canonical 'lab\wrong-review') | Out-Null
    Test-Layout 'wrong-lab-layout' (Join-Path $canonical 'lab\wrong-review') $canonical $true ''
    New-Item -ItemType Junction -Path $junction -Target $canonical | Out-Null
    Test-Layout 'reparse-ancestor' (Join-Path $junction 'lab\hostwebruntime-review') $junction $true ''
    $passed = $true
} catch { $failure = $_.Exception.Message }
finally {
    if (Test-Path -LiteralPath $junction) {
        if ([IO.Path]::GetFullPath($junction) -ne (Join-Path $fixture 'linked-root') -or -not ((Get-Item -LiteralPath $junction -Force).Attributes -band [IO.FileAttributes]::ReparsePoint)) { throw 'Owned junction cleanup identity changed.' }
        # PowerShell 5 Remove-Item fails on some directory junctions. Nonrecursive
        # Directory.Delete removes this checked link itself, never its target.
        [IO.Directory]::Delete($junction)
    }
    $resolved = [IO.Path]::GetFullPath($fixture)
    if ($resolved -ne (Join-Path $resultDir 'fixture') -or -not $resolved.StartsWith($PSScriptRoot + '\', [StringComparison]::OrdinalIgnoreCase)) { throw 'Fixture cleanup escaped the owned lab.' }
    Assert-Plain $resolved 'Container'
    Remove-Item -LiteralPath $resolved -Recurse -Force
    $cleaned = -not (Test-Path -LiteralPath $resolved)
    $stable = (Get-FileHash -Algorithm SHA256 -LiteralPath $runner).Hash.ToLowerInvariant() -ceq $runnerHash
    $passed = $passed -and $stable -and $cleaned -and $results.Count -eq 8
    $report = [ordered]@{ schema_version=1; run_id=$runId; passed=$passed; failure=$failure; runner_sha256=$runnerHash; runner_unchanged=$stable; fixture_cleaned=$cleaned; execution=$false; checks=@($results) }
    $destination = Join-Path $resultDir 'report.json'
    [IO.File]::WriteAllText($destination, ($report | ConvertTo-Json -Depth 6) + "`n", [Text.UTF8Encoding]::new($false))
    [ordered]@{passed=$passed; report=$destination; sha256=(Get-FileHash -Algorithm SHA256 -LiteralPath $destination).Hash.ToLowerInvariant()} | ConvertTo-Json
}
if (-not $passed) { exit 1 }
