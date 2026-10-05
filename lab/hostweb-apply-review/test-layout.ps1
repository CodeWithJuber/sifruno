$ErrorActionPreference='Stop'
$runner=Join-Path $PSScriptRoot 'run.ps1'
$pin=(Get-FileHash -LiteralPath $runner).Hash
$owned=[IO.Path]::GetFullPath((Join-Path $PSScriptRoot ('artifacts\testdata\layout-'+[DateTime]::UtcNow.ToString('yyyyMMddTHHmmssfff')+'-'+[Guid]::NewGuid().ToString('N').Substring(0,8))))
if(-not $owned.StartsWith(([IO.Path]::GetFullPath($PSScriptRoot)+[IO.Path]::DirectorySeparatorChar),[StringComparison]::OrdinalIgnoreCase)){throw 'Outside owned lab.'}
New-Item -ItemType Directory -Path $owned|Out-Null
$cases=@();$junction=$null;$utf8=[Text.UTF8Encoding]::new($false)
function Case([string]$Name,[string]$Root,[string]$Module,[bool]$Expected,[string]$Lab='hostweb-apply-review'){
 $dir=Join-Path $Root ('lab\'+$Lab);New-Item -ItemType Directory -Force -Path $dir|Out-Null
 [IO.File]::WriteAllText((Join-Path $Root 'go.mod'),("module "+$Module+"`n"),$utf8)
 $path=Join-Path $dir 'run.ps1';[IO.File]::WriteAllBytes($path,[IO.File]::ReadAllBytes($runner))
 $old=$ErrorActionPreference;$ErrorActionPreference='Continue'
 $output=& powershell -NoProfile -File $path -CheckLayout 2>&1;$code=$LASTEXITCODE;$ErrorActionPreference=$old
 if(($code -eq 0) -ne $Expected){throw ('Wrong layout verdict: '+$Name)}
 if($Expected){$parsed=($output -join "`n")|ConvertFrom-Json;if($parsed.mode -cne 'layout_only' -or $parsed.execution -ne $false){throw 'Layout invoked execution.'}}
 return @{name=$Name;exit_code=$code;expected_admitted=$Expected;pass=$true}
}
$canonical=Join-Path $owned 'canonical'
$cases+=Case 'canonical' $canonical 'sifruno' $true
$cases+=Case 'assigned_worktree' (Join-Path $canonical '.worktrees\web-apply-review-sol') 'sifruno' $true
$cases+=Case 'wrong_module' (Join-Path $owned 'wrong-module') 'unrelated' $false
$cases+=Case 'wrong_assigned_worktree' (Join-Path $canonical '.worktrees\other-worker') 'sifruno' $false
$cases+=Case 'wrong_lab' (Join-Path $owned 'wrong-lab') 'sifruno' $false 'other-lab'
# A real Windows junction, not a mocked attribute, must be refused before Go.
$redirect=Join-Path $owned 'redirect';New-Item -ItemType Directory -Path (Join-Path $redirect 'lab') -Force|Out-Null
[IO.File]::WriteAllText((Join-Path $redirect 'go.mod'),"module sifruno`n",$utf8)
$junction=Join-Path $redirect 'lab\hostweb-apply-review'
New-Item -ItemType Junction -Path $junction -Target (Join-Path $canonical 'lab\hostweb-apply-review')|Out-Null
$old=$ErrorActionPreference;$ErrorActionPreference='Continue'
$output=& powershell -NoProfile -File (Join-Path $junction 'run.ps1') -CheckLayout 2>&1;$code=$LASTEXITCODE;$ErrorActionPreference=$old
if($code -eq 0 -or ($output -join "`n") -notmatch 'Redirected review path refused'){throw 'Actual junction was not refused.'}
$cases+=@{name='actual_junction';exit_code=$code;expected_admitted=$false;pass=$true}
# Remove just this owned link, retaining the case files and source bytes.
if(-not ([IO.Path]::GetFullPath($junction).StartsWith(($owned+[IO.Path]::DirectorySeparatorChar),[StringComparison]::OrdinalIgnoreCase)) -or -not ((Get-Item -LiteralPath $junction -Force).Attributes -band [IO.FileAttributes]::ReparsePoint)){throw 'Owned link cleanup admission.'}
[IO.Directory]::Delete($junction,$false)
if((Get-FileHash -LiteralPath $runner).Hash -cne $pin){throw 'Runner changed during layout tests.'}
$report=@{schema_version=1;scope='real-portable-layout-admission';go_execution=$false;runner_sha256=$pin.ToLowerInvariant();cases=$cases;pass=$true}
$reportPath=Join-Path $owned 'report.json';[IO.File]::WriteAllText($reportPath,($report|ConvertTo-Json -Depth 6),$utf8)
[pscustomobject]@{report=$reportPath;sha256=(Get-FileHash -LiteralPath $reportPath).Hash;cases=$cases.Count;pass=$true}|ConvertTo-Json
