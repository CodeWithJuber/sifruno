param([switch]$CheckLayout)
$ErrorActionPreference = 'Stop'
function Assert-Plain([string]$Path,[string]$Kind,[switch]$Missing) {
    $absolute=[IO.Path]::GetFullPath($Path)
    if (-not $Missing -and -not(Test-Path -LiteralPath $absolute -PathType $Kind)) { throw 'Required review path missing.' }
    for($current=$absolute;$current;$current=[IO.Path]::GetDirectoryName($current)) {
        if(Test-Path -LiteralPath $current) {
            if((Get-Item -LiteralPath $current -Force).Attributes -band [IO.FileAttributes]::ReparsePoint){throw 'Redirected review path refused.'}
        }
    }
}
function Assert-Module([string]$Root) {
    Assert-Plain $Root 'Container';$file=Join-Path $Root 'go.mod';Assert-Plain $file 'Leaf'
    if((Get-Item -LiteralPath $file).Length -gt 65536){throw 'Module identity bound.'}
    $text=[IO.File]::ReadAllText($file).Replace("`r`n","`n")
    $matches=@([regex]::Matches($text,'(?m)^module[ \t]+([^\r\n]+)$'))
    if($matches.Count -ne 1 -or $matches[0].Groups[1].Value.Trim() -cne 'sifruno'){throw 'Wrong review module identity.'}
}
function Hash([string]$Path){Assert-Plain $Path 'Leaf';return (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToLowerInvariant()}
$reviewRoot=[IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..\..'))
if([IO.Path]::GetFullPath($PSScriptRoot) -ne (Join-Path $reviewRoot 'lab\hostweb-recovery-review')){throw 'Wrong fixed review layout.'}
Assert-Plain $PSScriptRoot 'Container'
$parent=[IO.Path]::GetDirectoryName($reviewRoot)
if([IO.Path]::GetFileName($parent) -eq '.worktrees'){
    if([IO.Path]::GetFileName($reviewRoot) -ne 'web-recovery-review-sol'){throw 'Unassigned review worktree refused.'}
    $primaryRoot=[IO.Path]::GetDirectoryName($parent)
}else{$primaryRoot=$reviewRoot}
Assert-Module $primaryRoot;Assert-Module $reviewRoot
if($CheckLayout){[ordered]@{mode='layout_only';module='sifruno';runner_kind=$(if($reviewRoot -eq $primaryRoot){'canonical'}else{'assigned_worktree'});execution=$false}|ConvertTo-Json;exit 0}
$runnerHash=Hash $PSCommandPath
$expectedTests=@('TestRecoveryReviewProtectedIPv6ParserFailsClosed','TestRecoveryReviewNativeConsumedApplyAndReplayCAS','TestRecoveryReviewNativeRepairRequiresRecompiledDenial','TestRecoveryReviewStableIntentBindsEveryIdentityAndAttempt','TestRecoveryReviewRequestCopyProtectsActualConfigAndAccounts','TestRecoveryReviewHistoricalCompletionMustMatchConsumedCounter','TestRecoveryReviewNativeLogicalIdentityCollision','TestRecoveryReviewNativeBootMetadataMatchesEveryPin','TestRecoveryReviewOriginalNativeApplyCommitCannotInventCounter','TestRecoveryReviewPostCallbackReconfirmationConsumesOnce','TestRecoveryReviewMalformedReceiptCannotCommitServing','TestRecoveryReviewHistoricalDeadCompletionCheckpointIsNotServing','TestRecoveryReviewHonestPartialTargetAndUnknownObserved','TestRecoveryReviewLeaseAndCancellationCannotAuthorizeReceipt','TestRecoveryReviewSnapshotGuardMatrix','TestRecoveryReviewSnapshotGuardUnknownObservedRefused')
$expectedTests+=@('TestRecoveryReviewNativeRetainedIdentityCannotHideAlias','TestRecoveryReviewSocketMemberLifetimeRejectsReuse')
$catalogPath=Join-Path $PSScriptRoot 'testdata\candidate-manifest.json';$catalogHash=Hash $catalogPath
$catalog=[IO.File]::ReadAllText($catalogPath)|ConvertFrom-Json
if($catalog.schema_version -ne 1 -or $catalog.kind -cne 'independent-web-recovery-candidate-pins' -or $catalog.files.Count -lt 10 -or $catalog.files.Count -gt 64){throw 'Invalid frozen candidate catalog.'}
$mapping=@{};$pins=@();$seen=@{};$counts=@{hostwebruntime=0;hostwebgeneration=0}
$attributes=Join-Path $PSScriptRoot '.gitattributes';$attributeHash=Hash $attributes
if([IO.File]::ReadAllText($attributes).Replace("`r`n","`n").Trim() -cne 'testdata/** -text whitespace=cr-at-eol'){throw 'Byte-preserving lab attributes missing or changed.'}
$pins+=@{scope='lab';path='.gitattributes';sha256=$attributeHash;bytes=(Get-Item -LiteralPath $attributes).Length}
$reference=Join-Path $PSScriptRoot 'testdata\snapshot_guard_reference_test.go';$referenceHash=Hash $reference
if($referenceHash -cne 'fb66a88fc3324c5523760940d772ab3229e418bcebf0f47e496d6279238025ca'){throw 'Root snapshot guard reference changed.'}
$guardRelative='internal/hostwebgeneration/coordinator_snapshot_guard_test.go'
foreach($entry in $catalog.files){
    $pathMatch=[regex]::Match($entry.path,'^internal/(hostwebruntime|hostwebgeneration)/[A-Za-z0-9_.-]+\.(go|md)$')
    if(-not $pathMatch.Success -or $entry.sha256 -cnotmatch '^[a-f0-9]{64}$' -or $seen.ContainsKey($entry.path)){throw 'Unadmitted candidate identity.'}
    $seen[$entry.path]=$true;$package=$pathMatch.Groups[1].Value
    $source=Join-Path $PSScriptRoot ('testdata\candidate\'+$entry.path.Replace('/','\'))
    if((Hash $source) -cne $entry.sha256 -or (Get-Item -LiteralPath $source).Length -ne $entry.bytes){throw 'Candidate pin mismatch.'}
    $pins+=@{scope='lab';path=('testdata/candidate/'+$entry.path);sha256=$entry.sha256;bytes=$entry.bytes}
    if($entry.path.EndsWith('.go')){$mapping[(Join-Path $reviewRoot $entry.path.Replace('/','\'))]=$source;$counts[$package]++}
}
if($counts.hostwebruntime -lt 5 -or $counts.hostwebgeneration -lt 2){throw 'Both complete candidate packages required.'}
foreach($package in @('hostwebruntime','hostwebgeneration')){
    $base=Join-Path $reviewRoot ('internal\'+$package);Assert-Plain $base 'Container'
    foreach($file in Get-ChildItem -LiteralPath $base -File -Filter '*.go'){
        $relative='internal/'+$package+'/'+$file.Name
        if($relative -ceq $guardRelative){
            $guardHash=Hash $file.FullName
            if($guardHash -cnotin @($referenceHash,'d108a5c1d71a0d6102254859143bfea297c21ef23c33c6b917b81383c74ab918') -or [IO.File]::ReadAllText($file.FullName).Replace("`r`n","`n") -cne [IO.File]::ReadAllText($reference).Replace("`r`n","`n")){throw 'Unreviewed root snapshot guard bytes.'}
            $pins+=@{scope='review';path=$guardRelative;sha256=$guardHash;bytes=$file.Length}
        }elseif(-not $seen.ContainsKey($relative)){throw 'Catalog omits a baseline candidate source.'}
    }
}
foreach($package in @('hostaccounts','hostweb','securestate')){
    $base=Join-Path $primaryRoot ('internal\'+$package);Assert-Plain $base 'Container'
    foreach($file in Get-ChildItem -LiteralPath $base -File -Filter '*.go'){
        $rel='internal/'+$package+'/'+$file.Name;$hash=Hash $file.FullName
        $mapping[(Join-Path $reviewRoot $rel.Replace('/','\'))]=$file.FullName
        $pins+=@{scope='canonical';path=$rel;sha256=$hash;bytes=$file.Length}
    }
}
$go=Join-Path $primaryRoot '.tools\go\bin\go.exe';$goHash=Hash $go
Assert-Plain (Join-Path $primaryRoot '.cache\go-mod') 'Container'
$run=[DateTime]::UtcNow.ToString('yyyyMMddTHHmmssfff')+'-'+[Guid]::NewGuid().ToString('N').Substring(0,8)
$out=Join-Path $PSScriptRoot ('artifacts\testdata\'+$run);Assert-Plain $out 'Container' -Missing
New-Item -ItemType Directory -Path $out|Out-Null
$utf8=[Text.UTF8Encoding]::new($false)
foreach($name in @('go.mod','go.sum')){
    $file=Join-Path $reviewRoot $name;$hash=Hash $file
    [IO.File]::WriteAllBytes((Join-Path $out ('review.'+$name)),[IO.File]::ReadAllBytes($file))
    $pins+=@{scope='review';path=$name;sha256=$hash;bytes=(Get-Item -LiteralPath $file).Length}
}
$modfile=Join-Path $out 'review.go.mod'
$mapping[(Join-Path $reviewRoot $guardRelative.Replace('/','\'))]=$reference
$pins+=@{scope='lab';path='testdata/snapshot_guard_reference_test.go';sha256=$referenceHash;bytes=(Get-Item -LiteralPath $reference).Length}
$baselineOverlay=Join-Path $out 'baseline-overlay.json'
[IO.File]::WriteAllText($baselineOverlay,(@{Replace=$mapping}|ConvertTo-Json -Depth 5),$utf8)
foreach($package in @('hostwebruntime','hostwebgeneration')){
    $test=Join-Path $PSScriptRoot ('testdata\'+$package+'_challenge_test.go');$hash=Hash $test
    $mapping[(Join-Path $reviewRoot ('internal\'+$package+'\independent_recovery_review_test.go'))]=$test
    $pins+=@{scope='lab';path=('testdata/'+$package+'_challenge_test.go');sha256=$hash;bytes=(Get-Item -LiteralPath $test).Length}
}
$snapshot=Join-Path $PSScriptRoot 'testdata\snapshot_guard_challenge_test.go';$snapshotHash=Hash $snapshot
$mapping[(Join-Path $reviewRoot 'internal\hostwebgeneration\independent_snapshot_guard_challenge_test.go')]=$snapshot
$pins+=@{scope='lab';path='testdata/snapshot_guard_challenge_test.go';sha256=$snapshotHash;bytes=(Get-Item -LiteralPath $snapshot).Length}
$challengeOverlay=Join-Path $out 'challenge-overlay.json'
[IO.File]::WriteAllText($challengeOverlay,(@{Replace=$mapping}|ConvertTo-Json -Depth 5),$utf8)
# Retain the exact source bytes that a historical report pins, even after a
# later candidate or test revision. Existing evidence is never overwritten.
foreach($entry in $pins){
    $root=switch($entry.scope){'lab'{$PSScriptRoot};'canonical'{$primaryRoot};'review'{$reviewRoot}}
    $source=Join-Path $root $entry.path.Replace('/','\')
    $copy=Join-Path $out ('source-evidence\'+$entry.scope+'\'+$entry.path.Replace('/','\'))
    New-Item -ItemType Directory -Force -Path ([IO.Path]::GetDirectoryName($copy))|Out-Null
    [IO.File]::WriteAllBytes($copy,[IO.File]::ReadAllBytes($source))
    if((Hash $copy) -cne $entry.sha256){throw 'Evidence copy differs from admitted source.'}
}
foreach($entry in @(@{source=$PSCommandPath;path='run.ps1';sha=$runnerHash},@{source=$catalogPath;path='candidate-manifest.json';sha=$catalogHash})){
    $copy=Join-Path $out ('source-evidence\lab\'+$entry.path)
    [IO.File]::WriteAllBytes($copy,[IO.File]::ReadAllBytes($entry.source))
    if((Hash $copy) -cne $entry.sha){throw 'Runner/catalog evidence differs.'}
}
$commands=@();$passed=$true
$envNames=@('GOCACHE','GOMODCACHE','GOPROXY','GOSUMDB','GOENV','GOTOOLCHAIN','GOOS','GOARCH','CGO_ENABLED')
$prior=@{};foreach($name in $envNames){$prior[$name]=[Environment]::GetEnvironmentVariable($name,'Process')}
try{
    $env:GOCACHE=Join-Path $out 'go-cache';$env:GOMODCACHE=Join-Path $primaryRoot '.cache\go-mod';$env:GOPROXY='off';$env:GOSUMDB='off';$env:GOENV='off';$env:GOTOOLCHAIN='local';$env:GOOS='windows';$env:GOARCH='amd64';$env:CGO_ENABLED='0'
    Push-Location -LiteralPath $reviewRoot
    try{
        foreach($phase in @('legacy','challenge','vet','linux_vet','linux_compile')){
            $overlay=$(if($phase -eq 'legacy'){$baselineOverlay}else{$challengeOverlay})
            $args=@()
            switch($phase){
                'legacy'{$args=@('test','-overlay',$overlay,'-modfile',$modfile,'-mod=readonly','-buildvcs=false','-count=1','-timeout=60s','-v','./internal/hostwebgeneration','./internal/hostwebruntime')}
                'challenge'{$args=@('test','-overlay',$overlay,'-modfile',$modfile,'-mod=readonly','-buildvcs=false','-count=1','-timeout=60s','-run','^TestRecoveryReview','-v','./internal/hostwebgeneration','./internal/hostwebruntime')}
                'vet'{$args=@('vet','-overlay',$overlay,'-modfile',$modfile,'-mod=readonly','-buildvcs=false','./internal/hostwebgeneration','./internal/hostwebruntime')}
                'linux_vet'{$env:GOOS='linux';$args=@('vet','-overlay',$overlay,'-modfile',$modfile,'-mod=readonly','-buildvcs=false','./internal/hostwebgeneration','./internal/hostwebruntime')}
                'linux_compile'{$env:GOOS='linux';$args=@('test','-overlay',$overlay,'-modfile',$modfile,'-mod=readonly','-buildvcs=false','-c','-o',(Join-Path $out 'hostwebruntime-linux.test'),'./internal/hostwebruntime')}
            }
            $nativeAction=$ErrorActionPreference
            try{$ErrorActionPreference='Continue';$output=@(& $go @args 2>&1);$code=$LASTEXITCODE}finally{$ErrorActionPreference=$nativeAction}
            $text=($output|ForEach-Object{$_.ToString()}) -join "`n"
            [IO.File]::WriteAllText((Join-Path $out ($phase+'-output.txt')),$text+"`n",$utf8)
            $passCount=@([regex]::Matches($text,'(?m)^--- PASS: TestRecoveryReview')).Count
            $ok=$code -eq 0
            if($phase -eq 'challenge'){
                $actual=@([regex]::Matches($text,'(?m)^--- PASS: (TestRecoveryReview[A-Za-z0-9_]+) ')|ForEach-Object{$_.Groups[1].Value})
                $ok=$ok -and $passCount -eq $expectedTests.Count -and $text -cnotmatch '(?m)^--- SKIP: TestRecoveryReview' -and @(Compare-Object ($expectedTests|Sort-Object) ($actual|Sort-Object)).Count -eq 0
            }
            $commands+=@{phase=$phase;arguments=$args;exit_code=$code;passed=$ok;review_pass_count=$passCount;output_sha256=(Hash (Join-Path $out ($phase+'-output.txt')))}
            $passed=$passed -and $ok
            if(-not $ok){break}
        }
    }finally{Pop-Location}
}finally{foreach($name in $envNames){[Environment]::SetEnvironmentVariable($name,$prior[$name],'Process')}}
$stable=(Hash $catalogPath) -ceq $catalogHash -and (Hash $go) -ceq $goHash -and (Hash $PSCommandPath) -ceq $runnerHash
foreach($entry in $pins){$root=switch($entry.scope){'lab'{$PSScriptRoot};'canonical'{$primaryRoot};'review'{$reviewRoot}};$file=Join-Path $root $entry.path.Replace('/','\');$stable=$stable -and (Hash $file) -ceq $entry.sha256}
$report=[ordered]@{schema_version=1;run_id=$run;passed=($passed -and $stable);catalog_sha256=$catalogHash;go_sha256=$goHash;runner_sha256=$runnerHash;attributes_sha256=$attributeHash;expected_review_tests=$expectedTests;commands=$commands;pins=$pins;source_pins_unchanged=$stable;evidence_boundary='Actual Windows Go tests of coordinator persistence and runtime helpers; injected executors/processes are protocol evidence. Linux ELF compilation is not Linux execution, native Apache/PHP activation, fault recovery, reboot, broker integration or vendor compatibility qualification.'}
$reportPath=Join-Path $out 'report.json';[IO.File]::WriteAllText($reportPath,($report|ConvertTo-Json -Depth 12)+"`n",$utf8)
Write-Output ('REPORT '+$reportPath);Write-Output ('SHA256 '+(Hash $reportPath))
if(-not $report.passed){exit 1};exit 0
