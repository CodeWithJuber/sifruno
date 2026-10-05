#Requires -Version 7.0
param()
$ErrorActionPreference = 'Stop'
$ownedWorkspace = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
$ownedAnalysis = Join-Path $ownedWorkspace '.tools\analysis'
$ownedManifest = Get-Content -LiteralPath (Join-Path $ownedAnalysis 'manifest.json') -Raw | ConvertFrom-Json
$ownedBinary = Join-Path $ownedWorkspace 'bin\panelctl.exe'

function New-OwnedDirectory([string]$Path) {
    $ownedAbsolute = [IO.Path]::GetFullPath($Path)
    if (-not $ownedAbsolute.StartsWith($ownedWorkspace + [IO.Path]::DirectorySeparatorChar, [StringComparison]::OrdinalIgnoreCase)) { throw 'Owned smoke paths must stay in this workspace.' }
    $ownedCurrent = $ownedWorkspace
    foreach ($ownedPart in $ownedAbsolute.Substring($ownedWorkspace.Length + 1).Split([IO.Path]::DirectorySeparatorChar)) {
        $ownedCurrent = Join-Path $ownedCurrent $ownedPart
        if (-not (Test-Path -LiteralPath $ownedCurrent)) { New-Item -ItemType Directory -Path $ownedCurrent | Out-Null }
        $ownedInfo = Get-Item -LiteralPath $ownedCurrent
        if (-not $ownedInfo.PSIsContainer -or ($ownedInfo.Attributes -band [IO.FileAttributes]::ReparsePoint)) { throw 'Owned smoke paths cannot contain junctions or symlinks.' }
    }
}

function Invoke-OwnedProcess([string]$Executable, [string[]]$Arguments, [string]$Label, [int]$TimeoutSeconds) {
    if ($Label -notmatch '^[a-z][a-z-]{0,63}$') { throw 'Invalid local process log label.' }
    $ownedStart = [Diagnostics.ProcessStartInfo]::new()
    $ownedStart.FileName = $Executable
    $ownedStart.WorkingDirectory = $ownedWorkspace
    $ownedStart.UseShellExecute = $false
    $ownedStart.CreateNoWindow = $true
    $ownedStart.RedirectStandardOutput = $true
    $ownedStart.RedirectStandardError = $true
    $ownedStart.Environment.Clear()
    foreach ($ownedEnvName in @('SystemRoot','WINDIR','ComSpec','PATHEXT')) {
        $ownedEnvValue = [Environment]::GetEnvironmentVariable($ownedEnvName)
        if ($null -ne $ownedEnvValue) { $ownedStart.Environment[$ownedEnvName] = $ownedEnvValue }
    }
    $ownedStart.Environment['PATH'] = (Split-Path $Executable -Parent) + ';' + (Join-Path ([Environment]::GetEnvironmentVariable('SystemRoot')) 'System32')
    $ownedStart.Environment['HOME'] = Join-Path $ownedRun 'home'
    $ownedStart.Environment['USERPROFILE'] = Join-Path $ownedRun 'home'
    $ownedStart.Environment['APPDATA'] = Join-Path $ownedRun 'home\appdata'
    $ownedStart.Environment['LOCALAPPDATA'] = Join-Path $ownedRun 'home\localappdata'
    $ownedStart.Environment['TEMP'] = Join-Path $ownedRun 'temp'
    $ownedStart.Environment['TMP'] = Join-Path $ownedRun 'temp'
    $ownedStart.Environment['GOTOOLCHAIN'] = 'local'
    $ownedStart.Environment['GOENV'] = 'off'
    foreach ($ownedArgument in $Arguments) { $ownedStart.ArgumentList.Add($ownedArgument) }
    $ownedProcess = [Diagnostics.Process]::new()
    $ownedProcess.StartInfo = $ownedStart
    $ownedOut = [Text.StringBuilder]::new()
    $ownedErr = [Text.StringBuilder]::new()
    $ownedDidStart = $false
    $ownedFault = $null
    try {
        if (-not $ownedProcess.Start()) { throw "Could not start $Label" }
        $ownedDidStart = $true
        $ownedWatch = [Diagnostics.Stopwatch]::StartNew()
        # Fixed-size reads also bound a single line without a newline.
        $ownedOutBuffer = [char[]]::new(4096)
        $ownedErrBuffer = [char[]]::new(4096)
        $ownedOutTask = $ownedProcess.StandardOutput.ReadAsync($ownedOutBuffer,0,$ownedOutBuffer.Length)
        $ownedErrTask = $ownedProcess.StandardError.ReadAsync($ownedErrBuffer,0,$ownedErrBuffer.Length)
        $ownedOutDone = $false; $ownedErrDone = $false
        while (-not ($ownedProcess.HasExited -and $ownedOutDone -and $ownedErrDone)) {
            foreach ($ownedStream in @('out','err')) {
                $ownedTask = if ($ownedStream -eq 'out') { $ownedOutTask } else { $ownedErrTask }
                if ($null -ne $ownedTask -and $ownedTask.IsCompleted) {
                    $ownedChars = $ownedTask.GetAwaiter().GetResult()
                    if ($ownedChars -eq 0) {
                        if ($ownedStream -eq 'out') { $ownedOutDone=$true; $ownedOutTask=$null } else { $ownedErrDone=$true; $ownedErrTask=$null }
                    } else {
                        $ownedRemaining = 2097152 - $ownedOut.Length - $ownedErr.Length
                        $ownedAppend = [Math]::Min($ownedChars,$ownedRemaining)
                        if ($ownedStream -eq 'out') { [void]$ownedOut.Append($ownedOutBuffer,0,$ownedAppend) } else { [void]$ownedErr.Append($ownedErrBuffer,0,$ownedAppend) }
                        if ($ownedChars -gt $ownedRemaining) { throw "$Label exceeded bounded output." }
                        if ($ownedStream -eq 'out') { $ownedOutTask=$ownedProcess.StandardOutput.ReadAsync($ownedOutBuffer,0,$ownedOutBuffer.Length) } else { $ownedErrTask=$ownedProcess.StandardError.ReadAsync($ownedErrBuffer,0,$ownedErrBuffer.Length) }
                    }
                }
            }
            if ($ownedWatch.Elapsed.TotalSeconds -gt $TimeoutSeconds) { throw "$Label exceeded its bounded deadline." }
            Start-Sleep -Milliseconds 20
        }
        return [pscustomobject]@{exit_code=$ownedProcess.ExitCode; stdout=$ownedOut.ToString(); stderr=$ownedErr.ToString()}
    } catch {
        $ownedFault = $_.Exception.Message
        throw
    } finally {
        if ($ownedDidStart) {
            try { if (-not $ownedProcess.HasExited) { $ownedProcess.Kill($true); [void]$ownedProcess.WaitForExit(5000) } } catch { }
            try { $ownedProcess.StandardOutput.Dispose(); $ownedProcess.StandardError.Dispose() } catch { }
        }
        [IO.File]::WriteAllText((Join-Path $ownedReportDir ($Label+'.stdout.txt')),$ownedOut.ToString(),[Text.UTF8Encoding]::new($false))
        [IO.File]::WriteAllText((Join-Path $ownedReportDir ($Label+'.stderr.txt')),$ownedErr.ToString(),[Text.UTF8Encoding]::new($false))
        if ($null -ne $ownedFault) {
            [ordered]@{process_failed=$true; reason=$ownedFault; cleanup_verified=$false} | ConvertTo-Json | Set-Content -LiteralPath (Join-Path $ownedReportDir ($Label+'.failure.json')) -Encoding utf8
        }
        $ownedProcess.Dispose()
    }
}

if (-not $IsWindows -or $ownedManifest.ghidra_version -ne '12.1.4' -or $ownedManifest.required_jdk_major -ne 21 -or $ownedManifest.headless_launch_verified -ne $true) { throw 'Verified project-local Windows Ghidra/JDK setup is required.' }
New-OwnedDirectory (Split-Path $ownedBinary -Parent)
$ownedBinaryInfo = Get-Item -LiteralPath $ownedBinary
if ($ownedBinaryInfo.PSIsContainer -or ($ownedBinaryInfo.Attributes -band [IO.FileAttributes]::ReparsePoint) -or $ownedBinaryInfo.Length -gt 33554432) { throw 'Only the bounded regular compiled bin/panelctl.exe is admitted.' }
foreach ($ownedToolDir in @($ownedManifest.ghidra_dir,$ownedManifest.java_home)) {
    if (-not [IO.Path]::GetFullPath($ownedToolDir).StartsWith($ownedAnalysis + [IO.Path]::DirectorySeparatorChar,[StringComparison]::OrdinalIgnoreCase)) { throw 'Analysis installation path escapes its local root.' }
    New-OwnedDirectory $ownedToolDir
}
$ownedSHA256 = (Get-FileHash -LiteralPath $ownedBinary -Algorithm SHA256).Hash.ToLowerInvariant()
$ownedRuntimeLatest = Get-Content -LiteralPath (Join-Path $ownedWorkspace 'deliverables\runtime-builds\latest.json') -Raw | ConvertFrom-Json
if ($ownedRuntimeLatest.run_id -notmatch '^\d{17}-[a-f0-9]{8}$') { throw 'Native runtime build provenance is missing or malformed.' }
$ownedRuntimeIndexPath = Join-Path $ownedWorkspace ('deliverables\runtime-builds\'+$ownedRuntimeLatest.run_id+'\index.json')
New-OwnedDirectory (Split-Path $ownedRuntimeIndexPath -Parent)
if ((Get-FileHash -LiteralPath $ownedRuntimeIndexPath -Algorithm SHA256).Hash.ToLowerInvariant() -ne $ownedRuntimeLatest.index_sha256) { throw 'Native runtime build index integrity failed.' }
$ownedRuntimeIndex = Get-Content -LiteralPath $ownedRuntimeIndexPath -Raw | ConvertFrom-Json
$ownedRuntimeArchive = $ownedRuntimeIndex.archives | Where-Object { $_.file.EndsWith('-windows-amd64.zip') } | Select-Object -First 1
$ownedRuntimeManifestPath = Join-Path $ownedWorkspace ('.cache\runtime-builds\'+$ownedRuntimeLatest.run_id+'\windows-amd64\manifest.json')
New-OwnedDirectory (Split-Path $ownedRuntimeManifestPath -Parent)
if (-not $ownedRuntimeArchive -or (Get-FileHash -LiteralPath $ownedRuntimeManifestPath -Algorithm SHA256).Hash.ToLowerInvariant() -ne $ownedRuntimeArchive.manifest_sha256) { throw 'Native Windows build manifest integrity failed.' }
$ownedRuntimeManifest = Get-Content -LiteralPath $ownedRuntimeManifestPath -Raw | ConvertFrom-Json
$ownedRuntimeBinary = $ownedRuntimeManifest.files | Where-Object path -eq 'bin/panelctl.exe' | Select-Object -First 1
if ($ownedRuntimeManifest.target -ne 'windows-amd64' -or $ownedRuntimeBinary.sha256 -ne $ownedSHA256) { throw 'Input digest does not match the independently packaged owned Windows panelctl.' }
$ownedID = [DateTime]::UtcNow.ToString('yyyyMMddTHHmmss') + '-' + [Guid]::NewGuid().ToString('N').Substring(0,8)
$ownedRun = Join-Path $ownedAnalysis ('owned-smoke\'+$ownedID)
$ownedReportDir = Join-Path $ownedWorkspace ('artifacts\analysis-setup\owned-artifact\'+$ownedID)
foreach ($ownedDirectory in @($ownedReportDir,(Join-Path $ownedReportDir 'project'),$ownedRun,(Join-Path $ownedRun 'temp'),(Join-Path $ownedRun 'home'),(Join-Path $ownedRun 'home\appdata'),(Join-Path $ownedRun 'home\localappdata'),(Join-Path $ownedRun 'settings'),(Join-Path $ownedRun 'cache'))) { New-OwnedDirectory $ownedDirectory }
$ownedGo = Invoke-OwnedProcess (Join-Path $ownedWorkspace '.tools\go\bin\go.exe') @('version','-m',$ownedBinary) 'go-build-identity' 20
if ($ownedGo.exit_code -ne 0 -or $ownedGo.stdout -notmatch '(?m)\bpath\s+sifruno/cmd/panelctl\s*$' -or $ownedGo.stdout -notmatch 'GOOS=windows' -or $ownedGo.stdout -notmatch 'GOARCH=amd64' -or $ownedGo.stdout -notmatch 'CGO_ENABLED=0') { throw 'Input is not the expected owned compiled panelctl binary.' }
$ownedSnapshot = Join-Path $ownedRun 'panelctl.exe'
Copy-Item -LiteralPath $ownedBinary -Destination $ownedSnapshot
if ((Get-FileHash -LiteralPath $ownedSnapshot -Algorithm SHA256).Hash.ToLowerInvariant() -ne $ownedSHA256) { throw 'Owned binary changed during snapshot.' }
$ownedCounts = Join-Path $ownedReportDir 'static-counts.json'
$ownedScript = @'
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.util.Locale;
import ghidra.app.util.headless.HeadlessScript;

public class SifrunoOwnedArtifactReport extends HeadlessScript {
    @Override public void run() throws Exception {
        String[] args = getScriptArgs();
        if (args.length != 2 || !args[1].matches("[a-f0-9]{64}")) throw new IllegalArgumentException("Invalid bounded owned-report arguments");
        String digest = currentProgram.getExecutableSHA256();
        if (!args[1].equals(digest)) throw new IllegalStateException("Imported artifact digest differs from the admitted owned snapshot");
        String json = String.format(Locale.ROOT,
            "{\"schema_version\":1,\"sha256\":\"%s\",\"functions\":%d,\"instructions\":%d,\"defined_data\":%d,\"analysis_timed_out\":%s}\n",
            digest, currentProgram.getFunctionManager().getFunctionCount(),
            currentProgram.getListing().getNumInstructions(), currentProgram.getListing().getNumDefinedData(),
            Boolean.toString(analysisTimeoutOccurred()));
        Files.writeString(Path.of(args[0]), json, StandardCharsets.UTF_8, StandardOpenOption.CREATE_NEW);
        println("Sifruno owned artifact counts written; static analysis only.");
    }
}
'@
Set-Content -LiteralPath (Join-Path $ownedReportDir 'SifrunoOwnedArtifactReport.java') -Value $ownedScript -Encoding utf8
# Ghidra rejects project-directory path elements beginning with '.', so its
# disposable project lives in the regular artifacts tree; tool/temp paths stay
# local under .tools and are not rewritten or aliased to evade admission.
$ownedJavaArgs = @('-Xmx1024M','-Xshare:off','-XX:ParallelGCThreads=2','-XX:CICompilerCount=2','-Dcpu.core.limit=2','-Djava.awt.headless=true','-Djava.system.class.loader=ghidra.GhidraClassLoader','-Dfile.encoding=UTF8','-Duser.country=US','-Duser.language=en','--enable-native-access=ALL-UNNAMED',"-Duser.home=$(Join-Path $ownedRun 'home')","-Dapplication.settingsdir=$(Join-Path $ownedRun 'settings')","-Dapplication.cachedir=$(Join-Path $ownedRun 'cache')","-Dapplication.tempdir=$(Join-Path $ownedRun 'temp')","-Djava.io.tmpdir=$(Join-Path $ownedRun 'temp')",'-cp',(Join-Path $ownedManifest.ghidra_dir 'Ghidra\Framework\Utility\lib\Utility.jar'),'ghidra.Ghidra','ghidra.app.util.headless.AnalyzeHeadless',(Join-Path $ownedReportDir 'project'),'sifruno-owned-smoke','-import',$ownedSnapshot,'-readOnly','-deleteProject','-analysisTimeoutPerFile','180','-max-cpu','2','-log',(Join-Path $ownedReportDir 'ghidra-application.log'),'-scriptlog',(Join-Path $ownedReportDir 'ghidra-script.log'),'-scriptPath',$ownedReportDir,'-postScript','SifrunoOwnedArtifactReport.java',$ownedCounts,$ownedSHA256)
Write-Host 'Importing and statically analyzing the hash-matched owned panelctl snapshot with official Ghidra; REA Windows isolation remains unavailable.'
$ownedStarted = [DateTime]::UtcNow
$ownedResult = Invoke-OwnedProcess (Join-Path $ownedManifest.java_home 'bin\java.exe') $ownedJavaArgs 'ghidra-owned-analysis' 300
if ($ownedResult.exit_code -ne 0 -or -not (Test-Path -LiteralPath $ownedCounts)) { throw "Owned Ghidra analysis failed or produced no counts; inspect local logs. Exit $($ownedResult.exit_code)" }
$ownedObserved = Get-Content -LiteralPath $ownedCounts -Raw | ConvertFrom-Json
if ($ownedObserved.sha256 -ne $ownedSHA256 -or $ownedObserved.functions -lt 1 -or $ownedObserved.instructions -lt 1) { throw 'Owned static analysis observations failed validation.' }
$ownedWarnings = @()
$ownedApplicationLog = Get-Content -LiteralPath (Join-Path $ownedReportDir 'ghidra-application.log') -Raw
if ($ownedApplicationLog -match 'Untested Go version|Missing Go bootstrap type info|Go symbol analyzer error|Go string analyzer error') { $ownedWarnings += 'Ghidra 12.1.4 could not reconstruct Go 1.27 bootstrap RTTI/symbol/string information.' }
if ($ownedApplicationLog -match 'GhidraScriptLoadException') { $ownedWarnings += 'At least one built-in analysis script failed to load; consult the preserved application log.' }
if ($ownedObserved.analysis_timed_out) { $ownedWarnings += 'The built-in per-file analysis deadline expired; counts cover partial analysis only.' }
$ownedSummary = [ordered]@{schema_version=1; evidence_kind='observed_owned_static_analysis'; provider='official-ghidra-direct'; provider_version='12.1.4'; artifact='bin/panelctl.exe'; sha256=$ownedSHA256; snapshot_hash_matched=$true; packaged_build_hash_verified=$true; packaged_build_run=$ownedRuntimeLatest.run_id; go_build_identity_verified=$true; functions=$ownedObserved.functions; instructions=$ownedObserved.instructions; defined_data=$ownedObserved.defined_data; analysis_timed_out=$ownedObserved.analysis_timed_out; coverage='partial-static-only'; analysis_warnings=$ownedWarnings; ghidra_exit_code=$ownedResult.exit_code; duration_seconds=[Math]::Round(([DateTime]::UtcNow-$ownedStarted).TotalSeconds,2); rea_windows_isolation_verified=$false; target_executed=$false; cpanel_artifact_analyzed=$false; certifies_compatibility=$false; logs=$ownedReportDir; limitations=@('Static import/analysis of our own compiled workbench only.','REA 3.2.1 Windows authority remains unsupported; this smoke does not bypass or satisfy that guard.','Function/instruction counts are observations, not recovery of full source or runtime behavior.','No cPanel/vendor artifact or unchanged ecosystem scenario was analyzed.')}
$ownedSummary | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath (Join-Path $ownedReportDir 'report.json') -Encoding utf8
$ownedSummary | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath (Join-Path $ownedWorkspace 'artifacts\analysis-setup\owned-artifact\latest.json') -Encoding utf8
[pscustomobject]$ownedSummary | Select-Object evidence_kind,sha256,functions,instructions,analysis_timed_out,duration_seconds,rea_windows_isolation_verified,certifies_compatibility | ConvertTo-Json
