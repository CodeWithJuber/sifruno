#Requires -Version 7.0
param([switch]$Offline)
$ErrorActionPreference = 'Stop'
$analysisWorkspace = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
$analysisRoot = Join-Path $analysisWorkspace '.tools\analysis'
$analysisReports = Join-Path $analysisWorkspace 'artifacts\analysis-setup'

function New-AnalysisDirectory([string]$Path) {
    $analysisAbsolute = [IO.Path]::GetFullPath($Path)
    if (-not $analysisAbsolute.StartsWith($analysisWorkspace + [IO.Path]::DirectorySeparatorChar, [StringComparison]::OrdinalIgnoreCase)) { throw 'Analysis paths must stay inside this workspace.' }
    $analysisCurrent = $analysisWorkspace
    foreach ($analysisSegment in $analysisAbsolute.Substring($analysisWorkspace.Length + 1).Split([IO.Path]::DirectorySeparatorChar)) {
        $analysisCurrent = Join-Path $analysisCurrent $analysisSegment
        if (-not (Test-Path -LiteralPath $analysisCurrent)) { New-Item -ItemType Directory -Path $analysisCurrent | Out-Null }
        $analysisInfo = Get-Item -LiteralPath $analysisCurrent
        if (-not $analysisInfo.PSIsContainer -or ($analysisInfo.Attributes -band [IO.FileAttributes]::ReparsePoint)) { throw 'Analysis directories must be regular workspace directories.' }
    }
}

function Get-AnalysisArchive([string]$Name, [string]$Url, [string]$SHA256, [long]$Size) {
    $analysisArchive = Join-Path $analysisRoot $Name
    if (-not (Test-Path -LiteralPath $analysisArchive)) {
        if ($Offline) { throw "Offline cache missing: $Name" }
        $analysisPartial = $analysisArchive + '.partial'
        if (Test-Path -LiteralPath $analysisPartial) { throw "A partial download exists. Inspect it before retrying: $Name.partial" }
        Write-Host "Downloading official $Name"
        Invoke-WebRequest -Uri $Url -OutFile $analysisPartial -TimeoutSec 240 -MaximumRetryCount 0
        if ((Get-Item -LiteralPath $analysisPartial).Length -ne $Size) { throw "Archive size mismatch: $Name" }
        if ((Get-FileHash -LiteralPath $analysisPartial -Algorithm SHA256).Hash.ToLowerInvariant() -ne $SHA256) { throw "Archive SHA256 mismatch: $Name" }
        Move-Item -LiteralPath $analysisPartial -Destination $analysisArchive
    }
    $analysisInfo = Get-Item -LiteralPath $analysisArchive
    if (($analysisInfo.Attributes -band [IO.FileAttributes]::ReparsePoint) -or $analysisInfo.Length -ne $Size) { throw "Invalid cached archive: $Name" }
    if ((Get-FileHash -LiteralPath $analysisArchive -Algorithm SHA256).Hash.ToLowerInvariant() -ne $SHA256) { throw "Cached SHA256 mismatch: $Name" }
    return $analysisArchive
}

function Expand-AnalysisArchive([string]$Archive, [string]$Folder) {
    $analysisDestination = Join-Path $analysisRoot $Folder
    if (Test-Path -LiteralPath (Join-Path $analysisDestination '.extracted')) { return $analysisDestination }
    if (Test-Path -LiteralPath $analysisDestination) { throw "Incomplete extraction exists; inspect it before retrying: $Folder" }
    New-AnalysisDirectory $analysisDestination
    # Validate ZIP entry confinement before any extraction. Archives are exact
    # official, pinned bytes; no third-party/native target is opened here.
    $analysisZip = [IO.Compression.ZipFile]::OpenRead($Archive)
    try {
        foreach ($analysisEntry in $analysisZip.Entries) {
            $analysisEntryPath = [IO.Path]::GetFullPath((Join-Path $analysisDestination $analysisEntry.FullName))
            if (-not $analysisEntryPath.StartsWith($analysisDestination + [IO.Path]::DirectorySeparatorChar, [StringComparison]::OrdinalIgnoreCase)) { throw 'ZIP entry escapes its workspace extraction directory.' }
            if ((($analysisEntry.ExternalAttributes -shr 16) -band 0xF000) -eq 0xA000) { throw 'Symlink ZIP entries are not accepted.' }
        }
    } finally { $analysisZip.Dispose() }
    Expand-Archive -LiteralPath $Archive -DestinationPath $analysisDestination
    Set-Content -LiteralPath (Join-Path $analysisDestination '.extracted') -Value 'Official pinned archive extracted.' -Encoding utf8
    return $analysisDestination
}

function Invoke-AnalysisJava([string]$Java, [string[]]$Arguments, [string]$Label) {
    $analysisStart = [Diagnostics.ProcessStartInfo]::new()
    $analysisStart.FileName = $Java
    $analysisStart.WorkingDirectory = $analysisWorkspace
    $analysisStart.UseShellExecute = $false
    $analysisStart.CreateNoWindow = $true
    $analysisStart.RedirectStandardOutput = $true
    $analysisStart.RedirectStandardError = $true
    $analysisStart.Environment.Clear()
    foreach ($analysisEnvName in @('SystemRoot', 'WINDIR', 'ComSpec', 'PATHEXT')) {
        $analysisEnvValue = [Environment]::GetEnvironmentVariable($analysisEnvName)
        if ($null -ne $analysisEnvValue) { $analysisStart.Environment[$analysisEnvName] = $analysisEnvValue }
    }
    $analysisStart.Environment['PATH'] = Split-Path $Java -Parent
    $analysisStart.Environment['TEMP'] = Join-Path $analysisRoot 'temp'
    $analysisStart.Environment['TMP'] = Join-Path $analysisRoot 'temp'
    $analysisStart.Environment['USERPROFILE'] = Join-Path $analysisRoot 'home'
    $analysisStart.Environment['APPDATA'] = Join-Path $analysisRoot 'home\appdata'
    $analysisStart.Environment['LOCALAPPDATA'] = Join-Path $analysisRoot 'home\localappdata'
    foreach ($analysisArg in $Arguments) { $analysisStart.ArgumentList.Add($analysisArg) }
    $analysisProcess = [Diagnostics.Process]::new()
    $analysisProcess.StartInfo = $analysisStart
    try {
        if (-not $analysisProcess.Start()) { throw "Could not launch $Label" }
        $analysisStdoutTask = $analysisProcess.StandardOutput.ReadToEndAsync()
        $analysisStderrTask = $analysisProcess.StandardError.ReadToEndAsync()
        if (-not $analysisProcess.WaitForExit(90000)) { $analysisProcess.Kill($true); throw "$Label exceeded 90-second verification limit." }
        $analysisStdout = $analysisStdoutTask.GetAwaiter().GetResult()
        $analysisStderr = $analysisStderrTask.GetAwaiter().GetResult()
        if ($analysisStdout.Length + $analysisStderr.Length -gt 262144) { throw "$Label output exceeded bounds." }
        Set-Content -LiteralPath (Join-Path $analysisReports ($Label + '.stdout.txt')) -Value $analysisStdout -Encoding utf8
        Set-Content -LiteralPath (Join-Path $analysisReports ($Label + '.stderr.txt')) -Value $analysisStderr -Encoding utf8
        return [pscustomobject]@{exit_code=$analysisProcess.ExitCode; stdout=$analysisStdout; stderr=$analysisStderr}
    } finally { $analysisProcess.Dispose() }
}

if (-not $IsWindows -or [Runtime.InteropServices.RuntimeInformation]::OSArchitecture -ne [Runtime.InteropServices.Architecture]::X64) { throw 'This pinned bootstrap targets this Windows x64 development workspace.' }
New-AnalysisDirectory $analysisRoot
New-AnalysisDirectory $analysisReports
foreach ($analysisRelative in @('temp', 'home', 'home\appdata', 'home\localappdata', 'settings', 'cache')) { New-AnalysisDirectory (Join-Path $analysisRoot $analysisRelative) }

$analysisGhidra = @{name='ghidra_12.1.4_PUBLIC_20260921.zip'; version='12.1.4'; size=569649598; sha256='ddac49f903da9d5bac833e5cc79395098b9c33cfd3279be5f31bd00387d2d4db'; url='https://github.com/NationalSecurityAgency/ghidra/releases/download/Ghidra_12.1.4_build/ghidra_12.1.4_PUBLIC_20260921.zip'; checksum_source='https://api.github.com/repos/NationalSecurityAgency/ghidra/releases/tags/Ghidra_12.1.4_build'}
$analysisJdk = @{name='OpenJDK21U-jdk_x64_windows_hotspot_21.0.12.1_1.zip'; version='21.0.12.1+1'; size=205073461; sha256='f9d6e191ab098c0d416e7d588a24420a8621cd2f4720dab2459b8b7b2d2d8b4e'; url='https://github.com/adoptium/temurin21-binaries/releases/download/jdk-21.0.12.1%2B1/OpenJDK21U-jdk_x64_windows_hotspot_21.0.12.1_1.zip'; checksum_source='https://github.com/adoptium/temurin21-binaries/releases/download/jdk-21.0.12.1%2B1/OpenJDK21U-jdk_x64_windows_hotspot_21.0.12.1_1.zip.sha256.txt'}
$analysisRequirements = 'https://raw.githubusercontent.com/NationalSecurityAgency/ghidra/Ghidra_12.1.4_build/README.md'
@{requirements_source=$analysisRequirements; required_jdk_major=21; ghidra=$analysisGhidra; jdk=$analysisJdk} | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath (Join-Path $analysisReports 'official-release-pins.json') -Encoding utf8

$analysisJdkArchive = Get-AnalysisArchive -Name $analysisJdk.name -Url $analysisJdk.url -SHA256 $analysisJdk.sha256 -Size $analysisJdk.size
$analysisGhidraArchive = Get-AnalysisArchive -Name $analysisGhidra.name -Url $analysisGhidra.url -SHA256 $analysisGhidra.sha256 -Size $analysisGhidra.size
$analysisJdkExtract = Expand-AnalysisArchive $analysisJdkArchive 'temurin-21.0.12.1-verified'
$analysisGhidraExtract = Expand-AnalysisArchive $analysisGhidraArchive 'ghidra-12.1.4-verified'
$analysisJavaHome = (Get-ChildItem -LiteralPath $analysisJdkExtract -Directory | Where-Object { Test-Path -LiteralPath (Join-Path $_.FullName 'bin\java.exe') } | Select-Object -First 1).FullName
$analysisGhidraHome = (Get-ChildItem -LiteralPath $analysisGhidraExtract -Directory | Where-Object { Test-Path -LiteralPath (Join-Path $_.FullName 'Ghidra\application.properties') } | Select-Object -First 1).FullName
if (-not $analysisJavaHome -or -not $analysisGhidraHome) { throw 'Official extracted distribution root is missing.' }
$analysisJava = Join-Path $analysisJavaHome 'bin\java.exe'
$analysisVersion = Invoke-AnalysisJava $analysisJava @('-version') 'java-version'
if ($analysisVersion.exit_code -ne 0 -or $analysisVersion.stderr -notmatch '21\.0\.12\.1') { throw 'Pinned JDK launch/version verification failed.' }
$analysisProperties = Get-Content -LiteralPath (Join-Path $analysisGhidraHome 'Ghidra\application.properties') -Raw
if ($analysisProperties -notmatch '(?m)^application.version=12\.1\.4\s*$') { throw 'Pinned Ghidra installed version mismatch.' }
$analysisVm = @('-Xmx768M', '-Xshare:off', '-XX:ParallelGCThreads=2', '-XX:CICompilerCount=2', '-Djava.awt.headless=true', '-Djava.system.class.loader=ghidra.GhidraClassLoader', '-Dfile.encoding=UTF8', '-Duser.country=US', '-Duser.language=en', '--enable-native-access=ALL-UNNAMED', "-Duser.home=$(Join-Path $analysisRoot 'home')", "-Dapplication.settingsdir=$(Join-Path $analysisRoot 'settings')", "-Dapplication.cachedir=$(Join-Path $analysisRoot 'cache')", "-Dapplication.tempdir=$(Join-Path $analysisRoot 'temp')", "-Djava.io.tmpdir=$(Join-Path $analysisRoot 'temp')")
# Same official classpath/main entry used by support/launch.bat, invoked without
# its Java auto-discovery/-save helper so no global preferences are configured.
$analysisHeadlessArgs = $analysisVm + @('-cp', (Join-Path $analysisGhidraHome 'Ghidra\Framework\Utility\lib\Utility.jar'), 'ghidra.Ghidra', 'ghidra.app.util.headless.AnalyzeHeadless', '-help')
$analysisHelp = Invoke-AnalysisJava $analysisJava $analysisHeadlessArgs 'ghidra-headless-help'
$analysisUsage = $analysisHelp.stdout + $analysisHelp.stderr
if ($analysisHelp.exit_code -notin @(0,1) -or $analysisUsage -notmatch 'analyzeHeadless|AnalyzeHeadless|Headless Analyzer') { throw 'Real Ghidra headless help did not launch successfully.' }
$analysisManifest = [ordered]@{schema_version=1; platform='windows-amd64'; ghidra_dir=$analysisGhidraHome; java_home=$analysisJavaHome; ghidra_version='12.1.4'; java_version='21.0.12.1+1'; required_jdk_major=21; requirements_source=$analysisRequirements; verified_checksums=@(@{name=$analysisJdk.name; archive=$analysisJdkArchive; sha256=$analysisJdk.sha256; official_source=$analysisJdk.url; checksum_source=$analysisJdk.checksum_source},@{name=$analysisGhidra.name; archive=$analysisGhidraArchive; sha256=$analysisGhidra.sha256; official_source=$analysisGhidra.url; checksum_source=$analysisGhidra.checksum_source}); headless_launch_verified=$true; headless_help_exit_code=$analysisHelp.exit_code; headless_log_dir=$analysisReports; application_home=(Join-Path $analysisRoot 'home'); application_settings=(Join-Path $analysisRoot 'settings'); application_cache=(Join-Path $analysisRoot 'cache'); application_temp=(Join-Path $analysisRoot 'temp'); global_configuration_changed=$false; cpanel_artifact_analyzed=$false; installed_at=[DateTime]::UtcNow.ToString('o')}
$analysisManifest | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath (Join-Path $analysisRoot 'manifest.json') -Encoding utf8
$analysisManifest | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath (Join-Path $analysisReports 'verification.json') -Encoding utf8
Write-Output 'Official Ghidra 12.1.4 and Temurin JDK 21.0.12.1 installed project-locally; archive SHA256 and real headless help verified.'
Write-Output 'No cPanel artifact was supplied or analyzed. Tool launch is not compatibility evidence.'
