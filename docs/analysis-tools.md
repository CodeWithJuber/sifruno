# Artifact investigation

Use source and documented interfaces first, then artifact investigation when it supplies missing evidence. A static import is evidence about a specific artifact; original API/runtime/vendor behavior requires executable differential tests against a frozen licensed reference.

## Verified local installation

On 2026-10-04, this Windows x64 workspace installed official Ghidra **12.1.4** and Temurin **21.0.12.1+1** inside `.tools/analysis`. The pinned [Ghidra release](https://github.com/NationalSecurityAgency/ghidra/releases/tag/Ghidra_12.1.4_build) requires a 64-bit JDK 21; the [official Temurin release](https://github.com/adoptium/temurin21-binaries/releases/tag/jdk-21.0.12.1%2B1) supplies it. No global runtime, service, file association or external client was changed.

```powershell
./scripts/bootstrap-analysis.ps1
./scripts/bootstrap-analysis.ps1 -Offline
node scripts/verify-analysis-environment.mjs
npm run tools:doctor
npm run tools:analyze -- bin/panelctl.exe
```

The bootstrap is Windows x64 specific. It checks exact official archive sizes and SHA256s before extraction and rejects escaping ZIP entries and symlinks. Both bootstrap commands passed. Real Java `-version` matched 21.0.12.1; real Ghidra emitted `Headless Analyzer Usage: analyzeHeadless`. That usage command exits 1, which the manifest records explicitly rather than labelling it a successful target analysis. Installation metadata is `.tools/analysis/manifest.json`; setup logs are in `artifacts/analysis-setup`.

Pinned archive hashes:

| Archive | SHA256 |
| --- | --- |
| ghidra_12.1.4_PUBLIC_20260921.zip | ddac49f903da9d5bac833e5cc79395098b9c33cfd3279be5f31bd00387d2d4db |
| OpenJDK21U-jdk_x64_windows_hotspot_21.0.12.1_1.zip | f9d6e191ab098c0d416e7d588a24420a8621cd2f4720dab2459b8b7b2d2d8b4e |

The wrapper passes only OS launch/locale paths plus its verified local installation paths. Inherited application credentials, Node injection flags and user Java flags are excluded. Manifest escaping and oversized-manifest checks passed with zero provider calls. Input must be a regular independent workspace artifact of at most 32 MiB; symlink/outside inputs are rejected. Reports require regular workspace directories and independent files; output is bounded to 8 MiB and a command deadline has a terminal grace period. Forced termination records cleanup as unverified. Prior snapshots are archived before each new analysis and stderr is replaced even when empty, so stale output cannot stand in for new evidence. These wrapper controls are not a Windows sandbox proof.

## Actual REA result

REA **3.2.1** is reused from the pinned npm package. The actual `panelctl.exe` analysis returned `provider_unavailable`, with `unsupported_host` for Ghidra. All eight Ghidra/JDK installation checks passed. Its Windows authority implementation deliberately reports that Job Object process ownership, private runtime DACL enforcement and reparse-safe path admission are unavailable. This guard is preserved. Hopper also does not support this Windows host.

The Windows doctor additionally encounters an upstream npm/npx batch-launch `spawn EINVAL`. A small adapter reuses the existing Doctor SDK, preserves failed probes and keeps overall readiness false. Neither configured paths nor headless help are substituted for REA analysis. Reports are `artifacts/rea/doctor.json`, `doctor.upstream.json` and `analyze.json`.

REA native analysis should be qualified on its supported Linux host or after upstream implements and verifies the Windows controls. This workspace has no provisioned Linux VM/WSL/container environment. No cPanel executable or vendor artifact was provided or investigated, and no compatibility obligation is promoted by tool installation.

## Observed owned-artifact smoke

`./scripts/verify-ghidra-owned.ps1` is a separate, narrowly scoped official Ghidra check. It accepts no arbitrary target argument: only `bin/panelctl.exe`, matching the independently hashed native Windows package manifest and expected Go build identity. It requires an existing runtime build and that exact packaged binary. It snapshots the admitted bytes, imports them read-only, runs the official Java entry point with local home/settings/cache/temp, checks the imported SHA256 and exports numeric counts. It does not execute the target or use REA's unavailable Windows provider.

The observed run on 2026-10-04 passed in **97.2 seconds**, observing **3,430 functions, 384,450 instructions and 43,065 defined data entries**, with no per-file timeout. Report: `artifacts/analysis-setup/owned-artifact/latest.json`. Its coverage remains **partial static only**: Ghidra 12.1.4 warned that it could not reconstruct Go 1.27 bootstrap RTTI/symbol/string information. Counts do not prove recovered source or runtime behavior.

The first disposable project path was rejected because Ghidra forbids path elements starting with a dot; the project now uses a normal workspace artifact directory. A sandboxed attempt imported/analyzed the owned snapshot but its postscript compiler encountered access denied on official installed libraries. Even though Ghidra exited 0, the wrapper rejected the missing report. The successful same-user run received automatic approval review for the official compiler's library access; it changed no SDK, ACL or global setting. Failed-run logs remain separate. REA's native isolation guard is intact, and cPanel compatibility remains 0 passed / 30 untested.

The owned runner uses fixed-size reads and a 2 Mi-character capture bound; it saves partial logs on failure and guards cleanup of unstarted/departed processes. A harmless Java version probe, forced deadline rejection and missing-executable/log checks passed after runner hardening. Forced-failure reports record cleanup as unverified. The full static analysis was not repeated for formatting and runner-only changes; its observed artifact/report digest and counts remain unchanged.
