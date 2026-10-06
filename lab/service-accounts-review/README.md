# Independent managed-service account core review

This lab owns only its review files and ignored build artifacts. It reviews
core `23e9a97f17b9735fdffa7ed4012f78e4e8e44a57` over baseline
`392700489d49f13810923586a94eef6b48ec9cf6`; product sources are never edited.
[acceptance.json](acceptance.json) records seven candidate raw/canonical Git
bindings, compiled package sources, own tests, commands, exits and raw logs.

`prepare.py` validates the assigned clean baseline and exact clean candidate,
then freezes seven raw candidate files into an owned read-only Go overlay.
Two independently authored test additions challenge defaults ambiguity/bounds,
report redaction/cancellation/capability and Linux command authority. Output
parents are checked componentwise before creation; symlinks/reparse points and
nonregular/multiply linked existing inputs are refused.

Run from the assigned reviewer worktree:

```powershell
python -I -B lab/service-accounts-review/prepare.py
$env:GOENV='off'; $env:GOPROXY='off'; $env:GOSUMDB='off'; $env:GOTOOLCHAIN='local'
$env:TEMP=(Resolve-Path artifacts/service-accounts-review/build/temp).Path
$env:TMP=$env:TEMP; $env:GOARCH='amd64'; $env:CGO_ENABLED='0'
$env:GOOS='windows'
pwsh -NoProfile -File ../../scripts/go.ps1 test -mod=readonly -count=1 -timeout=60s -json -overlay artifacts/service-accounts-review/build/overlay.json -run 'TestIndependentService|TestServiceAccountDefaultsPolicy|TestHostPolicyReport|TestPublicPolicyContextBoundary' ./internal/hostaccounts ./lab/service-accounts-review
$env:GOOS='linux'
pwsh -NoProfile -File ../../scripts/go.ps1 vet -mod=readonly -overlay artifacts/service-accounts-review/build/overlay.json ./internal/hostaccounts ./lab/service-accounts-review
pwsh -NoProfile -File ../../scripts/go.ps1 test -mod=readonly -trimpath -buildvcs=false -overlay artifacts/service-accounts-review/build/overlay.json -c -o artifacts/service-accounts-review/build/independent.test ./internal/hostaccounts
```

Actual focused Windows result: **84 named passes, two packages, no failures or
skips**. The untouched baseline's independent yes-literal regression control
exited **1 as expected**; its raw stdout/stderr/status are retained separately.
Linux vet and ELF compilation exited zero. No native execution occurred here.
The compiled independent ELF must later execute exactly these three families,
with no skip, before any Linux runtime qualification:

```text
^TestIndependentService(Defaults|PolicyContract|UseraddBoundary)$
```

Source review found no blocker. Runtime must prove the installed Shadow package
suppresses mail with `--system`, retains explicit IDs/home/private group/locked
nologin, and preserves expiry suspension, activation, reopening and recovery.
The command changes password-aging semantics; ordinary interactive identities
are outside this feature. Existing records are not migrated or relabeled.
Files-only NSS remains a prerequisite; stock/cPanel/CloudLinux/full-hosting,
all-OS and reboot gates remain open. No live state, host policy/account writes,
dependencies, credentials, services, providers or VM runs are part of this lab.
Generated Go test main and the entire Go distribution remain separate native
build-provenance gates; this compile-only receipt does not close them.

Recovery is source revert before activation, preserving ambiguous native
intent rather than automatic retries, deletion or identity adoption. Retain
original receipts/logs/ELFs unchanged; any repair needs a new supplemental
receipt and output directory. Root alone integrates reviewed commits.
