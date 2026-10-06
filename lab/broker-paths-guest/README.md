# ADAPTED disposable broker-path observation

This new harness qualifies the reviewed early configured-path guard on one
signed AlmaLinux 9.8 overlay. It reuses the admitted stock-policy harness's
mechanics, not its qualification result. The donor at baseline b4225d8 has raw
script SHA256 e8ae2aa53a4568cdf0e6c8ca57085f116a2ce70abdabb36018fff3f9191b7794
and fixture SHA256 251e9f91ab0fc989f5a6757aab79ef27bebc195563d9abfd039d71382692d316.
These existing files and all prior worktrees remain unchanged.

**Every native result is ADAPTED, never stock provisioning.** The fixture first
records the original fixed policy file/link metadata and verifies stock refusal.
Only in the admitted disposable guest, it atomically replaces NSS and useradd
defaults with root-owned regular 0644 files: files-only passwd/group/shadow and
literal disabled mail spool. It never follows the old NSS leaf link when replacing
it, reads shadow/keys, creates users or sends account mutation requests. Original,
adapted and final snapshots contain only labels/type/mode/size/SHA256. The
authselect target, login defaults, passwd/group metadata and utility bytes must
remain unchanged; after adaptation, all policy/listener snapshots must be stable.

Six exact conflict fixtures run each baseline and candidate on separate short
owned guest parents: homes regular sentinel, homes symlink, homes wrong mode,
unsafe socket-parent, occupied regular socket sentinel and fresh state plus
shared-home contents. Baseline additions are explicit: state only for the first
three, state/homes for the next two, and state/socket-parent/markers/database for
shared homes. Database bytes are observed, not predicted. Existing identities,
modes, hashes and sentinel bytes remain intact. The candidate must preserve the
complete before-tree and add nothing. No cleanup deletes conflict evidence.

On separate owned `/run` paths, the candidate starts an empty-account broker.
An owned Python child drops to existing numeric UID65534, sends only local Unix
`GET /v1/accounts`, and requires an empty response. The fixture observes socket
authority, sends owned SIGTERM, checks clean exit/socket removal, then reopens
the same paths with the same ELF and repeats. Persistent database bytes may
change during legitimate reopen; private marker identity/content must remain.

The eight-entry ISO uses only the original admitted aliases: three cloud-init
metadata files, baseline as panelctl, candidate as hostbroker, this new fixture
as qualifier.py, reviewed root core.test, and independent review as authority.test.
The old account qualifier/tests/CLI aliases are never executed. Root's eight exact
families (including the setgid-parent and declared-mode regressions) and independently reviewed exact test names
must run with PASS, no SKIP, no missing or additional top-level test result.
The independent builder receipt is a separately pinned authority; this harness
does not claim to have independently recompiled that ELF.

Source review and root-supplied frozen ELF/source/manifest/test/commit hashes
are required before actual QEMU. Candidate inputs are restricted to the fixed
broker-paths-integration worktree. All fixtures, TEMP/TMP, output, ISO, overlay,
failed receipts, raw serial and exact harness/fixture copies stay owned here.
Primary tools/dependencies/modules/image remain read-only; the primary wrapper's
normal Go compilation cache is explicitly allowed. Offline Linux amd64 CGO0
baseline builds use `-mod=readonly -trimpath -buildvcs=false`, fixed Windows
OS/PATHEXT, `GOENV=off`. Go-list linked source/module/standard library inputs,
compiler/linker tool files and all five pkg/include headers are pinned before
the baseline build and guest run. Generated Go test main is labelled compiler
generated; this is not an exhaustive Go-distribution proof.

```powershell
node --check scripts/verify-broker-paths.mjs
node --test lab/broker-paths-guest/contract.test.mjs
& C:/Users/Administrator/AppData/Local/Programs/Python/Python312/python.exe -I -B lab/broker-paths-guest/fixture_test.py
node scripts/verify-broker-paths.mjs --check-only
node scripts/verify-broker-paths.mjs --build-baseline
```

These tests are synthetic, and check-only/build never claim native evidence.
The actual command uses `--run --baseline-manifest` with the exact owned build
manifest path, root's `--candidate-binary --candidate-sha --candidate-source-sha
--candidate-manifest-sha --candidate-commit --core-test-binary --core-test-sha
--review-test-sha --review-manifest-sha --review-test-names`. Candidate source
digest is the check-only cmd/internal/mod catalogue digest; candidate manifest
SHA is the distinct complete raw Go/mod manifest file hash. Review names are
exact sorted comma-separated ASCII identifiers from root's pinned authority.

ISO generation reuses exact hash-pinned alma-account-iso.py and existing approved
PyCdlib1.21.0 wheel through Python `-I -B`, owned ROOT and primary read-only WHEEL.
No original ancestor/source/destination/hash/size validator is weakened. QEMU
has no NIC, host shares, display or monitor; maximum600sec/2MiB. Each broker
child has20sec/16KiB, check-host8KiB, test children20sec/64KiB. Child sessions
are killed/reaped and pipes drained in finally; SIGTERM success is separate
from forced cleanup. Strict nonce markers and raw compact JSON reject duplicate
keys, CR/ANSI aliases, truncation, foreign hashes/fields, false cleanup, policy
changes or incomplete tests. Boot decoration stays opaque outside the frame.

Bounded public receipts exclude raw host paths, policy contents and private
boot/tool logs. No live state/services/global credentials/firewall/provider
calls, installs or dependencies are touched. This does not prove atomic path
admission, recovery mutation-freedom, stock Alma/CloudLinux/cPanel provisioning,
full account isolation, production web composition, reboot, capacity, hostile
guest isolation or all-OS qualification. Recovery is source revert before
activation; disposable overlays and failures are retained.
