# Disposable stock-policy observation

This harness compares an unchanged baseline Linux hostbroker with the reviewed
candidate on one signed AlmaLinux 9.8 cloud-image overlay. It never runs the old
account qualifier, creates users, rewrites NSS/useradd policy, reads shadow/keys,
attaches a NIC or exposes host shares. Installed policy remains unsupported.

Before QEMU, source review and the root-supplied candidate freeze are required.
All fixtures, output, overlay and cloud-init ISO remain in this assigned worktree.
The primary Go wrapper's normal compilation cache is explicitly permitted by
root; primary module/dependency/tool/image inputs remain read-only. Build flags
are offline `-mod=readonly -trimpath -buildvcs=false`, Linux amd64 and CGO off;
TEMP/TMP and the baseline ELF/manifest are owned. Transitive linked Go sources,
standard library, modules, Go compiler/linker tools and source files are catalogued.
The candidate's separately supplied complete tracked Go/mod file manifest is
checked against every declared file; it is not confused with the smaller
cmd/internal source catalogue digest emitted by check-only mode.

From the assigned worktree, using existing primary Node/Python binaries:

```powershell
node --check scripts/verify-stock-policy.mjs
node --test lab/stock-policy-guest/contract.test.mjs
& C:/Users/Administrator/AppData/Local/Programs/Python/Python312/python.exe -I -B lab/stock-policy-guest/fixture_test.py
node scripts/verify-stock-policy.mjs --check-only
node scripts/verify-stock-policy.mjs --build-baseline
```

The checks/tests are synthetic; neither compilation nor check-only is native
policy evidence. The actual-run command must use the exact baseline manifest
returned by build, the frozen root candidate ELF/hash and the check-only emitted
`candidate_source_catalog_sha256`. Only the fixed integration worktree is
admitted as candidate; no arbitrary source roots are accepted:

```powershell
node scripts/verify-stock-policy.mjs --run --baseline-manifest OWNED_MANIFEST_ABSOLUTE_PATH --candidate-binary C:/Users/Administrator/Documents/Codex/2026-10-04/hi/.worktrees/stock-preflight-integration/.cache/stock-preflight/hostbroker-linux --candidate-sha b529cad85afd3106a3bb7fb85663d3b4806fe3050da93e9d80ec09d0dacd0e46 --candidate-source-sha CHECK_ONLY_CANDIDATE_SOURCE_DIGEST
```

ISO generation imports the exact SHA-pinned existing `alma-account-iso.py`
with Python `-I -B`, binds its ROOT to this worktree and its WHEEL to the primary
approved PyCdlib 1.21.0 wheel. PyCdlib is an existing dependency, not stdlib.
The original plan/source/destination/ancestor/hash/size validators remain intact.
Payload `panelctl` is only a staging alias for the baseline hostbroker; `hostbroker`
is the candidate, and `qualifier.py` is this new fixture. These aliases never run
old CLI/test/fixture code. Cloud-init only stages the script and payload, suppresses
default cloud-user creation and SSH key generation/import, then runs the fixture.
Policy invariance begins after that explicitly labelled preparation boundary.

The fixture verifies exactly one existing numeric UID 65534 from local passwd
metadata, runs bounded candidate `--check-host`, and observes baseline refusal
with empty declared directories versus candidate refusal without those directories,
store or socket. Separate parents are created only for fixture authority. Child
sessions are owned, drained with byte/time bounds and killed/reaped in `finally`.
No utility process is invoked. Policy snapshots contain only fixed labels,
file/link type, mode, byte count and SHA256; symlink hashes cover link bytes and
the known authselect policy target has its own metadata entry. Listener snapshots
contain only count/hash and must remain equal after each command.

QEMU has 600 seconds and 2 MiB combined stdout/stderr; broker children have
20 seconds and 16 KiB, and check-host has 8 KiB. Strict nonce markers, compact
ASCII JSON, exact field sets, child exit/cleanup, policy/listener invariance and
source/image/binary/tool rechecks determine PASS. Boot ANSI decoration outside
the report is permitted; report and marker bytes stay strict. All failures and
private serial/source bytes remain in owned ignored cache; bounded receipts are
under `artifacts/stock-policy`, with no raw host paths or private boot logs.

This proves one stock-policy refusal/admission ordering observation, not account
provisioning, broader NSS/mail support, CloudLinux/cPanel parity, production
controller/path/service readiness, reboot durability, hostile guest isolation or
atomic host-policy stability. Recovery is source revert; disposable overlays and
failed evidence are retained, and no running live service is touched.
