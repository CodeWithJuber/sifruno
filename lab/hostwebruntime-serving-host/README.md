# Disposable native-runtime serving host gate

This is a fixed Windows host harness for the paired
[`serving_guest.py`](../hostwebruntime-serving-guest/serving_guest.py) candidate.
It prepares a new offline AlmaLinux 9.8 x86_64 QEMU overlay and CIDATA ISO.
Preparation, parser tests and ISO tests are separate evidence from a successful
Linux serving run. This source does not activate production services, installer
hooks, account restrictions, vendor compatibility or public/private web routes.

The guest uses the frozen native executor driver to exercise two disposable
accounts, actual Apache/PHP requests, suspended-host denial, observed worker
credentials/chroots and cleanup. It explicitly adapts guest NSS to `files` and
useradd to avoid mail spools. Stock Alma NSS/useradd policy is not qualified.
SELinux must remain enforcing; external NICs, downloads and package installation
are excluded. The guest checks all 18 supplied RPM archive hashes, Alma signing
key/signatures, header/installed NEVRAs and `rpm -V --noscripts`, then measures
and rechecks 13 serving executable/module inputs and three public TLS inputs.
Those checks do not establish all-OS support, cPanel parity, original vendor
reference parity, production systemd activation or a general hosting release.

## Reproducible admission

Use Node from the repository's reviewed `scripts/bootstrap-tools.ps1` setup and
the existing admitted Python 3.12/pycdlib wheel/QEMU cache. This runner downloads
nothing and installs nothing. `pins.json` describes one dated, reviewed input
set. Source ZIPs exclude cache/artifact ELFs, RPMs, images and reports; the ZIP
alone cannot run this gate. A new checkout needs a separately prepared and
reviewed input cache/catalog and refreshed exact pins at the same bounded paths.
Rebuilding an ELF changes its provenance even if source content appears equal.
The fixed source and dependency catalogs must be verified with the executable.

Only two owner layouts are admitted: the primary repository with this lab at
`lab/hostwebruntime-serving-host`, or its exact assigned worktree
`.worktrees/release-plan-sol` with the same lab path. Both `go.mod` identities
must be `sifruno`; redirected/reparse paths, hard-linked inputs, arbitrary source
roots and alternate script/command/ELF arguments are refused. The explicit
primary root is a read-only source for pinned tools, package bytes, catalogs and
images. All new media, overlays, serial and reports belong to the owner's
`.cache/hostwebruntime-serving-host/serving-<time>-<nonce>` directory.

The prepared 18-package image is SHA `f362d8658bb7981b151b63110c41ffa71b09ec742a777bb3ca731e2d96b65c86`.
Its pinned installation reports bind it to the signed original image
`6bdab6376d46d42e4203ace3733efafc7c5d37c7cb443a6cc74750097002d74b`
and Alma signing fingerprint `BF18AC2876178908D6E71267D36CB86CB86B3716`.
Read-only `qemu-img info` also verifies its exact backing image and clean qcow2
state. The primary images are never modified or deleted. A fresh overlay is
created over the prepared image for every invocation.

Serving manifest `74e6aab996033480ffbfb63b86a4a2c6b937d78e08ac6ff262909727ddbb8e35`
binds driver `21b9b146674aa6e286cad0e8f180e263cb014bfa2d87efeb994ecc0cca7163f1`
and test ELF `431e2717f0919591c864b23792381fd9d4f81ca92ca72e76bb78a953a497865d`
to seven driver sources, ten executor sources, 17 canonical donor files, five
build records, 90 selected dependency files and the Go tool. Historical absolute
provenance paths are mapped to validated relative canonical/executor/module-cache
paths; they do not grant arbitrary execution or arbitrary source read authority.
Guest manifest `54236c90fd96d04eb093429490cf6317a08f7c3fa3098abdfc1c3bf736e2ae97`
binds fixture `99705157a37d290f6c5a3ed87c8f042ed45169b1c98c57f0017c99cc627acd9e`
and its paired tests/README. The canonical helper pin is
`73ef86f95b34d255b4ab5c6145caae718ad1578efba7f1c0d24f5712c57fc9ed`.

## Commands and review gate

From the admitted owner repository, explicitly point to the primary repository:

```powershell
$primary = (Resolve-Path <primary-repository>).Path
node --test lab/hostwebruntime-serving-host/test_inputs.mjs lab/hostwebruntime-serving-host/test_parser.mjs lab/hostwebruntime-serving-host/test_contract.mjs
$python = Join-Path $env:LOCALAPPDATA 'Programs/Python/Python312/python.exe'
& $python -I -B lab/hostwebruntime-serving-host/test_iso.py
node lab/hostwebruntime-serving-host/run.mjs --primary-root $primary --check-only
node lab/hostwebruntime-serving-host/run.mjs --primary-root $primary --prepare-only
```

`--check-only` hashes/admit inputs without creating a VM. `--prepare-only`
creates an ISO and owned overlay, hashes all 28 payload records and performs
actual completed-ISO readback. Neither boots QEMU; the preparation report keeps
`passed` and `native_serving_qualified` false. Node parser fixtures are synthetic
and are labeled as parser tests. The paired contract test imports only the
hash-admitted guest's pure validators on Windows, accepts the real generated
host admission, rejects the former mismatched kind, and checks input/profile/
snapshot digests. It uses `Path.as_posix` to characterize the Linux root string;
it does not execute guest setup on Windows.

After root/independent review of the frozen host and guest source plus prepared
media, the root owner may run the fixed gate:

```powershell
node lab/hostwebruntime-serving-host/run.mjs --primary-root $primary --run
```

That command creates another fresh owned overlay/ISO. It uses the admitted QEMU
with TCG, one CPU, 1536 MiB, no external NIC, no host shares, no display/monitor,
no inherited user configuration and a bounded child environment. The process
window is hidden. The 600-second host limit and 2 MiB serial limit kill only the
tracked launched child. Serial write errors/short writes close admission and
trigger owned-child cleanup; close/reap precedes receipt acceptance. The fixed
guest script powers off on every normal/error path; the host retains failed
artifacts. No shared image or unrelated process is deleted/killed.

## ISO and receipt contract

The fixed 28 files are three NoCloud files, seven admission/fixture/helper/
driver/test/catalog/package-report files, and 18 RPMs under `packages/`.
Completed ISO readback requires CIDATA, exact Rock Ridge names/inventory,
directory type/mode `040555`, every file regular type/mode `0100444`, one link,
exact bytes/SHA and fixed NoCloud header/instance/network metadata. The earlier
mechanics failure used nonregular `0444` files and executed no Go tests. This
harness inherits the corrected readback gate; an ISO being written alone is
insufficient evidence of bootability.

The root-private admission lives at `/run/sifruno-runtime-serving-admission`.
Its exact fields are `schema_version`, `kind`, `nonce`,
`prepared_image_sha256`, `fixture_sha256`, `helper_sha256`,
`source_catalog_sha256`, `package_report_sha256`, `driver_sha256`,
`test_sha256`, `zero_external_nics`. Kind is
`trusted-disposable-alma9-runtime-serving`; nonce is 24 lowercase hex characters.
All payload/writable fixture paths are fixed beneath
`/opt/sifruno-runtime-fixture`. No caller command/path is admitted by the guest.

The native test arguments are `-test.v -test.count=1 -test.timeout=60s`, then
the driver runs `--input /opt/sifruno-runtime-fixture/qualification-input.json`.
Nine mandatory top-level test RUN/PASS records and no skips/failures are required.
Raw native stdout is framed with `SIFRUNO_RUNTIME_SERVING_TEST_BEGIN/END <nonce>`.
The actual compact driver JSON file is framed with
`SIFRUNO_RUNTIME_SERVING_DRIVER_BEGIN/END <nonce>`; its SHA excludes the wrapper's
added newline. Guest JSON is a single line framed with
`SIFRUNO_RUNTIME_SERVING_BEGIN/END <nonce>`, followed by exactly one
`SIFRUNO_RUNTIME_SERVING_EXIT <nonce> 0`.

The host independently recomputes raw receipt hashes; rejects duplicate JSON
keys, duplicate/foreign markers and unknown top-level/nested fields; validates
all 11 check IDs, source admission, two identities, private sentinel receipts,
four exact binds, package inventory, environment/policy facts and all cleanup
booleans. Driver checks include three deterministic identities, nine ordered
observations, seven exact probes, actual static/PHP body hashes and two distinct
worker namespaces with all four UID/GID values, supplementary groups, zero
effective/permitted/inheritable/ambient capabilities and per-account chroots.
Driver prerequisites require enforcing SELinux and absent network admin/raw
capabilities. A successful host result requires QEMU exit 0, bounded clean
capture, valid guest/driver receipts and all input/payload/ISO pins unchanged.
Only that future result can qualify this narrow disposable serving gate.

Recovery is disposal of the owned failed overlay after evidence review, followed
by a new frozen source review and a fresh overlay. Keep failure reports distinct
from subsequent successful evidence; never reuse a modified guest as its base.
