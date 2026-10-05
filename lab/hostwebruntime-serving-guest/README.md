# Prepared Alma9 serving guest fixture

`serving_guest.py` is a fixed disposable-guest setup and qualification fixture
for the frozen Go executor driver. Import is safe; Windows contract tests never
launch utilities, create accounts, change policy or mount anything. Root owns
the separately reviewed host runner and actual guest execution. This fixture
contains no QEMU, downloads, package installation, host services, firewall,
SELinux disabling, product broker/API wiring or vendor compatibility proof.

The only invocation is root, Linux x86_64 Alma9:

```text
env -i PATH=/usr/sbin:/usr/bin:/sbin:/bin LANG=C LC_ALL=C HOME=/root /usr/bin/python3 -I /opt/sifruno-runtime-fixture/serving_guest.py
```

All payload/app paths are under root:root 0700
`/opt/sifruno-runtime-fixture`. No arguments are accepted. Nonexecutables are
single-link root:root regular 0600 files; driver/test ELFs are 0700. The fixed
root-only 0600 admission path is `/run/sifruno-runtime-serving-admission`.
Required exact JSON keys:

| Key | Required value |
|---|---|
| schema_version | integer 1 |
| kind | trusted-disposable-alma9-runtime-serving |
| nonce | 24 lower-case hexadecimal characters |
| zero_external_nics | boolean true |
| prepared_image_sha256 | host-admitted prepared-image SHA256 |
| fixture_sha256 | exact serving_guest.py SHA256 |
| helper_sha256 | 73ef86f95b34d255b4ab5c6145caae718ad1578efba7f1c0d24f5712c57fc9ed |
| source_catalog_sha256 | 74e6aab996033480ffbfb63b86a4a2c6b937d78e08ac6ff262909727ddbb8e35 |
| package_report_sha256 | exact generated prepared-packages.json SHA256 |
| driver_sha256 | 21b9b146674aa6e286cad0e8f180e263cb014bfa2d87efeb994ecc0cca7163f1 |
| test_sha256 | 431e2717f0919591c864b23792381fd9d4f81ca92ca72e76bb78a953a497865d |

The host payload inventory is exactly `serving_guest.py`, the pinned canonical
`web_runtime_fixture.py`, `source_catalog.json` (raw frozen serving manifest),
`prepared-packages.json`, `qualification-driver`, `serving-linux.test`, and 18
RPMs in `packages/<basename>.rpm`. The host validates the catalog's referenced
source/dependency/tool inputs before admission. The guest verifies catalog
bytes; it does not independently measure a disk-image SHA or reconstruct linked
sources from an ELF. Those are explicitly admitted outer provenance.

`prepared-packages.json` has exactly `schema_version: 1`,
`kind: "alma9-prepared-web-packages"` and `packages`. Its exact 18 entries have
`name`, `nevra`, `filename`, `sha256`, `bytes`. Names must match `PACKAGE_NAMES`
in the fixture (the previously selected official Apache/PHP package set), be
unique, and use x86_64/noarch NEVRAs. Filenames are bounded basenames, not paths.
Each RPM is at most 64 MiB, total at most 256 MiB. The guest checks actual bytes,
`rpm -Kv` cryptographic signature with the Alma9 key ID and public-key
fingerprint BF18AC2876178908D6E71267D36CB86CB86B3716, RPM header exact NEVRA,
installed exact NAME.ARCH query and `rpm -V --noscripts` over all 18 packages.
It does not install anything or run verification scripts. Hashes of the actual
Apache/FPM ELFs and eleven selected modules are measured and rechecked.

The pinned canonical helper is dynamically imported only after admission and
byte validation. Directly reused functions are clean_env, run_cmd, write_exact,
write_runtime_report, ensure_dir, mount_bind, unmount, prepare_guest_policies,
and make_certificates, including their fixed transitive file/certificate helpers.
The old daemon/panel/broker lifecycle is not copied or invoked. Short utility
commands have the helper's subprocess/output/deadline bounds; the test/driver
receive separate owned supervision described below.

Host files-only passwd/group/shadow NSS and CREATE_MAIL_SPOOL=no adaptations
use the existing guarded helper in this expressly admitted disposable guest.
Original and effective hashes plus stock_alma_nss_qualified=false and
stock_useradd_policy_qualified=false are recorded. This is an adapted guest
qualification, not stock host identity-policy certification. No SELinux policy
is disabled or changed. SELinux Enforcing=1 and only interface `lo` are checked
before and after. Missing prerequisites fail.

Only webalpha UID/GID20001 and webbravo UID/GID20002 fixture accounts are
created, with locked passwords, nologin, no mail spools and no supplemental
groups. No controller/panel/account-broker user is created. Homes/public_html
and runtime directories are tenant-owned 0750, tmp 0700. The host fixture root
stays root-only 0700. Inside each root-owned 0755 backend jail, the synthetic
absolute path ancestor chain is explicitly root-owned 0755, independent of
umask077. Own home and runtime mappings use bind mounts and must match actual
device/inode/ownership; public_html's inherited home bind is checked too.
Exact root-only jail passwd/group 0400, files NSS 0444 and mime.types 0444 match
the frozen executor. No host /etc is mounted. Shared libraries/modules load
through the stock daemons before their chroot discipline; this fixture does not
install a general tenant operating system inside the jail.

The actual host controller private sentinel (root:root0600) and both sibling
private sentinels (respective tenant0600) are created and their existence,
ownership, mode, expected hash and root read verified. PHP uses is_readable
against those actual paths, __FILE__, and core getmypid(), with exact
double-quoted newline output. UID/GID/groups/cap/root are independently observed
by the frozen Go driver, not PHP script ownership APIs. Public CA/leaf hashes
are recorded and stable; private key bytes/contents never enter reports.

The Linux unit ELF runs before activation:

```text
/usr/bin/setpriv --bounding-set=-net_admin,-net_raw,-net_bind_service,-net_broadcast -- /opt/sifruno-runtime-fixture/serving-linux.test -test.v -test.count=1 -test.timeout=60s
```

All nine Linux top-level PASS names in TEST_NAMES plus final PASS and exit0 are
required. Actual stdout appears between nonce-bound TEST_BEGIN/TEST_END markers.
Tests are mechanics/contract evidence; the fixture's synthetic Python cases do
not qualify native serving. The subsequent fixed driver command uses the same
bounding set and `--input <Root>/qualification-input.json`. SYS_ADMIN and
trace prerequisites are retained; no process is claimed qualified if policy
rejects them. Clean child HOME/work and TMPDIR/test-tmp are inside Root.

The test/driver use exact pidfds after spawn. All post-Popen acquisition and
selector setup are covered by cleanup. If per-child pidfd admission fails,
the single-threaded parent still owns the unreaped Popen child and kills/reaps
that child through Popen, with default SIGCHLD and no competing waiter enforced
before spawn. No process-group signals or arbitrary PID inputs are used in
this supervisor. Timeout/output failure sends exact TERM then KILL/reap. The
driver owns daemon PID namespaces; its unchanged registration/Pdeathsig and
shutdown semantics remain the runtime package's scope. Parent independently
checks fixed listener extinction and disappearance of the two actually observed
FPM worker namespaces, not every possible unobserved namespace. Reboot/service
survival, reload, resource accounting and hostile-root isolation are unqualified.

Each owned bind target records its exact mount ID, including bind-success/
make-private-failure paths. Cleanup refuses changed/foreign IDs, attempts other
owned mounts, uses the canonical lazy detach, and checks mountinfo removal.
This proves detachment from this mount namespace, not absence of all possible
external mount references. The guest has no customers or other tenants. Driver
shutdown and observed namespace extinction precede unmount; failed runs preserve
evidence and cannot become passed during cleanup. Source/input/RPM/system/TLS
public bytes and effective guest policy hashes are rechecked before success.
Setup is bounded by 330 seconds with a separate 45-second cleanup budget;
individual kernel/I/O calls are not a hard wall-clock bound. The host owns the
final VM timeout and poweroff on every path.

The exclusive root0600 `guest-report.json` and nonce-bound compact serial JSON
have exact top-level keys: schema_version, kind, nonce, driver_run_id,
fixture_only, passed, failure_code, checks, cleanup, provenance, environment,
policy_adaptations, packages, system_inputs, tls_public_inputs, accounts,
sentinels, binds, tests, driver. Kind is alma9-runtime-serving-qualification.
driver_run_id is SHA256("sifruno-serving:" + nonce)[:32]. `checks` must equal
CHECKS in order on success. Cleanup has exactly driver_reaped,
listeners_extinct, observed_worker_namespaces_extinct, mounts_removed, all true.
Tests receipt contains exit_code, reaped, timed_out, output_bound_exceeded,
stdout_sha256, stderr_sha256, passed_names and contract_passed. Driver receipt
contains the first six fields plus report_sha256 and passed. Both require
exit0, reaped=true, timeout/output-bound=false. Actual driver JSON is separately
emitted and bound by its byte hash, executable/input/run nonce and exact
profile/snapshot digests. Its nine ordered observations, seven exact probe
identities/statuses/body hashes, two actual worker records and prerequisite
facts are independently validated. Bound native failure JSON is retained before
success validation; no raw utility errors, response bodies, tokens or keys are
serialized.

Serial markers, each with one space then the 24hex nonce:

```text
SIFRUNO_RUNTIME_SERVING_TEST_BEGIN <nonce>
<actual native unit stdout>
SIFRUNO_RUNTIME_SERVING_TEST_END <nonce>
SIFRUNO_RUNTIME_SERVING_DRIVER_BEGIN <nonce>
<single-line actual driver JSON>
SIFRUNO_RUNTIME_SERVING_DRIVER_END <nonce>
SIFRUNO_RUNTIME_SERVING_BEGIN <nonce>
<single-line compact guest report JSON>
SIFRUNO_RUNTIME_SERVING_END <nonce>
```

The outer shell alone emits `SIFRUNO_RUNTIME_SERVING_EXIT <nonce> <actualcode>`
and powers off. The host must reject missing/duplicate/spoofed receipts and
cross-check raw native tests and driver JSON rather than accepting only the
fixture's summary. Early invalid admission has no bound success receipt.

Import-safe Windows verification:

```text
python -B -m unittest discover -s lab/hostwebruntime-serving-guest -p test_serving_guest.py -v
```

The private cache `.cache/hostwebruntime-serving-guest` records source hashes,
checks, and a pure Go overlay digest characterization. That characterization
confirms Python's exact Go struct JSON field order and 1ns suspended timestamp
against frozen generation helpers without modifying any driver/runtime file.
Passing these local checks is not an actual guest or serving verdict.
