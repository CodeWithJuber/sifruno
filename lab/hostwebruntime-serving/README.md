# Disposable native executor serving qualification

This Linux-only driver exercises the frozen `internal/hostwebruntime` executor,
with the compiler and generation types, in one long-lived process. It has no
broker/API/product wiring and creates no accounts, mounts, certificates, policy,
service units or package installation. The existing Python fixture's earlier
serving result does not certify this Go executor. Compilation and parser tests
are separate from a future real guest execution.

Run only in the separately prepared, root-approved disposable Alma guest:

```text
/opt/sifruno-runtime-fixture/qualification-driver --input /opt/sifruno-runtime-fixture/qualification-input.json
```

There are no other arguments. The private root is root:root 0700, the driver a
root:root single-link regular 0700 file, and input a single-link regular 0600
file. The exclusive report is `qualification-report.json` under the same root,
0600, at most 64 KiB. An existing report rejects execution before activation.
Symlinks/hardlinks, unsafe parents and outside writes are refused. Windows and
macOS fail without touching that path. Input admission is bounded to 32 KiB;
duplicate, unknown, missing and incorrectly cased JSON fields are rejected.

The exact top-level fields are `schema_version: 1`, `fixture_only: true`,
`run_id` (32 lower-case hexadecimal characters chosen by the guest wrapper),
`root: "/opt/sifruno-runtime-fixture"`, `profile`, and `accounts`. The profile
requires all 17 exact UpperCamelCase fields from `hostweb.Profile`, with these
values:

| Field | Value |
|---|---|
| Name | restricted-chroot-v1 |
| ManagedRoot | /opt/sifruno-runtime-fixture/managed |
| ManagedHomeRoot | /opt/sifruno-runtime-fixture/homes |
| FrontChroot | /opt/sifruno-runtime-fixture/front-jail |
| BackendChrootRoot | /opt/sifruno-runtime-fixture/backend-jails |
| RuntimeRoot | /opt/sifruno-runtime-fixture/runtime |
| TLSRoot | /opt/sifruno-runtime-fixture/tls |
| CAFile | /opt/sifruno-runtime-fixture/tls/ca.pem |
| ApacheModuleRoot | /usr/lib64/httpd/modules |
| ApacheBinary | /usr/sbin/httpd |
| FPMBinary | /usr/sbin/php-fpm |
| FrontendIP | 127.0.0.1 |
| FrontendPort | 18082 |
| BackendPort | 18443 |
| FrontUID / FrontGID | 48 / 48 |
| ControllerUID | 2000 |

The two accounts use the exact lower-case `hostaccounts.Account` JSON fields:
`id`, `username`, `domain`, `home`, `public_html`, `state`, `uid`, `gid`,
`revision`, `created_at`, `updated_at`. They are sorted by ascending unique
32-character lower-case hexadecimal ID. The first is webalpha/alpha.test with
UID/GID 20001; the second webbravo/bravo.test with UID/GID 20002. Both start
active, with positive non-overflowing revisions and valid timestamps. Their
homes are `<Root>/homes/<username>` and public_html is that home's
`public_html`. These are fixture data, not proof of broker account provisioning.

Preparation must satisfy the executor's real admission rules in its README:
root-owned read-only stock ELF/module/CA inputs; private managed root; root-owned
front/backend jail roots; tenant-owned home/public_html/tmp/runtime directories;
exact same-inode bind mappings of home/public_html/runtime at their absolute
paths inside each backend jail; exact root-owned files-only jail passwd/group
and mime/NSS files; correct TLS leaf IP SAN/CA/key modes; Apache/FPM required
libraries. The driver does not prepare or weaken these. Reuse the Python lab's
bounded provisioning helpers only through a new approved fixture with this
common root; its old disjoint path profile is incompatible.

Each `index.html` contains exactly `SIFRUNO_STATIC_<username>` plus a newline.
Each `probe.php` uses PHP core builtins and returns exactly five lines plus a
trailing newline:

```text
SIFRUNO_PHP_webalpha
SELF=readable
HOST=denied
SIBLING=denied
PID=<getmypid()>
```

Use `is_readable(__FILE__)` for SELF, and actual readability attempts against a
root-only controller private sentinel and the sibling's private sentinel for
HOST/SIBLING. Use double-quoted PHP newline escapes; literal backslash-n fails
the contract. The preparation fixture must create those sentinel files and
verify their intended permissions. PHP `getmyuid()` describes script ownership
and is not process evidence. No posix extension is required. After PHP 200 and
the exact body, the driver independently maps the returned namespace PID to the
actual FPM child, checks its namespace, four UID/GID fields, supplementary
groups, zero effective/permitted/inheritable/ambient capabilities and backend
root via `/proc`, and records those observed values. Journal PIDs are candidates
only. Runtime Observe checks the complete configuration/process/listener state
before and after these requests; an idle ondemand pool alone does not pass.

The fixed sequence is exact denied Bootstrap and Observe; active Apply revision
0 and Observe; both static 200 and PHP 200 plus workers; another Observe;
new suspended account snapshot (revision +1) and denied Apply revision 1;
Observe; known and foreign Hosts 403; final Observe; Shutdown, listener
extinction and Close. HTTP proxy and redirects are disabled and reads bounded.
No success is recorded if a stage is skipped or cleanup/stability fails.
The report binds wrapper run_id, random driver nonce, input/profile/snapshot/
bundle hashes, actual observed identities, executable SHA and frozen runtime
manifest SHA. The runtime is linked into the driver; there is no second runtime
binary. Reports contain hashes and bounded field observations, not response
bodies, keys, raw daemon output or arbitrary exception strings.

SELinux must remain Enforcing before/after. Effective/permitted/bounding
CAP_NET_ADMIN and CAP_NET_RAW must already be absent; no capability or policy
changes are made. Other needed capabilities, PID namespaces, openat2, pidfds,
ptrace exec registration and kernel policy are prerequisites, not inferred from
compilation. The outer guest wrapper must independently admit base image,
installed signed packages, zero external NICs and exact ELF/source pins; this
driver alone cannot attest those. Missing prerequisites remain a failed result.

SIGINT/SIGTERM cancel the serving sequence and use fresh bounded cleanup.
Individual executor operations have their existing cooperative deadlines;
filesystem/start/reap calls are not a hard wall-clock guarantee. Retained
creator-thread Pdeathsig means controller/thread death kills daemon namespace
init; this is not a service/reboot survival test. No reload, production rollback,
TLS fault injection, all-OS/vendor compatibility or hostile-root isolation
qualification is claimed here. Failed guest evidence must be preserved.

Offline verification from the assigned worktree uses the primary Go binary
`<primary>/.tools/go/bin/go.exe`, primary read-only GOMODCACHE, private
`.cache/go-serving` GOCACHE, GOPROXY=off/GOSUMDB=off. The recorded build uses a
read-only canonical production-source overlay for hostaccounts/hostweb/
hostwebgeneration/securestate and an exact copy of canonical go.mod/go.sum in
the private cache. Raw CRLF/LF provenance is retained even where normalized
source is identical. Apply these flags to every command below:
`-overlay=.cache/hostwebruntime-serving/canonical-overlay.json`
`-modfile=.cache/hostwebruntime-serving/canonical.go.mod`.

```text
go test -mod=readonly -buildvcs=false ./lab/hostwebruntime-serving
go vet -mod=readonly ./lab/hostwebruntime-serving
GOOS=linux GOARCH=amd64 go build -mod=readonly -buildvcs=false -o .cache/hostwebruntime-serving/qualification-driver ./lab/hostwebruntime-serving
GOOS=linux GOARCH=amd64 go test -mod=readonly -buildvcs=false -c -o .cache/hostwebruntime-serving/serving-linux.test ./lab/hostwebruntime-serving
```

These commands do not execute Apache/FPM. Actual guest qualification is a
separate root-owned gate after independent source review.

The handoff cache contains `manifest.json`, `canonical-overlay.json`,
`canonical-pins.json`, `dependencies.json`, the driver ELF and Linux test ELF.
The manifest records each lab/runtime source SHA, canonical donor source SHA,
selected Linux non-standard dependency source SHA, exact module inputs and Go
binary SHA, output hashes and check results. Donor/runtime pins are rechecked
after builds. The runtime freeze2 source remains byte-for-byte unchanged.
