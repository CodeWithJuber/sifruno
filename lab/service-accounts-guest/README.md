# NSS-only adapted service-account guest fixture

Assigned worktree: `service-accounts-guest-sol`; baseline
`392700489d49f13810923586a94eef6b48ec9cf6`. Own only this lab and
`scripts/verify-service-accounts.mjs`. No dependency additions.

The source reuses copied bounded child, source/tool catalog, ISO admission and
nonce framing machinery from the reviewed broker-paths harness already present
at the baseline. No previous harness source or receipts are edited.
Donor checkout raw SHA256: script
`35a96401e608d342021bc338a7b7e780e8dbbcb89dc82cf6aa25cc055b5e35fe`,
fixture `0bd9857152671b194264f154b89f9383c518711ae34153a3a003020a65df5d21`.
These are actual CRLF checkout bytes, separate from prior worker LF raw pins.
The primary ISO helper is imported read-only after its exact SHA check with owned ROOT and
the existing pinned PyCdlib wheel; PyCdlib is not Python stdlib. Static payload
aliases remain unchanged: metadata three plus `panelctl`, `hostbroker`,
`qualifier.py`, `core.test`, `authority.test`.

Scope is `NSS_ADAPTED_stock_mail_service_account_lifecycle`. Only the disposable
overlay NSS leaf is replaced with literal files-only policy. Useradd defaults
are never changed, even by synthetic tests. Before checks establish baseline
NSS/mail refusal and candidate NSS refusal/mail admission. After NSS adaptation
the baseline still refuses with no declared startup additions. The candidate
creates exactly one fresh owned service account through its actual Unix API as
the existing unique nonroot UID 65534. Owned bases under `/run` are traversable;
unrelated ancestors and controller identities are untouched.

The six lifecycle observations are create, duplicate 409, suspend revision 2,
stale 409, activate revision 3, and same-source reopen. Native passwd/group
metadata, passwd status and chage observations establish locked nologin,
private group, no supplementary memberships, disabled password aging, managed
0750 directories and active/suspended account expiry. Shadow/key bytes are
never read. No create retry, adoption or account deletion follows uncertainty.
Stock useradd defaults and utility/NSS policy metadata remain invariant except
the declared NSS replacement and the exact owned passwd/group rows. Unrelated
public identity rows, observed MAIL_DIR plus standard mail directories, no owned
spool, and subordinate-ID files are checked before/after. Mail entries are
metadata only; names are hashed and message bytes are never read.

Synthetic checks (no native qualification):

```powershell
node --test lab/service-accounts-guest/contract.test.mjs
& 'C:/Users/Administrator/AppData/Local/Programs/Python/Python312/python.exe' -I -B lab/service-accounts-guest/fixture_test.py
node scripts/verify-service-accounts.mjs --check-only
```

Do not run `--build-baseline` or `--run` until root supplies readiness and the
independent source gate. Actual run requires exact candidate/source/manifest
and both ELF hashes, sorted core/review family names, preserved original
builder receipt, and an owned baseline manifest. Expected original review ELF
receipt path is `artifacts/service-accounts-review/build/independent.test`;
the copied ELF lives in the candidate's `.cache/service-accounts`. Root will
provide final pins; no provisional ELF or old test families qualify this batch.

QEMU has no NIC or host shares, with 600 seconds/2 MiB combined output. Each
broker lifetime is bounded at 60 seconds, utility/test children 20 seconds,
peer request child 8 seconds with 5-second socket operations. Requests and
broker output are capped at 16 KiB; test output at 64 KiB. Processes are owned
and killed/reaped on failures. Inputs, fixed assembly headers and linked Go
sources are pinned before build/run and rechecked; this is not exhaustive Go
distribution verification. All outputs, overlays, raw serial and exact source
copies remain in assigned ignored recovery directories. Published receipts
exclude host paths, raw utility/HTTP responses and boot logs. No stock NSS,
CloudLinux, cPanel, full host, reboot or hostile-guest acceptance is claimed.

Initial synthetic Python checks failed twice in the NSS-only TempDir test:
Windows lacks `geteuid`/`fchmod`, then Windows CRT text writes added CR bytes.
The test now mocks Linux ownership/mode and binary descriptor semantics; native
guards and producer bytes remain unchanged. Those failures have tool-stream
authority with a labelled reconstructed summary in owned ignored preparation
cache, not an invented raw capture. Native observation remains pending.

Independent pre-execution review corrected two fixture assumptions from commit
`6cf8868`: the actual files-only NSS literal is 54 bytes (bound using its measured
length), and [Shadow 4.9 new_spent](https://raw.githubusercontent.com/shadow-maint/shadow/4.9/src/useradd.c)
sets the current last-password-change day before disabling system-account
aging limits. The fixture now records the measured C-locale day, requires it
inside the observed create/reopen UTC day bounds and unchanged across phases,
while retaining never-expiring/inactive password and maximum-aging -1 checks.
Only an actual epoch-zero clock may report a last-change value of never.
No product change or chage mutation was made to satisfy the fixture.
