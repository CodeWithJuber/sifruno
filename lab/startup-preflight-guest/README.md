# Offline startup preflight fixture

Assigned worktree `startup-preflight-guest-sol`, baseline
`67d527c76b8880f41b5481effc34003307de9df8`. Owned source is this lab and
`scripts/verify-startup-preflight.mjs`. Existing service-account fixture,
coordinator, pinned ISO helper, Python, PyCdlib wheel, QEMU and signed AlmaLinux
9.8 image are reusable read-only inputs. No dependency or live-host changes.

Scope: `read_only_stock_then_NSS_only_adapted_fresh_startup_admission`.
The seven-field schema1 report is an observation. It does not authorize startup,
recover persisted state, certify readiness, admit additional NSS providers, or
qualify stock provisioning, CloudLinux, cPanel, reboot or all operating systems.

The nonce-admitted disposable guest first pins the original regular root-owned
0644 NSS leaf: 2124 bytes, SHA256
`c1cc473688f64942669ee7eb72b262103db75498d9236356bdf25289828f5b46`.
The authselect NSS target must be absent. Original passwd/group/shadow profiles
are derived from bytes bound to that hash and expose only ordered allowlisted
provider tokens, row count, action presence and unknown-provider presence.
Unknown spelling becomes `unknown`; raw lines and private paths never enter the
typed report. Provider sequences are measured during execution, not guessed.

The candidate's original check must pass configuration, privilege, controller,
utilities and NSS-file checks, refuse NSS policy, and leave later checks
`not_checked/prerequisite_refused`. The fixture then replaces only the overlay
NSS leaf with the exact 54-byte files-only literal; useradd defaults remain
untouched. A fresh check must pass all nine checks while declared directories and
socket remain missing. Snapshots distinguish owned fixture setup from candidate
report activity. Candidate activity must preserve every conflict-tree entry and
metadata digest, policy/public account metadata, subids, mail and listeners.

Thirteen actual negative cases, in decoder order:

Owned negative directories use fixed indices `c00` through `c12`; public labels
below remain unchanged. Stock, adapted, all thirteen negatives and broker smoke
socket paths are checked against the existing absolute canonical 100-byte
contract before any broker spawn. The earlier case-label directory for the long
ancestor case measured 106 bytes and therefore deterministically violated the
configuration guard; its first failed VM evidence is preserved without claiming
the actual failed checkpoint was independently identified.

1. Absent UID60001, after proving absence: controller refusal.
2. UID0: grammar exit2, generic stderr, no JSON.
3. State file.
4. Homes file.
5. Homes symlink to an owned directory.
6. Dangling homes symlink.
7. Ancestor observed UID/GID65534 and mode0000: authority refusal. Mode0000 alone
   is not claimed to cause refusal.
8. Setgid owned root parent.
9. Socket regular file.
10. Bound owned Unix socket leaf, without listening.
11. Dangling socket symlink.
12. Nonempty state0700: final check `not_checked/persisted_state_recovery_not_checked`.
13. Unknown flag and private argument: grammar exit2, generic stderr, no JSON.

Path cases refuse the fixed paths check and skip fresh state. No public passwd
duplication is introduced; controller duplicates stay in isolated Go tests.

A separate owned serving regression starts the candidate twice, performs only
`GET /v1/accounts` as existing UID65534, observes an empty inventory, sends
SIGTERM, checks socket removal and reopens. It creates only its declared private
broker store. Its later admission check must remain unsupported with persisted
recovery not checked. No account mutation requests or account utility commands
are sent by the fixture. Actual `--check-host` retains its old envelope.

The core ELF runs exactly `TestStartupNativeFreshStateObservation` and
`TestStartupNativeGuardComposition`; the original independent ELF runs exactly
`TestIndependentStartupCancellation`, `TestIndependentStartupFreshAuthority`,
and `TestIndependentStartupProtocol`. Missing families, skips, stderr, wrong
nonce framing, schema additions, false no-writes claims, swapped policy metadata
or binary hashes, and incomplete owned-child cleanup reject the evidence.

Failure output may include a separate exact diagnostic object containing only
an allowlisted phase/case label, check index0..8 and allowlisted observed status
and reason. Missing check context uses nulls; unknown values become `unknown`.
Paths, arguments, raw errors and configuration never enter this object. Failed
nonce-framed evidence can be decoded separately for diagnosis but cannot qualify
the successful guest decoder. Successful report and guest schemas stay unchanged.

Native test children alone receive explicit `TMPDIR` below an exclusively
created `/run/sp-tests-NONCE` parent0700, with separate core/review directories
0700. Nofollow directory descriptors, same-inode checks and root-owned trusted
ancestor metadata are verified before the child starts. Preexisting paths,
links, untrusted owners, permissive modes and metadata drift are refused. This
owned fixture setup occurs after the no-writes observations and stays separate
from broker state and global `/tmp`; diagnostic and inventory environments
retain only the fixed PATH/LANG/LC_ALL variables.

Synthetic checks, with TEMP/TMP set to this worktree's ignored cache:

```powershell
& 'C:/Users/Administrator/AppData/Local/Programs/Python/Python312/python.exe' -I -B lab/startup-preflight-guest/fixture_test.py -v
node --test lab/startup-preflight-guest/contract.test.mjs
node scripts/verify-startup-preflight.mjs --check-only
```

No guest launches on import, tests, or check-only. `--build-baseline` builds only
the unchanged baseline under isolated owned TEMP/output, after tool/source pins.
`--run` remains gated by explicit root approval after independent source/harness
review and supplied frozen product, two test ELFs, source manifest, and original
independent receipt. The coordinator checks current input authority; it never
silently regenerates independent authority. Frozen candidate inputs live in
`startup-preflight-integration/.cache/startup-preflight/` as `hostbroker-linux`,
`core.test`, `independent.test`, `independent-authority.json`, and
`go-source-inputs.json`. The copied independent receipt is unchanged and binds
the original `artifacts/startup-preflight-review/build/independent.test` ELF.

The ISO retains eight fixed roles: three cloud-init metadata files plus baseline
broker at `payload/panelctl`, candidate broker, qualifier, core test ELF and
independent test ELF. A separate read-only PyCdlib inspection checks actual ISO
names, mode100444, link count1, payload sizes and hashes before QEMU. The baseline
broker is built, staged and hash-bound; this scope does not claim its execution.
Tool/header pins precede baseline build. Candidate and linked Go/module inputs,
full source freeze, original authority, harness, payload plan and binary hashes
are joined and rechecked after the run. Compiler-generated test main and the
entire Go distribution are not separately certified.

QEMU uses no NIC or shares, TCG, one CPU, 1536MiB, a disposable overlay, at most
600 seconds and 2MiB combined output. Diagnostic children use 10 seconds/8KiB;
native tests 20 seconds/64KiB; each broker lifetime 60 seconds/16KiB; inventory
requests 10 seconds/16KiB with five-second socket operations. Owned children are
killed and reaped on failure. Raw serial remains in the owned ignored cache;
published JSON contains only typed evidence. No host state, credentials,
firewall, service restart, publication or deployment is touched.

Recovery is removal of this unadopted harness commit or a later revert. Disposable
overlay, private serial and receipts remain in owned ignored directories for
review; no running host process cleanup is attempted. Native qualification stays
pending until an actual approved run and independent receipt audit pass.
