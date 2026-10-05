# Independent native Apply completion review

Run from a canonical Sifruno checkout or the assigned
`.worktrees/web-apply-review-sol` checkout:

```powershell
powershell -NoProfile -File lab/hostweb-apply-review/run.ps1 -CheckLayout
powershell -NoProfile -File lab/hostweb-apply-review/test-layout.ps1
powershell -NoProfile -File lab/hostweb-apply-review/run.ps1
```

The layout-only command executes no Go. Six independent layout cases cover
canonical and assigned checkouts, wrong module, wrong assigned worktree, wrong
lab and an actual Windows junction refusal. The full runner accepts no arbitrary
source root or command. It uses the primary checkout's pinned Go executable,
read-only module cache, offline module configuration and an owned build cache;
it restores every changed process environment variable.

The portable catalog freezes all 31 files in both candidate packages, including
the actual root snapshot guard at its original package path. Runtime freeze3
is pinned by manifest
`20c8fe9a1275cf9fada7b79fc2352b07ade8c575da112beb6086b7e8042dbd3d`;
coordinator freeze1 is pinned by
`b658c5832e8f4f51810e21cd351657a1382f7f4eb8e1e82571367e0062e94838`.
The shared DTO donor is exactly
`f2e78b21e913b12016c2d4328413ea73fcb3d5078e5305e549e9acf5e354e1ae`.
Runtime freeze2 remains preserved separately under
`artifacts/testdata/runtime-freeze2-source`; it is not the final candidate.

Candidate and challenge Go files live under `testdata/`, so they are excluded
from normal Go package discovery. Generated overlays, outputs and evidence
also live under `artifacts/testdata/`. The local attribute rule
`testdata/** -text whitespace=cr-at-eol` preserves exact byte-hashed fixture
inputs across Windows checkouts and recognizes their preserved CRLF endings.
No global Git attributes or Git index are changed. Each full run retains exact
input, runner and catalog bytes beside a new dated report and hashes inputs
again after execution; historical receipts are never overwritten.

Six sequential phases execute both packages' full Windows test suites, the
exact 20 independent Windows challenges without skips, Windows vet, Linux vet,
and separate Linux test ELF compilation for both packages. Reports bind each
command's real exit code and output hash, plus both ELF hashes and target
headers. Two additional Linux-only capacity challenges are compiled rather
than executed by this Windows runner; they are not counted among its passes.

The actual temporary coordinator journal is reopened after injected faults.
A counter-bearing executor model distinguishes native-only commit, both
counters committed before provider quarantine, checkpoint before first denial
intent, same-original native pending denial, malformed fresh receipt and
postcallback reconfirmation. Tests require counter consumption once, `Current`
preservation at checkpoint, retained recovery pending state, current-inventory
denial after suspension/removal, fresh CAS after owned-metadata change and
semantic rejection of a rehashed journal. Healthy exact original pending
completion can authorize denial; unrelated healthy clean state cannot.

Runtime common-helper challenges reject markerless counter inference,
Rollback/common-replacement marker synthesis, malformed immutable binding,
inconsistent durable completion, altered original/CAS, unrelated pending
inheritance and independently compiled retained identity aliases. They also
check exact retained identity acceptance and defensive compiled-input copying.
The alias challenge exercises global raw-reference consistency, without
claiming it isolates only the new marker traversal. Source review separately
checks that both original generations enter the raw inventory before dedup.

The runtime's durable Apply intent precedes daemon stop/start and serving
mutation. Immutable staging and syntax checking retain their earlier order;
this review does not claim the intent precedes all immutable file writes.
Source review and compiled capacity challenges check that both replacement
and the new dead-Apply denial entry reserve future master-pin metadata before
effects, rather than counting only currently present processes.

The first dated run at
`artifacts/testdata/20261005T103601132-e54d073c/report.json`, SHA256
`b8861d9b7fd4a8428128da7ff4b3608d34f84a1df9f32c271fe319989bbc316c`,
passed legacy and nine native independent challenges but failed the coordinator
crash fixture: its database-close hook fired during pre-Apply source observation.
The intended native-commit window was not reached. That receipt and its exact
source bytes remain preserved; it is a harness failure, not a candidate defect.
The corrected hook is restricted to the expected next native revision, and
failure diagnostics contain bounded metadata instead of compiled config bytes.

The second receipt at
`artifacts/testdata/20261005T103806550-91b9d15c/report.json`, SHA256
`fbe28cb998508c82d71d7d4ff50cb68b9914ab0c7640d3c4c3af0c61ef5d8749`,
passed 19 challenges but exposed another model error: a retained pending retry
replaced the receipt's original admitted CAS with its fresh current admission
CAS. The coordinator correctly refused that malformed receipt. The model now
preserves and compares the immutable pending binding while checking fresh CAS
separately, matching the reviewed native contract. This is also a preserved
harness correction, not a candidate red/green claim.

Final closed review: `artifacts/testdata/20261005T104135849-d041320d/report.json`,
SHA256 `1ae9821f4d0afad2c832ecf5a98fc7ef055bdea25d3d482090b119e1064d401e`.
All 78 legacy top-level tests and all 20 exact independent challenges passed
without skips or failures; all six command phases exited 0. Independent
rereading verified all 55 current and retained input pins, every command output
hash and both ELF hashes with no mismatch. The 31-file candidate catalog stayed
`e6c81e0e62ac243a87c5c31a0f5d14e8e94bf729e97befc18605217a442ac660`.
The compiled runtime ELF is
`afbba3dcada3a1226524934a7fa422d91b85db6677e0593fa1c346dc0a3d660a`;
the generation ELF is
`8a88a272dad105957c8bd27006a8aea367c56b2d57519a8f26ff899470b826c1`.
Both are ELF64 Linux AMD64; neither was executed.

The final six-case layout receipt is
`artifacts/testdata/layout-20261005T104200508-2d9055af/report.json`, SHA256
`85f89513943d2b46d187316fa0d226caaf0ead2c471f48ca03e469f9d71efa37`.
Actual Git attributes report `text: unset` and `whitespace: cr-at-eol`.
All 31 repository-relative staged-like fixture diffs had no whitespace
diagnostics; an outside-fixture trailing-space control was rejected with
exit 3 (difference plus whitespace error). The whitespace receipt is
`artifacts/testdata/whitespace-20261005T104613999-ac4a563e/report.json`, SHA256
`bc36027fb07bdaca0b84e5bdbcacc8b00a97229a5241e20bd73d48363917cd23`.
Source ownership and final candidate hashes were reread before handoff. No
known source blocker remains in this reviewed slice. Candidate adoption and
the immutable lab source inventory remain distinct from activation authority.

Windows injected tests and Linux compilation provide no native Apache/PHP-FPM
execution, SIGKILL/crash-fsync, kernel PID/listener, reboot, broker/API or
hostile-root qualification. Apply completion is historical counter evidence,
not a fresh serving receipt; strict Observe remains necessary for terminal
success. Markerless original native/coordinator divergence remains refused.
Earlier native positive serving receipts remain tied to their older source
and ELF pins. This lab grants no runtime activation, stock-system, whole-panel,
cPanel or 100-account claim and performs no guest launch or live daemon action.
