# Frozen hostweb lifecycle review

This independent review reads the canonical fixture and compiler; it does not
modify either file or the native run web-qualify-1791173960020-f35752b1.
The root native qualification result was pending during this review.

Source pins:

- canonical lab/web_runtime_fixture.py: A7EE5CA7771E4D4FCD36283B2315EB1AB959264A9EA79086EDAFAAD5E224E333
- canonical internal/hostweb/compiler.go: 8EE9EABD9C39E8B53B19D62E0F8B794AF72F02BEA89D5E932496E1A5A83EE17B
- canonical lab/hostweb-review/test_web_runtime_fixture.py: 8F3B293F33F4A61CF6A1AB20D80AD260215E09810A2491ECED9231A10EFD6A2C

## Findings requiring repair before lifecycle proof

1. **Cleanup accepts leader exit without group extinction.** At fixture lines
   823–834, stop_process returns immediately if poll reports an exited leader.
   For a live leader it sends group TERM and waits only for that leader; leader
   exit also skips KILL and any descendant/group extinction check. Two review
   tests use an actual isolated Windows Python parent and child. The child
   reports its real PPID and maintains a heartbeat after parent exit. Calling
   the frozen function in the exited-leader case makes zero signal calls, and
   the child remains alive. In the live-leader case Windows killpg delivery is
   substituted to terminate the parent while leaving the real child alive;
   the function makes one call and accepts cleanup. This is control-flow proof,
   not execution of Linux process-group signaling. Both children exit through
   owned stop files and their exit receipts are verified before cleanup.

   Minimal repair: register an admitted PGID and leader start identity at spawn,
   retain it after leader exit, signal the still-owned group, and require
   extinction after a bounded TERM grace period or bounded KILL escalation.
   Do not treat wait-on-leader success as group cleanup. Include process
   identity/reuse guards and reject unexpected group/session escape; record
   cleanup observations in the native result. A real Linux regression must
   exercise a worker ignoring TERM and a leader exiting before cleanup.

2. **Capability proof is narrower than a zero-capability claim.** At lines
   733–773 only CapEff is parsed and checked. Linux-format inputs with nonzero
   CapPrm, CapAmb or CapInh and zero CapEff are admitted by worker_matches.
   A nonzero permitted set can permit raising effective capabilities later.
   This review proves admission of these inputs, not that native workers
   actually retained them.

   Minimal repair: parse and validate CapPrm, CapAmb and CapInh alongside CapEff,
   require all four zero for tenant/front workers, and include them in native
   observations. CapBnd can be reported separately; a nonzero bounding set by
   itself does not mean a process currently possesses capabilities.

## Additional coverage limitation

children at lines 716–730 reads only /proc/PID/task/PID/children. It ignores
children created by secondary tasks. A synthetic proc tree in the review tests
contains child 88 for the leader task and child 99 for a secondary task; only
88 is enumerated. The configured Apache/FPM behavior may create workers from
their leader task, but this is not established by this Windows test.
For comprehensive process-tree proof, enumerate every admitted task's children
with bounded reads/PID counts, fail closed on incomplete sampling, and correlate
PID start identity/PPID/PGID/session across status/root reads. Current poll plus
descendant enumeration has no PID-reuse coherence check.

## Correct behavior observed in source and tests

- Admission compares all four real/effective/saved/filesystem UID and GID
  slots, rejects controller/front/foreign supplementary groups for tenant
  workers, requires CapEff zero, and compares the actual proc root path with
  the account-specific jail. Front workers must instead be UID/GID 48 with
  root / and may not hold tenant/controller UID slots.
- assert_worker and front admission retry for at most ten seconds while
  checking the global deadline and master liveness. Empty or unreadable
  samples cannot pass; every enumerated descendant must have a valid identity.
  These are sampled identity checks, not continuous enforcement.
- FPM is ondemand. The fixture requests PHP before requiring an observed FPM
  worker, avoiding admission based on a pool master alone.

## Compiler/runtime prerequisites inspected

The compiler emits per-account Apache ChrootDir, numeric User/Group, distinct
loopback backend TLS listeners, root-configured certificate paths and a private
FPM socket. The shared front uses UID/GID 48, proxy CA verification and peer
name/expiry checks. FPM emits numeric account identity, the same per-account
jail, clear_env, restricted PHP extensions, bounded children/request lifetime
and a tenant session directory.

The fixture prepares immutable root-owned jail roots, jail-local files-only NSS
with no host users/secrets, mime.types, account-owned temporary/runtime
directories and disjoint home/runtime bind mounts before syntax checks and
process startup. Generated config bytes remain unchanged. The selected staged
Apache modules, FPM build, TLS behavior, NSS lookup timing, bind mount access,
SELinux contexts, true process IDs and chroot behavior need the native guest
run; Python tests or compiler output do not qualify these prerequisites.

## Verification and recovery

Run from the assigned UI worktree:

    python -B lab/hostweb-lifecycle-review/test_lifecycle_review.py

The tests are independent characterization tests. Passing tests for findings
mean the pinned implementation admits the documented false positives. They
are not acceptance tests for a repaired Linux lifecycle. Source pin equality is
checked separately before handoff. All runtime subprocesses use temporary
state, no provider/main state and no native services. The review imports source
with bytecode writing disabled.

Recovery is deletion of this new review directory. No production code,
generated configs, frozen inputs, live processes or native-run state changed.

## Unintegrated repair candidate

repair_candidate.py provides replacement capability parser/admission functions,
OwnedProcess metadata, linux_start_identity, owned_launch and stop_process.
It is a candidate for root's sequential integration, not imported by the
canonical fixture. Translate LifecycleError to the existing FixtureError when
integrating. Add the dataclass import, replace only the parser/matcher/cleanup
functions and insert the owned-launch metadata helpers.

Change eight long-lived daemon Popen callsites to owned_launch: broker, panel,
per-account FPM and backend, initial front, both backend replacement launches,
and the suspended-layout front restart. Their explicit new-session flags remain.
The short-command run_cmd handler is separate and is not changed by this
candidate. Existing readiness/process-context methods work through OwnedProcess
attribute delegation. Update process list annotations if desired. Existing
identity test inputs must supply all four capability fields; missing fields now
fail closed. HTTP metadata, TLS leaf construction, diagnostics and readiness
after replacement are root-owned and must remain intact.

The candidate requires observed PGID/SID equal to the spawned leader PID,
refuses fixture group/PID<=1 and pins Linux starttime. Cleanup polls/reaps leader,
signals its admitted group even after leader exit, escalates TERM8s to KILL3s
and refuses success while the group remains. Cleanup grace periods are
independent of an expired overall fixture deadline. A group permission error,
changed leader identity, stubborn group or unadmitted Popen cannot pass.
Admission failure kills/reaps the exact Popen leader and rejects the disposable
guest; it never signals an unproven group.

Candidate tests use actual Windows parent/child processes with their actual
PPID and heartbeats. Linux PGID/session/starttime/signal delivery are explicitly
simulated. They cover launch contract, exited leader, TERM-surviving child,
KILL escalation, extinction, stubborn group, identity reuse, forbidden group,
permission error, expired fixture deadline and strict capability parsing.
No Linux process-group, capability, NSS, chroot or Apache/FPM proof follows.

The candidate retains the secondary-thread traversal gap identified above.
Process groups do not contain a descendant that deliberately creates a new
session; that remains a separate admission/containment limit. PID/group reuse
between Linux identity checks and signal delivery is not completely eliminated
by this helper; it must not be described as pidfd-strength containment.

At root's request, canonical source remained untouched while root finished the
native run and edited TLS/HTTP behavior. The latest source read was
E8B1F00EC9199014CFFE3DCF3DF531FB53012742C61B1A10EF88D0363E09BB9B.
frozen_fixture_excerpt.py retains only the verbatim original lifecycle functions
from that pin, so characterization tests remain reproducible after root repairs
the canonical source. It is test evidence and must never replace the fixture.

Final independent command:

    python -B -m unittest discover -s lab/hostweb-lifecycle-review -p 'test*.py' -v

All 16 tests passed before freeze (five characterization, eleven candidate).
The first candidate run exposed Windows' absent SIGKILL constant; only the
simulation test now supplies Linux signal number9. The candidate still uses
the real Linux signal constant. No native success claim is made.

## Integrated canonical verification

Root integrated the lifecycle functions and eight long-lived daemon callsites.
verify_integrated.py reads canonical source without writing it, compares all six
helper/class ASTs against the frozen candidate with only the exception-name
translation, and verifies every launch target plus the retained run_cmd Popen.
It extracts verbatim canonical helpers to integrated_helpers.py and registers
that module in sys.modules before dataclass execution. Tests run against that
module's actual function globals, with only a test exception-name alias.

The canonical pin was B2487A4D9B455C2BB9380DA1E53078210720703AD61F1F2832213C6F2FC77DEF,
stable before and after the run. All eleven repair tests passed against the
extracted canonical implementation. The first integrated run had a test setup
race reading a heartbeat during write_text truncation. The owned test helper
now stages and atomically replaces heartbeat files and registers cleanup before
later setup assertions. Neither candidate nor canonical helpers changed.

Portable command after copying this review directory:

    python -B lab/hostweb-lifecycle-review/verify_integrated.py --fixture lab/web_runtime_fixture.py

The runner also locates the primary Git checkout when no fixture argument is
supplied. integrated-report.json pins canonical, candidate, extracted module
and test/runner inputs; integrated-tests.log retains results. The generated
helper module is test evidence only. Real Windows parent/child plus simulated
Linux group operations remain the test boundary; root's native guest proof is
separate and was in flight during this read-only verification.

## Canonical portable source integration

Root authorized this new review directory as a disjoint source destination.
Only the six reproducible source/note files were copied after verifying each
frozen worktree hash. Historical reports/logs and generated helper modules were
not copied. The tiny frozen lifecycle excerpt is required for original-gap
characterization tests; it is not a duplicate runtime fixture.

The canonical runner sends generated module/report/log outputs to ignored
artifacts/integrated under this directory by default. An explicit --output-dir
can redirect local artifacts. Its source changed only for artifact placement.
Neither canonical runtime fixture, compiler, coordinator, Git configuration nor
other documentation was edited by this review integration.

Run from the repository root:

    python -B lab/hostweb-lifecycle-review/verify_integrated.py --fixture lab/web_runtime_fixture.py
    python -B -m unittest discover -s lab/hostweb-lifecycle-review -p 'test*.py' -v

The first command verifies current canonical helper ASTs, launch callsites and
imports, then runs eleven tests against extracted canonical functions. The
second separately runs sixteen frozen-gap/candidate characterization checks.
Passing these Windows tests does not qualify Linux execution or the sibling
path HTTP denial. Root owns the native sibling_path_not_denied investigation.
