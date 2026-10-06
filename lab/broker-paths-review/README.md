# Independent broker startup-path review

This lab reviews core commit `4af0b7190ba5b73271c57a824d8d713190587553`
against baseline `b4225d8877d798cdf93b49d3584cc0d8d4cc8375`.
The exact core patch is admitted only in the assigned review worktree.
No production function is replaced. The overlay adds one Linux test file;
the portable lab test calls the actual exported unavailable client.

Run `python lab/broker-paths-review/prepare.py` from the assigned
`broker-paths-review-sol` worktree. It checks the exact three-file core diff,
unchanged native/store/client/CLI/module guards, admission ordering, one-entry
directory read and descriptor identity check, then creates owned ignored
`artifacts/broker-paths-review/build/overlay.json` and source pins.
The helper refuses linked/reparse output components and admits an existing
overlay only when its content agrees after CRLF normalization. These are
cooperative checks in an exclusive checkout, not protection from a concurrent
privileged actor swapping paths.

Use the primary workspace `scripts/go.ps1` with this worktree as cwd,
`GOPROXY=off`, `GOSUMDB=off`, `GOENV=off`, `GOTOOLCHAIN=local`, and owned
`TEMP`/`TMP` at `artifacts/broker-paths-review/build/temp`.
The normal primary compilation cache is reused; module/tool inputs stay read-only.
Exact commands, raw output hashes and the ELF pin are in [acceptance.json](acceptance.json).

The private challenge binary is compiled with `GOOS=linux`, `GOARCH=amd64`,
`CGO_ENABLED=0`, `-mod=readonly`, `-trimpath` and `-buildvcs=false`.
The native guest must execute only this exact filter and report all three
families passing without skip:

```text
^TestIndependentBroker(DirectoryIdentity|FreshVersusNonemptyState|OptionBoundary)$
```

The directory test uses isolated temporary paths and checks final-link refusal,
non-directory refusal, changed descriptor identity and dangling child entries.
The fresh-state test owns a new subtree under an admitted `/root`, proves that
missing/empty state refuses unrelated homes without creating earlier paths,
and checks that nonempty state retains the later recovery boundary. It does not
claim that invalid persisted contents are valid. The options test checks root
socket parent, cross-path overlap, canonical spelling, NUL, controller zero,
nil context and pre-cancellation before host policy/identity inspection.

`acceptance.json` records source review, actual Windows portable execution and
Linux vet/compilation. Linux runtime remains pending there; a later actual
guest receipt has separate authority. No host policy, service, account, socket
or live state was changed by the reviewer. No cPanel, CloudLinux, all-OS,
full database-state admission or atomic privileged path-stability claim follows.
Recovery is to revert the source patch before activation; no cleanup of
preexisting conflicts is introduced.

## Supplemental setgid admission

[setgid-review.json](setgid-review.json) separately admits fix
`73ce4c5b9f9a83bcdb754c4469364461aa284faf`. The original acceptance receipt
and `build/independent.test` remain unchanged historical evidence. New source
pins, commands, overlay and ELF use `artifacts/broker-paths-review/build-setgid`.
No portable suite was repeated for this Linux-only correction.

The supplemental overlay adds both `private_linux_test.go.txt` and
`private_setgid_linux_test.go.txt` as new package test files, without replacing
any production source. Compile and vet commands in the supplemental receipt
use the same offline primary wrapper and owned TEMP/TMP. The later native
guest must execute the supplemental ELF with this exact filter, requiring
four families and every subtest to PASS without skip:

```text
^TestIndependentBroker(DirectoryIdentity|FreshVersusNonemptyState|OptionBoundary|SetgidParent)$
```

The additional challenge checks missing state/homes/socket destinations under
a setgid direct parent without any additions or parent metadata changes. It
also verifies an existing exact-mode child remains admitted, and calls the
post-create guard to measure actual kernel inheritance. The latter deliberately
creates one owned child before refusing its inherited mode; this is distinct
from the mutation-free pre-admission refusal. Parent identity and mode stay
unchanged; creating the child naturally changes parent directory timestamps.
Linux [mkdir documentation](https://man7.org/linux/man-pages/man2/mkdir.2.html)
describes inherited setgid. Documentation and compilation do not qualify the
actual guest runtime, which remains pending in this supplemental receipt.

## Actual adapted native receipt

[native-audit.json](native-audit.json) records the separate actual run
`adapted-paths-20261006T075519308Z-2a8a54ec`. Original portable/compile receipts
remain historical; they are not rewritten as executed. The audited guest
passes eight core and four independent Linux families without skip, including
the setgid inheritance challenge on the exact supplemental ELF.

The read-only `audit-native.mjs` takes worker root, actual report path, expected
report SHA and a fresh owned output path. It checks all 1,945 current catalog
inputs, all eight payload sources, 252 root Go/module inputs, the 1,457-entry
baseline catalog, declared tools and five pre-pinned assembler headers, exact
original review authority, nonce-framed private serial/report equality and
owned cleanup. It never prints or republishes raw serial bytes.
`audit-iso.py`, invoked with pinned primary Python `-I -B`, independently reads
all eight actual ISO members using the admitted existing PyCdlib wheel, checks
manifest/source bytes and CIDATA metadata/nonce/no-network configuration, and
writes only a fresh owned output. No dependency was installed.

Exact commands, exits, raw output/status hashes, source helper hashes and
redacted results are pinned in the native receipt. Additional read-only parsing
joins the actual 809 named portable passes in 27 packages, vet, build, seven
Node contracts and six Python fixtures; those counts have separate authority
from the 12 Linux test families and 53 independent synthetic parser cases.

Original stock NSS/mail policy remains refused. Only two explicit policy files
in the disposable guest overlay were adapted, after which 12 policy and 14
listener observations stayed stable. Six candidate conflict trees add nothing;
six baseline comparisons retain their partial directory additions. Empty
native inventory is read by an owned child using existing UID65534, followed
by owned SIGTERM/socket cleanup and same-source reopen. No account was created
or mutated. Compiler-generated test main is labelled and the complete Go
distribution is not certified. These are narrow adapted-image observations,
not stock provisioning, production activation or original vendor parity.
