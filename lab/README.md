# Disposable characterization lab

See the [complete documentation index](../docs/README.md) and
[current project state](../docs/PROJECT-STATE.md) before selecting a harness.
These tools and dated receipts have distinct prerequisites and qualification
limits. Their presence in main is not evidence of execution on current main.
The runtime-input guest archive is non-runnable WIP.

This is Phase 0 evidence tooling. It does not install a panel, validate a license,
reverse engineer an unavailable native artifact, or certify compatibility. The
Windows workspace has no supplied licensed reference Linux host. Original
vendor installer/license/runtime tests and the complete obligation inventory
remain release blockers.

The evidence library and offline comparisons are portable on Linux, Windows
and macOS without CGO. Original cPanel ecosystem execution is a Linux host
contract: Windows/macOS control planes can target a disposable Linux machine
or explicitly provisioned Linux guest. A portable client build does not prove
native cPanel/vendor compatibility on Windows or macOS. `capture.py` therefore
requires local execution inside the authorized Linux environment.

The agreed installation contract is a fresh AlmaLinux 9 or CloudLinux 9 x86_64
server, with original ecosystem programs and user configurations unchanged.
Freeze the exact reference build, OS release, enabled features and relevant
artifact hashes before implementing its behavior. A documentation version does
not identify an installed build.

## Local capture on a supplied lab host

Only run on a disposable host you are authorized to inspect, with a valid
reference license independently checked through the vendor's supported process.
The script records operator attestations; it cannot verify those declarations.
No password, token, license key or SSH credential is accepted. Copy it using your
normal authenticated transport; no transport credentials belong in this repo.

Create a new export directory owned by root with mode 0700, then run locally:

```sh
python3 capture.py \
  --role reference --id reference-exact-build \
  --feature whm-api1 \
  --out /root/sifruno-evidence/reference.json \
  --disposable-confirm I_HAVE_AUTHORIZED_THIS_DISPOSABLE_HOST \
  --licensed-reference-confirm I_VERIFIED_A_VALID_REFERENCE_LICENSE
```

`--feature` is repeatable and declares the enabled feature inventory reviewed
by the operator. This small bootstrap capture is not a complete inventory.
Run the same script on the disposable replacement with `--role candidate`, its
own ID/output, the identical enabled-feature labels and disposable confirmation.
The candidate still needs the original `/usr/local/cpanel` command structure.
Missing executables fail the capture; no substitute success is produced.

The fixed allowlist runs `/usr/local/cpanel/cpanel -V`,
`/usr/local/cpanel/bin/whmapi1 --output=jsonpretty version`, and the undefined
`sifruno_invalid_function` error probe. It accepts no custom command, shell,
account name, URL or credentials. Each execution has a 20-second deadline and
256 KiB per-stream limit. It retains real exit codes and exact stdout/stderr,
including errors; an API's JSON failure is distinct from its CLI exit code.
Capture hashes the executed artifacts before and after and aborts if they differ.
It strips inherited secrets and loader overrides from the process environment.
Only a new mode-0600 export is written. The referenced installation may log
ordinary invocations; the tool does not edit its configuration or account data.

The original CLI format and product-version concepts come from the official
[WHM API 1 introduction](https://api.docs.cpanel.net/whm/introduction) and
[version documentation](https://docs.cpanel.net/knowledge-base/cpanel-product/product-versions-and-the-release-process/).
The allowlist's operation behavior must be characterized on the actual frozen
build; these links do not count as execution evidence.

## Evidence schema and comparison

`internal/evidence` exports `Load`, `Save`, `Seal`, `Verify`, `Compare`, and
`CanonicalJSON`. Schema 1 bundles contain:

- `kind`: `synthetic` or `observed`, retained in all comparisons.
- `role`: `reference` or `candidate`; comparison requires that order.
- `provenance`: exact product/build/OS/architecture, UTC capture time, sorted
  feature labels, named absolute artifact paths and SHA-256 digests, and explicit
  disposable/license attestations.
- `cases`: unique operation/obligation IDs, CLI argv or HTTP method/path, exact
  exit code or HTTP status, output format, stdout/body and stderr.
- `sha256`: content digest over canonical schema contents excluding this field.

Load rejects unknown fields, duplicate keys, malformed provenance, missing
digests, tampering and excessive bounds. JSON responses compare sorted object
keys and exact normalized decimal values, keeping array order and all fields.
Text/newlines, stderr, CLI exit codes, HTTP status, operation definitions, missing
cases, OS/architecture and feature differences remain significant. There is no
implicit timestamp removal or suppression of error/default differences.

Envelope digest canonicalization is Sifruno v1, **not RFC 8785**: UTF-8 JSON,
sorted keys, Go-compatible string escaping and normalized exact scientific
notation for numbers. `capture.py` generates compatible digests without Go on
the lab host. `lab/fixtures` contains synthetic interoperability fixtures only.
Neither SHA-256 nor matching observed inputs authenticates a host, proves a
license, or establishes full product parity. Reports always say
`certifies_compatibility: false`; no result changes the release gate.

Captured responses can contain private runtime information. Keep exports in
private lab storage, review/redact them before sharing, and avoid Git. Redaction
is a new derived artifact with a new digest and must preserve its provenance;
do not silently modify an existing observation. The provided allowlist avoids
account listings and credentials. Arbitrary HTTP capture and account mutations
are intentionally not part of this bootstrap collector.

## Verification

```powershell
./scripts/go.ps1 test ./internal/evidence
python -m unittest discover -s lab -p 'test_*.py'
```

The Python tests and Go synthetic fixtures verify collector boundaries,
canonicalization, integrity and comparison semantics. They do not execute a
licensed cPanel build or satisfy any cPanel/vendor parity obligation.
