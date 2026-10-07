# WIP archive: native runtime input guest

Publication refresh, 2026-10-07: PR44 was merged externally into main. Its
archival status, missing parser and approval boundary are unchanged. This merge
does not authorize running or completing the draft. See [current project state](../../docs/PROJECT-STATE.md).

**NON-RUNNABLE. Not suitable for installation, qualification, or execution.**

This directory preserves unfinished work at the user's explicit closeout request.
It contains three existing draft files, unchanged, plus this archival README.
It is not a completed harness or an installation method. Do not execute the
runner, its check mode, imports, fixture, or ISO builder from this archive.

## Missing work and approval boundary

- `report.mjs` is absent. The runner imports it, so even default/check/import
  behavior is not operational. Parser creation was rejected twice by the path
  protection hook, including after the proposed scope was reduced. That approval
  boundary remains unresolved. No replacement or equivalent decoder is supplied.
- Synthetic parser tests and an independent final harness review are missing.
  ISO creation/readback, guest execution, and native input qualification have not
  been performed for this draft. No positive native result exists.
- The fixture still contains an incidental operating-system configuration read
  that was identified for removal from the narrowed scope. It is intentionally
  preserved here, not approved for execution. Earlier system-policy observation
  code was removed; no verified stock-policy preservation claim is made.
- Runner authority-pin and generated test-main cache checks received bounded
  static review and syntax checks only. Their complete build/input-closure flow
  has not run. Historical cached image and package receipts are prerequisites,
  not evidence that this new harness works.
- The proposed CA input is explicitly fixture bytes, not a valid certificate.
  Proposed installed-binary/module observations do not establish TLS validity,
  daemon syntax, runtime health, serving, lifecycle, vendor, or all-OS support.
- Execution requires a separately approved, independently reviewed completion of
  the missing work, exact input/tool/backing-chain admission, and root-controlled
  launch. This archival change authorizes none of those actions.

No Go build, QEMU invocation, guest launch, dependency installation, or live
service change was performed as part of this closeout. The original draft source
base was `f77ed89`; carrying these files onto a newer main branch does not qualify
that combination.

## Preserved source identities

Raw hashes identify the unchanged Windows working-file bytes. Git blob IDs
identify their canonical committed contents; line-ending normalization can make
raw and canonical hashes differ.

| File | Raw SHA-256 | Canonical Git blob |
| --- | --- | --- |
| `run.mjs` | `123b602f066a33cec53756458f1d94b7952478c8be67ad495a1d199177ac3671` | `19ccb05c57dc317b975853f4b4237382c0863d82` |
| `fixture.py` | `81c1ce6f4878b9f52eecebed0c39a35de219c7dfad472b59a22aa69e558e07e8` | `595a80e61092f8eef61f9041411ae7a40c5a36f4` |
| `make_iso.py` | `69abb7c743aa656486ae00945fafa632b58065f4142998539fe0e39235b6f56f` | `de7777c75da70cffc6657b71951b5f9f860ceb9d` |

Earlier runner before/after/content-address snapshots, their bounded diff, and
local receipts remain in the original author's ignored artifact area. They are
not shipped in this source archive; private artifacts and logs are excluded.
The merged archive remains explicitly unfinished and unsuitable for
installation. Recovery is to revert the archive-only changes; there is no native
state, migration, or service operation to undo.
