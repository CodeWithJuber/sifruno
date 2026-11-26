# Sifruno Community and Pro licensing

Copyright (C) 2026 Juber Shaikh (Hostlelo)

Original Sifruno Community source is licensed under GNU Affero General Public
License version 3 only (`AGPL-3.0-only`), unless a file or component carries a
different notice. The unmodified standard license is in [LICENSE](LICENSE).
[REUSE.toml](REUSE.toml) records the copyright and license of every file, and
[LICENSES/](LICENSES/) holds each license text; `reuse lint` checks both.
The license selection applies to owner-controlled original Sifruno code;
third-party material keeps its existing copyright notices and terms.

## Community rights

Community permits copying, modification, redistribution and commercial use
under AGPLv3. It does not prohibit forks, competitors or selling a compliant
service. When a modified covered version supports remote network interaction,
section 13 requires a prominent, free offer of its Corresponding Source to
those users. Distribution of binaries has separate source obligations.
Refer to the license itself for the complete conditions.

A link to source that the network users cannot open is not a source offer
to them. Operators releasing covered builds or running modified
network versions must provide source for the version they actually use,
including applicable build material. Source packages exclude operator state,
credentials, server keys and customer files; those are not project source.

## Paid plans and a future Pro edition

Sifruno may charge for hosting, support, updates and managed services while
fulfilling the Community license. Paying for a plan does not automatically
remove AGPL obligations or grant proprietary redistribution rights.

A future commercial license for covered owner-controlled code requires an
explicit written agreement from the relevant rights holder. This policy is
not that agreement, does not grant a commercial-license exception, and does
not establish that every contribution can be commercially relicensed.
Do not include third-party AGPL/GPL code in a proprietary offer without the
rights and compliance that its own license requires.

Existing GPLv3 releases and any earlier grants are not revoked by this choice.

## Contributions and commercial rights

Outside contributions are accepted only from people who have signed the
[Contributor License Agreement](CLA.md). The CLA leaves contributors their
copyright and grants the project owner a license that includes the right to
relicense the contribution, which is what a commercial edition next to the
AGPL Community edition needs. A pull request, copyright notice or developer
certificate of origin alone must not be treated as that permission.

The [CLA workflow](.github/workflows/cla.yml) asks each new contributor on
their first pull request to sign by posting a comment, and records the
signature in the `cla-signatures` branch. The owner and bots are on its
allowlist. Maintainers still document the provenance of any third-party
material a contribution brings in. Maintain a permissively licensed
integration boundary only when the files have actually been designated and
reviewed; there is no blanket plugin or SDK license exception here.

## Third-party material

The inspected Go dependency license texts use MIT, BSD or Apache-2.0 terms.
The installed direct UI dependencies mainly use MIT/ISC, with
class-variance-authority under Apache-2.0. Component and asset notices remain
in [NOTICE](NOTICE), `web/NOTICE.md`, `web/licenses/` and
`assets/brand/licenses/` in the source tree. Runtime archives place their notice index at `NOTICE.md` and component
texts under `licenses/`; retain that complete notice inventory.

Separate terms include Inter fonts (OFL-1.1), Lightning CSS build tooling
(MPL-2.0), caniuse-lite data (CC-BY-4.0), and Sharp's libvips tooling packages
(LGPL-3.0-or-later, including a mixed Apache/LGPL Windows package declaration).
These components are not relicensed as original Sifruno code. Installed
dependencies and tooling caches are excluded from the source ZIP; the runtime
packager preserves its dependency notice inventory. This inspection is an
inventory, not a certification of complete distribution compliance or title.

## Standard-text provenance

The root license text is the AGPLv3 body from GitHub's Choose a License template
at commit `f717b235f404c60b656bfbc1643f623d02ec10a7`. Only the template's YAML
metadata was removed. The text SHA-256 is
`8486a10c4393cee1c25392769ddd3b2d6c242d6ec7928e1414efff7dfb2f07ef`.

- [GNU AGPLv3 text](https://www.gnu.org/licenses/agpl-3.0.html)
- [Commit-pinned license template](https://github.com/github/choosealicense.com/blob/f717b235f404c60b656bfbc1643f623d02ec10a7/_licenses/agpl-3.0.txt)
- [GitHub license guide](https://choosealicense.com/licenses/agpl-3.0/)
