# Contributing to Sifruno

Thank you for helping. Sifruno is in Phase 1: it hosts WordPress and PHP sites
on a fresh AlmaLinux 9 server, and parts of it still need an outside review.
Small, well-tested changes are the easiest to merge.

- Found a bug? Open an issue with the bug report form.
- Want a feature or a larger change? Open an issue first, so we can agree on
  the approach before you spend time on it.
- Found a security problem? Do not open an issue. Follow [SECURITY.md](SECURITY.md).

Everyone taking part follows the [Code of Conduct](CODE_OF_CONDUCT.md).

## How the project works

[AGENTS.md](AGENTS.md) has the working rules for people and AI agents. The
ones that matter most for a pull request:

- One thin slice per pull request: a single flow someone can see working.
- Every root action is one of the broker's fixed, typed operations, with
  validated arguments and a direct exec of an absolute path. Nothing else
  reaches the host.
- The root broker, sign-in, permissions, credentials and migration cutover are
  read line by line by a person before merge. Keep a change to any of them in
  its own commit and write "needs human review" in the commit message and the
  pull request.
- `internal/whmapi` is frozen (bug and security fixes only), and
  `internal/mailhost`, `dnshost`, `tlshost` and `backuphost` take bug fixes
  only.
- New UI uses the one design system: shadcn/ui on Base UI with Tailwind 4,
  themed from `assets/design-tokens.json` ([DESIGN.md](DESIGN.md)).
- A new dependency needs the maintainer's approval. Say why in the pull
  request.
- Use made-up data in code, tests and docs: `example.com` names and the
  `192.0.2.0/24`, `198.51.100.0/24` and `203.0.113.0/24` documentation
  addresses. Never commit a real server address, customer data, a key or a
  token.

## Set up

You need Linux, Git, Go 1.27.1, Node.js 24.19.0 and Python 3. The CI
workflow pins the same versions.

```bash
git clone https://github.com/CodeWithJuber/sifruno.git
cd sifruno
npm ci --ignore-scripts --no-audit --no-fund
npm --prefix web ci --ignore-scripts --no-audit --no-fund
```

To run the panel on your machine, follow "Run from source on your own
machine" in [docs/installation.md](docs/installation.md). To run the hosting
proofs on a real AlmaLinux 9 guest, see [scripts/devvm](scripts/devvm/README.md).

## Run the checks

[.github/workflows/source-checks.yml](.github/workflows/source-checks.yml) is
the list of checks every pull request must pass. To run them locally:

```bash
# Go. One hostaccounts fixture fails under umask 077.
umask 022
go vet ./...
go test ./... -count=1

# UI and Node tests
npm run panel:typecheck
npm run panel:build
node --test web/src/lib/*.test.mjs scripts/*.test.mjs lab/*/*.test.mjs
npm run brand:check

# Python fixture tests: see the python job in source-checks.yml, for example
python3 -m unittest discover -s lab -p test_capture.py

# Workflows and licensing
npm run check:workflows
reuse lint
```

`reuse` is the [REUSE tool](https://reuse.software/) (`pipx install reuse`).
If you change a workflow, `npm run check:workflows` checks the rules for a
public repository; [AGENTS.md](AGENTS.md) lists them.

## Commits and pull requests

- Keep each commit to one change, with a short subject in the imperative
  ("Fix login redirect loop") and a body that says why.
- Add a line under "Unreleased" in [CHANGELOG.md](CHANGELOG.md) for a change
  users or operators will notice.
- Fill in the pull request template: what changed, how you tested it, and
  what you did not test.
- Say what ran where. A test that passes on your machine is not the same as a
  proof on the AlmaLinux 9 dev VM, and either is fine to report as long as it
  is clear which one you ran.

## Licence and the Contributor License Agreement

Sifruno is licensed under the [GNU AGPL version 3 only](LICENSE). Before your
first pull request can be merged, you sign the
[Contributor License Agreement](CLA.md) once: the CLA check comments on your
pull request, and you reply with

> I have read the CLA Document and I hereby sign the CLA

You keep the copyright in your work. The CLA lets the maintainer also offer
Sifruno under commercial terms; [LICENSING.md](LICENSING.md) explains why.

Every file needs copyright and licence information for `reuse lint`.
[REUSE.toml](REUSE.toml) covers new files as AGPL-3.0-only by default. If you
add a file from another project, keep its notice, add an annotation for it to
`REUSE.toml`, add its licence text with `reuse download <SPDX-ID>`, and say
where it came from in the pull request.
