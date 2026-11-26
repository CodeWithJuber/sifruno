# Sifruno

[![License: AGPL-3.0-only](https://img.shields.io/badge/license-AGPL--3.0--only-blue.svg)](LICENSE)
[![Source checks](https://github.com/CodeWithJuber/sifruno/actions/workflows/source-checks.yml/badge.svg?branch=main)](https://github.com/CodeWithJuber/sifruno/actions/workflows/source-checks.yml)
[![OpenSSF Scorecard](https://api.scorecard.dev/projects/github.com/CodeWithJuber/sifruno/badge)](https://scorecard.dev/viewer/?uri=github.com/CodeWithJuber/sifruno)

Sifruno is an open source hosting control panel for Linux servers, written in Go with a React web panel. The goal: a new user gets a WordPress site live in two minutes, a developer deploys an app in any language with `git push`, and an AI agent can do the same through the API. The first customer is HostLelo itself.

**Status: Phase 1, not yet for paying customers.** Sifruno installs with one command on a new AlmaLinux 9 server and hosts WordPress and PHP sites on OpenLiteSpeed. It has the New website wizard with SSL, a page per website with tabs, databases with one-click phpMyAdmin, a file manager, cron jobs, logs and usage, per-account limits, off-server backups with a restore drill, customer logins, a WHMCS module, and moving a website from a cPanel server. The scripts that prove each one on an AlmaLinux 9 server are in `scripts/devvm/proofs/`, and saved runs are in [docs/proofs/](docs/proofs/README.md). Before a paying customer: a person reviews the root broker, sign-in and permissions code (commits marked "needs human review"), and migration is proven on HostLelo's own cPanel servers. There is no published release yet.

![The panel's Home page in the new shell, running in the dev VM](docs/proofs/phase1-panel-shell/1440-light-home.jpg)

## How it works

The panel (`sifruno`) runs as an unprivileged user. Every change to the host goes through the root broker (`hostbroker`), which accepts only a fixed list of typed operations over a local socket: create an account, give a site its web server configuration, install WordPress, back up and restore, and so on. Websites run on OpenLiteSpeed with LSPHP, each under its own Linux user with an XFS disk quota; databases are MariaDB; backups use restic.

## Install

To install on a server, follow [docs/installation.md](docs/installation.md): build the release, copy it to a new AlmaLinux 9 server whose `/home` is its own XFS filesystem with quota, and run the installer. To run the panel on your own machine for development, build from source on Linux with Go 1.27.1 and Node.js 24.19.0:

```bash
git clone https://github.com/CodeWithJuber/sifruno.git
cd sifruno
npm ci --ignore-scripts --no-audit --no-fund
npm --prefix web ci --ignore-scripts --no-audit --no-fund
npm run panel:build
go build -buildvcs=false -o bin/sifruno ./cmd/sifruno
go build -buildvcs=false -o bin/panelctl ./cmd/panelctl
./bin/sifruno --listen 127.0.0.1:8080 --sites-listen 127.0.0.1:8082 --state "$HOME/.sifruno-state" --ui web/dist
```

Then open `http://127.0.0.1:8080`. The [installation guide](docs/installation.md) covers sign-in, the CLI, Windows and troubleshooting. To run the hosting proofs on a real AlmaLinux 9 guest, see the [dev VM guide](scripts/devvm/README.md).

## Where things are

| Path | What it holds |
| --- | --- |
| [AGENTS.md](AGENTS.md) | Working rules for people and AI agents |
| `cmd/`, `internal/` | Go server, CLI, root broker and hosting packages |
| `web/` | Panel UI (React, TypeScript, Tailwind, shadcn/ui) |
| `integrations/whmcs/` | The WHMCS provisioning module |
| `scripts/install/`, `scripts/devvm/` | The installer and release build, and the dev VM with its proofs |
| [docs/](docs/README.md) | Installation guide, brand guidelines and saved proof runs |
| `lab/` | Older characterization harnesses and their review receipts |

## Contributing

Contributions are welcome. Read [CONTRIBUTING.md](CONTRIBUTING.md) for setup, the checks to run and the commit style. Contributors sign the [Contributor License Agreement](CLA.md) once, on their first pull request. Everyone follows the [Code of Conduct](CODE_OF_CONDUCT.md).

## Security

Sifruno runs as root on the servers it manages. Report vulnerabilities privately through GitHub, as [SECURITY.md](SECURITY.md) describes, never in a public issue.

## Licence

Copyright (C) 2026 Juber Shaikh (Hostlelo).

Sifruno Community is free software under the [GNU Affero General Public License version 3 only](LICENSE) (AGPL-3.0-only), with no per-account fee. If you run a modified version for users over a network, the licence requires you to offer them its source. Third-party code, fonts and icons keep their own licences: see [NOTICE](NOTICE) and [REUSE.toml](REUSE.toml). [LICENSING.md](LICENSING.md) explains the Community licence and the plan for a commercial Pro licence next to it.
