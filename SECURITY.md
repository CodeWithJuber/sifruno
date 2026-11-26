# Security policy

Sifruno manages a server as root. The panel (`sifruno.service`, running as the
unprivileged `sifpanel` user) asks the root broker (`sifruno-broker.service`,
`hostbroker`) to make every change to the host, through a fixed list of typed
operations over a local Unix socket. A flaw in that boundary can give a website
owner, a panel user or a visitor root on the server or access to another
customer's sites. Please report such flaws privately.

## Report a vulnerability

Use GitHub's private vulnerability reporting: open the repository's
**Security** tab and choose **Report a vulnerability**, or go to
<https://github.com/CodeWithJuber/sifruno/security/advisories/new>. Only the
maintainers can read the report. Do not open a public issue, pull request or
discussion for a vulnerability.

Include what you can of:

- the commit or release you tested, and the operating system;
- the component and the steps to reproduce, with a proof of concept if you
  have one;
- what an attacker gains, and what they need first (an account, a website, a
  network position).

We aim to acknowledge a report within 7 days and to agree a disclosure date
with you. We credit reporters in the advisory unless they ask us not to.

## Supported versions

Sifruno is in Phase 1 and has no releases yet. Security fixes go to the `main`
branch. The root broker, sign-in and permissions code has not yet had an
outside review; do not use Sifruno for paying customers' sites yet.

## In scope

- `hostbroker`, the root broker: any way to run a command, read or write a
  file, or change an account, as root or as another account, outside its typed
  operations; path, symlink and race tricks against account homes, websites,
  backups, restores, file manager actions and migrations.
- The panel and its API (`sifruno`, `internal/api`, `internal/operator`):
  authentication, sessions and cookies, TOTP and passwords, the access key,
  CSRF, authorization between admins and customers, and anything that reaches
  the broker with arguments it should not accept.
- Configuration Sifruno writes: OpenLiteSpeed virtual hosts, PHP, DNS zones,
  certificates, cron jobs, phpMyAdmin sign-on and database grants, where a
  customer's input could reach another customer or the server.
- The installer and release build (`scripts/install/`): files or services left
  with unsafe owners or modes, unchecked downloads, and secrets written where
  others can read them.
- The WHMCS module in `integrations/whmcs/` and the frozen WHM API layer in
  `internal/whmapi/`.
- Secrets in this repository or in its GitHub Actions workflows.

## Out of scope

- Vulnerabilities in software Sifruno installs (OpenLiteSpeed, LSPHP,
  MariaDB, phpMyAdmin, WordPress, WP-CLI, AlmaLinux packages), unless the way
  Sifruno configures or calls it causes them. Report those upstream.
- Anything that already needs root on the server or a signed-in panel admin,
  unless it lets one customer reach another.
- The test harnesses in `lab/` and `scripts/devvm/`, which are not shipped.
- Denial of service by traffic volume, missing rate limits without a shown
  impact, reports from automated scanners without a working attack, and
  social engineering.

## Testing

Test only on servers you own, such as a fresh AlmaLinux 9 virtual machine
(`scripts/devvm/` builds one). Do not test against servers, accounts or data
that belong to others, including HostLelo's.
