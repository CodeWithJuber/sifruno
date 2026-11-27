# Changelog

## [Unreleased]

### Changed

- A certificate that Let's Encrypt did not issue is explained by its real
  cause: a refused contact address, a rate limit, a name it does not issue
  for, a CAA record, no DNS record, port 80 closed, another server
  answering, or Let's Encrypt not answering, each with what to do. The
  new website's last screen and its "Turn on https" step show it, with
  Let's Encrypt's own words under Technical details, and so does the
  panel's "Panel certificate:" log line. A refused contact address used to
  read as "could not be reached".
- The installer stops, before it changes anything, when `--acme-email` is
  at a domain Let's Encrypt refuses (example.com, .net and .org, .test,
  .invalid, .localhost and other names kept for examples and tests, or an
  IP address), and says to type an address at a domain you own.
- While browsers do not trust the panel's own certificate, a customer's
  setup link and "Open phpMyAdmin" carry a short warning: that the browser
  will show "Your connection is not private" first, why, and that Get
  started's step for the panel's address shows what to check.
- Home opened on the server itself without a sign-in says "Sign in to see
  what is next", with a Sign in button, instead of showing the readings
  with no next step.
- Moving a website from cPanel no longer refuses `.htaccess` lines
  OpenLiteSpeed can safely ignore or that Sifruno handles: cPanel's PHP
  handler block, Expires, compression, caching and security headers,
  `FileETag`, `Options -Indexes`, `AddType` and `AddDefaultCharset`. A
  refusal names the file, line and directive, says a folder would open only
  when an access rule is the reason, and names the lines to change on the
  old server; `panelctl htaccess scan --details` shows the same.
- Moving a website from cPanel carries the root `.htaccess`'s `php_value`
  and `php_flag` lines for memory and upload sizes, time and input limits,
  error display and reporting, output buffering, session cookies and the
  time zone into the site's web server config, so the copy's PHP runs with
  the old site's settings; `memory_limit` stays within the account's
  memory. Settings that name a file (such as `auto_prepend_file`),
  `open_basedir`, `disable_functions`, `php_admin_*` lines and settings in
  a folder's `.htaccess` refuse the move, naming the line. A `.user.ini`
  that loads a file before every script, such as Wordfence's firewall, is
  a note to accept before cutover: this server's PHP does not read
  `.user.ini` files. `proof.sh migrate-cpanel` shows it on a real server
  (`docs/proofs/real-server-2026-11-25/migrate-php-settings.txt`).
- Moving a website from cPanel carries the `.htaccess` lines WordPress
  plugins write: `<Files>` and `<FilesMatch>` rules that close
  `wp-config.php`, `xmlrpc.php`, Wordfence's `.user.ini` and other names
  answer 403 on the new server, at the root or in a folder, and the root
  `.htaccess`'s `Redirect` and `RedirectMatch` (301 and 302) and
  `ErrorDocument` pages move into the site's web server config. CORS and
  `X-Robots-Tag` headers, which this server cannot send yet, are notes to
  accept before cutover. What still cannot move is refused, naming the
  line. `proof.sh migrate-cpanel` shows it on a real server
  (`docs/proofs/real-server-2026-11-25/migrate-htaccess-wp.txt`).
- Every website answers 403 for PHP files under `.phtml`, `.php3` to `.php8`,
  `.phar`, `.pht` and `.phps` instead of sending their source: only `.php`
  runs as PHP here.
- Every website answers 403 for backup copies and database dumps (names
  ending in `.bak`, `.orig`, `.save`, `~` or `.sql`, such as
  `index.php.bak`) instead of sending them: they can hold source code and
  passwords.
- A session ends after 30 minutes without use and at 12 hours, instead of
  15 minutes after sign-in. Before sign-in the panel shows only the sign-in
  form.
- Each way a website move can fail says what happened and what to do next;
  the old server's own output is only under Technical details.
- MariaDB listens on 127.0.0.1 only, OpenLiteSpeed's WebAdmin console on
  127.0.0.1:7080, and the stock Example listener on port 8088 is removed.
- The installed programs get the SELinux type `bin_t`, so the broker can
  create accounts on an enforcing system.
- The repository is public. CI runs only on GitHub-hosted `ubuntu-24.04`
  runners: `source-checks.yml` runs Go vet and tests, the UI build, every
  Node test file, the Python fixture tests and `reuse lint` on pull requests
  and pushes to `main`. `scripts/ci/public-repo-guard.sh` replaces
  `no-github-billing.sh` and fails on self-hosted or larger runners, unpinned
  actions, missing permissions, checkouts that keep credentials, and
  `pull_request_target` workflows that check out pull request code. The
  nightly fresh-install test needs approval in the `nightly` environment and
  keeps its transcripts as a run artifact.
- The product plan replaces the zero-edit cPanel compatibility target.
  Earlier delivery notes were archived, the README is one page, and
  `internal/whmapi` is frozen.
- The account broker creates regular Linux users with subordinate ID ranges
  instead of system users, and the 100-account bound is now 2000.
- `--dns-reload-cmd` runs without a shell: give an absolute program and plain
  arguments, for example `/usr/sbin/rndc reload`. Shell syntax is refused at
  startup.

### Removed

- Material that is not for a public repository: the internal product plan,
  the archived delivery notes, the cPanel reference captures and API
  inventories (`docs/reference/`, `lab/reference/`), stale binaries in
  `dist/`, the operator's mobile preview scripts and an internal strategy
  review config. Test hosts and server addresses that remain use
  `example.com` and documentation addresses.
- The verbatim captures in `internal/whmapi`'s tests; `contract_test.go`
  uses synthetic fixtures with the same fields.
- The Compatibility and Platforms screens and the "hosting engine in
  development" notice. Their API routes remain.
- The Ghidra and REA analysis tooling and the `rea-agents` dev dependency.

### Added

- A QR code to scan with the authenticator app, on the first-run setup, on
  a customer's setup page and where Account changes the app. The panel
  draws it in the browser from the app's link (our own encoder, no new
  dependency), so the key goes nowhere; the key and the link stay beside
  it.
- Move a website here from a cPanel backup file: "Move a website here" now
  asks where the website is, and for a backup file (cpmove-USER.tar.gz,
  USER.tar.gz or backup-…_USER.tar.gz, up to 32 GiB) shows what it holds
  and what will not move before anything is made, then moves its files,
  databases with the same users and passwords, PHP version, cron and
  certificate as a move from a cPanel server does. The file is read with
  bounded sizes and refused when a name climbs out of its folder; it is
  kept only for the move and deleted at its end or after 24 hours.
- Get started on Home: the panel's own address and certificate, the first
  website, moving a website (optional), backups with one restore test, a
  customer login and Always use HTTPS, each read from the server's state,
  with why it matters and one button to the screen that does it. It can be
  hidden once done. From a UX audit of every journey on a real server
  (`docs/ux-audit.md`), whose top fixes also land: first-run setup on
  every page until an admin exists, job names on Home's tiles, the old
  static-site screens and Linux accounts in an Advanced menu group, the
  certificate's state on Domains and SSL, "Manage" and "Move a website
  here" on Websites, "Manage this website" after the wizard, "restore
  test" for drill, and plain words on Backups and Security.
- A website moved from cPanel keeps its https: the move copies the
  certificate the old site serves, with its key, so the copy answers https
  before the DNS changes. It is copied only when it is not self-signed, is
  valid for 7 more days, covers the site's domain and comes from an
  authority this server trusts; otherwise the step says why and the move
  goes on over http. The panel replaces a copied certificate with a Let's
  Encrypt one before it runs out, once the domain points here, and the
  Domains tab says where the certificate came from.
- Passkeys. An admin or customer adds one on Account, with the current
  password and a code, and then signs in with it alone. They work when the
  panel is opened by its name over a trusted certificate.
- "Keep me signed in on this device" at sign-in: 24 hours without use and
  7 days at most. Password and passkey sessions now survive a panel restart;
  access-key sessions still end with it.
- The panel gets its own Let's Encrypt certificate for `--panel-host` when
  `--acme-email` is set, and renews it without a restart.
- "Always use HTTPS" on a website's Domains tab, on by default: http answers
  with a redirect once a valid certificate is in force.
- Every live website without a certificate gets one requested once its name
  points at this server, at most three new websites an hour.
- Move a website from cPanel with the old server's WHM login (an API token or
  the root password, kept in memory only). Copying over SSH stays as "Use SSH
  instead".

- Files for an open-source project: `CONTRIBUTING.md`, `CODE_OF_CONDUCT.md`
  (Contributor Covenant 2.1), `SECURITY.md` (private vulnerability
  reporting), `NOTICE`, and `CLA.md`, an individual contributor licence
  agreement that supports the dual-licence plan in `LICENSING.md`, checked
  on pull requests by `cla.yml`. `REUSE.toml` and `LICENSES/` record every
  file's copyright and licence. Issue forms, a pull request template,
  `CODEOWNERS` and Dependabot (Go modules, npm, GitHub Actions).
- Supply-chain checks: dependency review on pull requests, gitleaks on pull
  requests and pushes (`.gitleaks.toml` allows the known false positives),
  and the OpenSSF Scorecard on pushes to `main` and weekly.
- WordPress install broker operation (needs human review): `InstallWordPress`
  runs WP-CLI 2.12.0, checked against its pinned sha512, with the site's
  LSPHP as the account's user, passwords on stdin. It runs outside the
  broker lock and blocks only a delete of that account meanwhile.
  `brokerdrive wordpress`, `dbdrive` and `proof.sh broker-wordpress` prove
  it on the dev VM; provisioning installs WP-CLI.
- Broker web operation (needs human review): `SetWeb` (`hostbroker
  --web-user`) gives OpenLiteSpeed read access to an account's site through
  an ACL written on no-follow directory handles, sets an XFS quota, renders
  the account's vhost with olsweb, tests it with `openlitespeed -t` and
  reloads gracefully. A config that fails its test is restored and
  journaled as rejected, leaving the account unchanged; delete takes the
  site out before removing the user. `proof.sh broker-web` proves it on the
  dev VM.
- The panel over HTTPS beyond loopback (needs human review):
  `--https-listen` with `--panel-host`, and `--tls-cert`/`--tls-key` or a
  self-signed certificate kept in the state directory (fingerprint printed
  at start). Over that listener only admin sign-in works, every API route
  needs an admin session, and the access key and first-run setup are
  refused. Loopback behaviour is unchanged.
- Admin sign-in with a password and a 6-digit authenticator code (needs
  human review). A new panel asks for first-run setup on its first private
  page: the server's access key, then a username and password, then an
  authenticator app. Passwords are Argon2id hashes in the private state
  directory; each code works once; each account allows five tries, then one a
  minute. The access key still signs in locally. New dependency:
  golang.org/x/crypto v0.57.0, approved by the owner.
- Phase 1 panel shell: a shadcn/ui sidebar and top bar, Ctrl+K search over
  pages and actions, and a URL for every page (TanStack Router). The menu
  names the job: Home, Websites (Files, Backups), Activity, and under
  Administration: Customers, Server, Security, Settings. Panel colours come
  from the brand tokens.
- Broker-managed SFTP keys: `SetSSHKeys` writes a root-owned key file per
  account, each key restricted to `internal-sftp`.
- `panelctl htaccess scan`: classifies every `.htaccess` directive and sorts
  sites into Native, Convertible or Compat for OpenLiteSpeed.
- `panelctl migrate verify`: compares an old site with its new copy, pages
  and closed (401/403) URLs, and keeps the cutover gate closed on any failure
  or unaccepted warning.
- `internal/olsweb`: renders OpenLiteSpeed config for a site from a typed spec.
- `scripts/devvm`: a disposable AlmaLinux 9 dev VM, the Phase 0 proofs and
  the Phase 1 panel shell proof (`proof.sh panel-shell`).

- Recovery archive v1 (`recovery-2026-10-11-v1`) for the Windows-server handoff:
  all 270 original dirty source paths, 130 recovery branches, an offline Git
  bundle and 11,995 additional artifact paths with checksums and a tested restore
  helper. User-selected secrets/runtime-state exclusions are explicit in
  `docs/server-recovery.md`. This is an archival prerelease, not a product release.

- Combined native static website lifecycle from reviewed PR62–67: display-name
  editing, sequential multiple-file upload, saved-file HTTP preview, single-file
  snapshot restore, snapshot recovery as a separate website and exact-confirmed
  website removal. Original feature evidence and combined browser evidence are
  linked in `docs/website-lifecycle-integration.md`.

- Confirmed removal of a selected saved native ZIP, freeing backup capacity while
  preserving the website's served files and remaining snapshots.
- Preview and explicitly restore a downloaded native Sifruno ZIP into an existing
  static website, preserving its identity, domain, backup history and schedule.
- Confirmed rename/move of a saved website file in File Manager, preserving
  bytes and refusing stale revisions, changed checksums and occupied paths.
- Download a saved text or binary file from File Manager, verified against the
  displayed revision, byte count and SHA-256 while retaining unsaved drafts.
- Main integration of the reviewed website domain-routing update, selected-site
  File Manager/Backups navigation and downloaded native ZIP recovery workflow.
- Local static-file upload and confirmed replacement bound to a file checksum
  and site revision, with existing backup restoration for recovery.

### Fixed

- The hosts file line for previewing a moved website no longer says
  www.www. for a site whose domain starts with www..
- phpMyAdmin no longer answers "Token mismatch": the panel's proxy now passes
  phpMyAdmin's own `__Secure-` session cookies, which it uses over HTTPS.
- The database tools sent each SQL statement to the mysql client as an
  argument, so a statement that sets a password exposed it to every local
  user; the SQL now goes on stdin (needs human review).
- Websites' saved ZIP restore now uses Backups' verified file comparison and
  explicit confirmation, retaining editor drafts and rejecting stale targets.
- Websites can display saved binary-asset details when the first or only file
  cannot be opened as UTF-8 text. Text editing, File Manager navigation and
  backup recovery remain available in the same website workflow.

Earlier deliveries and their original evidence are recorded in
the delivery plan (an internal document, not published). This section is an unreleased source
change, not a production release or hosting-compatibility qualification.
