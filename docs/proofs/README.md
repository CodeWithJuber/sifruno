# Proofs

Transcripts of the Phase 0 proofs from [the plan](../PRODUCT-PLAN.md), run on 2026-11-22 on a fresh dev VM built with [scripts/devvm](../../scripts/devvm/README.md): AlmaLinux 9.9, SELinux enforcing, OpenLiteSpeed 1.9.4, LSPHP 8.3.37, MariaDB 10.11.18, under QEMU software emulation (no KVM). Each `PASS` or `FAIL` line with two spaces is a check the script made against the running system; lines with one space are the verify tool's own report. A run passes only with zero `FAIL  ` lines.

| Plan item | Transcript | Result |
| --- | --- | --- |
| 7. Proof 1: WordPress on OpenLiteSpeed from config, own user, namespace container, quota | [phase0-proof1-wordpress-ols.txt](phase0-proof1-wordpress-ols.txt) | 26 passed, 0 failed |
| 8. Proof 2: the broker creates a real Linux user with SFTP sign-in; the 100-account bound is gone | [phase0-proof2-broker-sftp.txt](phase0-proof2-broker-sftp.txt) | 44 passed, 0 failed |
| 9. Proof 3 rehearsal: verify report with closed-URL checks | [phase0-proof3-rehearsal-migrate-verify.txt](phase0-proof3-rehearsal-migrate-verify.txt) | 15 passed, 0 failed |

What the Proof 3 rehearsal shows: a site with a password folder and a `<Files>` deny rule, copied unchanged to OpenLiteSpeed, serves both with 200, because OpenLiteSpeed reads only rewrite rules from `.htaccess`. The scan sends the site to the Compat tier, and verify keeps the cutover gate closed against the OpenLiteSpeed copy and opens it against an Apache copy.

What these runs do not show:

- **Proof 3 on a real cPanel site.** The rehearsal uses an Apache site built in the VM. The plan's proof copies one of HostLelo's own cPanel sites over root SSH; that needs the owner's server.
- **Speed on real hardware.** Without KVM, timings are upper bounds, not the plan's "2 minutes" gate: about 19 s per account create, 24 s to list 107 accounts, 259 s from account creation to a live WordPress site. An earlier run on a busier host needed more than two minutes for WordPress's first page after a restart.
- **Broker operations that do not exist yet.** In Proof 1 the script, not the broker, gives the web server access to the home (an ACL) and sets the XFS quota.

## Phase 1: panel shell

Run on 2026-11-23 with `scripts/devvm/proof.sh panel-shell` on a fresh dev VM (AlmaLinux 9.9, SELinux enforcing, QEMU software emulation). The panel ran inside the guest with throwaway state; headless Chrome on the host drove it through a loopback port forward.

| Slice | Transcript | Result |
| --- | --- | --- |
| New panel shell: sidebar menu by job, a URL per page, Ctrl+K search, sign-in, Websites to Files handoff, back button and reload, phone width, dark theme, public preview | [phase1-panel-shell.txt](phase1-panel-shell.txt) | 29 passed, 0 failed |

Screenshots from that run are in [phase1-panel-shell/](phase1-panel-shell/): Home, Websites (light and dark), the search box, and the phone menu.

What this run does not show: the screens inside the shell are still the old Astryx ones, and only English exists, so right-to-left layout was not checked.

## Phase 1: admin sign-in

Run on 2026-11-23 with the same `proof.sh panel-shell`, extended for sign-in, on a fresh dev VM (AlmaLinux 9.9, SELinux enforcing). The browser on the host acted as the authenticator app, computing RFC 6238 codes from the key the panel showed; the guest checked them against its own clock.

| Slice | Transcript | Result |
| --- | --- | --- |
| Admin sign-in: first-run setup (access key, username and password, authenticator), wrong and replayed codes refused, sign-out, sign-in with a fresh code, per-name rate limit, plus every panel shell check above | [phase1-admin-login.txt](phase1-admin-login.txt) | 40 passed, 0 failed |

Screenshots are in [phase1-admin-login/](phase1-admin-login/): the authenticator step (the key is masked) and the sign-in form after a wrong code.

What this run does not show: the panel off loopback (HTTPS is the next slice), more than one admin, and an outside review of the sign-in code, which the plan requires before paying customers.

## Phase 1: the panel over HTTPS

Run on 2026-11-23 with `proof.sh panel-shell` on the dev VM (AlmaLinux 9.9, SELinux enforcing). Besides the loopback panel, the guest ran the HTTPS listener on port 443 for `panel.sifruno.test` with a self-signed certificate; the host's browser reached it through QEMU's port forward as another machine would, with the name mapped to that port.

| Slice | Transcript | Result |
| --- | --- | --- |
| HTTPS beyond loopback: served certificate matches the fingerprint the panel printed, every page asks for sign-in first, readings 401 and access key and setup 403 over the network, unknown host name 421, admin sign-in over HTTPS with a Secure cookie, plus every sign-in and shell check above | [phase1-https.txt](phase1-https.txt) | 48 passed, 0 failed |

Screenshot: [Websites over HTTPS](phase1-https/1440-light-https-websites.jpg).

What this run does not show: a certificate from a real authority (Let's Encrypt via lego comes with the first-run hostname step), a firewall opened to the internet, or behaviour behind a reverse proxy.

## Phase 1: the broker's web operation

Run on 2026-11-23 with `scripts/devvm/proof.sh broker-web` on a fresh dev VM (AlmaLinux 9.9, SELinux enforcing, OpenLiteSpeed 1.9.4, LSPHP 8.3.37, QEMU software emulation). The root broker ran with `--web-user nobody`, and `brokerdrive`, acting as the panel's user, sent the typed requests.

| Slice | Transcript | Result |
| --- | --- | --- |
| Broker web operation: a site goes live from one request (web server ACL, XFS quota, vhost written, tested and gracefully reloaded, PHP running as the site user, `.htaccess` and `.git` denied), a config OpenLiteSpeed rejects changes nothing, the access grant refuses a swapped `public_html`, a tenant's broken docroot does not fail another account's change, and delete takes the site out first | [phase1-broker-web.txt](phase1-broker-web.txt) | 26 passed, 0 failed |

Earlier runs of the same proof found two problems, both fixed before this run: the broker would not start with `--web-user`, because the package installs `lswsctrl` as a symlink and the broker runs only regular root-owned tools (it now reloads through `systemctl reload lsws`); and the proof's own check on a broken docroot was stricter than the broker's rule (it now runs the broker's rule on the saved output).

What this run does not show:

- **The symlink refusal through a live request.** Section 5 runs the access grant as root against a throwaway fixture. Through the broker, a swap made before a request is caught first by its per-request identity check, which records the account for an operator.
- **A tenant's broken site during another account's change.** Section 6 records OpenLiteSpeed's real output for a moved docroot and judges it with the broker's rule; it does not run a change while the docroot is broken, for the same reason.
- **The recovery paths.** An apply interrupted by a crash, a delete whose config fails its test, and a filesystem without quota enforcement are covered by unit tests, not on the VM.
- **Speed on real hardware.** Under software emulation the web operation took 16 seconds in this run (10 to 13 in earlier ones).

## Phase 1: the New website wizard

Run on 2026-11-23 with `scripts/devvm/proof.sh wordpress-wizard` on the dev VM (AlmaLinux 9.9, SELinux enforcing, OpenLiteSpeed 1.9.4, LSPHP 8.3, MariaDB 10.11, QEMU software emulation), built from `f3affc7`. The panel ran in the VM as `sifpanel` with the real broker (`--web-user`) and the MariaDB admin option file that provisioning makes; headless Chrome on the host reached it through `vm.sh forward` and drove the wizard as an admin would.

| Slice | Transcript | Result |
| --- | --- | --- |
| New website: first-run admin sign-in, the wizard form (autocomplete, feedback only after leaving a field), Create starts a panel job that creates the account, puts the site live, creates the database and installs WordPress, the job page to the last screen (Open site, Open WordPress admin, Set up DNS; after a reload; at phone width), the same domain refused, the WordPress admin password in neither the jobs API, the browser's storage nor the job file; on the VM the job file is private, the files and `wp-config.php` (0600) are the site user's, the site serves the title typed in the wizard and `wp-admin` redirects to the login | [phase1-wordpress-wizard.txt](phase1-wordpress-wizard.txt) | 30 passed, 0 failed |

Screenshots are in [phase1-wordpress-wizard/](phase1-wordpress-wizard/): the form (the password masked), the job while it runs, and the last screen at desktop and phone width. The job took 318 s under software emulation.

The first run of this proof found a broker bug: `systemctl reload lsws` took 18 s on the busy VM, past the broker's 15 s command limit, so the web step was left pending and the wizard could not undo the account it had made. OpenLiteSpeed's config test and restart now have their own limits (`b8d3b97`), and delete removes the user on the operation's own limit (`f3affc7`).

What this run does not show:

- **SSL.** The site is http; certificates with lego are the next slice.
- **Real DNS.** The proof domain resolves nowhere; the site was reached with a Host header.
- **The failure paths on the VM.** Undo after a failed step, a pre-existing database name, a slow step and a panel restart during a job are covered by unit tests (`internal/wizard`), not by this run.
- **More than one job.** Jobs run one at a time; the refusal of a second is a unit test.
