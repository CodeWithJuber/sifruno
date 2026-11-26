# Proofs

Transcripts of the Phase 0 proofs from the product plan, run on 2026-11-22 on a fresh dev VM built with [scripts/devvm](../../scripts/devvm/README.md): AlmaLinux 9.9, SELinux enforcing, OpenLiteSpeed 1.9.4, LSPHP 8.3.37, MariaDB 10.11.18, under QEMU software emulation (no KVM). Each `PASS` or `FAIL` line with two spaces is a check the script made against the running system; lines with one space are the verify tool's own report. A run passes only with zero `FAIL  ` lines.

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

## Pace

The plan's Phase 0 gate asks how many slices run on a real VM each week, so that dates come from that count. The count below is of slices whose first passing transcript is on this page, by the day it was saved. A slice proven again later (on the real server) counts once, on its first day.

| Day | Slices first proven on a dev VM or real server | Which |
| --- | --- | --- |
| 2026-11-22 | 3 | The three Phase 0 proofs |
| 2026-11-23 | 5 | Panel shell, admin sign-in, panel over HTTPS, the broker's web operation, the broker's WordPress install |
| 2026-11-24 | 5 | Installer sshd checks, one-command fresh install, upgrade install, site actions, the New website wizard with SSL |
| 2026-11-25 | 12 | Account limits, backups with restore drill, file manager, scheduled jobs/logs/usage, tenant isolation, admin and customer login, other domains and redirects, WHMCS module, phpMyAdmin, migration v1, the .htaccess watcher, create and delete recovery |

That is 25 slices in 4 days. Four UI slices on 2026-11-25 (Home/Server/Security, Hosting accounts/Backups, Static sites/tour, File Manager) ran the real panel in a browser without a VM and are not counted.

What this count does not show: a whole week (the work so far spans 4 days), and the line-by-line human review the plan requires for the broker, login, permissions, credentials and migration code. On 2026-11-25, 158 commits were marked for that review.

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

## Phase 1: the broker's WordPress install

Run on 2026-11-23 with `scripts/devvm/proof.sh broker-wordpress` on the dev VM, built from `36f2a55`. The broker ran with `--web-user nobody`; `dbdrive` created the site's database through the panel's `dbhost` code (as root over the socket, standing in for the panel's admin option file), and `brokerdrive` asked the broker to install WordPress.

| Slice | Transcript | Result |
| --- | --- | --- |
| WordPress install: WP-CLI 2.12.0 pinned by sha512, run as the site user with its LSPHP, the database and admin passwords on stdin (no process argument held either in 153 samples taken during the install), `wp-config.php` 0600 pointing at 127.0.0.1, tables and admin user in the site's database, the site serving WordPress, a second install refused at the download step with nothing changed, and delete afterwards | [phase1-broker-wordpress.txt](phase1-broker-wordpress.txt) | 22 passed, 0 failed |

The install took 230 s under software emulation, past the broker's 45 s request limit, so this run also shows that the long-running response arrives. Later commits refused a suspend or web change during an install, refused passwords with an edge space (WP-CLI's prompt trims them), and gave OpenLiteSpeed's test and restart their own time limits; those are covered by unit tests and by the wizard proof below, which ran the same install through the panel. A re-run on `d99cdd0` failed at its first step because the proof's own driver stopped waiting for the web change after 60 s while the broker finished it; the driver now waits six minutes (`0b9bd2c`).

## Phase 1: the installer's sshd pre-checks

Run on 2026-11-24 with `scripts/devvm/proof.sh installer-sshd` on the dev VM (OpenSSH 9.9p1, SELinux enforcing), with `install.sh` and the guest script as in `3ba55f1`. The installer turns SSH passwords off; these checks decide whether someone could still sign in once it does. The proof loads the installer's functions alone and works on copies of the VM's sshd configuration and throwaway users.

| Slice | Transcript | Result |
| --- | --- | --- |
| sshd pre-checks: the candidate copy with the policy is accepted by `sshd -t`; other users get SFTP only and no passwords; root with a key counts, but not with `PermitRootLogin no`, an Allow or Deny rule that leaves it out, `AuthenticationMethods` needing a password, or a ForceCommand; Match rules on addresses are judged for the admin's own SSH connection, and refused when there is none; a wheel member counts only with a valid key, StrictModes-safe modes and a login shell; other users who would lose a shell are listed; the live sshd files are unchanged | [phase1-installer-sshd.txt](phase1-installer-sshd.txt) | 30 passed, 0 failed |

What this run does not show: a failed SELinux relabel, which was not provoked. The installer writing the policy on a fresh server is the fresh-install test below.

## Phase 1: one command installs on a fresh server

Run on 2026-11-24 with `scripts/devvm/fresh-install-test.sh --destroy-vm`, from source `10cd1ad` (release sha256 `3513fead…81a6`). It destroyed the dev VM, created a new AlmaLinux 9.9 one with SELinux enforcing, and provisioned it with `scripts/install/install.sh`, starting the services. It then smoke-tested the result and ran the installer a second time.

| Slice | Transcript | Result |
| --- | --- | --- |
| Fresh install: preflight on the new server (root, AlmaLinux 9, x86_64, `/home` XFS with user quota and empty, and root still able to sign in with a key once the sshd policy is in place); the release checked against its SHA256SUMS; packages, nsswitch and the sshd policy (written, checked, reloaded); both units active and enabled; the panel answering as `sifpanel`; the broker socket `sifpanel` 0600; `hostbroker --check-host`; SELinux still enforcing; a second run that succeeds and reports nothing changed | [phase1-fresh-install.txt](phase1-fresh-install.txt) | 12 passed, 0 failed |

The test drives the VM over SSH as root with a key throughout. Every command after the sshd step reached the VM through a new key sign-in under the new policy, which is the "second sign-in" the installer asks the operator to check. The installer took 61 minutes under software emulation, mostly package installation.

What this run does not show: a real server provider's image (cloud-init users, other sshd drop-ins) and the nightly schedule the plan asks for, which `.github/workflows/nightly-install.yml` now runs on a throwaway Linode once the owner adds its token. An upgrade is the next section.

## Phase 1: upgrading an installed server

Run on 2026-11-24 on the same dev VM, which the fresh-install test had installed from `10cd1ad`. The release built from `1871199` was copied in, checked against its `.sha256`, unpacked into a new folder, and its `install.sh --no-start` run over the existing installation, then run once more.

| Slice | Transcript | Result |
| --- | --- | --- |
| Upgrade in place: the tarball and every file match their checksums, preflight passes on the installed server, and the run adds only what the newer release brings (bzip2 and restic 0.20.0 at its pinned sha256 `c109579d…`), replaces the four programs and the panel UI, and leaves the units as they were (disabled, as `--no-start` asks); the run after it reports `Changed in this run: nothing` | [phase1-upgrade-install.txt](phase1-upgrade-install.txt) | installer exit 0, second run 0 |

What this run does not show: an upgrade with the units running (the panel and broker restarting under live sites), a downgrade, and an upgrade across a change to the broker's journal format.

## Phase 1: the site page's changes at the broker

Run on 2026-11-24 with `scripts/devvm/proof.sh broker-site-actions` on the dev VM the fresh-install test built (AlmaLinux 9.9, SELinux enforcing, OpenLiteSpeed 1.9.4), from `2ae3d56`'s broker and driver.

| Slice | Transcript | Result |
| --- | --- | --- |
| Site actions: a live site moves from PHP 8.3 to 8.4 and the account list shows it; suspend answers 403 for the home page and a PHP file, from `/var/lib/sifruno-suspended` (root 0755, empty, `var_lib_t`) with no `/home` path in the vhost, the site's files untouched and a file the tenant puts under `.well-known` not served; a second suspend is a recorded change; resume serves PHP 8.4 again from the home; delete removes the vhost and the user | [phase1-broker-site-actions.txt](phase1-broker-site-actions.txt) | 22 passed, 0 failed |

While suspended, the ACME challenge path served a challenge from the panel's own folder with 200: OpenLiteSpeed applies the challenge context before the vhost's deny rule, so renewal keeps working. An earlier run failed after the suspend because the proof's driver stopped waiting after 60 s while the broker finished the change (`d2246a5`).

What this run does not show: a tenant changing its own folders (the broker-isolation proof), and the panel's site page in a browser.

## Phase 1: the New website wizard, with SSL

Run on 2026-11-24 with `scripts/devvm/proof.sh wordpress-wizard` on the dev VM (AlmaLinux 9.9, SELinux enforcing, OpenLiteSpeed 1.9.4, LSPHP 8.3, MariaDB 10.11, QEMU software emulation), built from `70efa12`. The panel ran in the VM as `sifpanel` with the real broker (`--web-user`), the MariaDB admin option file, and ACME pointed at Pebble 2.10.1, Let's Encrypt's test CA, installed by provisioning (its DNS answers 127.0.0.1 for every name, so it validates HTTP-01 against this VM's OpenLiteSpeed). Headless Chrome on the host reached the panel through `vm.sh forward` and drove the wizard as an admin would.

| Slice | Transcript | Result |
| --- | --- | --- |
| New website: first-run admin sign-in, the wizard form (autocomplete, feedback only after leaving a field), a panel job that creates the account, puts the site live, gets a certificate (lego in the panel, HTTP-01 through the broker's challenge path, installed by the broker's `SetCertificate`), creates the database and installs WordPress with https; the job page and the last screen (https links, DNS help, reload, phone width), the same domain refused, the WordPress admin password in neither the jobs API, the browser's storage nor the job file; on the VM the site serves over https with a certificate chained to Pebble's root that names exactly the domain and is the broker's `cert.pem` (root 0600), and WordPress's home and siteurl are https | [phase1-wordpress-wizard.txt](phase1-wordpress-wizard.txt) | 43 passed, 0 failed |

Screenshots are in [phase1-wordpress-wizard/](phase1-wordpress-wizard/): the form (the password masked), the job while it runs, and the last screen at desktop and phone width.

Earlier runs found and fixed: a broker command limit too short for OpenLiteSpeed's restart on a busy VM (`b8d3b97`), a delete cut off by the request's own limit (`f3affc7`), and proof checks that looked for the step list on the last screen (`caf5b99`). One run on `caf5b99` passed every https check but its first plain-http request found no page within ten minutes, while the same page served at once later in the run and in the next run; the cause is not known.

What this run does not show:

- **Real DNS and a public CA.** Pebble stands in for Let's Encrypt and its DNS points every name at the VM.
- **Renewal.** The renewal loop and its one-week wait after a refused install are unit tests (`internal/acme`); no certificate came near expiry here.
- **The failure paths on the VM.** Undo after a failed step, a pre-existing database name, a slow step, a panel restart during a job and a skipped SSL step are unit tests (`internal/wizard`).
- **More than one job.** Jobs run one at a time; the refusal of a second is a unit test.

## Phase 1: create and delete recovery

Run on 2026-11-25 with `scripts/devvm/proof.sh create-recovery` on a throwaway AlmaLinux 9.8 cloud server with a fresh Sifruno install (SELinux enforcing, shadow-utils 4.9-16.el9, hardware virtualization rather than QEMU emulation), from `3478a75`, whose broker and native code are `22ead56`'s. `brokerdrive`, acting as the panel's user, sent the typed requests.

| Slice | Transcript | Result |
| --- | --- | --- |
| Create and delete recovery: groupadd and userdel wait on shadow-utils' lock and exit by themselves, with nothing killed, and the broker logs which step stopped; a useradd stopped after it made the home is finished at the next start; a create or delete the broker cannot finish holds up every account until the operator abandons the create or finishes the delete, and both refuse an account that is not stuck; a 200,000-file home's delete answers in 1 s, the trash drains it, and its UID is not given out meanwhile; the root-only Go tests of the same code | [phase1-create-recovery.txt](phase1-create-recovery.txt) | 81 passed, 0 failed |

Two things the code assumed and this run shows: with `/etc/.pwd.lock` held, userdel waited about 15 s and exited with status 1 by itself, changing nothing; and a home holding a tmpfs mount was renamed into the trash with the mount inside it, and the remover left that folder and logged it by the account's ID.

What this run does not show: the panel's screens for an account that needs recovery. The proof drives the broker directly.

## Phase 1 on a real server (2026-11-25)

Run on 2026-11-25 on a throwaway AlmaLinux 9.8 cloud server (hardware virtualization, SELinux enforcing, OpenLiteSpeed 1.9.4, LSPHP 8.3.37, MariaDB 10.11.18). `fresh-install-test.sh` installed Sifruno on it from a release built from `6a8e579`, and that installed release stayed on the server for every run below. Each proof builds its own broker and panel from the checkout and copies them in, so the table gives the checkout each run was built from, read from the checkout's reflog at the run's start time. `b7107cf` has the same product code and the same scripts for these proofs as `6a8e579`.

| Proof | Transcript | Checkout | Result |
| --- | --- | --- | --- |
| One command installs on the server; a second run changes nothing | [fresh-install.txt](real-server-2026-11-25/fresh-install.txt) | release and script from `6a8e579` | 12 passed, 0 failed |
| One command installs on a new server the nightly script made (`scripts/ci/nightly-fresh-install.sh`); the programs are `bin_t` and the broker runs as `unconfined_service_t`; an account is created and deleted through the installed panel and broker with `panelctl` | [fresh-install-installed-units.txt](real-server-2026-11-25/fresh-install-installed-units.txt) | release and script from `8fc8728` | 17 passed, 0 failed |
| The broker's WordPress install | [broker-wordpress.txt](real-server-2026-11-25/broker-wordpress.txt) | `6a8e579` | 24 passed, 0 failed |
| Per-account process, memory and CPU limits | [account-limits.txt](real-server-2026-11-25/account-limits.txt) | `6a8e579` | 58 passed, 0 failed |
| Backups with restic over SFTP, restore of files and database, restore drill | [backups.txt](real-server-2026-11-25/backups.txt) | `6a8e579` | 50 passed, 0 failed |
| File manager at the broker, as the site's user | [files.txt](real-server-2026-11-25/files.txt) | `6a8e579` | 37 passed, 0 failed |
| Scheduled jobs, logs and usage at the broker | [site-tools.txt](real-server-2026-11-25/site-tools.txt) | `6a8e579` | 21 passed, 0 failed |
| The New website wizard, with SSL | [wordpress-wizard.txt](real-server-2026-11-25/wordpress-wizard.txt) | `b7107cf` | 97 passed, 0 failed |
| A tenant's own folder change stays with its own account | [broker-isolation.txt](real-server-2026-11-25/broker-isolation.txt) | `b7107cf` | 46 passed, 0 failed |
| Site actions: PHP version, suspend, resume, delete | [broker-site-actions.txt](real-server-2026-11-25/broker-site-actions.txt) | `b7107cf` | 22 passed, 0 failed |
| Admin and customer login | [customer-login.txt](real-server-2026-11-25/customer-login.txt) | `993dc83` | 70 passed, 0 failed |
| A site's other domains and redirects, with a certificate | [site-domains.txt](real-server-2026-11-25/site-domains.txt) | `993dc83` | 53 passed, 0 failed |
| The WHMCS module: create, suspend, unsuspend, terminate | [whmcs-module.txt](real-server-2026-11-25/whmcs-module.txt) | `82de04a` | 24 passed, 0 failed |
| One-click phpMyAdmin | [phpmyadmin.txt](real-server-2026-11-25/phpmyadmin.txt) | `3478a75` | 86 passed, 0 failed |
| Migration v1 from a cPanel stand-in over root SSH: discovery, two sites moved (a hardened one its old web server read through the group, and one with a password folder, a closed folder and address lists), refusals and undo for four more | [migrate-cpanel.txt](real-server-2026-11-25/migrate-cpanel.txt) | `000813a` | 141 passed, 0 failed |
| Move a website here with the old server's WHM login (D-0005), run 2026-11-26 on a new server the nightly script made and kept (Linode 111981555, since deleted): the stand-in's cPanel tools refuse over SSH as on the owner's server, a WHM API stub on port 2087 lists the accounts and adds the key with `restrict`, one SSH fingerprint is confirmed, a WordPress site moves with its files and database, and the key goes over SSH while WHM deletes its file; the classified errors (D-0006) of a cPanel tool over SSH and of a WHM that prints no JSON; the token in no state, log, process argument or job record. Screenshots at 390 px: [connect](move-website-whm/move-connect-390.png), [certificate](move-website-whm/move-certificate-390.png), [classified error](move-website-whm/move-error-390.png), [one fingerprint](move-website-whm/move-confirm-390.png) | [migrate-cpanel-whm.txt](real-server-2026-11-25/migrate-cpanel-whm.txt) | `e8f64da` | 60 passed, 0 failed |
| The broker's .htaccess watcher: a tenant's rewrite rule takes effect with no panel action, and a flood of writes restarts OpenLiteSpeed at most once per window | [htaccess-reload.txt](real-server-2026-11-25/htaccess-reload.txt) | `000813a` | 19 passed, 0 failed |
| The Phase 1 gate with a public CA and real DNS (`scripts/devvm/proofs/public-ca-wizard.sh`), over the internet on a new server the nightly script made and kept (`SIFRUNO_NIGHTLY_KEEP=1`, AlmaLinux 9.8, installed with `--panel-host` and `--acme-email`): the admin signs in at `https://NAME:8443/` with password and authenticator code, and the wizard's WordPress site at `www.SERVER_IP.sslip.io` answers HTTPS 200 25.2 s after Create, its last screen at 37.2 s, with a Let's Encrypt production certificate (issuer YE2) that curl, openssl and Chrome trust with no extra CA | [public-ca-wizard.txt](real-server-2026-11-25/public-ca-wizard.txt) | release from `992432f` (product code of `17861d9`); the proof script as committed with it, but for one check fixed after the run | 25 passed, 1 failed (the proof's own check; see below) |
| Always use HTTPS, run 2026-11-26 on another new server the nightly script made and kept (AlmaLinux 9.8, OpenLiteSpeed 1.9.4), installed with `--panel-host panel.SERVER_IP.sslip.io` and `--acme-email`: `public-ca-wizard.sh` makes a WordPress site at `www.SERVER_IP.sslip.io` with one Let's Encrypt certificate (26 passed, 0 failed; HTTPS 200 27.3 s after Create) and WordPress's home and siteurl are https; then `always-https.sh`, over the internet with the system trust store: `http://NAME/some/path?x=1` answers 301 to `https://NAME/some/path?x=1`, https answers 200, `curl -L` from http ends on the site after one hop, a file in the ACME challenge folder is served over http and `/.well-known/acme-challenge/test` answers 404, an uncovered `.test` alias answers 200 on http with no new certificate asked for; turned off through the panel's API, http answers 200 and the config has no https rule; turned on again, 301 again, `/` too (not a cached page) | [always-https.txt](real-server-2026-11-25/always-https.txt) | release from `9edd296`; `always-https.sh` from `99ce70b` | 60 passed, 0 failed |
| The panel's own Let's Encrypt certificate, run 2026-11-26 on another new server the nightly script made and kept (Linode 111978604, AlmaLinux 9.8, OpenLiteSpeed 1.9.4), installed again with `--panel-host panel.SERVER_IP.sslip.io` and `--acme-email`: the broker serves the name on port 80 (403, the challenge folder 200), and the panel, started with its self-signed certificate, gets one from Let's Encrypt (issuer YE2, SAN that name alone, valid to 2027-02-24) in its first request, 11 s after start, and serves it without a restart; `panel-certificate.sh` over the internet: curl and `openssl s_client -verify_return_error` verify `https://NAME:8443/` with the system trust store, an IP address still gets the self-signed one, the chain and key are one `sifpanel` 0600 file, the renewal loop's record says installed and its first check asks for nothing, a restart serves the saved certificate and asks for nothing, the installer's second run changes nothing, and a PHP website, its www. form and an account named NAME are refused with "This name is the panel's own address. Use a different domain for the website."; then the server is deleted and the API answers Not found | [panel-certificate.txt](real-server-2026-11-25/panel-certificate.txt) | releases from `a00ed8d` (port 80 did not answer the name, see below), `ace350e` (the request) and `a3a50ba`; `panel-certificate.sh` as committed with it | 27 passed, 0 failed |
| Always use HTTPS in the panel, run 2026-11-26 on another new server the nightly script made and kept (Linode 111979154, AlmaLinux 9.8, OpenLiteSpeed 1.9.4), installed again with `--panel-host SERVER_IP` (so the panel asks Let's Encrypt for nothing) and `--acme-email`: a PHP site made before certificates were set up has none; `public-ca-wizard.sh` makes a WordPress site with the run's one Let's Encrypt certificate (26 passed, 0 failed); then `always-https.sh` with its browser part: on the Domains tab Chrome turns "Always use HTTPS" off at desktop width (curl: http answers 200, https 200, the list says off) and on at 390 px (curl: 301 to the same address on https), with no sideways scroll; a press on a page older than the site answers 409, the page says the website changed meanwhile and reads it again; the PHP site's switch shows on but cannot be pressed, says it has no certificate yet and to get one on this tab first, and its http answers 200; screenshots in [always-https-ui/](real-server-2026-11-25/always-https-ui/), the page's text showing `SERVER_IP` for the address; the panel's log names one certificate; then the server is deleted and the API answers Not found | [always-https-ui.txt](real-server-2026-11-25/always-https-ui.txt) | releases from `d7f2ffd` (the certificate) and `6525f74`; `always-https.sh` as committed with it | `always-https.sh` 56 passed, 0 failed; the wizard 26 passed, 0 failed (summarised) |
| Nothing public but SSH, websites and the panel's two HTTPS ports, run 2026-11-26 on three new servers the nightly script made and kept (Linodes 111993682, 111996427 and 111998021, AlmaLinux 9.8, OpenLiteSpeed 1.9.4, MariaDB 10.11.18), all deleted afterwards (the API answers Not found): after a fresh install of the branch head MariaDB listens on `0.0.0.0:3306` and `[::]:3306`, the WebAdmin console on `0.0.0.0:7080` (TCP and UDP) and the sample site on `0.0.0.0:8088`, all three reachable from the runner once the Cloud Firewall and firewalld let them through; after the installer of `3cd4927` as an upgrade (and of `286c195` before it) MariaDB is on `127.0.0.1:3306` only (`/etc/my.cnf.d/sifruno.cnf`, restarted once), the console on `127.0.0.1:7080`, the sample site gone with no `openlitespeed -t` or error.log line, and from the runner 3306, 7080 and 8088 answer with a TCP reset while 22, 80, 443, 8443 and 8444 connect; a second run changes nothing; fresh installs of `286c195` and `1710d6a` pass the 17 fresh-install checks with the same listeners; the public-CA wizard puts a WordPress site live over https in 28.9 s (its PHP connects to MariaDB at 127.0.0.1); phpMyAdmin's one-click sign-in opens, lists `www_wp` and reads its 14 tables. By hand on the same server: a graceful reload, and `systemctl restart lsws` too, leave a moved listener where it was while systemctl reports success, so the installer stops OpenLiteSpeed, waits for its processes to end and starts it | [listeners.txt](real-server-2026-11-25/listeners.txt) | releases from `59e703b` (before), `286c195`, `1710d6a` and `3cd4927`; the wizard and probe scripts from the checkout `380e5dc` and this session | 90 passed, 3 failed (the same check each time: phpMyAdmin's first page shows "Token mismatch", on the branch head's listeners too, so it comes from elsewhere) |

The public-CA run asked Let's Encrypt for one certificate, as decision D-0001 allows. Its one failed check is the proof's own: it read the text of the checked radio button, which has none (the label around it names it). The follow-up at the end of the transcript, on the same form without pressing Create, shows WordPress chosen and the fixed check passing; the job's own steps show WordPress installed. In its transcript the server's address, also inside the sslip.io name, is written `SERVER_IP`, and the trailing space after curl's status line is removed, as the script now does; nothing else is changed. The server stays up for the owner to try the panel.

The Always use HTTPS panel run does not show the broker's render at a certificate's NotAfter (`946ad21`): the certificate is valid for 90 days, so that is proven by `internal/hostaccounts/https_expiry_test.go` alone, which moves a fake clock (a synctest bubble) past NotAfter. Nor does it show a customer's login: that the switch shows only for a login whose session lists the route is a node test against the customer route table, not a browser run. Its screenshots replace the server's address in the page's text with `SERVER_IP` just before each is taken; nothing else on the page is changed.

The panel-certificate run found that the challenge vhost of `2e2018a` never loaded on a real server: OpenLiteSpeed's config test warned that its root-owned vhRoot's owner was below the minimum UID, the broker refuses a config with a warning for a vhost it wrote, and port 80 answered 404 for the panel's name. The setup checked port 80 from the internet before the panel was restarted, so Let's Encrypt was asked for nothing then; `1c5348f` names the web server's user and group in the vhost, and the one request came after it. What that run does not show: a renewal (the certificate is not due for 60 days; the renewal loop's unit tests cover it), a failed request's plain-words line on a real server (unit tests cover each kind), and the installer's warning for a `--panel-host` that is already a website's domain (run only against a sample `sifruno.conf`; on this server a dry run warned about nothing, as no website had the name).

The installed-units run found two bugs the other proofs missed, because they ran their own broker: the installed programs were `lib_t`, so systemd ran the broker as `init_t`, which may not set a process group, and every account create from the installed units answered 503 (`30d89f4`); and `panelctl accounts create` sent an empty `plan` the panel refuses (`102a70b`). Earlier runs on this server found and fixed: site-domains parsed the certificate manager's log line along with the JSON answer (`2e041f1`); customer-login's website picker had read the list before the proof made the sites (`993dc83`); the phpMyAdmin proof counted OpenLiteSpeed's listener once per worker and its request client ignored the browser's host mapping (`e99c721`), then read escaped grants, sampled too slowly to see the panel's mysql client, and counted the proof's own refusals as browser errors (`3478a75`); the WHMCS module lost a slow create's account ID, a product fix (`25402f9`); and migrate-cpanel's stand-in refused the migration key and never installed WordPress (`47ea830`), its checks and file layout did not match cPanel's or the product's (`289578d`, `000813a`), and its moves found three product bugs, fixed before the saved run: the database step's revision conflict (`82de04a`), a moved site's root `.htaccess` that OpenLiteSpeed loaded only at its next restart (`b0de7ee`), and files the old web server read only through their group (`8f14e45`).

The WHM login run (`proof.sh migrate-cpanel whm`) uses the same stand-in, which is not cPanel: its WHM API is a Python stub that answers in the shapes of cPanel's public API documentation, so how a real WHM answers a refused token and whether it takes the `restrict` option are not shown by it. The run before the saved one failed one check for the proof's own reason (the stand-in's log already held the refused request of the reachability check; fixed in `e8f64da`). The screenshots were taken after the saved run, on the same server and stand-in, through an SSH tunnel to the proof's panel rebuilt at `5330268`; taking them found two things fixed there: Try again after a failed connection asked to trust the certificate again (`5330268`), and a key WHM removed after SSH could not was reported with the SSH failure's "it is still there" (`e5ea9f8`). In migrate-cpanel-whm.txt the server's public address is written `SERVER_IP`; the stand-in's 10.88.0.3 is Podman's private network.

In migrate-cpanel.txt the server's public address is written `SERVER_IP`; nothing else is changed. `000813a` has the product code of `733056d`. Timed beside the htaccess-reload run (not in its transcript): each graceful restart held the broker's store lock for about 3.2 s (`openlitespeed -t` 0.1 s, `systemctl reload lsws` 3.1 s), and a broker request that arrived meanwhile waited up to 3.8 s; during the flood that happened once per restart, about every 33.5 s.

What these runs do not show:

- **A real cPanel server.** The migration moves sites from a Podman stand-in with stub `whmapi1` and `uapi` scripts, not from cPanel.
- **Create and delete recovery.** Its run on this server is in its own section above.
- **The other proofs.** broker-sftp, wordpress-ols, broker-web, migrate-verify, installer-sshd, panel-shell and the upgrade install were not run on this server.
- **A server the test made.** The fresh-install test used a server made beforehand, named in the dev VM's ports file; `scripts/ci/nightly-fresh-install.sh` now also makes and deletes a Linode for it (one run passed 12/12).
- **A public CA and real DNS.** Pebble stands in for Let's Encrypt in site-domains and wordpress-wizard, and its DNS answers this server for every name. Only public-ca-wizard (with always-https) and panel-certificate use Let's Encrypt and public DNS, each for one name and no aliases.
- **WHMCS itself.** The module's functions ran from the PHP command line with the repo's stubs in place of WHMCS.
- **A separate storage server.** For backups, an SFTP user on the same server stands in for one.
- **The panel over the internet.** The browser proofs reached the panel through SSH port forwards from the machine that ran them, not through a firewall opened to the public; public-ca-wizard alone signs in at the panel's public HTTPS address. Its first-run setup still went through the SSH forward, as the panel allows only there.

## Phase 1: Home, Server and Security on the design system

Run on 2026-11-25 without root and without the dev VM: the panel binary and UI of `acdc45a` with throwaway state on loopback, driven by Chrome 158 through agent-browser. The browser replaced only the service list's answer, with 31 standard Ubuntu services taken from the real one, so the host's own service names are not published; every other reading came from the running panel.

| Slice | Transcript | Result |
| --- | --- | --- |
| Home, Server (Services, Storage, Network) and Security rebuilt on shadcn/ui: no horizontal scroll at 1440 and 390 px in light and dark, keyboard focus, radio-group filters, progress bars, right-to-left layout | [phase1-ui-astryx-1.txt](phase1-ui-astryx-1.txt) | 36 passed, 0 failed |

Screenshots are in [phase1-ui-astryx-1/](phase1-ui-astryx-1/): each screen at 1440 and 390 px in light and dark, the public-preview Home, the revoke confirmation, and the service list's unavailable state.

What this run does not show: the dev VM (the readings are the runner host's, minus its service names), Security's own access-key form (the shell's sign-in comes first, so the page opens signed in), and a right-to-left language (the browser set `dir="rtl"`; the shell's sidebar then still sat on the left and covered the content there, which [the final slice](#phase-1-the-file-manager-and-the-end-of-astryx) fixes).

## Phase 1: Hosting accounts and Backups on the design system

Run on 2026-11-25 without root and without the dev VM: the panel binary of `04697ba` (its Go code is unchanged since) and the UI of `48f1887`, with throwaway state on loopback and the static-site backup runner switched on, driven by Chrome 158 through agent-browser. Jev chose to rebuild both pages rather than remove them: no newer screen lists every Linux account, makes a bare one or suspends one with a reason, and none touches the old static sites' ZIP backups.

Backups ran on real data: two static sites, two ZIP backups made with the rebuilt button around real file edits, and a daily schedule saved through the rebuilt form. This run has no Linux account broker, so Hosting accounts shows the real "no configured broker" answer once; its other screens show a synthetic four-account inventory the browser put in place of the broker's answers. Two error states (a refused account and a refused ZIP backup) were answered by the browser too; the transcript names each replaced answer.

| Slice | Transcript | Result |
| --- | --- | --- |
| Hosting accounts and Backups rebuilt on shadcn/ui: no horizontal scroll at 1440 and 390 px in light and dark, keyboard focus, dialog focus and Esc, restore preview, schedule save, error copy with Technical details, right-to-left layout | [phase1-ui-astryx-2.txt](phase1-ui-astryx-2.txt) | 42 passed, 0 failed |

Screenshots are in [phase1-ui-astryx-2/](phase1-ui-astryx-2/): both pages at 1440 and 390 px in light and dark, Backups with no websites, the restore, remove and schedule confirmations, Hosting accounts with no broker, its web configuration preview, the create and suspend dialogs, an error on each page, and both pages right to left.

What this run does not show: the dev VM, a real Linux account broker (no account was created or suspended; the create and suspend dialogs were opened, not confirmed), a confirmed restore, removal, download or ZIP upload, the pages' own access-key forms (the shell's sign-in comes first), and a right-to-left language (the browser set `dir="rtl"`; the shell's sidebar then still sat on the left, which [the final slice](#phase-1-the-file-manager-and-the-end-of-astryx) fixes).

## Phase 1: Static sites (old) and the Panel tour on the design system

Run on 2026-11-25 without root and without the dev VM: the panel binary and UI of `13de92f` with throwaway state on loopback, driven by Chrome 158 through agent-browser. Nothing was replaced in the browser: the pages show only sample static sites on `example.test` that the run made through the panel's own API. The tour ran as the public preview, with the meta tag `cmd/panelpreview` adds.

| Slice | Transcript | Result |
| --- | --- | --- |
| Static sites (old) and the public Panel tour rebuilt on shadcn/ui: no horizontal scroll at 1440 and 390 px in light and dark, keyboard focus, the Files / ZIP backups radio group, dialog focus, save, backup, rename, suspend, create, import, remove, the File Manager and restore handoffs, no private calls from the tour, right-to-left layout | [phase1-ui-astryx-3.txt](phase1-ui-astryx-3.txt) | 42 passed, 0 failed |

Screenshots are in [phase1-ui-astryx-3/](phase1-ui-astryx-3/): both pages at 1440 and 390 px in light and dark, the ZIP backups pane, a binary file's details, the remove, import and refused-create dialogs, a search with no match, the tour's Backups, and right-to-left views.

What this run does not show: the dev VM, the old File Manager's own screen (still on Astryx in this run and only opened by the handoff; [the final slice](#phase-1-the-file-manager-and-the-end-of-astryx) rebuilds it), a site that needs recovery (the run cannot cause one), the pages' own access-key form (the shell's sign-in comes first), and a right-to-left language (the browser set `dir="rtl"`; the shell's sidebar then still sat on the left and covered the content there, which [the final slice](#phase-1-the-file-manager-and-the-end-of-astryx) fixes).

## Phase 1: the File Manager and the end of Astryx

Run on 2026-11-25 without root and without the dev VM: the panel binary and UI of `1386a8e` with throwaway state on loopback, driven by Chrome 158 through agent-browser. The browser replaced only the service list's answer, with 31 standard Ubuntu services, so the host's own service names are not published; the static sites are samples on `example.test`.

The old static sites' File Manager (`/websites/static/files`) is rebuilt on shadcn/ui, the last Astryx screen, and the `@astryxdesign` packages, their CSS and the `<Theme>` wrapper are gone (`rg -i astryx web/src web/package.json` finds nothing). Before the final run, the UI before and after the removal served the same state side by side: the computed styles of 4,044 elements on 20 pages, in light and dark, differ only in the font-family fallback list after the loaded Inter, because a small base layer keeps the colour scheme, font smoothing and text line height the screens were built with. The shell now puts its menu on the start side in a right-to-left page, at 1440 px and in the phone menu. The run also checks the slice's small fixes: a duplicate domain says so, alert titles match their text, the old ZIP backups page is named "Static site backups (old)", the dark charts' two lines differ by 3.41:1, and the sidebar footer shows the whole sign-in line.

| Slice | Transcript | Result |
| --- | --- | --- |
| File Manager rebuilt on shadcn/ui and Astryx removed: no horizontal scroll at 1440 and 390 px in light and dark, test ids and accessible names, upload, multiple upload, save, a changed-revision conflict, replace, rename, download, the saved-file link, delete, dialog focus and Esc, keyboard focus, right-to-left page and shell, earlier screens without Astryx, the small fixes | [phase1-ui-astryx-final.txt](phase1-ui-astryx-final.txt) | 56 passed, 0 failed |

Screenshots are in [phase1-ui-astryx-final/](phase1-ui-astryx-final/): the File Manager at 1440 and 390 px in light and dark, its binary-file, upload, multiple-upload, conflict, replace, rename and delete views, right to left at both widths with the phone menu, one light 1440 px shot of each earlier rebuilt screen (Home, Server, Storage, Network, Security, Customers, Hosting accounts, Static site backups (old), Static sites (old) and the Panel tour), the dark charts, the duplicate-domain dialog and the sidebar footer.

What this run does not show: the dev VM, the File Manager's own access-key form and a site that needs recovery (as before), the native ZIP import's duplicate-domain message (that route keeps its own error code), and a right-to-left language (the browser set `dir="rtl"`).

Follow-up polish, run the same way at 2026-11-25T09:27Z (UI of `2d38a81` before, `c395b14` after; [phase1-ui-astryx-final/polish.txt](phase1-ui-astryx-final/polish.txt), 17 passed, 0 failed): on Static sites (old) the "Local HTTP preview" and "New website" links went from 12.8 px and 28 px to 14 px and 30 px like the buttons beside them; the light charts' two lines went from 1.06:1 to 3.87:1 apart, with the teal mix 3.65:1 and ink 14.12:1 on the white card and the legend matching; the dark charts read as before (3.41:1, 3.28:1 and 11.18:1). Screenshots are the `polish-1440-*.jpg` files: Static sites (old) in light, Home and Network in light and dark.

## Phase 1: a standalone sign-in page

Before sign-in the panel shows only the sign-in or setup form, with the logo and a theme switch: no sidebar, page names, search or readings. The sign-in form gives each field a stable name, keeps `autocomplete` username, current-password and one-time-code, turns autocorrect off for the username and has a Show password switch. [sign-in-page.txt](phase1-sign-in-page/sign-in-page.txt) with [1440 px](phase1-sign-in-page/sign-in-1440.png), [390 px](phase1-sign-in-page/sign-in-390.png) and [first-run setup](phase1-sign-in-page/first-run-setup-1440.png) screenshots: signed out shows no sidebar at either width, signing in brings the full panel back, signing out returns to the form. The same transcript shows Keep me signed in ([390 px](phase1-sign-in-page/keep-signed-in-390.png), [Security page](phase1-sign-in-page/security-kept-1440.png)): a kept session gets 7 days and its badge; a normal one ends after 30 minutes unused or at 12 hours.
