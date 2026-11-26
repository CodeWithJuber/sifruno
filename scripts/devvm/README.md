# Dev VM

A disposable AlmaLinux 9 guest for the product's proofs (saved runs are in [docs/proofs](../../docs/proofs/README.md)). A slice is done when it runs here, not when it compiles.

The VM runs under QEMU as an ordinary user and is reachable only through loopback port forwards. Root signs in with a key made for this VM alone. It uses KVM when `/dev/kvm` is usable and software emulation otherwise; emulation works on any machine but is several times slower (the first boot takes a few minutes and the package install about half an hour).

## What you need on the host

`qemu-system-x86_64`, `qemu-img`, `cloud-localds`, `ssh`, `curl`, `python3`, and the Go version CI pins. On Ubuntu:

```bash
sudo apt-get install qemu-system-x86 qemu-utils cloud-image-utils
```

About 4 GB of disk for the image and the VM's disks.

## Create, provision, prove

Provisioning runs the real installer, so build the release first. It needs the Go and Node versions CI pins and the repo's npm packages (`npm ci --ignore-scripts --no-audit --no-fund` and `npm --prefix web ci --ignore-scripts --no-audit --no-fund`).

```bash
scripts/install/build-release.sh
```

```bash
scripts/devvm/vm.sh create
```

```bash
scripts/devvm/vm.sh start
```

Put the release, its checksum and the provisioning script in:

```bash
scripts/devvm/vm.sh put artifacts/release/sifruno-linux-amd64.tar.gz /root/sifruno-linux-amd64.tar.gz
```

```bash
scripts/devvm/vm.sh put artifacts/release/sifruno-linux-amd64.tar.gz.sha256 /root/sifruno-linux-amd64.tar.gz.sha256
```

```bash
scripts/devvm/vm.sh put scripts/devvm/provision.sh /root/provision.sh
```

```bash
scripts/devvm/vm.sh ssh 'bash /root/provision.sh'
```

```bash
scripts/devvm/proof.sh broker-sftp 105
```

`scripts/devvm/proof.sh broker-web` proves the broker's web operation (web server access, quota, vhost, reload, delete) after provisioning.

The panel shell proof drives the panel in the VM with a browser on the host, so it also needs Node with the repo's npm packages and Playwright's Chromium (or a Chrome binary named in `SIFRUNO_PROOF_CHROME`):

```bash
scripts/devvm/proof.sh panel-shell
```

`proof.sh` prints PASS or FAIL for each check, saves the transcript under `artifacts/devvm/` and exits non-zero if anything failed. When you are finished:

```bash
scripts/devvm/vm.sh destroy
```

`vm.sh` keeps its files in `~/.cache/sifruno-devvm`; set `SIFRUNO_DEVVM_DIR` to put them elsewhere.

## What provisioning sets up

`provision.sh` is a wrapper for the dev VM. It checks the release against its `.sha256`, unpacks it to `/root/sifruno-release` and runs the product's installer, `scripts/install/install.sh`, with `--no-start`: the two Sifruno units are written but left off, because each proof starts its own broker and panel. Then it adds what only the proofs need. Set `SIFRUNO_RELEASE` to use a tarball or an unpacked release at another path.

The installer's part is the same on a real server, and [the installation guide](../../docs/installation.md) lists what it changes:

- **Repositories.** LiteSpeed, EPEL, CRB and Remi. Remi is required: LiteSpeed's `lsphp` extension packages link against library builds EL9 only gets from there.
- **Packages.** OpenLiteSpeed, LSPHP 8.3, MariaDB 10.11, Podman, and Apache for the Compat tier (installed, left off).
- **`/home`.** The installer refuses a server whose `/home` is not a separate XFS filesystem mounted with user quota, because XFS only enables quota at mount time. `vm.sh create` makes that disk. Root is the only login, so `/home` holds nothing but accounts, which the broker requires of its homes directory.
- **Broker host policy.** `passwd`, `group` and `shadow` in `nsswitch.conf` are set to `files` (stock AlmaLinux lists `sss` and `systemd` too, and the broker refuses that). The controller user `sifpanel` and the root-owned key directory `/etc/sifruno/ssh/authorized_keys` (mode 0711) are created. `/var/lib/sifpanel` is root's (0711); the panel writes in `/var/lib/sifpanel/state`, which `hostsetup --apply` makes together with `/var/lib/sifruno-broker` and `/run/sifruno-broker`.
- **sshd policy.** Deny by default: every login is SFTP-only and reads its keys from the broker's directory, with forwarding and TTYs off, unless it is root or in `wheel`. The file is validated with `sshd -t` before a reload and taken out again if sshd rejects it.
- **Programs and units.** `sifruno`, `hostbroker`, `hostsetup` and `panelctl` in `/usr/local/lib/sifruno/bin`, the panel UI in `/usr/local/lib/sifruno/ui`, WP-CLI (pinned checksum) beside them, the panel's MariaDB option file `/var/lib/sifpanel/db-admin.cnf`, and `sifruno-broker.service` and `sifruno.service`.
- **Certificates.** `/var/lib/sifruno-acme` (sifpanel, 0755) holds the panel's HTTP-01 challenge files, which every vhost serves at `/.well-known/acme-challenge/`.
- **Page cache.** `/var/lib/sifruno-lscache` (root, 0711) holds each live site's LSCache store, which OpenLiteSpeed makes and gives to its user. Stores that earlier releases left in `/usr/local/lsws/cachedata` are removed as OpenLiteSpeed's user once no vhost names them.

For the proofs only, `provision.sh` then:

- moves Apache to loopback port 8080, so the migrate-verify proof can start it next to OpenLiteSpeed. The installed panel listens on 127.0.0.1:8080 too, so the two cannot run at once;
- creates `/opt/sifruno-proof`, where `proof.sh` copies each proof's programs;
- installs Let's Encrypt's test CA Pebble (pinned release and checksums) and its DNS test server as the `pebble` and `pebble-challtestsrv` units, off at boot: the DNS server answers 127.0.0.1 for every name, and Pebble's ACME directory is `https://127.0.0.1:14000/dir`, served with a certificate from `/etc/pebble/api-ca.pem`. Pebble makes a new issuing CA at every start; fetch it from `https://127.0.0.1:15000/roots/0`.

## Fresh-install test

`fresh-install-test.sh` is the test for the Phase 1 gate "one command installs on a new AlmaLinux server". It builds the release, deletes the dev VM, creates a new one, provisions it with the installer starting the services, and then checks that both units are active, the panel answers on loopback, the broker socket exists, `hostbroker --check-host` passes and SELinux is still enforcing. It runs the installer a second time to show that a second run changes nothing, and saves the transcript under `artifacts/devvm/`. It deletes the VM's disks, so it asks for a flag:

```bash
scripts/devvm/fresh-install-test.sh --destroy-vm
```

It leaves both units running. The proofs start their own broker on the same socket, so turn the units off before a proof:

```bash
scripts/devvm/vm.sh ssh 'systemctl disable --now sifruno sifruno-broker'
```

`--existing-host` installs on the server a `ports` file names instead. Every night, `.github/workflows/nightly-install.yml` runs it that way on a throwaway Linode that `scripts/ci/nightly-fresh-install.sh` creates and always deletes. That test is off until the owner adds the repository secret the workflow names. The script also runs by hand with a Linode token in `SIFRUNO_NIGHTLY_LINODE_TOKEN`; there `SIFRUNO_NIGHTLY_KEEP=1` keeps the Linode for a manual test, with its SSH key in `SIFRUNO_NIGHTLY_KEEP_DIR`, and prints the command that deletes it.

## Proofs

Saved transcripts of these runs are in [docs/proofs](../../docs/proofs/README.md).

| Plan item | Command | What it shows |
| --- | --- | --- |
| Phase 0, item 8 (Proof 2) | `proof.sh broker-sftp [extra-accounts]` | The root broker creates a regular Linux user with subordinate ID ranges; the user signs in over SFTP with a broker-managed key; it gets no shell and no port forwarding; a key it adds itself is ignored; a second account cannot read the first; suspend, resume, key removal and delete behave; more than 100 accounts work. |
| Phase 0, item 7 (Proof 1) | `proof.sh wordpress-ols` | The broker creates the account; `olsweb` renders the OpenLiteSpeed config from a typed spec; WP-CLI installs WordPress as that user against its own database; PHP runs as the user inside OpenLiteSpeed's namespace container and sees only its own home; sensitive paths are denied at the vhost; a 200 MiB XFS quota holds. Web-server access (an ACL) and the quota are set by the proof script, standing in for broker operations still to build. Run `broker-sftp` first. |
| Phase 1 gate: restic backups off the server, with a restore drill | `proof.sh backups` | An SFTP user on the VM (home in `/srv`, outside the broker's `/home`) stands in for the storage server; a target with a wrong host key is refused; the broker backs up a WordPress site and its database there; its files are deleted and a table dropped; the broker restores both, the site serves its title again and the table is back; no temporary MariaDB user or staging folder is left; the drill passes; no password is in any process's arguments. Installs restic the installer's way if the VM predates it. |
| Phase 1: file manager on the real home folder | `proof.sh files` | The broker runs the file helper as the site's user: seen while a paused upload waits, it runs as that user from `/usr/local/lib/sifruno/bin/sifruno-files`, in the home, in `user-<uid>.slice` in its own `sifruno-site-` unit, with NoNewPrivs and no capabilities. A 20 MiB upload is the user's, arrives whole and raises the account's XFS quota use; 50 MiB more is refused at the 64 MiB quota and leaves nothing. A link to `/etc/shadow` is listed as a link; reading, downloading or writing through it, or through a link to `/etc`, is refused. An edit of `index.php` changes what the site serves, and a save at a stale version is refused. Deleting a folder holding links to a folder in the home and to `/etc` leaves both targets alone. A suspended site's files list but do not change. Not run yet. |
| Phase 1: small WHMCS module (create, suspend, unsuspend, terminate) | `proof.sh whmcs-module` | The module in `integrations/whmcs` runs with the VM's lsphp PHP CLI against the real panel and broker. The panel also serves HTTPS on loopback with its self-signed certificate; an API token is made through the session API with the access key. TestConnection passes with the token and the certificate file, and refuses a wrong token and a missing certificate file; CreateAccount starts the wizard, the job finishes, the account ID is saved, and the service's username and password sign in to WordPress; Suspend gives 403, Unsuspend serves WordPress again, Terminate removes the site and its Linux user; no token or password is in the module log or the panel log. Not run yet. |
| Phase 1: admin and customer login | `proof.sh customer-login` | The panel runs as sifpanel with the broker and also serves HTTPS for `panel.sifruno.test`. A browser on the host sets up the admin, has the wizard make two PHP sites, and gives a customer a login for one on the new Customers page. The customer, over HTTPS, opens the one-time setup link (a wrong code is refused; the link then works no more), signs in, sees the site-owner menu and only its site; another site's address and API answers are refused like a site that does not exist, as are the server, accounts, other logins, wizard jobs and suspending its own site. It signs out and in again with a fresh code. The admin views the panel as the customer (banner naming the customer, the customer's menu and site only) and goes back; turning the login off signs the customer out. In the VM, `customers.json` is sifpanel's, 0600, with an Argon2id hash and no setup link, and the panel log holds no link. Not run yet. |
| Phase 1: Migration v1 from cPanel over root SSH | `proof.sh migrate-cpanel` | Against a stand-in, not cPanel: a Podman container (AlmaLinux 9.6 pinned by digest) with sshd, MariaDB, Apache and PHP-FPM, and stub `whmapi1`/`uapi` scripts that print the JSON shapes of cPanel's public API docs for its six accounts. The panel (driven through its API with a session) connects with a key made for the move; reading the server is refused until the fingerprint `ssh-keygen -lf` shows there is confirmed, and refused again until the admin's command adds the key line; discovery lists the accounts. A WordPress 7.1.5 site that keeps the stock Akismet plugin moves, its Akismet `.htaccess` converted (the copy answers 403 for the plugin folder, its PHP and a path-info trick, and 200 for the allow-listed CSS, JS and images, and verify checks them on both sites): same account name and `public_html`, `wp-config.php` unchanged, the database user with the same password hash, the same rows, the same PHP version, the cron job; the preview on this server serves it; verify passes; "ready" names A records at the VM's address; the key line is gone from the old server and the key from this one; no password or hash is in any process's arguments or the job record. A site with a password folder (user file in `.htpasswds`) and a `Deny from all` folder moves, converted: the copy answers 401 without the password and with a wrong one, 200 with it (subfolder and PHP page too), 403 for the closed folder; the realm's user file is root's, 0640, in `/var/lib/sifruno-realms/<site>/`, readable by the web server user through an ACL; verify checks 401 and 403 on both sites; root rewrite rules into the closed folders answer 401 and 403, not their content; other spellings of the paths (double slash, dot segments, %-escapes, a trailing slash) answer exactly 401 or 403; a folder open to 127.0.0.2 only and one closed to it answer 200 and 403 by client address (`curl --interface`), and port 80 has no IPv6 listener. A site with a directive the converter does not know is refused before anything is created; a site whose database has a trigger fails the copy and its account, database and user are removed. A tenant that swaps a folder for a link to `/root` during the copy, or holds a hard link to a root-only file, gets nothing of `/root` onto this server: the old server reads the home as the account. A token cannot open a source. Not run yet. |
| Phase 1 gate: the wizard puts an SSL WordPress site live in 2 minutes, with a public CA | `proofs/public-ca-wizard.sh LOGIN_FILE DOMAIN` | Not through `proof.sh` or the VM: run from your own machine against a server installed with `--panel-host` and `--acme-email` whose admin exists, for a DOMAIN in public DNS with 80 and 443 open. A browser signs in at the panel's HTTPS address and runs the wizard; the script times Create to the last screen and to the site's first HTTPS 200, then checks the Let's Encrypt certificate with curl, openssl and a browser, all with the system's trust store. It asks for one real certificate, so run it once per domain. |
| Phase 1: Always use HTTPS on a site with a public certificate | `SIFRUNO_DEVVM_DIR=FOLDER proofs/always-https.sh LOGIN_FILE DOMAIN` | Run from your own machine after `public-ca-wizard.sh` made DOMAIN, with the same login file, and `SIFRUNO_DEVVM_DIR` naming the server's `vm.sh` folder. Over the internet with the system's trust store: plain http for DOMAIN answers 301 to the same address on https with the path and query kept, https answers 200, and following the redirect ends on the WordPress site after one hop. A file in the ACME challenge folder is served over http, and an alias the certificate does not cover (a `.test` name, so no certificate is asked for) answers 200 on http. The admin signs in to the panel's API at its HTTPS address and turns the switch off (http answers 200, the config has no https rule) and on again (301 again, not a cached page); a switch that is not true or false and a stale revision are refused. It asks for no certificate. |
| Phase 0, item 9 (Proof 3), rehearsal | `proof.sh migrate-verify` | On a stand-in site, not a real cPanel one: the `.htaccess` scan sends a site with a password folder to the Compat tier; its access rules become probes; `migrate verify` keeps the cutover gate closed against an OpenLiteSpeed copy, where the folder opens, and opens it against an Apache copy. The real Proof 3 needs a HostLelo cPanel site and root SSH to it. |

The real Proof 3 against one of HostLelo's cPanel sites takes two commands. The scan runs as root on the cPanel server and only reads; verify runs from any machine that can reach both servers:

```bash
panelctl htaccess scan --root /home/USER/public_html --layout single --json --details > scan.json
```

```bash
panelctl migrate verify --old https://example.com --new https://example.com --new-connect NEW_SERVER_IP:443 --insecure-new-tls --probes-file probes.json --out report.json
```

`--insecure-new-tls` is needed only until the copied certificate is installed on the new server; it is a warning, and warnings keep the gate closed, so after reviewing the report rerun with `--accept-warnings` as well. `probes.json` is a JSON list of `{"path": "/private/", "kind": "auth"}` and `{"path": "/wp-config.php.bak", "kind": "deny"}` entries; `proofs/migrate-verify.guest.sh` shows how to build it from `scan.json`. Exit status 0 means the gate is open, 3 that it is closed.
