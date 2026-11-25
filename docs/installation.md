# Install Sifruno

There are two ways to run Sifruno:

- **On a server:** the installer sets up a fresh AlmaLinux 9 server with one command. Start here.
- **On your own machine:** [build from source and run a private loopback panel](#run-from-source-on-your-own-machine). This is for development; it installs no services and hosts nothing.

## Install on a fresh AlmaLinux 9 server

The installer is `install.sh` inside the release tarball. It checks the server first and changes nothing if a check fails. You can run it again at any time: a second run changes nothing.

Status: the proof for this section is `scripts/devvm/fresh-install-test.sh`, which installs on a new VM and saves a transcript. Until a transcript of it is in [docs/proofs](proofs/README.md), the installer has been checked in parts only (the release build, a dry run, and the nsswitch and sshd rollbacks in a sandbox), not on a whole server.

### What the server needs

- **AlmaLinux 9 on x86_64**, freshly installed, and root access. Other systems are refused.
- **An SSH key for root** (or for a member of `wheel`). The installer turns password sign-in over SSH off. It refuses to run if it finds no key, so that you are not locked out.
- **`/home` on its own XFS filesystem, mounted with user quota, and empty.** Each website's disk limit is an XFS user quota. XFS turns quota on only when the filesystem is mounted, so it cannot be added later with a remount. The account broker also takes `/home` as its own: every folder in it must be an account the broker made.
- **Ports 80 and 443 open** for websites, and 8443 if you want the panel reachable from other machines. The installer does not change firewall rules.

### Set up /home

Do this before you run the installer. Sign in as root, not as a user whose home is in `/home`.

1. Move any other user's home out of `/home`, or remove the user:

   ```bash
   mkdir -p /var/home && usermod -m -d /var/home/NAME NAME
   ```

2. Find the empty disk or partition for `/home`. `mkfs.xfs` erases it, so check the name twice:

   ```bash
   lsblk -f
   ```

3. Make the filesystem and mount it with quota. Replace `/dev/vdb` with your device:

   ```bash
   mkfs.xfs /dev/vdb
   echo "UUID=$(blkid -s UUID -o value /dev/vdb) /home xfs defaults,usrquota,grpquota 0 0" >> /etc/fstab
   mount /home
   ```

   If `/home` is already its own XFS filesystem without quota, add `usrquota,grpquota` to its line in `/etc/fstab`, then run `umount /home && mount /home`.

4. Check it. The first command must show `xfs` and `usrquota`; the second must show `Accounting: ON` and `Enforcement: ON`:

   ```bash
   findmnt -no FSTYPE,OPTIONS /home
   xfs_quota -x -c 'state -u' /home
   ```

### Build the release

There is no published download yet, so build the release from source on a Linux machine with Git, Go **1.27.1** and Node.js **24.19.0**:

```bash
git clone https://github.com/CodeWithJuber/sifruno.git
cd sifruno
npm ci --ignore-scripts --no-audit --no-fund
npm --prefix web ci --ignore-scripts --no-audit --no-fund
scripts/install/build-release.sh
```

This writes `artifacts/release/sifruno-linux-amd64.tar.gz` and `sifruno-linux-amd64.tar.gz.sha256`. The tarball holds the four programs, the panel UI, `install.sh` and a `SHA256SUMS` of those files.

### Install

1. Copy both files to the server:

   ```bash
   scp artifacts/release/sifruno-linux-amd64.tar.gz artifacts/release/sifruno-linux-amd64.tar.gz.sha256 root@SERVER:/root/
   ```

2. On the server, as root, check the tarball and unpack it:

   ```bash
   cd /root && sha256sum -c sifruno-linux-amd64.tar.gz.sha256 && tar -xzf sifruno-linux-amd64.tar.gz && cd sifruno-linux-amd64
   ```

3. See what the installer would do. This changes nothing:

   ```bash
   ./install.sh --dry-run
   ```

4. Install. Without options the panel answers on the server's loopback address only:

   ```bash
   ./install.sh
   ```

   To also reach the panel from other machines over HTTPS on port 8443, and to turn on Let's Encrypt certificates for websites, name the panel's host and a contact address:

   ```bash
   ./install.sh --panel-host panel.example.com --acme-email admin@example.com
   ```

   `--acme-email` accepts the certificate authority's terms of service. `--no-start` installs everything but leaves the two Sifruno units off.

5. Keep your SSH session open. Open a second one and check that you can still sign in before you close the first.

The installer ends by printing the first-run steps and the rollback steps for this server.

### First run

1. The panel answers at `http://127.0.0.1:8080/` on the server. From your own computer, forward the port and open that address there:

   ```bash
   ssh -L 8080:127.0.0.1:8080 root@SERVER
   ```

2. Open **Websites**. The panel asks for the operator access key, then a username, a password of at least 12 characters and an authenticator app. The key is in `/var/lib/sifpanel/state/operator/access.key`, which only root and `sifpanel` can read. Open it on the server. Do not print it in a shared terminal, paste it into chat, or include it in screenshots.
3. If you gave `--panel-host`, sign in from anywhere at `https://NAME:8443/` after that. Only the admin sign-in works there; the access key and first-run setup stay on the server. The certificate is self-signed, so compare the fingerprint your browser shows with the one the panel logged: `journalctl -u sifruno | grep SHA-256`.

### What the installer changes

| Area | Change |
| --- | --- |
| Repositories | Adds LiteSpeed, EPEL and Remi, and enables CRB. |
| Packages | OpenLiteSpeed, LSPHP 8.3, MariaDB 10.11, Podman, and Apache for the Compat tier (installed, left off), plus a few tools. MariaDB and OpenLiteSpeed are enabled and started. |
| Users | Creates the system user `sifpanel`, which the panel runs as. |
| `/etc/nsswitch.conf` | Sets `passwd`, `group` and `shadow` to `files`. Users from SSSD or LDAP no longer resolve. If authselect manages the file, do not apply an authselect profile afterwards. A backup is kept beside the file. |
| sshd | Writes `/etc/ssh/sshd_config.d/40-sifruno.conf`: password sign-in off, and every user except root and members of `wheel` is SFTP-only with keys the broker manages in `/etc/sifruno/ssh/authorized_keys`. Checked with `sshd -t`, then sshd is reloaded. |
| OpenLiteSpeed | Adds one `include` line and turns on namespace isolation in `/usr/local/lsws/conf/httpd_config.conf`. A backup is kept beside the file. |
| MariaDB | Creates the admin user `sifpanel_dbadmin`; its password is only in `/var/lib/sifpanel/db-admin.cnf` (0600, `sifpanel`). |
| Files | Programs in `/usr/local/lib/sifruno/bin`, the panel UI in `/usr/local/lib/sifruno/ui`, WP-CLI (pinned checksum) in `/usr/local/lib/sifruno/wp-cli.phar`, restic 0.20.0 for backups (pinned checksum) in `/usr/local/lib/sifruno/restic`. |
| Folders | `/var/lib/sifpanel` and the panel's state in it, `/var/lib/sifruno-broker`, `/var/lib/sifruno-acme`, `/var/lib/sifruno-lscache` (root's, 0711: each website's page cache), `/etc/sifruno`, `/run/sifruno-broker`. On an upgrade, page caches that earlier releases kept in `/usr/local/lsws/cachedata` are removed, as OpenLiteSpeed's user, once no website uses them. |
| Services | `sifruno-broker.service` (root; the only part that changes the host) and `sifruno.service` (the panel, as `sifpanel`), enabled and started. |

It never changes the SELinux mode or the firewall. Backups are named `<file>.bak-YYYYMMDD-HHMM`. If sshd rejects the new policy, or the system cannot look up root after the nsswitch change, the installer puts the previous file back by itself and stops.

### Roll back

The installer prints these steps with the real backup names at the end of every run. Keep one SSH session open while you do this.

1. Stop and remove Sifruno's units:

   ```bash
   systemctl disable --now sifruno.service sifruno-broker.service
   rm /etc/systemd/system/sifruno.service /etc/systemd/system/sifruno-broker.service
   systemctl daemon-reload
   ```

2. Remove the sshd policy and reload sshd:

   ```bash
   rm /etc/ssh/sshd_config.d/40-sifruno.conf
   sshd -t && systemctl reload sshd
   ```

3. Put `nsswitch.conf` back from its backup:

   ```bash
   cp -a /etc/nsswitch.conf.bak-YYYYMMDD-HHMM /etc/nsswitch.conf
   ```

4. Put OpenLiteSpeed's config back from its backup:

   ```bash
   cp -a /usr/local/lsws/conf/httpd_config.conf.bak-YYYYMMDD-HHMM /usr/local/lsws/conf/httpd_config.conf && systemctl restart lsws
   ```

Packages, the `sifpanel` user, websites and databases stay. Remove them by hand if you want them gone.

### If the installer stops

- **"REFUSED"** lines come from the checks at the start. Each says what is wrong, why it matters and what to do. Nothing was changed.
- **A unit did not start:** the installer prints the unit's last log lines. `journalctl -u sifruno-broker` and `journalctl -u sifruno` show more.
- **Run it again** after you fix the cause. Steps that are already done are skipped.

## Run from source on your own machine

These steps build the source and run a private loopback panel for development. They do not install services, create hosting accounts or configure DNS, TLS or mail. The commands below were source-reviewed, not replayed on a clean machine.

### Windows (PowerShell)

1. Install Git, Node.js **24.19.0** (including npm), and Go **1.27.1**. Obtain them from their official distributors. The repository also provides the pinned Windows tool bootstrap described below; it downloads tools only when you explicitly run it. Open PowerShell as your ordinary user.
2. Clone the repository and enter its root. Every command below runs from that directory:

   ```powershell
   git clone https://github.com/CodeWithJuber/sifruno.git
   Set-Location sifruno
   ```

3. Install the locked root and UI dependencies, without dependency lifecycle scripts:

   ```powershell
   npm ci --ignore-scripts --no-audit --no-fund
   npm --prefix web ci --ignore-scripts --no-audit --no-fund
   npm run panel:build
   ```

4. Build the panel and local CLI with your installed Go toolchain:

   ```powershell
   New-Item -ItemType Directory -Force bin | Out-Null
   go build -buildvcs=false -o bin/sifruno.exe ./cmd/sifruno
   go build -buildvcs=false -o bin/panelctl.exe ./cmd/panelctl
   ```

   Builds may download the module versions recorded by `go.mod`/`go.sum`. Do not substitute a different dependency set. For the repository's pinned Windows Go bootstrap/wrapper, see the toolchain note below.

5. Choose a dedicated private state directory, outside source assets and any web-served directory. Keep the same value for the panel and CLI:

   ```powershell
   $panelState = Join-Path $env:LOCALAPPDATA 'Sifruno/local-panel'
   ./bin/sifruno.exe --listen 127.0.0.1:8080 --sites-listen 127.0.0.1:8082 --state "$panelState" --ui web/dist
   ```

   Keep this terminal open. Visit **http://127.0.0.1:8080**. The second listener is for app-owned static-site previews; it is not Apache/PHP hosting. Do not expose either listener publicly.

6. Create the admin account. Open **Websites**: a new panel asks for first-run setup.
   - Open the generated operator key privately on this machine using a local editor and enter it. The file is `operator/access.key` inside the chosen state directory. Do not print it to the terminal, paste it into chat, commit it, include it in screenshots, or serve the state directory.
   - Choose a username and a password of at least 12 characters.
   - Add the key the panel shows to an authenticator app (Google Authenticator, Microsoft Authenticator, 1Password and others), then enter the 6-digit code it shows.

   From then on, sign in with username, password and a fresh code. The access key still signs in on this machine, for example when the phone with the authenticator app is lost. Sessions last 15 minutes.

7. Optional: reach the panel from another machine. Add `--https-listen 0.0.0.0:2083 --panel-host panel.example.com` (your server's name or IP; several names are comma-separated). Without `--tls-cert` and `--tls-key` the panel makes a self-signed certificate and prints its SHA-256 fingerprint; your browser warns until you use a real certificate, so compare the fingerprint before you continue. Over HTTPS only the admin sign-in works: the access key and first-run setup stay on the server. Open the port in your firewall yourself; this guide does not change firewall rules.

8. To try static hosting, create a website in **Websites**, open its **File Manager**, and choose **Upload file**. Select a static asset, review its relative path and confirm. Open the website preview to check the file, then use **Backups** to create a native ZIP. Follow the [upload and recovery walkthrough](archive/site-file-upload.md) for the exact scope and limits.

9. Verify the panel and CLI using the commands below, from a second terminal in the repository root. Stop the panel with **Ctrl+C** in its original terminal. Preserve its state directory to retain sites, recovery history and operator state; deleting it is not an upgrade procedure.

#### Pinned Windows Go toolchain (alternative to installed Go)

From the repository root, explicitly run the bootstrap, without `-Analysis`:

```powershell
.\scripts\bootstrap-tools.ps1
.\scripts\go.ps1 build -buildvcs=false -o bin/sifruno.exe ./cmd/sifruno
.\scripts\go.ps1 build -buildvcs=false -o bin/panelctl.exe ./cmd/panelctl
```

The bootstrap downloads Go 1.27.1 Windows amd64 and checks its pinned SHA-256. The wrapper uses repository-local tooling/cache. This is a development tool bootstrap, not a panel/service installer.

#### Verify local responses

While the panel is running, in a second PowerShell terminal set the same state path:

```powershell
$panelState = Join-Path $env:LOCALAPPDATA 'Sifruno/local-panel'
Invoke-RestMethod http://127.0.0.1:8080/api/v1/server
Invoke-RestMethod http://127.0.0.1:8080/api/v1/status
Invoke-RestMethod http://127.0.0.1:8080/openapi.json
./bin/panelctl.exe --state "$panelState" --panel-url http://127.0.0.1:8080 sites list
```

The server response is telemetry; status is compatibility data, not a production-readiness or health certificate. `sites list` exercises authenticated HTTP using the local key without displaying it. `panelctl status` checks local compatibility; `status --require-ready` is expected to fail while compatibility obligations remain unqualified. There is no documented `/health` route.

On Linux/macOS, use `curl --fail http://127.0.0.1:8080/api/v1/server` and `./bin/panelctl --state "$panel_state" --panel-url http://127.0.0.1:8080 sites list` from a second terminal, with the same state value. Keep authentication material private.

### Linux and macOS

Use an installed Git/Node.js/npm/Go toolchain matching the versions above. Run as a normal nonroot user; hosting on a server is the installer's job, described above.

```sh
git clone https://github.com/CodeWithJuber/sifruno.git
cd sifruno
npm ci --ignore-scripts --no-audit --no-fund
npm --prefix web ci --ignore-scripts --no-audit --no-fund
npm run panel:build
mkdir -p bin
go build -buildvcs=false -o bin/sifruno ./cmd/sifruno
go build -buildvcs=false -o bin/panelctl ./cmd/panelctl
panel_state="$HOME/.local/share/sifruno/local-panel"
./bin/sifruno --listen 127.0.0.1:8080 --sites-listen 127.0.0.1:8082 --state "$panel_state" --ui web/dist
```

Open the same loopback URL and complete first-run setup as in step 6. Stop with Ctrl+C and retain state. Windows execution has been observed. Linux qualification covers specific isolated slices described in the evidence guides, not every distribution or a full hosting installation. macOS native execution remains unverified; successful compilation does not establish runtime qualification.

### Hosting accounts on a development machine

Accounts and websites need the Linux account broker, which the local-panel steps above do not set up. Use [the installer](#install-on-a-fresh-almalinux-9-server) on an AlmaLinux 9 server, or the [dev VM](../scripts/devvm/README.md), which runs the same installer.

### Troubleshooting the local panel

- **UI or modules missing:** run both `npm ci` commands, then `npm run panel:build`. `--ui web/dist` is relative to the process working directory; start from the repository root.
- **Port already in use:** stop your own earlier panel, or choose unused loopback ports with `--listen` and `--sites-listen`. Use the same panel URL for CLI requests. Do not change firewall rules to make this guide work.
- **State appears empty or sign-in differs:** confirm the panel and CLI use the same absolute state directory. Do not replace an existing operator key or delete state as a quick fix.
- **Lost the admin password or authenticator app:** sign in with the access key from this machine to keep working. To set up the admin again, stop the panel, move `operator/admins.json` out of the state directory, and start the panel; it asks for first-run setup. Keep the moved file until the new admin works.
- **"Too many sign-in attempts":** each account allows five tries, then one more per minute. Wait a minute; the access key is not affected.
- **Accounts unavailable:** the local-panel steps do not set up the account broker. Use the installer on an AlmaLinux 9 server, or the dev VM.
- **Build fails:** verify tool versions and run from the repository root. Source builds and runtime qualification are separate; no prebuilt release asset is promised here.
