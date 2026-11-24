# Native Linux account foundation

This package separates an unprivileged controller from a root-only local Unix
socket broker. It supplies managed regular Linux identities with subordinate ID
ranges, private primary groups, homes, public_html directories and SFTP keys. Domain is validated reserved metadata only: this slice
does not configure web servers, DNS, TLS, mail, databases, PHP or cPanel behavior.

The broker requires an explicitly declared dedicated root-owned state directory
(0700), managed homes parent (0755), and root-owned nonwritable socket parent
(0755). It never silently changes unrelated /home or host policy. The socket is
exclusive0600 and controller-owned inside that root-owned parent. An existing
socket is refused; only the broker's original socket inode is removed on normal
shutdown. Broker SO_PEERCRED admission allows exactly one existing non-root
controller UID, rejecting root and other identities. Clients validate socket
ownership/mode, root parent authority and root server peer credentials. No remote
network listener, passwords, free-form commands, deletion or rollback API exists.

Native execution requires preinstalled regular root-owned binaries at fixed
paths: /usr/sbin/groupadd, useradd, usermod, nologin; /usr/bin/passwd and chage.
Arguments are fixed typed options and validated account identity. Subprocesses
have fixed credential-free locale/PATH, no shell and bounded output. Commands
have15second deadlines within the broker request's45second overall deadline;
the controller client also has45seconds. No /etc/shadow hashes are read or logged;
locked-password and account-expiry observations use passwd status and chage list.
Only exact locked status tokens L and LK are supported. The root-owned regular
nonwritable /etc/default/useradd must contain exactly one literal
CREATE_MAIL_SPOOL=yes or CREATE_MAIL_SPOOL=no line. This bounded policy is rechecked
before utilities; the broker never rewrites it. New identities are regular
(non-system) users created by fixed useradd arguments with explicit UID/GID and
home creation, retaining locked passwords and nologin. Regular mode lets shadow
allocate the subordinate UID and GID ranges from login.defs, which rootless
containers need; the earlier system-account mode with a zero subordinate count
ruled them out. Mail policy is a useradd default, not a login.defs -K key: with
CREATE_MAIL_SPOOL=yes a regular user gets a spool file, and Delete removes that
one file when it is a regular file owned by the account. The earlier
[service-account contract](../../docs/archive/service-account-mail-policy.md)
describes the system-account mode this replaced. Explicit --groups '' excludes
supplementary defaults; native verification requires the private primary group
only and no member additions. The broker does not check the subordinate ranges
itself; the dev VM proof does.

This implementation explicitly requires files-only passwd/group/shadow policy in
the existing nsswitch.conf. LDAP, SSSD, systemd dynamic identities and other NSS
providers are unsupported. It never rewrites this policy. A disposable guest may
declare the files-only qualification fixture; that is an explicit precondition,
not zero-configuration AlmaLinux, production installer or vendor compatibility.
The policy is rechecked before operations. The dedicated homes parent starts
empty and subsequently contains only journal-reserved account directories.

Usernames are3–32ASCIIbytes, `[a-z][a-z0-9_]*`, with reserved service names refused;
these are native foundation limits, not cPanel username rules. Domain must be a
lowercase ASCII multi-label DNS name and remains metadata. Actor is1–120bytes;
reason is1–500UTF8bytes, with controls and outer whitespace refused. Requests are
strict JSON≤16KiB (a certificate request up to 160 KiB), including duplicate/unknown/case-alias/null/invalidUTF8 guards.
There are at most 2000 managed accounts (`MaxAccounts`) and 256 immutable audit event
rows per account, so one account takes about 127 operations before its journal is full.

UID/GID pairs in20000–60000 are reserved in durable private bbolt metadata before
OS changes. Controller UID, existing local users/groups/homes and metadata
username/domain reservations are never adopted. groupadd/useradd create a fresh
private group, explicit UID/GID, regular-user mode, nologin shell, locked password and an empty home
from a private empty skeleton. A root-only ownership marker stays in broker state,
outside tenant-owned directories. Home/public_html mutation uses nofollow opened
directory handles. Captured dev/inode identities are durably recorded before
ownership changes; subsequent observation requires those exact identities.

Each mutation appends immutable linked intent/result audit rows with operationID,
sequence, before/after account metadata, actor/reason, status and timestamps.
Replay validates identity, revision and terminal-state consistency. These are OS
operation records, not file checkpoints that can undo native accounts. No private
password, key, shell output or credential content enters the journal or errors.

Interrupted operations retain their ID, UID/GID, username/domain and pending
journal. List exposes recovery_required and all further mutations stop. Restart
can complete only an exact journal-owned identity and captured filesystem object,
or confirm a completed expiry transition. Group-only/no-user outcomes, uncaptured
preexisting public_html, changed OS identity/ownership/inodes and other ambiguous
results remain blocked. No automatic useradd retry, adoption, deletion or cleanup
of OS accounts is attempted. Manual recovery tooling is outside this slice.

Active means no account-expiry restriction, while passwords stay locked and shell
stays nologin. Suspended sets account expiry to1970-01-02. It restricts PAM-aware
account admission; existing processes, databases and mail remain unaffected, and
a live site stops serving (see Websites). It does not establish full SSH or
hosting suspension. External changes
to UID/GID, tag, shell, home, lock/expiry or recorded directory identity require
recovery. Existing file content inside public_html is not inventoried or restored.

Portable tests use a typed fake solely for validation, serial reservation, durable
audit and recovery logic; they cannot certify provisioning. Real shadow-utils,
Unix peer credentials and ownership require root-owned disposable guest execution.
Non-Linux or unconfigured clients expose unavailable capability. No production
account actions are authorized by compiling or testing this package.

## SFTP keys

`SetSSHKeys` replaces an account's whole key set. A key is admitted only as
`type base64 [comment]` of an allowed type (ed25519, ECDSA P-256/384/521, RSA
2048 to 4096 bits) whose blob is exactly one well-formed key of that type; an
options prefix is refused. The broker writes the set to the fixed root-owned
file `/etc/sifruno/ssh/authorized_keys/<username>` (root, the account's private
group, 0640), each key behind `restrict,command="internal-sftp"`. The file lives
outside the home so an account cannot add keys or plant a link, and it is
replaced by rename so sshd never reads a partial file. The directory must
already exist as root-owned 0711; the broker does not create host policy, and
without it the operation reports unavailable. The intent and the target set are
journaled before the file changes, and an interrupted write is finished on
restart. The journal names a set by digest and never copies key text.

The shell stays nologin and the password stays locked. Whether a key gives SFTP
depends on the host's sshd policy, which the installer owns: `AuthorizedKeysFile`
must point at the directory above, and accounts must be held to
`ForceCommand internal-sftp` with forwarding off. `scripts/devvm/provision.sh`
shows that policy. SFTP is not chrooted; accounts are kept apart by home
ownership and mode.

## Websites

`SetWeb` puts an account's site live on OpenLiteSpeed with a PHP version
(8.1 to 8.4) and a disk quota (64 MiB to 1 TiB). It is off unless hostbroker
runs with `--web-user` (OpenLiteSpeed's `user` from `httpd_config.conf`); only
then does the broker admit its tools (`xfs_quota`, `openlitespeed`
and `systemctl`). The web settings are not part of
the pinned broker options, so the operation can be turned on for an existing
broker.

- Web server access: the broker writes a POSIX ACL (`u:<web uid>:--x` on the
  home, `r-x` on public_html) with `fsetxattr` on directory handles opened
  without following links and matched to the identities recorded at create.
  A tenant who swaps public_html for a symlink gets a refusal, not a grant on
  the target; `setfacl` is not used because it follows a symlink argument.
  The mode stays 0750.
- Quota: `xfs_quota` sets a hard limit and a soft limit 10% lower by numeric
  UID on the homes filesystem, which must have user quota enforced.
- Config: olsweb renders every live site from the broker's own records (no
  config text comes from the caller) into `conf/sifruno.conf` and
  `conf/vhosts/sifruno-u<id>/vhconf.conf`, written atomically, owned like the
  OpenLiteSpeed config directory and 0600, through directory handles. The
  broker refuses a config directory that the web user owns or that others
  may write, and sets the owner and mode only of directories it creates.
  `openlitespeed -t` is judged per vhost: a vhost whose config this change
  rewrote fails on an error or a warning, anything outside broker vhosts on
  an error, and a broker vhost the change did not touch is skipped, because
  what it reports comes from its own tenant's files. If the test fails, the
  old files go back with their owner and mode. Then `systemctl reload
  lsws` restarts OpenLiteSpeed gracefully (its unit reloads with
  `lswsctrl restart`). The broker never edits `httpd_config.conf`: the
  installer adds `include /usr/local/lsws/conf/sifruno.conf` and
  server-level `namespace 1` once. New files take their SELinux label from
  the directory they are written in.

The step that depends on the tenant's own files, the access grant, runs
first and is idempotent: if the tenant swapped or changed those directories
the request is refused (409) before anything is journaled, so a tenant cannot
leave an unfinished operation that blocks every account. Then the intent is
journaled and the apply runs under its own four-minute limit, not the
caller's; within it the config test gets 60 seconds and the graceful restart
120, because on a busy host a restart has taken longer than the 15 seconds
every other command gets. If quota is not enforced or the new config fails its test, the
old files and the recorded quota go back (none for a first enable: the
broker owns its accounts' quotas, so one set by hand is removed), the
operation is journaled as `rejected` with the account unchanged, and the
request answers 422 `web_rejected`. Any other failure leaves the operation
pending; it is finished, or ends rejected, on the next start. That includes
a reload that fails after the test passed: the new files stay in place, the
operation is journaled `recovery_required`, and every mutation of every
account is refused (503 `recovery`) until the broker restarts and its
reconcile installs the config again. This holds for every operation that
installs the config: web, certificate, state and delete. A web
operation needs two history rows and is refused (409) when they are not
free. Delete takes the site out of the config before the user and home go;
if that config fails its test, the delete ends `rejected` with the account
unchanged (422), and after any other failure the user is kept.

A state change of an account with a live site rewrites the site list too: a
suspended account's site stays in the config marked suspended, so
OpenLiteSpeed answers 403 for every request (ACME challenges included), and
an active one serves again. A suspended site's vhRoot and docRoot are
`/var/lib/sifruno-suspended`, not the tenant's home: an empty directory,
root-owned 0755, that the broker makes with `mkdirat` when the web operation
starts, so it keeps `/var/lib`'s SELinux label like the challenge directory.
If it holds anything or others can write it, the web operation does not
start. Every path a suspended vhost names (that directory, its logs, its
certificate, the challenge directory) is outside every home, so its config
test depends on nothing the tenant controls: a tenant who moves
`public_html` away cannot make their own suspend end rejected. Resumed, the
site gets its own home and `public_html` back.

In a state change the account changes first, as it does without a
site; then the list is installed under the web operation's four-minute
limit. If that config fails its test, the old files go back, the account is
put back into the state it had, and the change is journaled as `rejected`
with the account unchanged (422 `web_rejected`). Any other failure leaves
the change pending: on the next start the broker installs the list again
once the account is in its new state, or ends the change `rejected` the same
way. A pending state change whose account the next start finds in its old
state changed nothing (the broker stopped before the account changed, or
after a rejected list put it back) and ends `rejected`, unchanged, so it
does not block every account. Every later install of the site list, for
any account, also marks the sites of accounts that were suspended before
this rule. To enforce one at once, suspend it again: a suspend of a suspended account with a live site
installs the site list again, journaled like any state change (the
revision goes up by one). Without a live site, or for a resume of an active
account, the same state changes nothing.

The account list shows `web` (`php_version`, `quota_mib`) for each account
with a live site, so the panel can change one setting and keep the other;
a state change's answer shows it the same way. Both read it from the record: the stored account and the journal's rows
do not carry it, and a stored account that does is refused as damaged.

Limits for now:

- Delete of an account with a live site needs the web operation on: a broker
  started without `--web-user` cannot rewrite the config, so it refuses.
- Delete of an account with a live site is rejected while OpenLiteSpeed's
  config is broken outside the tenants' sites, or the `include` line is
  missing: the site cannot be taken out, so the user stays.
- Delete removes the vhost's `vhconf.conf` but leaves its empty directory and
  the site's logs under `/usr/local/lsws/logs/sifruno`.
- A state change of an account with a live site needs the web operation on,
  as its delete does, and is refused (503) before anything is journaled
  without it.
- A resume counts the site's own vhost as changed, and OpenLiteSpeed 1.9.4
  warns for a vhost whose tenant moved `public_html` away, so a resume of
  such an account ends `rejected` and the site stays suspended until the
  directory is back. A suspend does not depend on it (not yet run on the dev
  VM).

## Certificates

`SetCertificate` (`POST /v1/accounts/{id}/certificate`) installs a finished
certificate and key for an account's live site. The broker never runs ACME:
the panel obtains the certificate (HTTP-01 through the shared challenge
directory `/var/lib/sifruno-acme`, which every vhost maps at
`/.well-known/acme-challenge/`) and sends it here. The input is exactly
`expected_revision`, `cert_pem`, `key_pem` and `reason`; it needs the web
operation on (`--web-user`), and the request may be up to 160 KiB.

Checked before anything is journaled:

- Form (400 `invalid`): each PEM at most 64 KiB, with nothing but
  whitespace around its blocks and no PEM headers. The chain is 1 to 4
  `CERTIFICATE` blocks, each signed by the next, so the leaf comes first.
  If the leaf lists extended key usages, `serverAuth` is one of them. The
  key is one EC key on P-256 or P-384 (SEC 1 or PKCS #8) or one RSA key of
  2048 to 4096 bits (PKCS #1 or PKCS #8), and it matches the leaf.
- Fit (422 `certificate_rejected`): the leaf's DNS names include the
  account's domain exactly (the common name is ignored, and a wildcard does
  not count), and NotBefore <= now < NotAfter.
- Account (409 `conflict`): the revision matches, the account is active, its
  site is live, no WordPress install is running, and its identity verifies.

The broker writes only what it parsed: each certificate re-encoded from its
DER, leaf first, and the key as PKCS #8, never the caller's text. Files live
in `/etc/sifruno/tls`, which the broker makes root-owned 0700 with `mkdirat`
under a root-owned `/etc/sifruno` (the installer's), and opens with
`O_NOFOLLOW` from a handle on its parent; each site has its own 0700
directory there, `/etc/sifruno/tls/u<id>/`. Every file is root-owned 0600,
written beside its target with `O_EXCL|O_NOFOLLOW`, synced and renamed.

1. The parsed pair is staged as `cert.pem.next` and `key.pem.next` in the
   site's directory. OpenLiteSpeed never reads these.
2. The intent is journaled: action `certificate`, the target names the
   leaf's SHA-256 and NotAfter, the record's `tls_next` holds them, and the
   intent's `after` row has the revision plus one and the new certificate.
3. Under the web operation's own four-minute limit, the staged pair is read
   back, checked again and compared with the journaled leaf, then written as
   `cert.pem` (full chain) and `key.pem`. Every site with a certificate is
   rendered with a `vhssl` block, and the HTTPS listener (`*:443`,
   `sifruno-https`) is rendered, mapping only those sites. The listener's
   own certificate, `/etc/sifruno/tls/listener.crt` and `listener.key`, is
   made in Go when the first site gets a certificate (self-signed, CN
   `sifruno`, ECDSA P-256, ten years) and made again only if it is missing,
   broken or expired. No `openssl` runs.
4. `openlitespeed -t` is judged with the web operation's per-vhost rule;
   the site counts as changed when its certificate files changed, even if
   its vhconf.conf did not. Then `systemctl reload lsws`.
5. The result is journaled: `succeeded` with the record's `tls` and the
   account's `certificate` set, or `rejected` when the test failed. A
   rejected install puts back the old certificate files and config and
   leaves the account unchanged (422 `web_rejected`). Then the staged pair
   is removed.

Any other failure leaves the operation pending. On the next start the
broker finishes it from the staged pair, or ends it `rejected` if the config
now fails its test. If the staged pair is missing or names another
certificate, the operation stays pending for a person: the broker does not
guess what to install. The account list shows `certificate` (`not_after` in
Unix seconds, `fingerprint` as lowercase hex SHA-256 of the leaf) for each
account that has one, so the panel can renew in time; the journal's before
and after rows record it too. Delete takes the site out of the config first,
then removes the site's TLS directory with the user: only the live and
staged pairs and `writeAt`'s temporary names, and an unexpected file keeps
the delete pending rather than being removed.

Limits for now:

- One certificate per site, for the account's own domain only.
- A suspended site answers 403 to challenges as to everything else, so it
  cannot renew while suspended.
- OpenLiteSpeed refuses a challenge context whose directory is missing, so
  `/var/lib/sifruno-acme` must exist before any site's config is tested; the
  installer makes it, owned by the panel user, 0755.

## WordPress

`InstallWordPress` (`POST /v1/accounts/{id}/wordpress`) installs WordPress
into an account whose site is live (`SetWeb` first; it needs `--web-user`).
The caller sends the title, the admin user and email, and the database name
and user, both with the account's `<username>_` prefix. The site address is
the account's own domain, http or https. Both passwords travel in the request
body and reach WP-CLI on stdin (`--prompt=dbpass`, `--prompt=admin_password`),
never in a process argument. They are 12 to 128 printable characters with no
leading or trailing space, because WP-CLI trims what its prompt reads and the
database would not.

- WP-CLI 2.12.0 runs from `/usr/local/lib/sifruno/wp-cli.phar`, a root-owned
  0644 file that the installer downloads; the broker checks its bytes
  against the release's sha512, pinned in code, before every install.
- It runs with the site's own LSPHP CLI, as the account's user: its UID and
  GID, no supplementary groups, a clean environment, in public_html. Go's
  exec drops to that user before it changes directory. So the install can
  write only what the tenant can already write; a tenant's own files can
  change what it does, not what it may touch.
- Steps: `core download` (en_US), `config create` with database host
  127.0.0.1 (sites run in a namespace container that does not see the
  MariaDB socket), `wp-config.php` set to 0600, `core install` with
  `--skip-email`, then `core version` for the result.
- The checks run under the broker lock; the install does not, so a slow
  download holds no other account. The account is marked busy meanwhile:
  a second install, a suspend, a web change and a delete get 409, because
  the install runs as that user with the site's current PHP, and a user
  with running processes cannot be removed. The install has its own ten-minute limit,
  not the caller's.
- Nothing is journaled: the install changes only the tenant's files, with
  the tenant's rights, and the panel's job log records who asked. A failed
  step answers 422 `install_failed` with the step and the end of its output
  (printable ASCII, the passwords removed, at most 512 bytes). Whatever the
  step left in public_html stays there; installing again over an existing
  WordPress fails at the download step.

## Backups

Website backups go to an SFTP storage server with restic 0.20.0, which the
installer puts at `/usr/local/lib/sifruno/restic` (root, 0755). The broker
checks the binary's sha256 against the pin in `backup.go` before every run.
Each operation is fixed and typed; nothing goes through a shell.

| Route | Operation |
| --- | --- |
| `GET /v1/backup` | The broker's public key, whether restic is ready, the target. The first call makes the key pair and the repository password. |
| `POST /v1/backup/target` | `host`, `port`, `user`, `path`, `known_hosts`, `reason`. Opens the repository there with the broker's password, or makes one. |
| `POST /v1/accounts/{id}/backup` | `databases`, `reason`. The account's home and the named databases, as one snapshot. |
| `GET /v1/accounts/{id}/backups` | The account's snapshots, newest first. |
| `POST /v1/accounts/{id}/restore` | `expected_revision`, `snapshot`, `files`, `databases`, `reason`. |
| `POST /v1/accounts/{id}/drill` | `reason`. A restore drill of the latest snapshot. |
| `POST /v1/backup/prune` | `reason`. Keeps 7 daily and 4 weekly snapshots per site. |

One backup operation runs at a time, outside the broker lock, so a long
backup holds no other account; another account's unfinished operation does
not stop a backup, list or drill, only the account's own does. The status
never waits for a running operation, and a target change during one is
refused (409) rather than queued.

A failed step answers 422 `backup_failed` with the step (`target`,
`connect`, `password`, `repository`, `database`, `dump`, `backup`,
`snapshot`, `restore`, `copy`, `import`, `compare`, `check`, `prune`) and the
end of its output (printable ASCII, secrets removed, at most 512 bytes).

Secrets stay with the broker, in `<state>/backup/` (root, 0700):

- `ssh_key`: an ed25519 key made in Go (0600). The panel shows its public
  half for the admin to install on the storage server.
- `password`: the repository password, 32 random bytes (0600). restic reads
  it through `RESTIC_PASSWORD_FILE`; it is never an argument. The target
  change that first opens or makes a repository returns it once, so the
  admin can save it; no later answer carries it.
- `known_hosts`: the storage server's keys, from the admin (ssh-keyscan
  output), under the fixed alias `sifruno-backup-target`. There is no trust
  on first use. A new target is tried with `known_hosts.next` and replaces
  the old file only when its repository opens; a refused target changes
  nothing. A path holding a repository this password does not open is
  refused (`password`).

restic reaches the server with `-o sftp.command=`: restic splits that string
and starts `/usr/bin/ssh` directly with `-F /dev/null`, `BatchMode`,
`StrictHostKeyChecking=yes`, only the broker's key and known_hosts, no agent,
no password prompt and no forwarding. Every word is checked to hold no space,
quote or backslash, so the split gives back exactly that argument list.

Backup: the databases must carry the account's `<username>_` prefix, pass
dbhost's identifier rule and not fall inside another account's prefix. Each
is checked as root first: a database that does not exist, or has views,
triggers, stored routines or events, is refused (`database`). Restoring such
objects would let a `DEFINER` name another MariaDB user, so backups cover
tables and rows only. `mariadb-dump --no-defaults --single-transaction
--skip-triggers --hex-blob` dumps each as root over the socket into
`<state>/backup/dump/<id>/` (0700); restic backs up the home
(`--one-file-system`) and that folder as one snapshot tagged with the
account and its databases, and the dumps are removed. A backup changes no
account and holds no lock on it.

Restore (the account must be active or suspended, at its revision, and is
busy meanwhile, so a delete, suspend, web change or install gets 409):

1. The snapshot must be the account's own (host, tag and paths), holding
   each database asked for.
2. restic restores, as root, into a fresh staging folder
   `/var/lib/sifruno-restore/<op>` (0700), without the files' SELinux
   labels (`--exclude-xattr security.selinux`): the copy gives the home's
   files the home's. The folder is outside every home and
   outside the 0700 state, so the site user can be let in: the broker makes
   `/var/lib/sifruno-restore` root 0711 with `mkdirat`.
3. The staged home is given the account's owner and mode 0750, and the
   staging folder becomes root:<site group> 0750: only the site user may
   enter it.
4. `cp -R -P --preserve=mode,timestamps,links --remove-destination -T` runs
   as the site user (its UID and GID, no supplementary groups, a clean
   environment) and copies the staged home over the home. Files added since
   the backup stay. Root writes nothing into a path the tenant controls; a
   tenant's own files can harm only that tenant.
5. For each database: root makes it if it is gone, and a temporary user
   `sifruno_rst_<16 hex>` granted only `SELECT, INSERT, UPDATE, DELETE,
   CREATE, DROP, ALTER, INDEX, LOCK TABLES, REFERENCES` on exactly that
   database (escaped as dbhost escapes grants). The statements reach MariaDB
   on stdin. Its option file is root:<site group> 0440 in the staging
   folder. `mariadb --defaults-file=... --binary-mode --one-database` runs
   as the site user with the dump on stdin; `--binary-mode` turns off the
   client's own commands, such as `\!`. Without SUPER, SET USER, TRIGGER or
   routine privileges, nothing in a dump can name another `DEFINER`. The
   user is dropped afterwards, also when the load fails.

Nothing is written to the accounts' journal: it holds 256 rows per account,
and a nightly backup would fill it in four months. A backup and a drill
change no account; a restore changes only the tenant's own files and
databases with the tenant's rights, as a WordPress install does, and the
panel's job log records who asked. What a restore or drill leaves as root,
its staging folder and its temporary users, is listed in the broker's
database before it is made and removed afterwards; an interrupted one is
removed before the next backup operation starts.

Drill: the latest snapshot is restored with `--verify` into a root-only
staging folder (never opened to the site user), every file, folder and link
`restic ls` lists is compared by kind, size and link target, and
`restic check --read-data-subset=n/8` reads the week's eighth of the
repository's data, so all of it is read every eight weeks. A drill that
cannot run, or finds a difference, answers `passed: false` with the step.

Limits for now:

- SFTP only; S3 later.
- A database with views, triggers, routines or events is not backed up.
- A restore does not remove files added since the backup.
- The panel cannot yet take a saved password back: a new server opens an
  old repository only if this broker's own password does.
- `restic forget` keeps the last 7 daily and 4 weekly snapshots of a
  deleted site until they are removed by hand.

## Verification cost

Every request checks every account's files: its passwd and group identity (from
one cached parse, reused only while both files are the same objects with the
same change times), its home and public_html identities, and its ownership
marker. That check starts no process. The password-lock and expiry observation
needs `passwd --status` and `chage --list`, two processes per account, and
running it for all accounts on every request is what limited the broker to
about a hundred. It now runs for the account an operation touches and for a
rotating batch of 16 accounts per request, so an outside change to lock or
expiry is noticed when that account is next touched or when the rotation
reaches it, not on the very next request. With 16 accounts or fewer nothing
changes: all are fully checked every time.

`BenchmarkStoreScale` measures the store and journal at the account bound with
the fake native system. Native costs are measured on the dev VM.
