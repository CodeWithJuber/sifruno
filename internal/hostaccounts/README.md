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
strict JSON≤16KiB, including duplicate/unknown/case-alias/null/invalidUTF8 guards.
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
account admission; existing processes, static serving, databases and mail remain
unaffected. It does not establish full SSH or hosting suspension. External changes
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
then does the broker admit its tools (`xfs_quota`, `openlitespeed`,
and `lswsctrl`). The web settings are not part of
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
  may write. `openlitespeed -t` must report no error and no warning about a
  broker vhost; otherwise the old files go back. Then `lswsctrl reload`
  restarts gracefully. The broker never edits `httpd_config.conf`: the
  installer adds `include /usr/local/lsws/conf/sifruno.conf` and
  server-level `namespace 1` once. New files take their SELinux label from
  the directory they are written in.

The step that depends on the tenant's own files, the access grant, runs
first and is idempotent: if the tenant swapped or changed those directories
the request is refused (409) before anything is journaled, so a tenant cannot
leave an unfinished operation that blocks every account. Then the intent is
journaled and the apply runs under its own two-minute limit, not the
caller's. If quota is not enforced or the new config fails its test, the old
files and the old quota go back, the operation is journaled as `rejected`
with the account unchanged, and the request answers 422 `web_rejected`. Any
other failure leaves the operation pending; it is finished, or ends
rejected, on the next start. Delete takes the site out of the config before
the user and home go, and keeps the user if that fails.

Limits for now:

- Delete of an account with a live site needs the web operation on: a broker
  started without `--web-user` cannot rewrite the config, so it refuses.
- Delete removes the vhost's `vhconf.conf` but leaves its empty directory and
  the site's logs under `/usr/local/lsws/logs/sifruno`.
- A suspended account's site keeps serving; suspension still blocks new
  logins only.

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
