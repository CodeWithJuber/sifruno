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
controller UID, rejecting root and other identities. The controller UID must
lie outside the account range, 20000 to 60000; the broker and hostsetup
refuse one inside it. Clients validate socket
ownership/mode, root parent authority and root server peer credentials. No remote
network listener, passwords, free-form commands, deletion or rollback API exists.

Native execution requires preinstalled regular root-owned binaries at fixed
paths: /usr/sbin/groupadd, useradd, usermod, userdel, nologin; /usr/bin/passwd,
chage, kill (which runs only as an account's own user, see Processes),
systemctl (`daemon-reload` and `list-units` of one slice, see Resource
limits, and `kill` of a site run's own unit) and systemd-run (a site run's transient service, see WordPress).
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
strict JSON≤16KiB (a certificate request up to 160 KiB, a domains request up to 96 KiB), including duplicate/unknown/case-alias/null/invalidUTF8 guards.
There are at most 2000 managed accounts (`MaxAccounts`) and 256 audit event rows
per account at a time (`MaxHistoryRows`); compaction (below) keeps an account in
use far below that.

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

Every journaled change takes two rows (three when it needs recovery), so the
history is compacted. At the start of an operation, when no account has an
unfinished operation (an adopt may find a conflict on its own account, which
is left as it is), the history of each account that holds 192 rows or more is
compacted in one bbolt transaction:

- The last 32 rows are kept, from the first intent among them, for audit.
- Every row before them is removed, and one checkpoint row takes the sequence
  just before the kept rows. It records the account exactly as the last
  removed row left it (status and action `checkpoint`, actor
  `broker-compaction`, no before, the account as its after), so it stands for
  every row up to its own sequence.
- The record names the checkpoint's sequence (`history_start`). Sequences only
  grow: the next row follows the last kept one.
- The new history is checked as replay checks it before the transaction
  commits. A crash leaves the old history or the new one, never a mix, and a
  compaction that fails leaves the old one; the next operation tries again.

Replay accepts a checkpoint only as the first row, at the sequence the record
names, for a settled account (active or suspended) with the identity of the
record; the next intent's before must equal its after, as it must equal the
after of the operation before it in a history never compacted. A history whose
record names no start must still begin with the create at sequence 1, as
every history written before compaction does. Like the rest of the journal
this is a consistency check, not a signature: whoever can write the broker's
database can rewrite both consistently.

Compaction runs at the start of an operation, not only when the broker starts:
a broker may run for years between restarts, and every journaled operation of
the panel starts there, under the broker lock, with every account settled. It
does not run while the account list or a snapshot is read, so a snapshot
lease never sees a record change under it.

The operations a tenant can reach (web, domains, cron, certificate, adopt, SFTP
keys, plan) are refused (409) before anything is journaled once fewer than 19
rows are free: their two rows and a spare, plus 16 that stay for the
operator's suspend, resume and delete and the broker's own conflict record,
which are refused only when fewer than 3 rows are free (an adopt that ends a
conflict, which holds up every account, counts as the operator's). With compaction these
limits are a backstop for an account whose history could not be compacted.

Interrupted operations retain their ID, UID/GID, username/domain and pending
journal. List exposes recovery_required and all further mutations stop. Restart
can complete only an exact journal-owned identity and captured filesystem object,
or confirm a completed expiry transition. Group-only/no-user outcomes, uncaptured
preexisting public_html, changed OS identity/ownership/inodes and other ambiguous
results remain blocked. No automatic useradd retry, adoption, deletion or cleanup
of OS accounts is attempted. Manual recovery tooling is outside this slice.

Active means no account-expiry restriction, while passwords stay locked and shell
stays nologin. Suspended sets account expiry to1970-01-02. It restricts PAM-aware
account admission, a live site stops serving (see Websites), and the account's
running processes end (see Processes); databases and mail remain unaffected. It
does not establish full SSH or hosting suspension. External changes
to UID/GID, tag, shell, the home directory object or its owner, lock/expiry or
the ownership marker require recovery: only root can make them. Existing file
content inside public_html is not inventoried or restored.

### A tenant's own folders

The account's user owns its home and can change what the broker recorded
there: rename, replace or remove public_html, or change the mode of the home
or public_html. That concerns its own account only:

- It is not a conflict. Refresh checks only what root controls; the account
  list shows `site_folder_changed` for the account and its state stays
  active or suspended. Capability stays available.
- Operations that write into those folders verify them first and answer 409
  before anything is journaled: web, certificate and WordPress install.
  A resume of a live site whose public_html is gone ends rejected (see
  Websites).
- Everything else verifies only what root controls, before and after the
  intent: state changes (so the operator can suspend, suspend again and
  resume), SFTP keys, plan and delete. Delete checks the home's object and
  owner, not its mode, and removes it without following links. Restart
  finishes their interrupted operations the same way, so a tenant cannot
  keep one pending.
- Other accounts' web changes do not judge the changed account's vhost
  (see the config test under Websites).

The folder is fixed by the tenant putting it back, or by an operator
adopting the current one: `AdoptPublicHTML`
(`POST /v1/accounts/{id}/public-html`, input `expected_revision` and
`reason`).

- Checked before anything is journaled: the revision, no WordPress install
  running, and what only root controls (`VerifyAccount`; if that fails the
  answer is 503 `recovery`, because a new folder would not fix it). With
  the recorded folder in place there is nothing to adopt and nothing is
  journaled.
- The native step opens the homes directory, the home and public_html one
  component at a time with `O_NOFOLLOW|O_DIRECTORY` and requires the
  recorded home, owned by the account, and a public_html that is a
  directory owned by the account and its group on the home's filesystem.
  A missing folder, a link, a file or someone else's directory is refused
  (409) with nothing changed. Then it sets both to 0750 with `fchmod` on
  those handles. For a live site the web server's access is granted on the
  new folder the same way as for a web change: a folder that changed again
  meanwhile is 409, an ACL the host could not write is 503 `unavailable`.
  Both steps touch only the tenant's own directories and are safe to repeat.
- The intent (action `adopt`, the target naming the directory as
  `<device>:<inode>`) and the result are journaled and the revision goes
  up by one. A restart between the two records the named directory.
- An earlier broker journaled a conflict for these folder changes too. Such
  a conflict still stops every mutation, as the journal says; adopting the
  account's folder ends it `reconciled`, unchanged, before the adopt, once
  what only root controls verifies again. No other conflict is resolved
  this way.

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

## Processes

Delete and suspend end every process that runs as the account: an open SFTP
session, a PHP worker, a cron job, anything the tenant started. Not yet run
on the dev VM: `scripts/devvm/proofs/broker-isolation.guest.sh` and
`TestRootOnlyEndProcessesTakesOnlyTheAccount` are the proof to run.

- The broker runs `/usr/bin/kill -s KILL -- -1` as the account's own user:
  its UID and GID, no supplementary groups, in `/`, with a clean environment
  and no input, by a direct exec. Go's exec sets the groups, GID and UID in
  the child before it runs kill, and runs nothing when that fails. kill(2)
  with PID -1 from a process that is not root signals every process that
  user may signal, other than itself: those whose real or saved user ID is
  the account's, and those in user namespaces the account made (rootless
  containers). No other user's process can be hit, and the broker never
  sends a signal to -1 itself.
- Before every run the credential is checked again: the UID must be in the
  range the broker allocates (20000 to 60000, so never 0 or a system user),
  equal the GID, not be the controller's, and passwd and group must show
  exactly this account on it now (one user with its name and none other on
  its UID, the recorded home, tag and nologin shell, and its private group).
  Otherwise nothing runs. kill is one of the fixed binaries checked at start.
- A pass signals, then reads `/proc` until no process has the account's UID
  as its real, effective or saved user ID (a zombie not yet reaped counts),
  for up to 250 ms. Up to four passes catch what started meanwhile: a fork
  that raced the signal, or a process root started for the account. A scan
  stops between entries once its time is up.

Delete: after the intent is journaled and the site is out of the config, an
active account is expired and locked as a suspend does, so no new login or
cron job starts for it; then its processes end and `userdel` runs. userdel
refuses a user it finds busy (exit 8) before it changes anything
(shadow-utils 4.9 `userdel.c`); it checks threads and the account's
subordinate IDs too, so it is tried up to three times, each after the
processes were ended again. Ending processes has 20 seconds in all, every
pass of every try, apart from the delete's own limit: a tenant with very
many processes makes each `/proc` scan slow, and when the 20 seconds are
spent the user counts as busy.

Whatever stops the delete before userdel changed anything takes one path:
the user still busy, the 20 seconds spent, kill or a `/proc` read failing,
the lock failing, or the delete's time running out. The account gets back
the expiry it had, on a fresh limit of its own, and is checked; the site
goes back into the config; and the delete ends `rejected` with the account
unchanged, so every other account can still change. A busy user answers 409
`delete_busy` (the client's `ErrDeleteBusy`, which is also a conflict); the
other causes answer 503 `unavailable`. The next start does
the same for an interrupted delete. A delete stays pending, and stops every
mutation, only when a root step fails or its effect is unknown: the expiry
cannot be put back or the account does not check out afterwards, the site
cannot go back into the config (its test now fails, or the reload does), or
userdel exits other than 0 or 8, or does not finish, since nobody knows what
it changed.

The panel shows a busy refusal in plain words: "The account still had
running processes after 3 attempts, so nothing was removed. Suspend the site
first (that stops its processes and keeps the site off), then delete it
again." A delete from the site's page does that itself for an active site:
it suspends the site and asks for the delete once more, and says it did. If
that is refused too, the site stays suspended and the message says so. When
the 20 seconds run out first, fewer than three attempts were made; the
message still says three.

A tenant whose processes fork faster than the kill passes end them could
keep refusing the delete of an active site. The account's process limit
(Resource limits) bounds how many it can have: 100 tasks by default, in its
user slice and, for PAM sessions, as RLIMIT_NPROC, so the passes catch up.
`scripts/devvm/proofs/account-limits.guest.sh` is the proof to run on the
dev VM; it has not run yet. Suspending first still makes the operator's
intent win: a suspension stands even when processes survive it, so the site
is off and no login, cron job or PHP request starts for the account while
the delete is asked again.

Suspend: after the suspension is journaled (and a live site's list
installed), the account's processes end. This runs with the tenant's own
rights and changes no record, so it is not journaled. The suspension stands
either way; if a process outlived the last pass the answer is 503
`unavailable`, and a suspend of the suspended account, with or without a
site, ends its processes again. A suspend the next start finishes does not
end them: suspend again.

## Resource limits

Every account has limits on all of its processes together (`limits` on the
account: `processes`, `memory_mib`, `cpu_percent`). A new account gets
`DefaultLimits`: 100 tasks, 1024 MiB, 100% (one CPU). `SetPlan` changes
them (`POST /v1/accounts/{id}/plan`, input `plan`, optional `limits` with
all three keys, `expected_revision`, `reason`); left out, they stay. Bounds:
32 to 4096 tasks, 256 to 65536 MiB, 10 to 6400%.

Where they apply:

- User slice. The broker writes
  `/etc/systemd/system/user-<uid>.slice.d/50-sifruno-limits.conf`
  (`[Slice]` `TasksMax=`, `MemoryMax=<n>M`, `CPUQuota=<n>%`; root, 0644)
  and, when the slice is loaded, runs `/usr/bin/systemctl daemon-reload`
  (below). pam_systemd puts every PAM
  session of the user (SFTP, cron, `runuser`) in a scope under
  `user-<uid>.slice`, with `user@<uid>.service`; a slice's limits bound
  everything below it. The path is built only from a UID in the account
  range (never 0, a system user or the controller), reached through
  directory handles opened without following links from the root-owned
  unit directory, and the file is written beside its target and renamed.
  systemd reads a unit's configuration, drop-ins included, when the unit
  is first referenced, and a reload is needed only for a unit already in
  memory (systemd.unit(5), "Unit Garbage Collection", v252). So after a
  write the broker asks `systemctl list-units --all --plain --no-legend
  --full -- user-<uid>.slice`, which lists the units systemd has in memory
  and loads none (systemctl(1), list-units), and runs `daemon-reload` only
  when the slice is listed or the question fails: for a plan change of an
  active slice, and for a reused UID whose slice is still loaded, but not
  for a brand-new account. A reload rereads every unit file and reruns the
  generators, which on a busy host can take longer than a request, so the
  create's root steps (the drop-in, the reload, useradd and the home) run
  on the web operation's own four-minute limit, not the request's 45
  seconds, as a plan change does.
- PHP. Read from the OpenLiteSpeed 1.9.4 source, not yet run (the
  account-limits proof, section 6, checks it): OpenLiteSpeed can put lsphp
  in the user's slice. The server's `cgroups` in `CGIRLimit` is 0
  disallowed (its default), 1 allowed and off unless a vhost turns it on, 2
  allowed and on (`src/http/serverprocessconfig.h:48-50`,
  `src/extensions/cgi/cgidworker.cpp:409-416`); a vhost's `cgroups` is 1
  off or 2 on, and counts only when the server's is not 0
  (`src/http/httpvhost.cpp:3401-3405`). The installer sets the server's to
  1 and the broker renders 2 in each live vhost. lscgid then writes the new
  process into
  `/sys/fs/cgroup/user.slice/user-<uid>.slice/litespeed-exec.scope` and
  runs `/bin/systemctl start user-<uid>.slice` (`cgroup_v2`,
  `src/extensions/cgi/lscgid.cpp:471-529`, called at 620-622), so the
  slice's limits cover the site's PHP too. The lsphp app also gets `memSoftLimit`/`memHardLimit` (the plan's
  memory, as each process's RLIMIT_AS) and `procSoftLimit`/`procHardLimit`
  (the plan's processes as RLIMIT_NPROC, raised to the floor OpenLiteSpeed
  keeps, 496 for 4 children and 8 workers, `olsweb.ProcessFloor`). Read
  from the 1.9.4 source, not run: OpenLiteSpeed sets those rlimits on the
  path without its namespace container, and none in the container's path
  (`ns.c`), which broker sites use; there the slice is the bound.
- Every PAM session, as a backstop. The installer's
  `/etc/security/limits.d/90-sifruno-accounts.conf` sets nproc 4096 (soft
  and hard), the largest plan, for UIDs 20000 to 60000. The per-plan bound
  is the slice's TasksMax, which covers PAM sessions too (pam_systemd puts
  them in the slice). pam_limits applies the file in the session phase;
  RLIMIT_NPROC counts all tasks of the real UID on the host, so a fork loop
  in a session that somehow runs outside the slice still stops at fork().
  One number for every account never cuts below a plan; a per-account file
  would count the same tasks under a second limit that had to follow every
  plan change. It does not reach processes started without PAM: lsphp from
  lscgid and the broker's WP-CLI and placeholder runs, which run in the
  slice, or the broker's own fixed kill and cp as the account.

Create writes the drop-in before anything is journaled; if it cannot, the
create is refused (503) and nothing changes. A plan change journals its
intent with the new limits (`limits_next` in the record) and then applies
them: the drop-in, and for a live site whose limits changed the site list
(which needs the web operation; without it, or while WordPress installs,
it is refused before the intent). If the drop-in cannot be written or
loaded, or the site list fails its test, the old drop-in goes back and the
change ends `rejected` with the account unchanged (503 `unavailable` or 422
`web_rejected`); no other account is held up. A site list that fails after
its test stays pending like any web change; the next start finishes it.
Delete removes the drop-in once the user is gone; if that fails the delete
still succeeds. At every start, before the socket accepts requests, the
broker writes every account's recorded limits (the defaults for an account
made before limits were) and removes drop-ins of account-range UIDs no
account holds, then reloads once. A failure there is reported on stderr and
the broker starts anyway. The account list and the journal's rows show the
limits; an unchanged plan is a no-op only while the drop-in still holds
them.

Limits for now (not yet run on the dev VM):

- That `daemon-reload` applies a changed drop-in to an active slice at once
  is inferred, not documented: `systemctl set-property` is the documented
  runtime path. The dev VM proof reads `pids.max` after a change.
- Read from the OpenLiteSpeed 1.9.4 source, not yet run: OpenLiteSpeed
  writes into the slice's cgroup directory itself, outside systemd's
  knowledge (`lscgid.cpp:479-509`); how systemd treats that scope when the
  slice stops is not checked.
- No IO limit: IOWeight stays at its default, 100, for every account.
- systemctl is pinned at start like the other fixed utilities, so after a
  systemd package update creates and plan changes answer 503 until the
  broker restarts.

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
  what it reports comes from its own tenant's files. A served vhost of
  another account whose tenant changed its folder (`site_folder_changed`)
  that this change rewrote is excused one thing only: OpenLiteSpeed's
  missing-document-root pair, `configuration failed!` in that vhost's
  context together with `Path for document root is not accessible: <its
  public_html>/` (the broker-web proof, section 6). Its errors and every
  other warning still fail the change. A render rewrites every vhost once
  after an upgrade changes the rendered form, and that tenant's warning
  would otherwise reject every change of every account until the folder was
  back. The site the change is about, and a suspended site, are judged in
  full. If the test fails, the
  old files go back with their owner and mode. Then `systemctl reload
  lsws` restarts OpenLiteSpeed gracefully (its unit reloads with
  `lswsctrl restart`). The broker never edits `httpd_config.conf`: the
  installer adds `include /usr/local/lsws/conf/sifruno.conf` and
  server-level `namespace 1` once, and the package's stock `module cache`
  block if the file has none. New files take their SELinux label from
  the directory they are written in.
- Page cache (LSCache): each live site's `vhconf.conf` has its own
  `module cache` block with `ls_enabled 1` and its own store,
  `/usr/local/lsws/cachedata/sifruno-u<id>`, outside every home, so the
  purge headers a site's PHP sends reach its own pages only. OpenLiteSpeed
  makes that directory as root when it loads the config (mode 2770, owned
  by the web user); the package's `cachedata` is root-owned 0755, so no
  tenant can put a link there. `enableCache 0`: nothing is cached unless the
  site's response asks (the LiteSpeed Cache WordPress plugin does), and the
  module never caches a POST. A suspended site has `ls_enabled 0` and no
  store, because the module answers from its store when the request headers
  arrive, before the 403 rule. Delete removes the site's store once the
  site has left the config and its user is gone: the broker opens
  `cachedata` (root's and writable by no one else along its whole path) and
  removes each entry by name in its own directory handle, opened with
  O_NOFOLLOW, so a link in the store is removed itself, never followed. If
  that fails the delete still succeeds; what is left is cached pages under a
  name no new account gets. The site's logs stay.
- One invalid vhost at a restart: OpenLiteSpeed 1.9.4 configures each vhost
  on its own, at start and at a graceful restart, which starts a new
  instance (`configVHosts` in `src/main/httpserver.cpp`). A vhost whose
  config fails is left out with the warning `configuration failed!` and the
  server starts with the others; the listener maps no domain to it, because
  `addVirtualHostMapping` finds no vhost by that name. It stops reading a
  vhost at the first failure, and the document root comes first
  (`HttpVHost::config` in `src/http/httpvhost.cpp`), so while a tenant's
  public_html is missing the rest of that vhost's config is not checked.
  This is read from the 1.9.4 source, not run: what a request for the
  left-out vhost's domain then gets was not checked.

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
unchanged (422), and after any other failure the user is kept. If userdel
still finds the account busy after its processes were ended, the site goes
back and the delete ends `rejected` (409; see Processes).

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
- A tenant can make OpenLiteSpeed report an error, not the missing-folder
  warning, for its own vhost: for example a public_html that links into a
  directory OpenLiteSpeed denies. Errors stay fatal, so a change that
  rewrites that vhost (once after an upgrade changes the rendered form) is
  rejected until the link is gone, and a delete of that account that userdel
  refused cannot put its site back and stays pending.
- The process check reads each process's own user IDs. userdel also counts
  a thread with the account's UID inside another user's process, and a
  process under the account's subordinate IDs in a namespace someone else
  made; kill as the account cannot end those, so such a delete ends
  rejected.

## Domains and redirects

`SetSiteDomains` (`POST /v1/accounts/{id}/domains`) replaces a live site's
other domains (aliases) and its redirects; `GET` on the same path reads
them. The input is exactly `aliases` (a list of domains), `redirects` (a
list of objects with `domain` or `path`, `target` and `status`, each key
once and in this case), `expected_revision` and `reason`; both lists are
required, each possibly empty, and the request may be up to 96 KiB. It
needs the web operation on. The broker sorts both lists; the answer and the
record hold them in that order.

Checked before anything is journaled:

- Form (400 `invalid`): at most 15 aliases (with the account's own domain,
  olsweb's 16 per site), each a lowercase DNS name with at least two labels
  that OpenLiteSpeed can map (not `www.www.*` or `www.<one label>`), not the
  account's own domain, listed once. At most 100 redirects, checked with
  olsweb's own rules (`CheckRedirects`): a status of 301 or 302; a domain
  redirect names one of the site's domains, once, and a target of
  `http://` or `https://`, a host and an optional port, with no path, that
  is not the domain itself or another redirected domain; a path redirect
  names `/` and then up to 128 bytes of letters, digits and `- . _ ~ /`,
  with no empty part or part starting with a dot (so neither the ACME
  challenge path nor a hidden file), once, and a target of up to 256 bytes
  of `http://` or `https://`, a host that is a DNS name (no IP address or
  user name), an optional port, and a path and query of letters, digits and
  `- . _ ~ / ? & = + , : ; @`, that is not the same path on one of the
  site's domains. None of these alphabets holds a rewrite metacharacter
  (`$`, `%`, `\`) or one of the config file's (whitespace, `#`, braces,
  `<`), so no value can end a rule, add a flag or rule, read a variable or
  leave the rules block. The set as the record holds it is at most 60 KiB.
- Another account (409 `domain_taken`): no alias is another account's
  domain or alias, recorded or being installed, compared as OpenLiteSpeed
  maps names, with one leading `www.` removed. A create is refused (409
  `conflict`) for such a domain too.
- Account (409 `conflict`): the revision matches, the account is active,
  its site is live, no WordPress install is running, and its identity and
  folders verify.

The intent is journaled (action `domains`, target the SHA-256 of the new
set, the record's `domains_next` holding it), then the site list is
rendered, tested and reloaded as for a web change, under the same rules for
other tenants' vhosts. olsweb puts the aliases after the account's domain
in the plain listener's `map` line, and in the HTTPS listener's only those
the certificate covers (see Certificates). A domain redirect is two
`RewriteCond` lines (the Host header, with or without a port, and not the
ACME challenge path, so a redirected domain still renews) and a
`RewriteRule` that keeps the path and query; a path redirect is one
`RewriteRule`; each ends `[R=301,L]` or `[R=302,L]`. They come after the
deny rules in the vhost's own rewrite block, which the broker writes,
never in the tenant's `.htaccess`. A suspended site keeps its suspended
rendering: its aliases stay mapped to it and answer 403, and it redirects
nothing. A failed test restores the old files and ends the change
`rejected` with the account unchanged (422 `web_rejected`); any other
failure leaves it pending, and the next start finishes it or ends it
rejected, as for a web change. An unchanged set changes nothing. The
account list shows `site_domains` (`aliases` and the number of
`redirects`) for a site that has any; the stored account and the journal's
rows never carry it.

Limits for now:

- The panel's own `--panel-host` names are refused by the panel, not the
  broker, which does not know them.
- A suspended site's domains and redirects do not change; resume it first.
- That OpenLiteSpeed 1.9.4 applies the `RewriteCond` lines as Apache does
  is read from its documentation; the site-domains dev VM proof runs it.

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
- Fit (422 `certificate_rejected`): the leaf names DNS names only (no IP
  address, email or URI), each once and each one of the site's domains (the
  account's own and its aliases, see Domains and redirects), the account's
  own domain among them (the common name is ignored, and a wildcard is no
  site's domain), and NotBefore <= now < NotAfter. A domain of the site the
  leaf leaves out, because its DNS does not point here yet, is served over
  http only.
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
   `sifruno-https`) is rendered, mapping only those sites, each with only
   the domains its certificate names that the site still has. The listener's
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
Unix seconds, `fingerprint` as lowercase hex SHA-256 of the leaf, `names`
as the leaf's DNS names sorted and joined with commas) for each account
that has one, so the panel can renew in time and see which domains are
covered; the journal's before and after rows record it too. A certificate
installed before the broker kept its names has none listed and covers the
account's own domain only. Delete takes the site out of the config first,
then removes the site's TLS directory with the user: only the live and
staged pairs and `writeAt`'s temporary names, and an unexpected file keeps
the delete pending rather than being removed.

Limits for now:

- One certificate per site, for the account's own domain and those of its
  aliases it names. An alias added later, or one whose DNS pointed
  elsewhere, is served over http until the panel installs a certificate
  that names it; one removed stays named by the installed certificate until
  the next, but is no longer mapped.
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
  GID, no group but its own (the broker admits only an account that is in
  no group), a clean environment, in public_html. So the install can write
  only what the tenant can already write; a tenant's own files can change
  what it does, not what it may touch.
- The tenant controls code that WP-CLI loads (`wp-cli.yml` in public_html,
  `wp-config.php`, mu-plugins), so each step runs bounded, inside the
  account's own slice. The broker runs `/usr/bin/systemd-run --quiet --wait
  --pipe --collect --unit=sifruno-site-<uid>-<16 random hex>.service
  --slice=user-<uid>.slice --uid=<uid> --gid=<uid>
  --working-directory=<public_html> --property=TasksMax=<plan's processes>
  --property=RuntimeMaxSec=<seconds left> --property=KillMode=control-group
  --property=KillSignal=SIGKILL --setenv=...` and the program. systemd
  starts it as a transient service under the account's user slice, so the
  plan's task, memory and CPU limits cover it and every process it starts,
  and drops to the user before it enters public_html (`execute.c` at
  systemd v252). When the program ends, systemd kills whatever is left in
  the unit, a process that called setsid too, and systemd-run returns the
  program's exit status. At the step's time limit the broker runs
  `systemctl kill --signal=SIGKILL` on that unit name, which must match
  `sifruno-site-<5 digits>-<16 hex>.service`; RuntimeMaxSec stops it even
  if the broker is gone. systemd expands `$NAME` and `${NAME}` in a
  service's arguments, so the broker doubles every `$`, which systemd turns
  back into one. Not yet run on the dev VM (account-limits proof, section
  8).
- Its environment is `PATH=/usr/bin:/bin`, `LANG=C.UTF-8`, `USER` and
  `LOGNAME` (the account), `HOME=/var/lib/sifruno-site-home`,
  `WP_CLI_CACHE_DIR=/dev/null` and `WP_CLI_DISABLE_AUTO_CHECK_UPDATE=1`.
  WP-CLI 2.12.0 uses HOME only for its global config
  (`~/.wp-cli/config.yml`), its packages (`~/.wp-cli/packages`, whose
  autoloader it loads) and its cache; the install needs none of them, so
  HOME is an empty root-owned 0755 directory that the broker makes with the
  web operation (and refuses to start that operation if it is not root's
  and empty), and the cache is off (`/dev/null` turns it off without a
  warning in WP-CLI's FileCache).
- Steps: `core download` (en_US), `config create` with database host
  127.0.0.1 (sites run in a namespace container that does not see the
  MariaDB socket), `wp-config.php` set to 0600, `core install` with
  `--skip-email`, then the LiteSpeed Cache plugin (steps `cache plugin` and
  `cache setting`), then `core version` for the result.
- LiteSpeed Cache is how WordPress asks OpenLiteSpeed's cache module to keep
  a page (see Websites). WP-CLI installs version 7.9.3, pinned in code, from
  wordpress.org as the site's user (`plugin install litespeed-cache
  --version=7.9.3`), checks every file against wordpress.org's published
  checksums for that version (`plugin verify-checksums`, which must print
  `Verified 1 of 1 plugins.`, because WP-CLI also answers success when it
  could not fetch the checksums), activates it, and turns its "Cache
  Logged-in Users" off (`litespeed-option set cache-priv false`, the form
  of the plugin's own example in `cli/option.cls.php`), so a signed-in
  visitor's pages are never cached. That command prints the key and the
  value it stored; the step must print `cache-priv:` and `0`. The broker
  itself fetches nothing.
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
  WordPress fails at the download step. So the answer also has
  `wordpress_installed`: true when a step after `core install` failed
  (`cache plugin`, `cache setting` or `version`). WordPress then works and
  only the cache plugin is not set up; do not install again, but set up
  LiteSpeed Cache in WordPress (Plugins), or remove the site's files and
  install again.

## Placeholder page

`InstallPlaceholder` (`POST /v1/accounts/{id}/placeholder`, input
`expected_revision` only) puts a small `index.php` into a live site's
public_html when the folder is empty, so a new PHP site shows that it is
ready and that its PHP runs. The page is fixed in code; the caller cannot
send text or a path.

- It runs the site's own LSPHP CLI as the account's user, exactly as the
  WordPress install runs WP-CLI: `php -n -r <fixed script>` in public_html,
  the page on stdin. Root writes nothing into the home.
- The script writes only into an empty folder (one hidden file is enough
  to leave it alone) and only as a new file (`fopen` mode `x`, which is
  `O_CREAT|O_EXCL` and never follows a link), then sets it to 0644. It
  answers `{"written": true}`, or `false` when the folder held something.
- The same checks as the WordPress install, under the broker lock: the
  revision, an active live site, its folders verified, no install running.
  The account is busy meanwhile, the run has its own one-minute limit, and
  nothing is journaled. A failed run answers 422 `install_failed` with step
  `placeholder` and the end of what PHP printed.

## Backups

Website backups go to an SFTP storage server with restic 0.20.0, which the
installer puts at `/usr/local/lib/sifruno/restic` (root, 0755). The broker
checks the binary's sha256 against the pin in `backup.go` before every run.
Each operation is fixed and typed; nothing goes through a shell.

| Route | Operation |
| --- | --- |
| `GET /v1/backup` | The broker's public key, whether restic is ready, the target, whether the admin confirmed saving the password (`password_saved`). The first call makes the key pair and the repository password. |
| `POST /v1/backup/target` | `host`, `port`, `user`, `path`, `known_hosts`, `reason`. Opens the repository there with the broker's password, or makes one. |
| `POST /v1/backup/password` | `reason`. The repository password, only while a target is set and the password is not confirmed saved (409 after). |
| `POST /v1/backup/password-saved` | `reason`. Records that the admin saved the password. |
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
`connect`, `password`, `repository`, `database`, `space`, `dump`, `backup`,
`snapshot`, `restore`, `copy`, `import`, `compare`, `check`, `prune`) and the
end of its output (printable ASCII, secrets removed, at most 512 bytes).

Secrets stay with the broker, in `<state>/backup/` (root, 0700):

- `ssh_key`: an ed25519 key made in Go (0600). The panel shows its public
  half for the admin to install on the storage server.
- `password`: the repository password, 32 random bytes (0600). restic reads
  it through `RESTIC_PASSWORD_FILE`; it is never an argument. It is shown
  in two steps, so a lost answer does not lose it: every target change
  answers it, and `POST /v1/backup/password` reads it again, until the admin
  confirms with `POST /v1/backup/password-saved`. From then on no answer
  carries it. The file stays root 0600 throughout; the confirmation is the
  stored target's `password_shown` flag, which a broker before this step
  set when it showed the password once.
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
   each database asked for, and each database must still exist. The broker
   checks names only by prefix and cannot see dbhost's registry, so it
   never makes a database: one that is gone is refused (`database`). The
   panel sends only databases its registry records for the site.
2. The snapshot must fit on the staging disk (see Disk space). restic
   restores, as root, into a fresh staging folder
   `/var/lib/sifruno-restore/<op>` (0700), with `--sparse`, so a tenant's
   sparse file stays sparse, and without the files' SELinux
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
5. For each database: root makes a temporary user
   `sifruno_rst_<16 hex>` granted only `SELECT, INSERT, UPDATE, DELETE,
   CREATE, DROP, ALTER, INDEX, LOCK TABLES, REFERENCES` on exactly that
   database (escaped as dbhost escapes grants). The statements reach MariaDB
   on stdin. Its option file is root:<site group> 0440 in the staging
   folder. `mariadb --defaults-file=... --binary-mode --one-database` runs
   as the site user with the dump on stdin; `--binary-mode` turns off the
   client's own commands, such as `\!`. Without SUPER, SET USER, TRIGGER or
   routine privileges, nothing in a dump can name another `DEFINER`. The
   user is dropped afterwards, also when the load fails.

Nothing is written to the accounts' journal: a nightly backup would take two
rows a night, and soon the last rows compaction keeps would hold nothing but
backups. A backup and a drill
change no account; a restore changes only the tenant's own files and
databases with the tenant's rights, as a WordPress install does, and the
panel's job log records who asked. What a restore or drill leaves as root,
its staging folder and its temporary users, is listed in the broker's
database before it is made and removed afterwards. What an interrupted one
left, such as a staging folder whose option file holds the temporary
user's password, is removed when the broker starts, before its socket
accepts requests (at most 30 seconds). If that fails, for instance because
MariaDB is not running yet, the broker says so on stderr and starts
anyway, and the next backup operation tries again before it runs.

Disk space. The dumps, the staging folders and restic's cache sit on the
server's own disk, usually the filesystem that also holds the broker's
state and MariaDB. Every write leaves a margin free: 5% of the filesystem
(XFS reserves nothing for root) and never less than 2 GiB. Free space is
statfs's `f_bavail`, so ext4's root reserve is not counted.

- Before a restore or drill stages anything, `restic stats --mode
  restore-size` gives the whole snapshot's size; with one block more per
  entry it must fit in the staging filesystem's free space less the margin,
  or the operation is refused (`space`). restic counts a sparse file at its
  full length, so a site holding a huge sparse file may be refused a
  restore that `--sparse` would have fitted; the disk never fills.
- Each database dump may use the free space beyond the margin, measured
  before it starts, and at most 32 GiB. The dump goes through a counting
  writer that fails past that, so `mariadb-dump` gets a broken pipe and
  stops; the dumps are removed and nothing is backed up (`space`, or `dump`
  at 32 GiB). restic backup starts only with room beyond the margin.
- restic's cache is `<state>/backup/cache` and its temporary folder
  `<state>/backup/tmp`. The cache holds the repository's index and folder
  data for every site, so it grows with the repository and restic does not
  bound it; the drill's `restic check` makes a second, temporary cache
  inside it and removes it afterwards. A backup or prune keeps a few packs
  (restic's default pack size is 16 MiB) in the temporary folder while
  they upload. Both are covered by the margin, and a backup does not start
  without it.

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

## Scheduled jobs

`SetCron` (`POST /v1/accounts/{id}/cron`, input `jobs`, `expected_revision`,
`reason`) replaces an account's whole job set; `GET /v1/accounts/{id}/cron`
lists it with each job's next run and the broker's clock (`server_time`).
Root never runs a job's command: it writes the crontab, and cronie's crond
runs the jobs as the account's user.

- A job is a schedule and a command. The schedule is five fields one space
  apart, each a comma list of `*`, `*/step`, `n`, `n-m` or `n-m/step` with
  numbers of one or two digits in the field's bounds (minute 0-59, hour
  0-23, day 1-31, month 1-12, weekday 0-7): a strict subset of what cronie
  1.5.7 parses (`entry.c`), without names, `@` shortcuts or `~`. The command
  is 1 to 1024 bytes of UTF-8 on one line: no control character, no
  `U+2028`/`U+2029`, no outer space and no `%`, which cron turns into a new
  line and standard input; nor does it start with `-`, which AlmaLinux 9's
  cronie reads as an entry option (its `n_option` patch), or `*`, which
  cronie refuses as a typo. At most 50 jobs and 16 KiB of job lines. The
  request is read as strictly as the others (each job exactly `schedule`
  and `command`, once each), up to 128 KiB.
- The file is `/var/spool/cron/<username>`: a fixed header, `MAILTO=""` (no
  mail: the account has no mailbox; cronie `do_command.c`), and one line per
  job. Nothing else is written, so a job runs with cronie's defaults,
  `/bin/sh`, HOME the home and PATH `/usr/bin:/bin`; no tenant can set a
  variable such as `XDG_SESSION_CLASS`, which AlmaLinux 9's cronie passes to
  PAM. No jobs: no file.
- Written directly, not with `crontab -u`: root 0600, beside its target
  under a name crond skips (`.sifruno-new-<id>`; `not_a_crontab` skips dot
  names) with `O_EXCL|O_NOFOLLOW`, synced and renamed. That is
  what cronie's `crontab` leaves when root runs it (`crontab.c`: the owner is
  root when the real and effective IDs are root's; `mkstemp` makes it 0600),
  and what crond's `check_open` accepts (regular, one link, `mode & 07533 ==
  0400`, owner root or the user). The write either happens whole or not at
  all, the broker can compare what is installed with its record, and delete
  removes the same file by name after the user is gone, which `crontab -r
  -u` cannot.
  crond sees the rename through inotify (`IN_MOVED_TO`) or the directory's
  modification time. `/var/spool/cron` must be root's along its path and
  0700, as the cronie package makes it; otherwise the change is refused
  (503) before anything is journaled, as it is (409) when something other
  than a regular single-link file of root or the user is at the name.
- The account's own user can rewrite its crontab with cronie's setuid
  `crontab` (from PHP or a job; the shell is nologin). The jobs still run as
  that user, so this gives nothing beyond what its PHP can do, but the panel
  then lists the broker's record, not the file; the next save writes the
  record's list again. The broker therefore never reads the file back after
  its rename: a tenant's rewrite at that moment must not leave a change
  pending. Denying tenants the `crontab` program (`/etc/cron.allow`; crond
  itself does not read it) is the host's choice and is not made here.
- Journal: the checks come first (input, every account settled, revision,
  history room, what only root controls, a usable directory). The new set
  is stored in the `hostaccounts-cron-v1` bucket under its SHA-256, the
  intent journaled (action `cron`, target the digest, revision plus one;
  no command enters the journal), the crontab written, and the result
  journaled. A write that failed changed nothing (the rename or unlink is
  its last step), so it ends `rejected`, unchanged (503 `unavailable`). Only
  a crash or a failed journal write leaves the change pending; the next
  start writes the stored set. An unchanged set is a
  no-op only while the installed file still holds it; a file edited outside
  the broker is rewritten through the journaled path. Each change takes two
  of the account's history rows.
- How crond runs them, read from source, not yet run (proof
  `site-tools.guest.sh`): for each job crond calls PAM service `crond`
  (`security.c`: `pam_acct_mgmt`, `pam_setcred`, `pam_open_session`), then
  `setgid`, `initgroups` and `setreuid` to the user, and runs `/bin/sh -c`.
  cronie's `pam/crond` includes `system-auth`; authselect 1.2.6's `sssd` and
  `minimal` profiles put `pam_unix` in its account stack (so a suspended,
  expired account runs no job), and `pam_limits` and `-pam_systemd` in its
  session stack. pam_systemd puts the session's scope in `user-<uid>.slice`
  (pam_systemd(8), systemd v252), under the plan's TasksMax, MemoryMax and
  CPUQuota, and pam_limits applies `limits.d/90-sifruno-accounts.conf`
  (nproc 4096). That AlmaLinux 9's installed `/etc/pam.d/crond` is cronie's
  file unchanged, and that the host's authselect profile is one of those
  two, is inferred.
- Times are the server's: the broker and crond both read `/etc/localtime`.
  The next run follows cronie's day rule (both day fields must match when
  either starts with `*`, otherwise either); around a daylight saving change
  crond's own rule differs, so the time is a guide there.
- Delete removes the crontab and the temporary name with the account's
  other files (`removeAccountFiles`), root's or the user's, after userdel. It
  must: crond keeps a crontab whose user is gone and loads it again when a
  user of that name appears (`database.c`, `check_orphans`). An unexpected
  object there keeps the delete pending.

## Logs and usage

`GET /v1/accounts/{id}/logs/access` and `/logs/error` return the end of the
site's OpenLiteSpeed logs; `GET /v1/accounts/{id}/usage` and `GET /v1/usage`
(every account) its disk use and this month's traffic. They need the web
operation, which admits `xfs_quota` and knows the web server's user.

- These only read, outside every home. They depend on nothing an unfinished
  operation half-changes, so no pending record, the account's own included,
  stops them, and they hold the broker lock only to read the records. The
  cron list reads only the broker's records and is not stopped either.
- Logs are read from `olsweb.LogRoot/<site name>/`, which must be root's
  and writable by no one else along its path, through handles opened with
  `O_NOFOLLOW`; the file must be regular, single-link, and root's or the web
  server's user's (OpenLiteSpeed hands its logs to its user,
  `logrotate.cpp`). At most the last 256 KiB are read and the last 200 whole
  lines returned, made valid UTF-8 and otherwise as written: they hold what
  visitors sent, so the panel shows them as text only.
- Disk is `xfs_quota -x -c "report -u -b -n -N -L <uid> -U <uid>" <homes>`,
  read-only, in KiB (xfsprogs 6.3 `report.c`); the list reads the accounts' UIDs
  in reports of at most 500 accounts, each within a command's 64 KiB of output.
- Traffic is the response body bytes OpenLiteSpeed's access log records
  (`accesslog.cpp`: the field after the status is `getBodySent()`, headers
  not counted) for the server's current month. Each site has a counter in
  `<state>/usage/<id>.json` (root 0600, directory 0700): the month, its
  total, and where reading stopped (device, inode, modification time,
  offset after the last whole line). A read goes on from there, through the
  copies OpenLiteSpeed rotated the log into (`access.log.YYYY_MM_DD[.NN]`,
  `archiveFile` renames the file, so it is found by its inode), oldest
  first, then the live log, at most 64 MiB per read (shared by all sites,
  at least 4 MiB each), counting whole lines of the current month only. A
  line over 64 KiB is skipped. When what is left of the budget ends inside
  a line, the read stops before that line and the next read counts it. `traffic_complete` is false while earlier
  lines remain. If the file read last is gone (`keepDays` removed it), the
  files written after it are read. Usage reads run one at a time; a counter
  is saved only while its account exists, and delete removes it.

## Verification cost

Every request checks every account's files: its passwd and group identity (from
one cached parse, reused only while both files are the same objects with the
same change times), its home's identity and owner, and its ownership marker.
That check starts no process. The account list also reads each home's mode
and public_html, for `site_folder_changed`. The password-lock and expiry observation
needs `passwd --status` and `chage --list`, two processes per account, and
running it for all accounts on every request is what limited the broker to
about a hundred. It now runs for the account an operation touches and for a
rotating batch of 16 accounts per request, so an outside change to lock or
expiry is noticed when that account is next touched or when the rotation
reaches it, not on the very next request. With 16 accounts or fewer nothing
changes: all are fully checked every time.

`BenchmarkStoreScale` measures the store and journal at the account bound with
the fake native system. Native costs are measured on the dev VM.
