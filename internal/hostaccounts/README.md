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
paths: /usr/sbin/groupadd, useradd, usermod, userdel, groupdel (abandoning a
create, below), nologin; /usr/bin/passwd,
chage, kill (which runs only as an account's own user, see Processes),
systemctl (`daemon-reload` and `list-units` of one slice, see Resource
limits, and `kill` of a site run's own scope), systemd-run, setpriv and env
(a site run's transient scope, its drop to the account's user and its
environment, see WordPress).
Arguments are fixed typed options and validated account identity. Subprocesses
have fixed credential-free locale/PATH, no shell and bounded output. A command
that changes no account file (passwd, chage, a systemctl listing, xfs_quota)
has a 15-second deadline. groupadd, useradd, usermod, userdel and groupdel write
/etc/passwd, group, shadow and gshadow; killed mid-way they leave half an
account (on a loaded host useradd was killed after it had written passwd and
group and made the home, which shadow-utils makes root's with mode 0 before it
chowns it), so they are never cut short at 15 seconds. Each runs until its
operation's own limit ends: a create, a delete and a suspend or resume run
their root steps on a four-minute limit of their own, not on the request's 45
seconds, and the controller client waits for them longer than that. No /etc/shadow hashes are read or logged;
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
one file when it is a regular file owned by the account. It replaced an
earlier system-account mode. Explicit --groups '' excludes
supplementary defaults; native verification requires the private primary group
only and no member additions. The broker does not check the subordinate ranges
itself; the dev VM proof does.

This implementation explicitly requires files-only passwd/group/shadow policy in
the existing nsswitch.conf. LDAP, SSSD, systemd dynamic identities and other NSS
providers are unsupported. It never rewrites this policy. A disposable guest may
declare the files-only qualification fixture; that is an explicit precondition,
not zero-configuration AlmaLinux, production installer or vendor compatibility.
The policy is rechecked before operations. The dedicated homes parent starts
empty and subsequently contains only journal-reserved account directories
and the broker's trash of deleted homes (`.sifruno-trash`, Deleted homes).

Usernames are3–32ASCIIbytes, `[a-z][a-z0-9_]*`, with reserved service names refused;
these are native foundation limits, not cPanel username rules. Domain must be a
lowercase ASCII multi-label DNS name and remains metadata. Actor is1–120bytes;
reason is1–500UTF8bytes, with controls and outer whitespace refused. Requests are
strict JSON≤16KiB (a certificate request up to 160 KiB, a domains request up to 96 KiB), including duplicate/unknown/case-alias/null/invalidUTF8 guards.
There are at most 2000 managed accounts (`MaxAccounts`) and 256 audit event rows
per account at a time (`MaxHistoryRows`); compaction (below) keeps an account in
use far below that. One account's stored record is at most 160 KiB: the largest
the inputs can make (two domain sets at their bound, ten SFTP keys, a
certificate for 16 names) takes about 153 KiB, and a record past the bound is
refused before it is written, since the account list refuses to read one.

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

The operations a tenant can reach (web, domains, Always use HTTPS, cron,
certificate, adopt, SFTP keys, plan) are refused (409) before anything is journaled once fewer than 19
rows are free: their two rows and a spare, plus 16 that stay for the
operator's suspend, resume and delete and the broker's own conflict record,
which are refused only when fewer than 3 rows are free (an adopt that ends a
conflict, which holds up every account, counts as the operator's). With compaction these
limits are a backstop for an account whose history could not be compacted.

Interrupted operations retain their ID, UID/GID, username/domain and pending
journal. List exposes recovery_required and all further mutations stop. Restart
can complete only an exact journal-owned identity and captured filesystem object,
or confirm a completed expiry transition. One partial home is completed too:
the one useradd leaves when it is stopped between its mkdir and its chown. A
directory directly in the homes directory, named as the journaled user, owned
by root:root, mode 0, empty and on the homes filesystem, while passwd and group
show the journaled user and its private group with the journaled IDs, can only
be useradd's: the homes directory and those above it are root's and writable
by no one else, and the create's user cannot sign in before it finishes. The
broker records its identity, then gives it to the account through the open
handle and finishes the create as usual. Group-only/no-user outcomes, uncaptured
preexisting public_html, a home that differs from that state in any way,
changed OS identity/ownership/inodes and other ambiguous results remain blocked.
No automatic useradd retry, deletion or cleanup of OS accounts is attempted.

A delete removes the ownership marker last, so a delete that finds it gone
and no user of the account left had finished everything before it, and
running it again finishes the rest. A marker counts as gone only when its
own name is missing from the real markers folder (`<state>/owners`, root's,
mode 0700, under parents only root can write, read through a handle that is
still that folder); a missing or odd folder, a link or another file there
is a recovery answer, never a missing marker.

Once its site has left the config, and before its native removal begins,
a delete saves `user_removal` on its pending record. A start that finds a
delete unfinished without it checks the account first, as before; with it
the user may already be gone, so the start finishes the delete from the
journal alone, without that check: it removes a user only when it is the
only one with the account's name and UID and has the journaled UID, GID,
tag, home and nologin shell; a group only when it is the account's private
group alone, also one userdel left; the home only when it is the recorded
directory; then the account's files, the marker last, and the slice
drop-in. What is already gone counts as removed; anything else stays
pending, its reason logged. A delete that stopped before it saved
`user_removal` still ends rejected; one that saved it is finished at the
start even if userdel had not run yet. The delete's last row (`succeeded`, or
`reconciled` at a start) and the removal of the record are one bbolt
transaction that reads the stored record again: a crash leaves the delete
unfinished or ended, never one without the other. The account list refuses
a record that carries `user_removal` without a pending delete.

A delete that cannot be finished automatically is the operator's to finish
(`POST /v1/accounts/{id}/finish-delete`, reason only; the panel serves it
to signed-in admins, never to an API token), once what stopped it is
fixed. Only an account whose pending operation is a delete can be
finished. If the delete had not yet taken the site out of the config,
that comes first. Then the native delete runs as at a start, without
checking the account first, and checks everything before it removes
anything: a refusal answers 409 `delete_refused` with its reason
(`no_unfinished_delete`, `marker`, `user`, `group`, `home`, `trash`,
`processes`), removes no user, group or file and journals nothing, and the
recovery log names it; a site this run took out of the config stays out,
since the delete is still the account's pending operation. Otherwise it removes as a delete does, the slice drop-in goes,
and one bbolt transaction journals the delete's last row (status
`finished`, with the operator's actor and reason) and removes the record,
so every other account can change again. A run stopped half way leaves
the delete unfinished, and running it again treats what is already gone
as removed. The same refusals hold a delete pending when it runs as
usual or at a start.

A create that cannot be finished is the operator's to abandon
(`POST /v1/accounts/{id}/abandon-create`, reason only; the panel serves it to
signed-in admins, never to an API token). Only an account whose pending
operation is a create can be abandoned. The broker checks everything first
and removes nothing when anything is not provably the create's own: the
ownership marker must be the recorded one whenever a user, group, home or
mail spool is there; a user with the account's name or UID must be the only
one, with the journaled UID, GID, tag, home and nologin shell; a group with
its name or GID must be its private group alone; the home, directly in the
homes directory and not a link, must be the recorded one or one useradd made
for the journaled user (as above), and hold nothing but the empty public_html
the broker made; the mail spool must be a regular file of the account's or
root's. A refusal answers 409 `abandon_refused` with its reason
(`no_unfinished_create`, `marker`, `user`, `group`, `home`, `home_not_empty`,
`mail_spool`, `processes`), and the recovery log names it. Otherwise the
broker records the home's identity, then removes as a delete does: the user
(its processes ended first), the group if userdel left it (groupdel, also
for a group whose useradd never ran), the home, the spool, the slice
drop-in, and the marker last. In one bbolt transaction it then journals the
create's last row (status `abandoned`, with the operator's actor and reason)
and removes the record, so every other account can change again. Replay reads
only the histories of records that exist, so it never reads that row; the
rows stay for audit. A run stopped half way leaves the create unfinished, and
running it again treats what is already gone as removed.

The broker says why, in one line on its standard error (journald keeps it for
the broker's unit), whenever an operation journals recovery_required, a start
cannot finish an interrupted operation, a check finds what only root changes
changed, or a request is answered 503 recovery, including a change refused
because another account's operation is unfinished:

    sifruno broker: recovery: operation=create account=<id> user=<name> step="useradd" error="useradd was stopped at its time limit"

The step and the error class are fixed words, a fixed program's exit status or
an errno's name; a line never carries an error's own text, a path in a
tenant's home, file content, a key or a password.

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
  owner, not its mode, and moves it into the trash (Deleted homes). Restart
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

## Deleted homes

A delete detaches the home instead of removing its files under the store
lock, so it answers at once however many files the home holds, and no
other account waits for it (Jev, `detach_then_delete` 0.99; forge D-0001).

- Under the lock, after userdel, the broker renames the home by handle:
  `renameat2` with `RENAME_NOREPLACE` from the held homes directory into
  the held trash, `<homes>/.sifruno-trash/<account ID>`. Before and after
  the move it checks the entry's identity (device, inode, the account's
  UID and GID, a directory, read with `fstatat` and `AT_SYMLINK_NOFOLLOW`).
  It journals `home_in_trash` on the pending record and ends the delete as
  before. A home already gone from the homes directory, moved or removed
  whole, counts as done.
- The trash is root's own: the broker makes it through the homes handle,
  root:root mode 0700, and refuses a link, another owner, another mode or
  a folder on another filesystem, before it removes anything.
- A remover empties the trash outside the store lock: when the broker
  starts, after each delete, and every 10 minutes while entries remain. It
  starts only from entries named as account IDs. It walks by directory
  handles (`openat` with `O_NOFOLLOW|O_DIRECTORY`, `unlinkat`), holding a
  few descriptors at any depth; each step up through `..` is checked
  against the folder it came from, and a folder that moved stops it. It
  never follows a link, checks its context before every entry, never
  enters a folder on another device or mount (that folder and those above
  it stay, the rest of the entry goes, and the entry is left and logged),
  and logs by account ID only. A bind mount of the same device shows only
  in the statx mount ID, so a kernel that does not report it (before Linux
  5.8) makes the remover refuse to run rather than guess. A removal stopped half way is resumed by
  the next run.
- Plan, the only allocator of UIDs and GIDs, skips every UID and GID that
  owns a trash entry, so a deleted account's files never count against a
  new account's XFS quota. A create checks its planned IDs are still free
  rather than still the lowest, since the remover may free a lower one
  meanwhile.

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
  server-level `namespace 1` once, the package's stock `module cache`
  block if the file has none, and removes the package's sample site
  (`virtualHost Example` and its `listener Default` on 8088), so
  `openlitespeed -t` no longer prints that vhost's two ownership warnings.
  New files take their SELinux label from
  the directory they are written in.
- Page cache (LSCache): each live site's `vhconf.conf` has its own
  `module cache` block with `ls_enabled 1` and its own store,
  `/var/lib/sifruno-lscache/sifruno-u<id>`, outside every home, so the
  purge headers a site's PHP sends reach its own pages only. OpenLiteSpeed
  makes that directory as root when it loads the config and gives it alone
  to the web user (mode 2770). The installer makes
  `/var/lib/sifruno-lscache` root's 0711, which OpenLiteSpeed never changes,
  so neither a tenant nor the web user can put a link there. (The package's
  own `cachedata` is not used for this: OpenLiteSpeed gives it to the web
  user at every start; `internal/olsweb/doc.go` has the source lines.)
  `enableCache 0`: nothing is cached unless the
  site's response asks (the LiteSpeed Cache WordPress plugin does), and the
  module never caches a POST. A suspended site has `ls_enabled 0` and no
  store, because the module answers from its store when the request headers
  arrive, before the 403 rule. Delete removes the site's store once the
  site has left the config and its user is gone: the broker opens
  `/var/lib/sifruno-lscache` (root's and writable by no one else along its
  whole path) and removes each entry by name in its own directory handle,
  opened with O_NOFOLLOW, so a link in the store is removed itself, never
  followed. If that fails the delete still succeeds; what is left is cached
  pages under a name no new account gets, and the broker logs a
  `sifruno broker: cleanup:` line with the store's path and the error's
  class. The site's logs stay.
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

### .htaccess changes

OpenLiteSpeed reads a site's `.htaccess` only when it starts or restarts
gracefully (`internal/htaccess` doc.go has the sources). A `.htaccess` that
WordPress, WP-CLI, the file manager, a restore or the tenant over SFTP
writes later is not used until the next restart, and one that was missing at
the last restart stays unread. With the web operation on, the broker
restarts OpenLiteSpeed itself when that happens (`htaccess_watch.go`,
`htaccess_watch_linux.go`):

- One fanotify group marks the homes filesystem (`FAN_MARK_FILESYSTEM`,
  notification class, `FAN_REPORT_DFID_NAME`) for names created, closed
  after writing, moved or deleted. Only a name that is exactly `.htaccess`
  counts. The broker opens, reads and follows nothing a tenant names: it
  skips the directory handle in each event, so it does not know which site
  changed, and restarts for all of them, as any graceful restart does.
- Changes are coalesced. A restart starts 5 seconds after the last change,
  or 30 seconds after the first when changes keep coming, and at least 30
  seconds after the previous restart ended. A tenant who writes `.htaccess`
  in a loop, or floods the filesystem with other events until the kernel's
  event queue overflows, costs every account one restart per window and no
  memory: the kernel's queue is limited, and the broker reads into one
  buffer and adds to two counters.
- A restart is a web change that changes nothing: under the store lock, so
  it never runs inside a web operation; refused while any operation is
  unfinished (logged as `an unfinished operation holds up every change`,
  naming no account); the site list installed again from the records (normally the
  same bytes, so nothing is written), the config test, then `systemctl
  reload lsws`, under the web operation's four-minute limit. It changes no
  account and is not journaled. Each restart logs `sifruno broker:
  htaccess: OpenLiteSpeed restarted gracefully for N .htaccess changes`,
  with counts only, never a name or a path. A failed one logs a
  `sifruno broker: recovery: operation=htaccess` line with the error's class
  and is tried again 30 seconds after it ended; it holds up another account
  only while it holds the lock.
- The broker also restarts once, 5 seconds after it starts, for changes
  made while no watcher ran.
- If fanotify cannot be set up (no `CAP_SYS_ADMIN`, a kernel without
  fanotify, a homes filesystem that refuses the mark, a group or mark
  limit), the broker logs `the .htaccess watcher could not start` once and
  runs without it: a `.htaccess` change then takes effect at the next web
  change or OpenLiteSpeed restart. It does not poll instead, because it
  cannot tell whether a `.htaccess` changed without reading tenants'
  folders.

Limits for now:

- The mark covers the whole filesystem the homes folder is on, so a
  `.htaccess` change elsewhere on it (the trash remover emptying a deleted
  home, for example) restarts OpenLiteSpeed too.
- A folder moved into place with a `.htaccess` already inside it, and
  `truncate(2)` on a path, are not seen; the next change, web change or
  restart picks them up.
- While a tenant changes `.htaccess` without pause, other accounts' panel
  operations wait for the lock during one restart per window (a restart
  took about 20 seconds on a busy dev VM).
- Read from the man pages and the Linux 5.14 source, and the event parsing
  run against Linux 6.8 with a non-root directory mark. The filesystem mark
  on AlmaLinux 9 (`TestRootOnlyHtaccessWatchRestartsOnceForAWrite` and
  `scripts/devvm/proofs/htaccess-reload.guest.sh`) has not been run yet.

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

## Always use HTTPS

A live site whose certificate is in force sends plain http to https: for
each domain the certificate covers, olsweb renders a rule after the site's
own redirects that answers 301 to the same address on https, path and
query kept (`RewriteCond %{HTTPS} !on`, the Host header with or without a
port, and not the ACME challenge path, so HTTP-01 renewal still works over
http). It is on by default: the account's `plain_http` is false unless the
site's owner turned the switch off, and an account stored before the field
existed reads false. No rule is rendered while the site has no certificate
or its certificate's NotAfter has passed, for a domain the certificate does
not cover, or for a suspended site.

`SetAlwaysHTTPS` (`POST /v1/accounts/{id}/always-https`) turns it on or
off. The input is exactly `always_https` (`true` or `false`, required),
`expected_revision` and `reason`; it needs the web operation on. The setting
is kept with or without a certificate and takes effect once one is in force.

The rule is rendered when the site list is installed: at every web change,
about five seconds after the broker starts (the .htaccess watcher's first
restart, which also brings an upgraded broker's rules into force), and
after a tenant's .htaccess changes. A certificate whose renewal keeps
failing would leave http redirected to an expired https after its NotAfter
until the next of those, so the broker also renders the site list at that
second (`https_expiry.go`): one timer, for the earliest NotAfter of a
redirect the last render put in force, set again after every journaled
change. The render is the .htaccess watcher's (`reloadWebServer`): under
the store lock, never while an operation is unfinished, tested before it
is loaded; it changes no account and journals nothing. A render that fails
is logged by its class, naming no account, and tried again a minute later.
A broker that did not render the config at start (no panel host) renders
at once if a redirect's certificate expired while it was stopped.

Checked before anything is journaled: the form (400 `invalid`), and the
account (409 `conflict`) as for a domains change: the revision matches, the
account is active, its site is live, no WordPress install is running, and
its identity and folders verify. An unchanged setting changes nothing.

The intent is journaled (action `https`, target `on` or `off`); its after
is the account with the next revision and `plain_http` turned over, and
replay refuses an https intent that changes anything else. Then the site
list is rendered, tested and reloaded as for a domains change: a failed
test restores the old files and ends it `rejected` with the account
unchanged (422 `web_rejected`); any other failure leaves it pending, and
the next start finishes it or ends it rejected. The answer is the account,
and the account list shows `plain_http` when it is true.

Limits for now:

- The timer counts on the machine's clock: a clock stepped forward, or a
  machine paused, leaves the render late by that much.
- OpenLiteSpeed reads `%{HTTPS}` as `on` when the request carries
  `X-Forwarded-Proto: https` (olsweb doc.go), so a client that sends it on
  plain http is not redirected. That only keeps the client itself on http.

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
account's own domain only; so does one copied from an old server whose
names are not all plain domains (see Migration). Delete takes the site out of the config first,
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
  account's own slice. The broker runs `/usr/bin/systemd-run --quiet --scope
  --collect --unit=sifruno-site-<uid>-<16 random hex>.scope
  --description='sifruno site step' --slice=user-<uid>.slice
  --property=TasksMax=<plan's processes> --property=RuntimeMaxSec=<seconds
  left> --property=KillMode=control-group --property=KillSignal=SIGKILL --
  /usr/bin/setpriv --reuid=<uid> --regid=<uid> --clear-groups
  --no-new-privs --inh-caps=-all --bounding-set=-all --pdeathsig=keep --
  /usr/bin/env -i --chdir=<public_html> -- PATH=... HOME=... <program>
  <arguments>`. systemd-run puts itself in a transient scope under the
  account's user slice, so the plan's task, memory and CPU limits cover the
  step and every process it starts, and then executes setpriv itself: the
  program's input and output are the broker's own pipes, and its exit
  status comes back directly (`start_transient_scope` in `src/run/run.c` at
  systemd v252). A scope is started through PID 1's private socket; the
  earlier `--wait --pipe` transient service needed the system bus, and from
  the broker's service it failed with "Connection reset by peer".
  systemd-run's own `--uid`, which would skip `setgroups`, is not used.
  setpriv (util-linux 2.37) drops to the account's UID and GID with no
  supplementary group, sets no_new_privs, empties the inheritable and
  bounding capability sets, so the program holds no capability, and sets
  the parent-death signal again after the drop cleared it. env (coreutils
  8.32) clears the environment, sets the fixed one below and enters
  public_html as the user, so root never follows a path in the home.
  Nothing on the way expands `$` or `%`: an argument reaches the program as
  the broker sent it. A program's path never holds `=`, which env would take
  for a variable. env exits 125 when it cannot enter the folder, setpriv or
  env 126 or 127 when they cannot run what follows; the broker reports
  those as its own failure, not the program's. A scope does not end when
  its first process does, so after every step (success, failure, time out
  or cancel) the broker runs `systemctl kill --signal=SIGKILL` on the scope
  name, which must match `sifruno-site-<5 digits>-<16 hex>.scope`, with its
  own 15 second limit; that kills a process that called setsid too. When
  nothing was left, systemd has usually unloaded the scope already and
  answers "Unit <name> not loaded.", which counts as done, because systemd
  never unloads a unit whose cgroup still holds a process; any other
  failure fails the step. RuntimeMaxSec stops the scope even if the broker
  is gone. Not yet run on the dev VM (account-limits proof, section 8).
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

## File manager

`POST /v1/accounts/{id}/files/{op}` lists, reads, writes, uploads,
downloads, makes folders, renames, deletes and changes the mode of files in
an account's home. Root never opens a path inside the home for it.

- Every operation runs `/usr/local/lib/sifruno/bin/sifruno-files`
  (`cmd/sifruno-files`, `internal/sitefiles`), which ships in the release
  beside the broker, as the account's user: the WordPress install's site
  step (`systemd-run` transient scope in `user-<uid>.slice`, the plan's
  task limit, the time left as `RuntimeMaxSec`; setpriv's drop with
  no_new_privs and no capability; killed by name after the run), started in
  the home instead of public_html, with no argument. Before each
  run the broker checks the helper as it checks its other fixed tools: a
  regular root-owned file with one link in root-owned folders no one else
  may write, executable by the site user. It needs the web operation
  (`--web-user`), which makes the empty HOME every site step gets.
- The request is one JSON line on stdin (`op`, `path`, and the operation's
  own fields), followed for a write or upload by exactly its `size` in
  bytes. The answer is one JSON line on stdout, followed for a read or
  download by exactly the file's size in bytes. The helper refuses to run
  as root.
- Paths are relative to the home: at most 1024 bytes and 64 names, each 1
  to 255 bytes of UTF-8; an absolute path, `.`, `..`, an empty name, NUL or
  any other control character is refused. The helper opens each name from
  the home with `O_NOFOLLOW`, so a link is listed as a link (never
  followed), a path through a link is refused (`is_link`), and a delete or
  rename acts on the link itself. A folder delete opens each folder from its
  parent's handle with `O_NOFOLLOW` and removes every name relative to it.
- Bounds: the editor reads and writes UTF-8 text with no NUL byte, at most
  1 MiB; an upload is at most 64 MiB, a download at most 1 GiB, a list at
  most 5000 names. A write or upload goes to a new `O_EXCL` temporary file
  beside the target, is synced and given its mode (a replaced file keeps
  its own; a new one gets 0644), then renamed over the target, or linked to
  a name that must be free for an upload that may not overwrite. A failed
  one leaves the file as it was. A mode change sets the permission bits
  only; setuid, setgid and sticky are refused.
- The helper's answer comes from a process with the tenant's rights, which
  the tenant's own processes may trace, so the broker bounds and checks it
  (`sitefiles.ParseAnswer`) before using any of it, and fails a helper that
  sends more or fewer bytes than it promised. The client checks the broker's
  answer again.
- A write's `expected_version` is the file's `version` from the read: 16 hex
  digits from its device, inode, size and modified and change times. A file
  changed since answers `changed`. An empty one makes a new file only, so a
  write never replaces a file it did not read (`exists`).

Checked under the broker lock, then run outside it on the operation's own
limit (two minutes; fifteen for an upload or download), which does not
follow the caller:

- Only this account must have no unfinished operation (503 `recovery`);
  another account's does not stop a file operation, as for backups, because
  the operation touches only this tenant's home with its rights.
- A suspended account's files can be listed, read and downloaded, so an
  operator can look at a suspended site and take its files; changes answer
  409 until it is resumed, so a suspension stays a freeze. Changes also
  answer 409 while a WordPress install or a restore writes into the home.
- Up to four file operations run at once per account (409 beyond); other
  accounts are not counted against it.
- Nothing is journaled, and the account is never marked busy: a suspend or
  delete goes ahead and ends a running helper with the account's other
  processes. What only root controls (user, group, home object, marker) is
  checked again just before the run, so the helper starts only with the UID
  that belongs to this account now; a delete that lands between that check
  and systemd's start is the remaining window.

A refusal of the helper's answers 422 `{"error": "file_failed", "reason":
"<code>"}` (`not_found`, `exists`, `is_link`, `not_a_folder`, `is_a_folder`,
`not_a_file`, `too_large`, `binary`, `changed`, `permission`, `quota`,
`no_space`, `too_deep`, `unsupported`, `invalid`, `failed`); the quota applies
because the helper writes as the tenant. Not yet run on the dev VM:
`scripts/devvm/proofs/files.guest.sh` (`proof.sh files`) is the proof to run.

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
3. restic gives the staged files the owner they had, the site's user.
   While the staging folder is still root-only, every entry of the staged
   home goes to root and the site's private group, readable by that group
   (folders g+rx, files g+r, no setuid or setgid bit; links are changed
   with lchown only and followed nowhere). Staged files owned by the site's
   user would count against its XFS quota wherever the staging folder
   shares the homes filesystem, and the user's own copy would then need
   twice the site's size (Jev 2026-11-24: root and the private group, 0.98,
   over an ACL on each entry or a raised quota). For the length of restic's
   run the staged files still count against the user, so a site close to
   its quota can briefly hit it. The staged home gets mode 0750 and the
   staging folder becomes root:<site group> 0750: only the site user may
   enter it. Each entry that lacked a bit added here is listed, by its path
   relative to the staged home, in a root 0600 manifest per change
   (`modes-g-r`, `modes-g-rx`, `modes-g-x`, NUL-separated) in the staging
   folder; the staged home and public_html are not listed, the broker sets
   their mode.
4. `cp -R -P --preserve=mode,timestamps,links --remove-destination -T` runs
   as the site user (its UID and GID, no supplementary groups, a clean
   environment) and copies the staged home over the home. Files added since
   the backup stay. Then `xargs -0 -r -- chmod <change> --` runs as the site
   user in its home with each manifest on stdin and takes back exactly the
   bits step 3 added, so a 0600 wp-config.php comes back 0600 and a 0700
   folder 0700. chmod follows a link it is given, but as the site user it
   reaches only what that user may change anyway. Root writes nothing into
   a path the tenant controls; a tenant's own files can harm only that
   tenant.
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
  cronie refuses as a typo. No format character (Unicode category Cf: bidi
  overrides and isolates, zero-width characters, the byte order mark), so
  the command reads as it runs; a set stored before this rule still reads
  and runs. At most 50 jobs and 16 KiB of job lines. The
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

## Migration

Migration v1 (the product plan's Phase 1) moves one website account
from a cPanel server, over root SSH, into a Sifruno account of the same
name. Mail and DNS stay on the old server. The panel's website job
(`internal/wizard`, kind `migration`) drives it; the broker does every
root step. The design, with the owner's choices recorded from Jev on
2026-11-24:

- Source access. `POST /v1/migrations` (`host`, `port`, `reason`) makes a
  new ed25519 key for this migration only, in `<state>/migrate/<id>/`
  (root 0700, key 0600), and reads the source's host keys with
  `ssh-keyscan`. Nothing is trusted yet. The panel shows each key's SHA-256
  fingerprint and a one-line command the admin runs as root on the old
  server: it appends `restrict <key> sifruno-migration-<id>` on a line of
  its own (`printf '\n%s\n'`, so a last line without a new line stays
  whole) to `/root/.ssh/authorized_keys` (Jev: admin pastes the line, 0.88, over
  typing the root password once). Sifruno never sees a source password.
  `POST /v1/migrations/{id}/host-key` (`fingerprint`, `reason`) pins the
  offered key whose fingerprint the admin compared with the old server's
  own (`ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub`); before that no
  command runs there. A migration lives 24 hours, at most 16 at a time.
  An expired one is ended as a finish ends it, with the key the broker
  still holds, by a sweep that runs in the background at start and every
  30 minutes, and before a new migration opens; a folder no record names
  is removed then too.
- Every source command is fixed: `internal/cpsource` builds it from fixed
  words and names that passed strict patterns, and cites cPanel's public
  API page for each (`whmapi1 listaccts`, `domainuserdata`,
  `php_get_vhost_versions`; `uapi Mysql list_databases`, `list_users`);
  `crontab -l -u`; SQL to the source's MariaDB on standard input (`SHOW
  CREATE USER` for each user's `mysql_native_password` hash, the
  `mysql.db` grant table); the dump tool; `printf '%s\n'
  "$SSH_CONNECTION"` for the address the source sees this server come
  from. ssh runs as
  `/usr/bin/ssh -F /dev/null -T` with `BatchMode`,
  `StrictHostKeyChecking=yes`, only the migration's key and known_hosts
  under the alias `sifruno-migration-source`, no agent, no password
  prompt, no forwarding, as root.
- With the old server's WHM login (D-0005), `POST /v1/migrations` carries
  `via: "whm"`, and the record keeps it. The panel, as itself and never as
  root, holds the WHM login in memory for that connection only, adds the
  broker's public key line through WHM's API, and fetches over HTTPS what
  the copy asks of cPanel: WHM API 1 `listaccts` for the account,
  `domainuserdata`, `php_get_vhost_versions` for its virtual host, and
  UAPI `Mysql list_databases` and `list_users` through `uapi_cpanel`, and
  for the certificate step alone `fetch_vhost_ssl_components` for the
  site's virtual host. Plan, `migrate-files`, `migrate-database` and
  `migrate-certificate` carry them as `cpanel` (at most 1
  MiB a request) and the broker reads them with the same `cpsource`
  parsers and checks as the same answers over SSH: they are the old
  server's word either way. For such a migration the broker runs no
  `whmapi1` or `uapi` over SSH (a hijacked or broken cPanel refuses there;
  rsync, the dump, `crontab -l` and SQL are not cPanel's tools and still
  run over SSH), refuses a step without `cpanel`, and does not list
  accounts itself; an SSH migration refuses `cpanel`.
- `GET /v1/migrations/{id}/accounts` lists the source's accounts;
  `POST /v1/migrations/{id}/plan` (`username`, `reason`) reads one: its
  domain, home and document root (which must be `<home>/public_html`), PHP
  package, databases and users (which must carry the `<user>_` prefix),
  each user's hash and grants, its crontab, the address the source sees
  this server come from (`client_address`, empty when its sshd does not
  say: verify then fails every folder open to some addresses only), and
  the tier. For the tier
  rsync fetches only the `.htaccess` files of the home and public_html into
  a root-only staging folder, and `internal/htaccess` scans and converts
  them there. The answer carries the hashes: the panel hands them to its
  database service on standard input and records none.
- Tier (Jev: refuse what is not Native, 0.96; then D-0003, 0.93: build a
  fail-closed converter first). Only OpenLiteSpeed serves hosted accounts
  today. Native means rewrite rules, access rules the converter
  turns into OpenLiteSpeed config (`internal/htaccess` convert.go: deny
  all, deny all with a `<Files>`/`<FilesMatch>` allow-list such as
  Akismet's, IP lists, `<IfModule [!]mod_authz_core.c>` pairs that agree,
  Basic password folders), and lines OpenLiteSpeed ignores that a handling
  class covers (`internal/htaccess` handling.go): harmless to ignore
  (Expires, FileETag, compression, caching and security headers, plain
  `AddType`, `AddDefaultCharset`), handled by Sifruno (cPanel's PHP handler
  block, `Options -Indexes`), or a warning (`php_value`, `php_flag`). The
  plan lists each converted file and what it became (`converted`), the
  warnings (`tier_warnings`: those PHP settings, and a PHP handler naming
  another version than the plan's, which the panel shows as notes that keep
  the cutover gate closed until accepted), or why a site was refused, line by
  line (`tier_refusals`, "file line N (directive): reason", paths relative
  to public_html), with `tier_access` when an access rule is the reason and
  `tier_fix` naming the lines to change. A site with anything else
  OpenLiteSpeed would ignore (an unconverted access rule, an unknown
  directive, a line no class covers, a `.htaccess` below a converted folder
  or in the home above public_html, or a rewrite rule whose result could be
  a file path, which OpenLiteSpeed would serve without the folder's check)
  is not put live, not even on the preview. The panel stops before it
  creates anything; only an access rule would open a folder, and only then
  does its message say so. `migrate-files` scans and converts the copied
  files again and refuses before they reach the home.
- Protected folders (`folders.go`, needs human review). When the copy
  converts, `migrate-files` puts the folders live before `cp` runs: each
  realm's user file is read from the root-only staging copy by handle,
  never following a link, must lie in the source home, and keeps only
  `user:hash` lines whose hash OpenLiteSpeed checks against the password
  alone: `$apr1$`, `{SHA}`, `$2y$` and `$2b$`. A crypt hash (DES, `$1$`,
  `$5$`, `$6$`) refuses the copy and names the user whose password must be
  set again, because OpenLiteSpeed 1.9.4 would also accept its stored text
  as the password (owner's review over Jev's 0.59 for keeping them); it is
  written root-owned to
  `/var/lib/sifruno-realms/<site>/realmN.htpasswd`, readable by the web
  server user alone through an ACL (Jev: root copy, 0.91, over reading the
  tenant's file). Then the folders are journaled as one `folders`
  operation and the site list is written, tested and reloaded, or the
  files are removed and the copy stops (`tier`). olsweb renders one regex
  context per folder with rewriting off inside it. The answer lists the
  folders and the URLs verify checks: 403 for a closed folder, 401 for a
  password folder, the same for the first real subfolder below each of
  them (by name, a name a URL holds as it is, from the staged copy), 200
  for up to three real files a closed folder leaves open, and each folder
  open to some addresses only with its rule, from which verify works out
  what each site must answer the address it sees verify come from (D-0002).
  A delete removes the site's realm files. The folders are a
  snapshot: a later edit of the tenant's `.htaccess` or user file changes
  nothing.
- `POST /v1/accounts/{id}/migrate-files` (`migration`,
  `expected_revision`, `reason`) copies as a restore does. The account must
  be active, at its revision, and its name the source account's; the
  broker reads the source's home itself. On the old server the sender
  runs as the account, never as root: `--rsync-path=/usr/sbin/runuser -u
  <account> -- /usr/bin/rsync` (rsync hands it to the source's shell as it
  is; every word is fixed or the checked account name). A tenant that
  swaps a folder for a link to `/root`, or holds a hard link to a file it
  may not read, gets nothing it could not read itself; what the account
  may not read stops the copy (rsync 23) with that reason. The `.htaccess`
  fetch for the tier runs the same way. Here rsync runs as root into a fresh
  staging folder under `/var/lib/sifruno-restore` (root 0700), with
  no owner copied (the staged files are root's, then root's and the site's
  group as a restore's are, so they never count against its quota),
  `--sparse`, setuid and setgid bits dropped, no device
  or special files, one filesystem, and the mail, settings, logs, `.ssh`,
  `ssl` and cache folders of a cPanel home left out. The source's disk
  figure only decides whether the copy starts: the staging disk is read
  every 2 seconds while rsync runs, and rsync is stopped (`space`) before
  the margin is crossed. The staged home and
  public_html get the modes the broker records (0750); a public_html that
  is a link is refused. Then the staging folder becomes root:<site group>
  0750 and `cp` runs as the site's user, then the mode fix, exactly as the
  restore's copy does, so files keep the old server's modes, and the web
  server's access is granted again. Root writes nothing
  into a path the tenant controls, and the tenant never holds the key.
  For a live site the unchanged site list is then installed once more
  (`ApplySites`, a graceful restart), while the account is still busy:
  OpenLiteSpeed reads a site's `.htaccess` (its rewrite rules) only when it
  restarts, and the protected folders' restart ran before the files were
  in the home (D-0004). If it fails, the step is `reload`: the files are
  in place, but the rewrites are not in force.
- Group read (D-0001). The copy gives files the site's own group, so what
  the old web server read through the group alone (a 0640 file, a 0750
  folder, group `nobody` on cPanel or `apache` on a plain Apache) would
  be closed to OpenLiteSpeed. rsync marks the groups (`-g
  --groupmap=nobody:<site gid>,apache:<site gid>,*:0`, by the source's
  group names); before `groupStaged` takes the marks away, each marked
  folder with group read and traverse, or regular file with group read,
  that others may not read is listed. On the staged copy, while the
  staging folder is root's alone, each gets one named ACL entry for the
  web server user (`r--`, `r-x` on a folder), reached from the staged
  home's handle one folder at a time without following a link, with the
  mask equal to the group bits so the mode stays; `cp --preserve=mode`
  carries the ACL into the home. Nothing else changes: no mode, no group,
  no other path. A folder the group may only traverse (0710) gets
  nothing, so a file below it stays closed to the web server.
- `POST /v1/accounts/{id}/migrate-database` (`migration`, `database`,
  `expected_revision`, `reason`): the database must exist here (the panel
  made it, with the same name, and the user with the same hash, so
  wp-config.php needs no edit), be listed on the source under the account,
  and hold no view, trigger, routine or event there. The dump streams over
  SSH into the staging folder under the same 32 GiB cap and disk margin as
  a backup, and loads as the site's user through the restore's temporary
  MariaDB user. Every table's rows are then counted on both sides (the
  source after its dump); the answer lists them, and the panel reports a
  difference.
- `POST /v1/accounts/{id}/migrate-certificate` (`migration`,
  `expected_revision`, `reason`) copies the certificate the old site
  serves, so the moved site answers https before its DNS changes. The
  account must be live, the old server's account of the same name and
  domain (as for `migrate-files`), and the old server is asked for WHM API
  1 `fetch_vhost_ssl_components`, filtered to the virtual host whose
  `servername` is the account's domain, so no other site's key is printed.
  It is copied only when the leaf is not self-signed, is valid now and for
  7 days more, covers the account's own domain as a browser checks it
  (a wildcard counts), chains through its own text and the CA bundle (in
  any order) to an authority in this system's trust store, with at most 4
  certificates served (the root left out), and its key is an EC P-256 or
  P-384 or RSA 2048 to 4096 key that matches it. It is then installed by
  the certificate operation's own steps (staged, journaled, tested), with
  one difference from `SetCertificate`'s fit: a copied leaf may name more
  than the site's domains (its `www.`, `mail.` and other names there),
  and only the site's domains among them are mapped on the HTTPS listener;
  a leaf whose names are not all plain domains, or more than a site has,
  records no `names` and covers the account's own domain. One that cannot
  be used, or none, answers `copied: false` with `refused` (`no_certificate`,
  `self_signed`, `not_yet_valid`, `expired`, `expires_soon`,
  `other_domain`, `untrusted`, `key_mismatch` or `unusable`) and plain
  words in `detail`, and changes nothing; the move goes on. The key is in
  no record, journal row, answer or error: only in the staged pair and the
  site's live files, as an issued certificate's.
- `POST /v1/migrations/{id}/finish` (`reason`) removes the key's line from
  the source (`sed` on whole lines `restrict ssh-ed25519 <blob>
  sifruno-migration-<id>`), proves
  it by a sign-in that is then refused with `Permission denied`, and
  removes the local folder and record whatever the source answered. A
  line not proved removed (the source unreachable, the removal refused, a
  migration whose host key was never confirmed) is kept as a stale line
  before the migration is forgotten: its server, SSH port and the exact
  line to remove. `GET /v1/migrations/stale` lists them; `POST
  /v1/migrations/{id}/stale-cleared` (`reason`) drops one once the admin
  removed it by hand. A finish of a migration already ended answers its
  stale line, never "removed"; one with neither is not found.
- Locks: `migrateMu` guards the records only; no source command runs
  under it, so a plan waiting for `backupMu` behind a long backup never
  holds up the admin's finish.
- A failed step answers 422 `migration_failed` with the step, the
  broker's own words (`detail`) and, apart from them, the end of the error
  output only (`output`): what a source command printed on standard output
  can hold password hashes. The panel shows `output` under Technical
  details only and explains each step (D-0006): `unreachable`,
  `key_refused` and `host_key_changed` are read from ssh's own message
  (`connect` when it names none), `cpanel_tool` is whmapi1 or uapi exiting
  with an error, `cpanel_output` is their answer not in its documented
  JSON, `account_missing` an account the old server does not have; then
  `host_key`, `source`, `tier`, `space`, `fetch`, `copy`, `reload`,
  `database`, `dump`, `import`, `compare` and `remove_key`.
  Copies run one at a time with backups (they share the staging root and
  the temporary users), and their root-side leftovers go through the
  backup leftover list.

Not in v1: IPv6 source addresses, a certificate the old server's
authority does not vouch for (the copy then runs over http until DNS
points here), parked and addon domains (listed, not added), the Compat
tier, and a panel page to change a converted password folder's users.

Known gaps, found in review and not fixed in v1:

- The plan's `.htaccess` fetch does not bring a folder reached through a
  link, so such a site plans as Native; the copy's own scan then refuses
  it (`tier`) and the panel's job removes the account it made. Fail-closed,
  but later than the plan promises.
- A finish, or an expiry, does not stop a copy already running with the
  key (up to its two hours).
- A home holding files the account may not read (root's, another
  user's) cannot be moved until they are given to the account or removed
  on the old server.
- Grants are copied as the narrower set: a grant on a name with an
  unescaped `_` covers that one database only, and one on a `%` pattern is
  left out (the job notes it).
- A source host that resolves to a private (RFC 1918) address is
  accepted: admins move sites from their own private networks.
- The plan fetches only `.htaccess` files, so a password folder whose user
  file is missing, outside the home or holds a hash shape this server does
  not keep plans as Native and is refused at the copy (`tier`).
- Verify expects a folder open to some addresses only to answer the old
  site's client as the address the source's sshd saw this server come
  from. If the site's HTTP reaches the old server another way (a proxy or
  CDN in front of it, IPv6 where SSH used IPv4), the check can fail; it
  fails closed, and a person checks the folder and accepts.

### From a cPanel backup file

`POST /v1/migrations/archive` takes a backup file the admin uploaded
(`cpmove-USER.tar.gz`, `USER.tar.gz`, `backup-…_USER.tar.gz`): one framing
line with its exact `size` (at most 32 GiB) and the reason, then the bytes
(`decodeFramed`, as a file upload). The broker writes it as
`<state>/migrate/<id>/archive`, root 0600, in a folder of its own (root
0700), after a room check, and reads it with `cpmove.Read`
(docs/migration-design.md): one TAR stream, every size, count and path
bounded, names outside the archive's one top folder refused, links out of
the home, hard links and special files left out with a reason, setuid,
setgid and sticky bits dropped. The record has `via: "archive"`, no host,
port or keys, and what the file holds (account, domain, databases, the
old home's path, what does not move); it lives 24 hours like any
migration, and finishing or expiring it deletes the folder. The upload runs
outside `migrateMu`; its id is reserved meanwhile so the sweep does not
take its folder for a stray one.

The steps are the SSH path's with the file as the source: the plan reads
the file's metadata and stages only its `.htaccess` files for the tier;
the copy extracts the home (`homedir/`, the same parts left out as the
SSH copy's excludes) through an `os.Root` into the root-only staging
folder, within the free space margin, and from there it is the same
`placeFiles` as rsync's staged copy: groups and modes, the scan and
conversion again, protected folders first, `cp` as the site's user. A
database step extracts `mysql/DB.sql` alone and loads it as the site's user
through the temporary MariaDB user; with no live database to count
against, each table's source count is the copy's. The certificate step
reads `apache_tls/DOMAIN` and checks it as an SSH move's certificate. No
command runs on any other server.

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
