# Native Linux account foundation

This package separates an unprivileged controller from a root-only local Unix
socket broker. It supplies native managed service identities, private primary groups, homes and
public_html directories. Domain is validated reserved metadata only: this slice
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
before utilities; the broker never rewrites it. New identities use fixed
useradd --system with explicit UID/GID and home creation, retaining locked
passwords and nologin. Shadow's system-account mode omits mail creation and
ordinary password-aging defaults; expiry suspension remains explicit. Mail
policy is a useradd default, not a login.defs -K key. See the
[service-account contract and qualification](../../docs/service-account-mail-policy.md).
Subordinate UID/GID allocation is disabled through supported fixed -K
count options. Explicit --groups '' excludes supplementary defaults; native
verification requires the private primary group only and no member additions.

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
There are at most100managed accounts and256immutable audit event rows per account.

UID/GID pairs in20000–60000 are reserved in durable private bbolt metadata before
OS changes. Controller UID, existing local users/groups/homes and metadata
username/domain reservations are never adopted. groupadd/useradd create a fresh
private group, explicitUID/GID, system-account mode, nologin shell, locked password and an empty home
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
