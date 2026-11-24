package hostaccounts

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"path"
	"regexp"
	"slices"
	"sort"
	"strconv"
	"strings"
	"time"
)

// Website backups with restic, kept off the server on an SFTP storage
// server. The broker holds everything secret: the repository password, the
// SSH key it signs in with and the storage server's host key. The panel only
// names the target, the account and its databases.
const (
	// The installer puts restic 0.20.0 here (restic_0.20.0_linux_amd64.bz2,
	// sha256 0ccd9fa7...7f7 from the release's SHA256SUMS, decompressed).
	// The broker checks the decompressed binary against this before every
	// run, as it does WP-CLI.
	resticPath   = "/usr/local/lib/sifruno/restic"
	resticSHA256 = "c109579d3a1a4d26094bef5400ac5645fceb1043414c05f51b8fb48272001c72"
	maxRestic    = 64 << 20

	sshPath         = "/usr/bin/ssh"
	mariadbPath     = "/usr/bin/mariadb"
	mariadbDumpPath = "/usr/bin/mariadb-dump"
	cpPath          = "/usr/bin/cp"
	// mariadbSocket is the AlmaLinux MariaDB socket; root signs in over it
	// with unix_socket authentication, as the installer does.
	mariadbSocket = "/var/lib/mysql/mysql.sock"

	// restoreRoot holds each restore's staging folder. It is outside every
	// home and outside the broker's 0700 state, because the site user must
	// reach its own staging folder to copy from it: root-owned 0711, and each
	// folder in it root:<site group> 0750 while the copy runs.
	restoreRoot = "/var/lib/sifruno-restore"

	// backupHost is the host name every snapshot carries, so snapshots stay
	// together if the server's own name changes.
	backupHost = "sifruno"
	// hostKeyAlias is the name ssh checks the storage server's key under, so
	// the known_hosts file does not depend on how the host and port are
	// spelled.
	hostKeyAlias = "sifruno-backup-target"

	// Retention: 7 daily and 4 weekly snapshots per site, pruned weekly.
	keepDaily  = 7
	keepWeekly = 4
	// The drill reads one eighth of the repository's data each week, so all
	// of it is read every eight weeks.
	drillSubsets = 8

	maxBackupDatabases = 16
	maxHostKeys        = 8
	maxSnapshots       = 512
)

// Timeouts do not follow the caller, so a client that gives up does not
// cut a step in half.
const (
	backupTimeout       = 2 * time.Hour
	backupTargetTimeout = 3 * time.Minute
	backupListTimeout   = 2 * time.Minute
)

// ErrBackupFailed means a backup step failed: the storage server could not
// be reached, restic or a database tool reported an error, or a check found
// a difference. BackupError says which step.
var ErrBackupFailed = errors.New("backup step failed")

// BackupError names the failed step with the end of what it printed
// (printable ASCII only, secrets removed, at most 512 bytes).
type BackupError struct {
	Step   string `json:"step"`
	Detail string `json:"detail"`
}

func (e *BackupError) Error() string        { return "backup " + e.Step + " failed" }
func (e *BackupError) Is(target error) bool { return target == ErrBackupFailed }

// The steps a BackupError can name. The panel explains each one.
var backupSteps = []string{"target", "connect", "password", "repository", "database", "dump", "backup", "snapshot", "restore", "copy", "import", "compare", "check", "prune"}

// BackupTargetInput names the SFTP storage server. KnownHosts is the
// server's host key as ssh-keyscan prints it: one or more lines of
// "[host] type base64"; lines starting with # are skipped. There is no trust
// on first use: ssh accepts only these keys.
type BackupTargetInput struct {
	Host       string `json:"host"`
	Port       int    `json:"port"`
	User       string `json:"user"`
	Path       string `json:"path"`
	KnownHosts string `json:"known_hosts"`
	Reason     string `json:"reason"`
}

// BackupTarget is the configured storage server. HostKeys are canonical
// "type base64" lines.
type BackupTarget struct {
	Host     string   `json:"host"`
	Port     int      `json:"port"`
	User     string   `json:"user"`
	Path     string   `json:"path"`
	HostKeys []string `json:"host_keys"`
}

// BackupStatus is what the Backup storage page shows. PublicKey is the
// broker's own key, to install on the storage server; Ready says restic is
// installed and matches its pin.
type BackupStatus struct {
	Ready      bool          `json:"ready"`
	PublicKey  string        `json:"public_key"`
	Configured bool          `json:"configured"`
	Target     *BackupTarget `json:"target,omitempty"`
}

// BackupTargetResult answers a target change. Password is the repository
// password, filled in exactly once: the first time a repository is made or
// confirmed. Without it the backups cannot be restored anywhere else.
type BackupTargetResult struct {
	Status      BackupStatus `json:"status"`
	Initialized bool         `json:"initialized"`
	Password    string       `json:"password,omitempty"`
}

// BackupInput backs up an account's home and the databases the panel names.
type BackupInput struct {
	Databases []string `json:"databases"`
	Reason    string   `json:"reason"`
}

// Snapshot is one backup of one account.
type Snapshot struct {
	ID        string    `json:"id"`
	Time      time.Time `json:"time"`
	Bytes     uint64    `json:"bytes"`
	Files     uint64    `json:"files"`
	Databases []string  `json:"databases"`
}

// RestoreInput restores an account's files, its databases, or both, from
// one of its own snapshots.
type RestoreInput struct {
	ExpectedRevision uint64   `json:"expected_revision"`
	Snapshot         string   `json:"snapshot"`
	Files            bool     `json:"files"`
	Databases        []string `json:"databases"`
	Reason           string   `json:"reason"`
}

// RestoreResult says what was restored.
type RestoreResult struct {
	Snapshot  string   `json:"snapshot"`
	Files     bool     `json:"files"`
	Databases []string `json:"databases"`
}

// DrillInput asks for a restore drill of an account's latest snapshot.
type DrillInput struct {
	Reason string `json:"reason"`
}

// DrillResult is one restore drill. A drill that could not run, or found a
// difference, is Passed false with the step and its detail.
type DrillResult struct {
	AccountID    string    `json:"account_id"`
	Snapshot     string    `json:"snapshot"`
	SnapshotTime time.Time `json:"snapshot_time"`
	CheckedAt    time.Time `json:"checked_at"`
	Passed       bool      `json:"passed"`
	Files        uint64    `json:"files"`
	Subset       string    `json:"subset"`
	Step         string    `json:"step,omitempty"`
	Detail       string    `json:"detail,omitempty"`
}

// PruneInput applies the retention rule to every site's snapshots.
type PruneInput struct {
	Reason string `json:"reason"`
}

// PruneResult counts the snapshots the retention rule removed.
type PruneResult struct {
	Removed int `json:"removed"`
}

// BackupService is the broker's backup surface, implemented by the client.
// It is separate from Service so existing Service implementations keep
// compiling; callers that need backups assert for it.
type BackupService interface {
	BackupStatus(ctx context.Context) (BackupStatus, error)
	SetBackupTarget(ctx context.Context, in BackupTargetInput, actor string) (BackupTargetResult, error)
	BackupAccount(ctx context.Context, id string, in BackupInput, actor string) (Snapshot, error)
	ListBackups(ctx context.Context, id string) ([]Snapshot, error)
	RestoreAccount(ctx context.Context, id string, in RestoreInput, actor string) (RestoreResult, error)
	DrillAccount(ctx context.Context, id string, in DrillInput, actor string) (DrillResult, error)
	PruneBackups(ctx context.Context, in PruneInput, actor string) (PruneResult, error)
}

var (
	backupUserPattern     = regexp.MustCompile(`^[a-z_][a-z0-9_.-]{0,31}$`)
	backupHostPattern     = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)*$`)
	backupPathPattern     = regexp.MustCompile(`^(/[A-Za-z0-9._-]+)+$`)
	snapshotIDPattern     = regexp.MustCompile(`^[a-f0-9]{64}$`)
	restoreUserPattern    = regexp.MustCompile(`^sifruno_rst_[a-f0-9]{16}$`)
	restoreSecretPattern  = regexp.MustCompile(`^[a-f0-9]{32}$`)
	resticSafeArgumentSet = regexp.MustCompile(`^[A-Za-z0-9._/=:@,-]+$`)
)

// validBackupHost accepts a lowercase DNS name or an IP address; it never
// starts with "-", so ssh cannot read it as an option.
func validBackupHost(s string) bool {
	if s == "" || len(s) > 253 {
		return false
	}
	if ip := net.ParseIP(s); ip != nil {
		return ip.String() == s && !ip.IsUnspecified()
	}
	return backupHostPattern.MatchString(s)
}

// validBackupPath accepts an absolute, clean path of plain characters:
// restic splits the sftp command on spaces and quotes, and the path is part
// of the repository location.
func validBackupPath(s string) bool {
	if len(s) > 512 || !backupPathPattern.MatchString(s) || path.Clean(s) != s {
		return false
	}
	for _, part := range strings.Split(s[1:], "/") {
		if part == "." || part == ".." {
			return false
		}
	}
	return true
}

// parseHostKeys reads ssh-keyscan output: each non-comment line is
// "type base64" or "host type base64". A host field must name the target
// (plain or "[host]:port") or be hashed. Keys go through the same check as
// account keys; their comments are dropped.
func parseHostKeys(text, host string, port int) ([]string, bool) {
	if len(text) > 8<<10 || strings.ContainsAny(text, "\x00\r") {
		return nil, false
	}
	keys := []string{}
	seen := map[string]bool{}
	for _, line := range strings.Split(text, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) >= 3 && !sshKeyTypes[fields[0]] {
			named := fields[0]
			ok := strings.HasPrefix(named, "|1|") || named == host || named == "["+host+"]:"+strconv.Itoa(port) || named == hostKeyAlias
			if !ok {
				return nil, false
			}
			fields = fields[1:]
		}
		if len(fields) < 2 {
			return nil, false
		}
		canonical, _, ok := normalizeSSHKey(fields[0] + " " + fields[1])
		if !ok || seen[canonical] {
			return nil, false
		}
		seen[canonical] = true
		keys = append(keys, canonical)
	}
	if len(keys) == 0 || len(keys) > maxHostKeys {
		return nil, false
	}
	return keys, true
}

// sshKeyTypes are the key types normalizeSSHKey admits.
var sshKeyTypes = map[string]bool{"ssh-ed25519": true, "ecdsa-sha2-nistp256": true, "ecdsa-sha2-nistp384": true, "ecdsa-sha2-nistp521": true, "ssh-rsa": true}

// validBackupTarget checks the form and returns the target with canonical
// host keys.
func validBackupTarget(in BackupTargetInput, actor string) (BackupTarget, bool) {
	if !validBackupHost(in.Host) || in.Port < 1 || in.Port > 65535 || !backupUserPattern.MatchString(in.User) || !validBackupPath(in.Path) || !validText(in.Reason, 500) || !validText(actor, 120) {
		return BackupTarget{}, false
	}
	keys, ok := parseHostKeys(in.KnownHosts, in.Host, in.Port)
	if !ok {
		return BackupTarget{}, false
	}
	return BackupTarget{Host: in.Host, Port: in.Port, User: in.User, Path: in.Path, HostKeys: keys}, true
}

// validStoredTarget rechecks a target read back from the broker's state.
func validStoredTarget(t BackupTarget) bool {
	if !validBackupHost(t.Host) || t.Port < 1 || t.Port > 65535 || !backupUserPattern.MatchString(t.User) || !validBackupPath(t.Path) || len(t.HostKeys) == 0 || len(t.HostKeys) > maxHostKeys {
		return false
	}
	for _, k := range t.HostKeys {
		if c, _, ok := normalizeSSHKey(k); !ok || c != k || strings.Count(k, " ") != 1 {
			return false
		}
	}
	return true
}

// knownHostsFile is the broker's known_hosts for the target: every key
// under the alias ssh is told to check.
func knownHostsFile(t BackupTarget) []byte {
	var b strings.Builder
	for _, k := range t.HostKeys {
		b.WriteString(hostKeyAlias + " " + k + "\n")
	}
	return []byte(b.String())
}

// accountDatabases checks the databases named for an account: each carries
// the account's "<username>_" prefix, passes dbhost's identifier rule, and
// does not fall inside another account's prefix (bob's bob_x_wp would be
// inside account bob_x's). They come back sorted, without repeats.
func accountDatabases(names []string, username string, others []string) ([]string, bool) {
	if len(names) > maxBackupDatabases {
		return nil, false
	}
	prefix := username + "_"
	out := []string{}
	seen := map[string]bool{}
	for _, name := range names {
		if seen[name] || !strings.HasPrefix(name, prefix) || len(name) == len(prefix) || !validDatabaseName(name) {
			return nil, false
		}
		for _, other := range others {
			if other != username && strings.HasPrefix(name, other+"_") {
				return nil, false
			}
		}
		seen[name] = true
		out = append(out, name)
	}
	sort.Strings(out)
	return out, true
}

// sftpCommand is the ssh command restic starts for the SFTP connection. It
// is one string because restic takes it as an option and splits it into
// arguments itself, then starts the program directly: no shell runs it.
// Every part is a fixed word or a value checked to hold no space, quote or
// backslash, so the split gives back exactly sftpArgs.
func sftpCommand(dir, knownHosts string, t BackupTarget) (string, bool) {
	args := sftpArgs(dir, knownHosts, t)
	for _, a := range args {
		if !resticSafeArgumentSet.MatchString(a) {
			return "", false
		}
	}
	return strings.Join(args, " "), true
}

// sftpArgs is the exact argument list: no configuration file but these
// options, only the broker's key, only the host keys in the broker's
// known_hosts under a fixed alias, no agent, no password prompt, no
// forwarding. "--" ends ssh's options before the host. knownHosts is the
// file in dir that holds the target's keys: known_hosts, or the candidate
// known_hosts.next while a new target is tried.
func sftpArgs(dir, knownHosts string, t BackupTarget) []string {
	return []string{sshPath,
		"-F", "/dev/null",
		"-o", "BatchMode=yes",
		"-o", "StrictHostKeyChecking=yes",
		"-o", "UserKnownHostsFile=" + dir + "/" + knownHosts,
		"-o", "GlobalKnownHostsFile=/dev/null",
		"-o", "HostKeyAlias=" + hostKeyAlias,
		"-o", "UpdateHostKeys=no",
		"-o", "IdentitiesOnly=yes",
		"-o", "IdentityAgent=none",
		"-o", "PasswordAuthentication=no",
		"-o", "KbdInteractiveAuthentication=no",
		"-o", "ForwardAgent=no",
		"-o", "ForwardX11=no",
		"-o", "ClearAllForwardings=yes",
		"-o", "ConnectTimeout=20",
		"-o", "ServerAliveInterval=30",
		"-o", "ServerAliveCountMax=4",
		"-i", dir + "/ssh_key",
		"-p", strconv.Itoa(t.Port),
		"-l", t.User,
		"-s", "--", t.Host, "sftp",
	}
}

// resticGlobal is what every restic run starts with: the repository, the
// SFTP command, the broker's cache, and a wait for another run's lock.
func resticGlobal(dir, knownHosts string, t BackupTarget) ([]string, bool) {
	command, ok := sftpCommand(dir, knownHosts, t)
	if !ok {
		return nil, false
	}
	return []string{"--repo", "sftp::" + t.Path, "--option", "sftp.command=" + command, "--cache-dir", dir + "/cache", "--retry-lock", "10m"}, true
}

// resticEnv holds no secret: the password is a file only root can read.
func resticEnv(dir string) []string {
	return []string{"PATH=/usr/bin:/bin", "LANG=C.UTF-8", "HOME=" + dir, "TMPDIR=" + dir + "/tmp", "RESTIC_PASSWORD_FILE=" + dir + "/password"}
}

func accountTag(id string) string  { return "acct-" + id }
func databaseTag(db string) string { return "db-" + db }

// dumpDir is where an account's database dumps wait for restic. The path is
// fixed per account so restic finds the previous snapshot as its parent.
func dumpDir(dir, id string) string { return dir + "/dump/" + id }

func backupArgs(home, dumps, id string, dbs []string) []string {
	tags := []string{"sifruno", accountTag(id)}
	for _, db := range dbs {
		tags = append(tags, databaseTag(db))
	}
	return []string{"backup", "--json", "--host", backupHost, "--tag", strings.Join(tags, ","), "--one-file-system", home, dumps}
}

func snapshotsArgs(id string) []string {
	return []string{"snapshots", "--json", "--no-lock", "--host", backupHost, "--tag", accountTag(id)}
}

func forgetArgs() []string {
	return []string{"forget", "--json", "--host", backupHost, "--keep-daily", strconv.Itoa(keepDaily), "--keep-weekly", strconv.Itoa(keepWeekly), "--prune"}
}

// drillSubset names the week's share of the repository the drill reads.
func drillSubset(now time.Time) string {
	_, week := now.UTC().ISOWeek()
	return fmt.Sprintf("%d/%d", week%drillSubsets+1, drillSubsets)
}

// dumpArgs dumps one database as root over the socket. No option file is
// read. Tables and rows only: --skip-triggers, and routines and events are
// off by default; a database that has any of them, or views, is refused
// before the dump (see dbObjectsSQL), because restoring them would let a
// DEFINER name another MariaDB user.
func dumpArgs(db string) []string {
	return []string{"--no-defaults", "--protocol=socket", "--socket=" + mariadbSocket, "--user=root",
		"--single-transaction", "--skip-triggers", "--hex-blob", "--default-character-set=utf8mb4", "--", db}
}

// rootSQLArgs runs SQL from stdin as root over the socket, no option file.
func rootSQLArgs() []string {
	return []string{"--no-defaults", "--protocol=socket", "--socket=" + mariadbSocket, "--user=root", "--batch", "--skip-column-names", "--raw"}
}

// importArgs loads a dump as the temporary user, from its own option file,
// into exactly one database. --binary-mode turns off the client's own
// commands (such as \! for a shell) while reading the dump.
func importArgs(cnf, db string) []string {
	return []string{"--defaults-file=" + cnf, "--binary-mode", "--batch", "--one-database", db}
}

// copyArgs copies the staged home into the account's home as the site user:
// recursive, links kept as links, mode (with ACLs), times and hard links
// kept, and an existing file replaced rather than written through.
func copyArgs(from, to string) []string {
	return []string{"-R", "-P", "--preserve=mode,timestamps,links", "--remove-destination", "-T", "--", from, to}
}

// validDatabaseName is dbhost.ValidateIdentifier's rule for a database
// (1 to 64 of [a-zA-Z0-9_]). The broker does not import dbhost, which is
// Linux-only, so this package keeps building for the client on every
// system; a test holds the two rules equal.
func validDatabaseName(s string) bool { return databaseNamePattern.MatchString(s) }

var databaseNamePattern = regexp.MustCompile(`^[a-zA-Z0-9_]{1,64}$`)

// grantDatabase names exactly one database in a GRANT: "_" and "%" are
// wildcards there, so they are escaped, as dbhost.GrantDatabase does (a
// test holds the two equal), and the name is backquoted.
func grantDatabase(db string) string {
	return "`" + strings.NewReplacer("`", "``", `\`, `\\`, `_`, `\_`, `%`, `\%`).Replace(db) + "`"
}

func sqlString(s string) string {
	return "'" + strings.NewReplacer(`\`, `\\`, `'`, `\'`).Replace(s) + "'"
}

// dbObjectsSQL lists what a table-and-rows dump would leave out, and
// whether the database exists at all.
func dbObjectsSQL(db string) string {
	q := sqlString(db)
	return "SELECT 'missing' FROM DUAL WHERE NOT EXISTS (SELECT 1 FROM information_schema.SCHEMATA WHERE SCHEMA_NAME=" + q + ")" +
		" UNION ALL SELECT 'view' FROM information_schema.VIEWS WHERE TABLE_SCHEMA=" + q +
		" UNION ALL SELECT 'trigger' FROM information_schema.TRIGGERS WHERE TRIGGER_SCHEMA=" + q +
		" UNION ALL SELECT 'routine' FROM information_schema.ROUTINES WHERE ROUTINE_SCHEMA=" + q +
		" UNION ALL SELECT 'event' FROM information_schema.EVENTS WHERE EVENT_SCHEMA=" + q + ";\n"
}

// restoreArgs restores a snapshot, or one folder of it, into target. The
// SELinux label of each file is not restored: the staged files take the
// staging folder's, and the copy gives the home's files the home's.
func restoreArgs(source, target string, verify bool) []string {
	args := []string{"restore", "--json", "--exclude-xattr", "security.selinux"}
	if verify {
		args = append(args, "--verify")
	}
	return append(args, source, "--target", target)
}

// restorePrivileges are what a table-and-rows dump needs: no TRIGGER, no
// routine, event or view privilege, and nothing beyond the one database.
// Without SUPER or SET USER the user cannot name another DEFINER either.
const restorePrivileges = "SELECT, INSERT, UPDATE, DELETE, CREATE, DROP, ALTER, INDEX, LOCK TABLES, REFERENCES"

// createRestoreUserSQL makes the database if it is gone and a temporary
// user granted only on it. The statement travels on stdin, never in an
// argument.
func createRestoreUserSQL(db, user, password string) string {
	return "CREATE DATABASE IF NOT EXISTS `" + db + "` CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;\n" +
		"CREATE USER " + sqlString(user) + "@'localhost' IDENTIFIED BY " + sqlString(password) + ";\n" +
		"GRANT " + restorePrivileges + " ON " + grantDatabase(db) + ".* TO " + sqlString(user) + "@'localhost';\n"
}

func dropRestoreUserSQL(user string) string {
	return "DROP USER IF EXISTS " + sqlString(user) + "@'localhost';\n"
}

// restoreClientConfig is the temporary user's option file. The values are
// fixed-form (checked by the patterns above), so no escaping is needed.
func restoreClientConfig(user, password string) []byte {
	return []byte("[client]\nuser=" + user + "\npassword=" + password + "\nprotocol=socket\nsocket=" + mariadbSocket + "\n")
}

// resticSnapshot is restic's JSON for one snapshot.
type resticSnapshot struct {
	ID       string    `json:"id"`
	Time     time.Time `json:"time"`
	Hostname string    `json:"hostname"`
	Paths    []string  `json:"paths"`
	Tags     []string  `json:"tags"`
	Summary  struct {
		TotalFiles uint64 `json:"total_files_processed"`
		TotalBytes uint64 `json:"total_bytes_processed"`
	} `json:"summary"`
}

// parseSnapshots keeps the account's own snapshots, newest first. A
// snapshot counts only with this server's host name, the account's tag and
// exactly the account's two paths.
func parseSnapshots(out []byte, id, home, dumps string) ([]Snapshot, error) {
	var raw []resticSnapshot
	if json.Unmarshal(out, &raw) != nil || len(raw) > maxSnapshots {
		return nil, &BackupError{Step: "snapshot", Detail: "restic's snapshot list could not be read"}
	}
	items := []Snapshot{}
	for _, s := range raw {
		if !snapshotIDPattern.MatchString(s.ID) || s.Hostname != backupHost || !slices.Contains(s.Tags, accountTag(id)) {
			continue
		}
		paths := slices.Clone(s.Paths)
		sort.Strings(paths)
		want := []string{home, dumps}
		sort.Strings(want)
		if !slices.Equal(paths, want) {
			continue
		}
		dbs := []string{}
		for _, tag := range s.Tags {
			if db, ok := strings.CutPrefix(tag, "db-"); ok && validDatabaseName(db) {
				dbs = append(dbs, db)
			}
		}
		sort.Strings(dbs)
		items = append(items, Snapshot{ID: s.ID, Time: s.Time.UTC(), Bytes: s.Summary.TotalBytes, Files: s.Summary.TotalFiles, Databases: dbs})
	}
	sort.SliceStable(items, func(i, j int) bool { return items[i].Time.After(items[j].Time) })
	return items, nil
}

// backupSummary is the last line restic backup --json prints.
type backupSummary struct {
	MessageType string    `json:"message_type"`
	SnapshotID  string    `json:"snapshot_id"`
	BackupStart time.Time `json:"backup_start"`
	TotalFiles  uint64    `json:"total_files_processed"`
	TotalBytes  uint64    `json:"total_bytes_processed"`
}

func parseBackupSummary(out []byte) (backupSummary, bool) {
	lines := strings.Split(strings.TrimSpace(string(out)), "\n")
	for i := len(lines) - 1; i >= 0; i-- {
		var s backupSummary
		if json.Unmarshal([]byte(lines[i]), &s) == nil && s.MessageType == "summary" {
			return s, snapshotIDPattern.MatchString(s.SnapshotID)
		}
	}
	return backupSummary{}, false
}

// parsePruneRemoved counts what restic forget removed across all groups.
func parsePruneRemoved(out []byte) int {
	var groups []struct {
		Remove []json.RawMessage `json:"remove"`
	}
	start := strings.Index(string(out), "[")
	if start < 0 || json.NewDecoder(strings.NewReader(string(out[start:]))).Decode(&groups) != nil {
		return 0
	}
	n := 0
	for _, g := range groups {
		n += len(g.Remove)
	}
	return n
}

// lsNode is one entry of restic ls --json.
type lsNode struct {
	MessageType string `json:"message_type"`
	Type        string `json:"type"`
	Path        string `json:"path"`
	Size        uint64 `json:"size"`
	LinkTarget  string `json:"linktarget"`
}

func validBackupInput(in BackupInput, actor string) bool {
	return validText(in.Reason, 500) && validText(actor, 120) && len(in.Databases) <= maxBackupDatabases
}

func validRestoreInput(in RestoreInput, actor string) bool {
	return in.ExpectedRevision != 0 && snapshotIDPattern.MatchString(in.Snapshot) && (in.Files || len(in.Databases) > 0) && len(in.Databases) <= maxBackupDatabases && validText(in.Reason, 500) && validText(actor, 120)
}

// backupDetail is installDetail under the backup name: the end of a step's
// output, printable ASCII, secrets removed, at most 512 bytes.
func backupDetail(out []byte, secrets ...string) string { return installDetail(out, secrets...) }

func backupFailed(step string, out []byte, secrets ...string) error {
	return &BackupError{Step: step, Detail: backupDetail(out, secrets...)}
}
