package hostaccounts

import (
	"context"
	"errors"
	"net"
	"path"
	"strconv"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"
	"sifruno/internal/cpsource"
)

// Migration v1 (README, Migration): the broker reads one website account
// from a cPanel server over root SSH and copies it into a Sifruno account
// of the same name. Every source access is one of these fixed operations.
// The broker holds the migration's private key and the source's pinned host
// key; the panel only names the server, the fingerprint the admin
// confirmed, the account, and the database to copy.
const (
	migrateHostKeyAlias = "sifruno-migration-source"
	sshKeyscanPath      = "/usr/bin/ssh-keyscan"
	rsyncPath           = "/usr/bin/rsync"
	// The source's own programs, for the sender of a copy: util-linux's
	// runuser and rsync, where RHEL-family and Ubuntu servers keep them.
	sourceRunuserPath = "/usr/sbin/runuser"
	sourceRsyncPath   = "/usr/bin/rsync"

	// A migration's key lives this long. Past it every operation refuses
	// the migration and its folder is removed.
	migrationLifetime = 24 * time.Hour
	maxMigrations     = 16

	migrateScanTimeout   = 30 * time.Second
	migrateRemoteTimeout = 2 * time.Minute
	migrateFinishTimeout = time.Minute
)

// ErrMigrationFailed is a migration step that failed: the source could not
// be reached or refused the key, or a tool reported an error. MigrationError
// says which step.
var ErrMigrationFailed = errors.New("migration step failed")

// MigrationError names the failed step and the end of what it printed
// (printable ASCII, at most 512 bytes).
type MigrationError struct {
	Step   string `json:"step"`
	Detail string `json:"detail"`
}

func (e *MigrationError) Error() string        { return "migration " + e.Step + " failed" }
func (e *MigrationError) Is(target error) bool { return target == ErrMigrationFailed }

// The steps a MigrationError can name. The panel explains each one.
var migrationSteps = []string{"connect", "host_key", "source", "tier", "space", "fetch", "copy", "database", "dump", "import", "compare", "remove_key"}

func migrationFailed(step string, out []byte) error {
	return &MigrationError{Step: step, Detail: installDetail(out)}
}

// MigrationOpenInput names the source server. Host is a lowercase DNS name
// or an IPv4 address; the user is always root.
type MigrationOpenInput struct {
	Host   string `json:"host"`
	Port   int    `json:"port"`
	Reason string `json:"reason"`
}

// MigrationHostKey is one host key the source offered, by type and SHA-256
// fingerprint as ssh-keygen -l prints it ("SHA256:...").
type MigrationHostKey struct {
	Type        string `json:"type"`
	Fingerprint string `json:"fingerprint"`
}

// Migration is one source session. PublicKey is the line the admin adds to
// root's authorized_keys on the source (InstallCommand does it); HostKeys
// are what the source offered, and Pinned the fingerprint the admin
// confirmed, empty until then.
type Migration struct {
	ID             string             `json:"id"`
	Host           string             `json:"host"`
	Port           int                `json:"port"`
	PublicKey      string             `json:"public_key"`
	InstallCommand string             `json:"install_command"`
	HostKeys       []MigrationHostKey `json:"host_keys"`
	Pinned         string             `json:"pinned_fingerprint"`
	CreatedAt      time.Time          `json:"created_at"`
	ExpiresAt      time.Time          `json:"expires_at"`
}

// MigrationPinInput confirms one of the offered host keys.
type MigrationPinInput struct {
	Fingerprint string `json:"fingerprint"`
	Reason      string `json:"reason"`
}

// MigrationPlanInput names the source account to read.
type MigrationPlanInput struct {
	Username string `json:"username"`
	Reason   string `json:"reason"`
}

// MigrationProbe is a URL from the converted .htaccess rules that verify
// checks on both sites: 401 (auth), 403 (deny), 200 for a file a closed
// folder leaves open to everyone (allow), or a folder open to some
// addresses only (hosts), whose rule it carries: Hosts (only or except),
// Networks and Realm. Verify works out from that rule what each site must
// answer the address it sees verify come from.
type MigrationProbe struct {
	Path     string   `json:"path"`
	Kind     string   `json:"kind"`
	Hosts    string   `json:"hosts,omitempty"`
	Networks []string `json:"networks,omitempty"`
	Realm    bool     `json:"realm,omitempty"`
}

// MigrationPlan is what the source holds for one account. Users' hashes are
// credentials: the panel passes them to its database service and records
// none of them.
type MigrationPlan struct {
	Username      string                  `json:"username"`
	Domain        string                  `json:"domain"`
	Aliases       []string                `json:"aliases"`
	WWW           bool                    `json:"www"`
	PHPSource     string                  `json:"php_source"`
	DiskUsedMiB   int64                   `json:"disk_used_mib"`
	DiskLimitMiB  int64                   `json:"disk_limit_mib"`
	Databases     []cpsource.Database     `json:"databases"`
	Users         []cpsource.DatabaseUser `json:"users"`
	GrantsSkipped []string                `json:"grants_skipped"`
	Cron          []cpsource.CronLine     `json:"cron"`
	CronSkipped   []string                `json:"cron_skipped"`
	Tier          string                  `json:"tier"`
	TierCauses    []string                `json:"tier_causes"`
	// Converted lists the .htaccess files whose access rules were converted
	// for OpenLiteSpeed (Native includes them); TierRefusals says, file by
	// file, why a site is not Native.
	Converted    []MigrationFolder `json:"converted"`
	TierRefusals []string          `json:"tier_refusals"`
	Probes       []MigrationProbe  `json:"probes"`
	Htaccess     int               `json:"htaccess_files"`
	// ClientAddress is the address the source sees this server's
	// connections come from (its SSH_CONNECTION), or empty when it did not
	// say: verify needs it for folders open to some addresses only.
	ClientAddress string `json:"client_address"`
}

// MigrateFilesInput copies the source account of the same name into the
// account's home.
type MigrateFilesInput struct {
	Migration        string `json:"migration"`
	ExpectedRevision uint64 `json:"expected_revision"`
	Reason           string `json:"reason"`
}

// MigrateFilesResult says whether the copy holds a WordPress site
// (wp-config.php in public_html or the home), which protected folders its
// .htaccess files were converted to, now in the site's web server config,
// and the URLs verify checks for them, open files among them. Revision is
// the account's revision after the copy: protected folders going live
// raise it, and the panel's next step for the account sends this one.
type MigrateFilesResult struct {
	WordPress bool              `json:"wordpress"`
	Folders   []MigrationFolder `json:"folders"`
	Probes    []MigrationProbe  `json:"probes"`
	Revision  uint64            `json:"revision"`
}

// MigrateDatabaseInput copies one source database of the account into the
// database of the same name, which must already exist here.
type MigrateDatabaseInput struct {
	Migration        string `json:"migration"`
	Database         string `json:"database"`
	ExpectedRevision uint64 `json:"expected_revision"`
	Reason           string `json:"reason"`
}

// MigrationTable compares one table's rows on the source, counted after the
// dump, with the copy.
type MigrationTable struct {
	Table  string `json:"table"`
	Source int64  `json:"source"`
	Copy   int64  `json:"copy"`
}

// MigrateDatabaseResult is the database's tables, compared.
type MigrateDatabaseResult struct {
	Database string           `json:"database"`
	Tables   []MigrationTable `json:"tables"`
}

// MigrationFinishInput ends a migration.
type MigrationFinishInput struct {
	Reason string `json:"reason"`
}

// MigrationFinishResult says whether the key's line left the source's
// authorized_keys, proved by a sign-in that is then refused. The local key
// is removed either way.
type MigrationFinishResult struct {
	RemovedFromSource bool   `json:"removed_from_source"`
	Detail            string `json:"detail"`
}

// MigrationService is the broker's migration surface, implemented by the
// client.
type MigrationService interface {
	OpenMigration(context.Context, MigrationOpenInput, string) (Migration, error)
	GetMigration(context.Context, string) (Migration, error)
	PinMigrationHostKey(context.Context, string, MigrationPinInput, string) (Migration, error)
	MigrationAccounts(context.Context, string) ([]cpsource.Account, error)
	PlanMigration(context.Context, string, MigrationPlanInput, string) (MigrationPlan, error)
	MigrateFiles(context.Context, string, MigrateFilesInput, string) (MigrateFilesResult, error)
	MigrateDatabase(context.Context, string, MigrateDatabaseInput, string) (MigrateDatabaseResult, error)
	FinishMigration(context.Context, string, MigrationFinishInput, string) (MigrationFinishResult, error)
	StaleMigrationKeys(context.Context) ([]StaleMigrationKey, error)
	ClearStaleMigrationKey(context.Context, string, MigrationFinishInput, string) error
}

// validMigrationHost is a lowercase DNS name or an IPv4 address: rsync
// names the source as host:path, which an IPv6 address would need brackets
// for, so v1 leaves IPv6 out.
func validMigrationHost(s string) bool {
	if ip := net.ParseIP(s); ip != nil {
		return ip.To4() != nil && ip.String() == s && !ip.IsUnspecified() && !ip.IsLoopback()
	}
	return validBackupHost(s) && strings.Contains(s, ".")
}

func validMigrationOpen(in MigrationOpenInput, actor string) bool {
	return validMigrationHost(in.Host) && in.Port >= 1 && in.Port <= 65535 && validText(in.Reason, 500) && validText(actor, 120)
}

func validMigrationPin(in MigrationPinInput, actor string) bool {
	return strings.HasPrefix(in.Fingerprint, "SHA256:") && len(in.Fingerprint) <= 64 && resticSafeArgumentSet.MatchString(strings.ReplaceAll(in.Fingerprint, "+", "-")) && validText(in.Reason, 500) && validText(actor, 120)
}

func validMigrationPlan(in MigrationPlanInput, actor string) bool {
	return validUsername(in.Username) && validText(in.Reason, 500) && validText(actor, 120)
}

func validMigrateFiles(in MigrateFilesInput, actor string) bool {
	return idPattern.MatchString(in.Migration) && in.ExpectedRevision > 0 && validText(in.Reason, 500) && validText(actor, 120)
}

func validMigrateDatabase(in MigrateDatabaseInput, actor string) bool {
	return idPattern.MatchString(in.Migration) && validDatabaseName(in.Database) && in.ExpectedRevision > 0 && validText(in.Reason, 500) && validText(actor, 120)
}

// migrationRecord is the broker's own record of a migration: the source,
// the host keys it offered, the one the admin confirmed, and the public
// half of the migration's key. The private key and known_hosts are files in
// the migration's folder.
type migrationRecord struct {
	ID        string    `json:"id"`
	Host      string    `json:"host"`
	Port      int       `json:"port"`
	PublicKey string    `json:"public_key"`
	HostKeys  []string  `json:"host_keys"`
	Pinned    string    `json:"pinned"`
	Actor     string    `json:"actor"`
	Reason    string    `json:"reason"`
	CreatedAt time.Time `json:"created_at"`
}

func (m migrationRecord) valid() bool {
	if !idPattern.MatchString(m.ID) || !validMigrationHost(m.Host) || m.Port < 1 || m.Port > 65535 || len(m.HostKeys) == 0 || len(m.HostKeys) > maxHostKeys || m.CreatedAt.IsZero() {
		return false
	}
	if _, _, ok := normalizeSSHKey(m.PublicKey); !ok {
		return false
	}
	pinned := m.Pinned == ""
	for _, k := range m.HostKeys {
		canonical, _, ok := normalizeSSHKey(k)
		if !ok || canonical != k {
			return false
		}
		pinned = pinned || k == m.Pinned
	}
	return pinned
}

func (m migrationRecord) expired(now time.Time) bool {
	return now.Sub(m.CreatedAt) >= migrationLifetime || now.Before(m.CreatedAt.Add(-time.Hour))
}

// fingerprint is a key line's SHA-256 fingerprint and type.
func fingerprint(line string) (MigrationHostKey, bool) {
	key, _, _, _, err := ssh.ParseAuthorizedKey([]byte(line))
	if err != nil {
		return MigrationHostKey{}, false
	}
	return MigrationHostKey{Type: key.Type(), Fingerprint: ssh.FingerprintSHA256(key)}, true
}

func (m migrationRecord) view() Migration {
	out := Migration{ID: m.ID, Host: m.Host, Port: m.Port, PublicKey: cpsource.KeyLine(m.PublicKey, m.ID), InstallCommand: cpsource.InstallKeyCommand(m.PublicKey, m.ID), HostKeys: []MigrationHostKey{}, CreatedAt: m.CreatedAt, ExpiresAt: m.CreatedAt.Add(migrationLifetime)}
	for _, k := range m.HostKeys {
		if fp, ok := fingerprint(k); ok {
			out.HostKeys = append(out.HostKeys, fp)
			if k == m.Pinned {
				out.Pinned = fp.Fingerprint
			}
		}
	}
	return out
}

// migrateSSHArgs is ssh's option list for one migration: no configuration
// file but these options, only the migration's key, only the pinned host
// key under a fixed alias, no agent, no password prompt, no forwarding, no
// terminal, always as root. dir is the migration's folder.
func migrateSSHArgs(dir string, port int) []string {
	return []string{
		"-F", "/dev/null",
		"-T",
		"-o", "BatchMode=yes",
		"-o", "StrictHostKeyChecking=yes",
		"-o", "UserKnownHostsFile=" + dir + "/known_hosts",
		"-o", "GlobalKnownHostsFile=/dev/null",
		"-o", "HostKeyAlias=" + migrateHostKeyAlias,
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
		"-p", strconv.Itoa(port),
		"-l", "root",
	}
}

// migrateRemoteArgs runs one command on the source. The command is one
// string, as ssh sends it to the source's shell; cpsource builds it from
// fixed words and checked names only.
func migrateRemoteArgs(dir string, m migrationRecord, command string) ([]string, bool) {
	if command == "" || strings.ContainsAny(command, "\x00\r\n") || !validMigrationHost(m.Host) {
		return nil, false
	}
	return append(migrateSSHArgs(dir, m.Port), "--", m.Host, command), true
}

// migrateRsh is the --rsh value rsync starts ssh with. rsync splits it on
// spaces and runs the program directly, then appends the host and its own
// server command; every word is checked to hold no space, quote or
// backslash, so the split gives back exactly migrateSSHArgs.
func migrateRsh(dir string, port int) (string, bool) {
	words := append([]string{sshPath}, migrateSSHArgs(dir, port)...)
	for _, w := range words {
		if !resticSafeArgumentSet.MatchString(w) {
			return "", false
		}
	}
	return strings.Join(words, " "), true
}

// migrateExcludes are the parts of a cPanel home that are not the website:
// mail and its settings stay on the old server in v1, logs and caches are
// the old server's, .ssh would carry old keys (SFTP keys here are the
// broker's), ssl holds the old server's private keys, and www is a link to
// public_html. Anchored at the home.
var migrateExcludes = []string{
	"/mail/", "/etc/", "/.cpanel/", "/.cphorde/", "/logs/", "/tmp/", "/access-logs", "/www",
	"/.trash/", "/ssl/", "/.ssh/", "/.cagefs/", "/.cl.selector/", "/.softaculous/", "/.spamassassin/",
	"/.razor/", "/.lastlogin", "/.bash_history", "/public_ftp/", "/.gnupg/",
}

// senderPath is rsync's --rsync-path for a copy from the source: the
// source's rsync, run as the account that owns the home, never as root. The
// account's tree is the tenant's, and a root sender could be raced into
// reading through a link or hard link the tenant swaps in (/root, another
// account's wp-config.php); as the account it reads only what the account
// itself may read. rsync hands this value to the source's shell as it is
// (rsync(1), --rsync-path: "PROGRAM is run with the help of a shell"), so
// every word is fixed or the account name, which must match the home's last
// part and the account name rule. runuser -u runs the program directly,
// not through the account's own shell, so a nologin or jailed shell does
// not stop it.
func senderPath(home string) (string, bool) {
	user := path.Base(home)
	if !validUsername(user) || home != path.Clean(home) || !strings.HasPrefix(home, "/") {
		return "", false
	}
	return sourceRunuserPath + " -u " + user + " -- " + sourceRsyncPath, true
}

// fetchArgs copies the source user's home into dest: the sender runs as
// the account (senderPath), the receiver as root; recursive, links as
// links, modes without setuid or setgid bits, times, devices and special
// files left out, one filesystem, the excludes above. Owners are not
// copied: the staged files are root's until groupStaged gives them the
// site's group. Groups mark one thing only: an entry whose group on the
// source is the old web server's (nobody on cPanel, apache on a plain
// Apache) gets webMark, every other one group 0 (rsync's --groupmap
// matches the source's group names, and "*" the rest, nameless ones
// included), so webGroupEntries can find what that web server read
// through the group (D-0001).
func fetchArgs(rsh, host, home, dest string, webMark int) ([]string, bool) {
	sender, ok := senderPath(home)
	if !ok || webMark <= 0 {
		return nil, false
	}
	mark := strconv.Itoa(webMark)
	args := []string{"--rsh=" + rsh, "--rsync-path=" + sender, "-rlptg", "--groupmap=nobody:" + mark + ",apache:" + mark + ",*:0", "--sparse", "--chmod=ug-s", "--one-file-system", "--timeout=600"}
	for _, x := range migrateExcludes {
		args = append(args, "--exclude="+x)
	}
	return append(args, "--", host+":"+home+"/", dest+"/"), true
}

// htaccessArgs copies only the .htaccess files of the home and its
// public_html into dest, keeping the folders, so the scan sees the site's
// tree of rules. The sender runs as the account, as for the copy; files
// stay root's in the root-only staging folder.
func htaccessArgs(rsh, host, home, dest string) ([]string, bool) {
	sender, ok := senderPath(home)
	if !ok {
		return nil, false
	}
	return []string{"--rsh=" + rsh, "--rsync-path=" + sender, "-rlt", "--prune-empty-dirs", "--one-file-system", "--timeout=300",
		"--include=/public_html/", "--include=/public_html/**/", "--include=.htaccess", "--exclude=*",
		"--", host + ":" + home + "/", dest + "/"}, true
}

// migrateKeyscanArgs reads the source's host keys.
func migrateKeyscanArgs(host string, port int) []string {
	return []string{"-T", "10", "-p", strconv.Itoa(port), "-t", "ed25519,ecdsa,rsa", "--", host}
}
