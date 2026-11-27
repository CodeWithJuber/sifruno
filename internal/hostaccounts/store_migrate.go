package hostaccounts

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"slices"
	"strconv"
	"strings"
	"time"

	bolt "go.etcd.io/bbolt"
	"sifruno/internal/cpmove"
	"sifruno/internal/cpsource"
	"sifruno/internal/htaccess"
	"sifruno/internal/olsweb"
)

// Migrations are not written to the accounts' journal, as backups are not:
// reading the source changes no account, and a copy changes only the
// tenant's own files and databases with the tenant's rights, as a restore
// does. The panel's job log records who asked. What a copy leaves as root
// (its staging folder and temporary MariaDB users) goes through the backup
// leftover list, so a broker stopped mid-copy removes it at start.
var migrateBucket = []byte("hostbroker-migrate-v1")

// staleKeyBucket lists key lines the broker could not prove gone from an
// old server: a migration that expired, or was finished, while the source
// did not remove its line. They stay until the admin says the line is
// removed (POST /v1/migrations/{id}/stale-cleared).
var staleKeyBucket = []byte("hostbroker-migrate-stale-v1")

// maxStaleKeys bounds that list; past it an expired migration is kept, key
// and all, rather than forgotten without a trace.
const maxStaleKeys = 256

// StaleMigrationKey is a key line that may still be in root's
// authorized_keys on an old server: the line ending in Comment on Host.
type StaleMigrationKey struct {
	ID      string    `json:"id"`
	Host    string    `json:"host"`
	Port    int       `json:"port"`
	Comment string    `json:"comment"`
	Detail  string    `json:"detail"`
	At      time.Time `json:"at"`
}

func (k StaleMigrationKey) valid() bool {
	return idPattern.MatchString(k.ID) && validMigrationHost(k.Host) && k.Port >= 1 && k.Port <= 65535 && k.Comment == cpsource.KeyComment(k.ID) && len(k.Detail) <= 1024 && !k.At.IsZero()
}

// migrateEngine is the Linux side of a migration: the migration's folder
// with its key and known_hosts, and the programs it runs. Tests use a fake.
type migrateEngine interface {
	// Open makes the migration's private folder with a new ed25519 key
	// and returns its public half ("ssh-ed25519 AAAA...").
	Open(id string) (string, error)
	// Scan reads the source's host keys (ssh-keyscan); nothing is trusted
	// until the admin confirms one.
	Scan(ctx context.Context, host string, port int) ([]byte, error)
	// Pin writes the migration's known_hosts with exactly this key.
	Pin(id, key string) error
	// Remote runs one command on the source as root with the migration's
	// key; stdin, when set, is its input, stdout, when set, takes its
	// output. Exit 255 is ssh's own failure.
	Remote(ctx context.Context, m migrationRecord, command string, stdin io.Reader, stdout io.Writer, limit time.Duration) ([]byte, int, error)
	// Preflight copies only the site's .htaccess files into a root-only
	// staging folder and scans them; home is whether the home itself,
	// above public_html, has one.
	Preflight(ctx context.Context, m migrationRecord, sourceHome string, l backupLeftover) (site htaccess.SiteResult, home bool, err error)
	// Files copies the source home into the account's home: rsync as root
	// into a fresh staging folder, then cp as the site's user. When the
	// copy's .htaccess files convert to protected folders, protect puts
	// them live before cp runs; its error stops the copy.
	Files(ctx context.Context, m migrationRecord, sourceHome string, r record, needMiB int64, l backupLeftover, protect func(SiteProtection) error) (MigrateFilesResult, error)
	// ServerPreflight is Preflight for a site on another Linux server: the
	// document root's .htaccess files, fetched as its owner, or for nginx
	// the files its converted rules become, staged and scanned. leftOut
	// names the .htaccess files an nginx site holds, which nginx never
	// read and the copy leaves out.
	ServerPreflight(ctx context.Context, m migrationRecord, src serverSource, l backupLeftover) (site htaccess.SiteResult, leftOut []string, err error)
	// ServerFiles is Files for a site on another Linux server: rsync of
	// the document root, as its owner, into the staged public_html, nginx's
	// rules written as .htaccess files and wp-config.php pointed at the
	// database here on that root-only copy, then the same placement.
	ServerFiles(ctx context.Context, m migrationRecord, src serverSource, r record, needMiB int64, l backupLeftover, protect func(SiteProtection) error) (MigrateFilesResult, error)
	// Database dumps the source's database source into staging and loads
	// it into db, here, as the site's user through l's temporary MariaDB
	// user, then compares every table's rows. A cPanel source's database
	// has the same name on both servers.
	Database(ctx context.Context, m migrationRecord, source, db string, r record, l backupLeftover) (MigrateDatabaseResult, error)
	// SaveArchive makes the migration's folder for an uploaded backup file
	// and writes exactly size bytes of body into it, root's and 0600, within
	// the disk margin; then it reads the file once (cpmove.Read) without
	// extracting anything. For a backup file's migration, Preflight, Files
	// and Database take their part from the file instead of the old server.
	SaveArchive(ctx context.Context, id string, size int64, body io.Reader) (*cpmove.Archive, error)
	// ReadArchive reads the migration's backup file again, extracting
	// nothing.
	ReadArchive(ctx context.Context, m migrationRecord) (*cpmove.Archive, error)
	// Forget removes the migration's folder: its private key goes.
	Forget(id string) error
	// Folders names the migration folders on disk.
	Folders() ([]string, error)
}

// limitBuffer keeps a whole answer up to max bytes and fails the write past
// it, which stops the program's output copy.
type limitBuffer struct {
	b   []byte
	max int
}

func (w *limitBuffer) Write(p []byte) (int, error) {
	if len(w.b)+len(p) > w.max {
		return 0, ErrUnavailable
	}
	w.b = append(w.b, p...)
	return len(p), nil
}

func (s *store) migrationRecords() ([]migrationRecord, error) {
	var items []migrationRecord
	err := s.db.View(func(tx *bolt.Tx) error {
		b := tx.Bucket(migrateBucket)
		if b == nil {
			return nil
		}
		return b.ForEach(func(k, v []byte) error {
			var m migrationRecord
			d := json.NewDecoder(bytes.NewReader(v))
			d.DisallowUnknownFields()
			if d.Decode(&m) != nil || string(k) != m.ID || !m.valid() {
				return ErrUnavailable
			}
			items = append(items, m)
			return nil
		})
	})
	if err != nil || len(items) > maxMigrations {
		return nil, ErrUnavailable
	}
	return items, nil
}

func (s *store) putMigration(m migrationRecord) error {
	if !m.valid() {
		return ErrUnavailable
	}
	raw, err := json.Marshal(m)
	if err != nil {
		return ErrUnavailable
	}
	if s.db.Update(func(tx *bolt.Tx) error {
		b, e := tx.CreateBucketIfNotExists(migrateBucket)
		if e != nil {
			return e
		}
		return b.Put([]byte(m.ID), raw)
	}) != nil {
		return ErrUnavailable
	}
	return nil
}

func (s *store) dropMigration(id string) error {
	if s.db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket(migrateBucket)
		if b == nil {
			return nil
		}
		return b.Delete([]byte(id))
	}) != nil {
		return ErrUnavailable
	}
	return nil
}

func (s *store) staleKeys() ([]StaleMigrationKey, error) {
	items := []StaleMigrationKey{}
	err := s.db.View(func(tx *bolt.Tx) error {
		b := tx.Bucket(staleKeyBucket)
		if b == nil {
			return nil
		}
		return b.ForEach(func(k, v []byte) error {
			var item StaleMigrationKey
			d := json.NewDecoder(bytes.NewReader(v))
			d.DisallowUnknownFields()
			if d.Decode(&item) != nil || string(k) != item.ID || !item.valid() {
				return ErrUnavailable
			}
			items = append(items, item)
			return nil
		})
	})
	if err != nil || len(items) > maxStaleKeys {
		return nil, ErrUnavailable
	}
	return items, nil
}

func (s *store) staleKey(id string) (StaleMigrationKey, bool, error) {
	items, err := s.staleKeys()
	if err != nil {
		return StaleMigrationKey{}, false, err
	}
	for _, item := range items {
		if item.ID == id {
			return item, true, nil
		}
	}
	return StaleMigrationKey{}, false, nil
}

// putStaleKey records a line that may still be on the source, before the
// migration that knew it is forgotten.
func (s *store) putStaleKey(m migrationRecord, detail string) error {
	items, err := s.staleKeys()
	if err != nil {
		return err
	}
	if len(items) >= maxStaleKeys {
		return ErrUnavailable
	}
	item := StaleMigrationKey{ID: m.ID, Host: m.Host, Port: m.Port, Comment: cpsource.KeyComment(m.ID), Detail: installDetail([]byte(detail)), At: time.Now().UTC()}
	if !item.valid() {
		return ErrUnavailable
	}
	raw, err := json.Marshal(item)
	if err != nil {
		return ErrUnavailable
	}
	if s.db.Update(func(tx *bolt.Tx) error {
		b, e := tx.CreateBucketIfNotExists(staleKeyBucket)
		if e != nil {
			return e
		}
		return b.Put([]byte(item.ID), raw)
	}) != nil {
		return ErrUnavailable
	}
	return nil
}

// manualRemoval names exactly the line to remove and where.
func manualRemoval(m migrationRecord) string {
	return "Remove the line ending in " + cpsource.KeyComment(m.ID) + " from /root/.ssh/authorized_keys on " + m.Host + " (SSH port " + strconv.Itoa(m.Port) + ")."
}

// expireMigration ends a migration whose day is over. With a confirmed host
// key the source is asked to remove the line, with the key the broker still
// holds; whatever is not proved removed is recorded as a stale line, with
// the exact line and server, before the migration and its key are
// forgotten. Callers hold migrateMu.
func (s *store) expireMigration(ctx context.Context, m migrationRecord) error {
	if m.Via == ViaArchive {
		// No server holds a key: the file goes with the folder.
		return s.forgetMigration(m.ID)
	}
	result := MigrationFinishResult{Detail: "The old server's host key was never confirmed, so Sifruno never signed in there. If the key line was added there, it is still there. " + manualRemoval(m)}
	if m.Pinned != "" {
		result = s.removeSourceKey(ctx, m)
	}
	if !result.RemovedFromSource {
		if err := s.putStaleKey(m, "The migration expired before it ended. "+result.Detail); err != nil {
			return err
		}
	}
	return s.forgetMigration(m.ID)
}

// clearStaleKey drops a stale line the admin says is removed.
func (s *store) clearStaleKey(ctx context.Context, id string, in MigrationFinishInput, actor string) error {
	if ctx == nil || !idPattern.MatchString(id) || !validText(in.Reason, 500) || !validText(actor, 120) {
		return ErrInvalid
	}
	s.migrateMu.Lock()
	defer s.migrateMu.Unlock()
	if _, found, err := s.staleKey(id); err != nil || !found {
		if err != nil {
			return err
		}
		return ErrNotFound
	}
	if s.db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket(staleKeyBucket)
		if b == nil {
			return nil
		}
		return b.Delete([]byte(id))
	}) != nil {
		return ErrUnavailable
	}
	return nil
}

// listStaleKeys lists the key lines that may still be on old servers.
func (s *store) listStaleKeys(ctx context.Context) ([]StaleMigrationKey, error) {
	if ctx == nil {
		return nil, ErrInvalid
	}
	s.migrateMu.Lock()
	defer s.migrateMu.Unlock()
	return s.staleKeys()
}

// forgetMigration removes the migration's folder, then its record; a
// folder that cannot be removed keeps the record, for the next sweep.
func (s *store) forgetMigration(id string) error {
	if s.migrate.Forget(id) != nil {
		return ErrUnavailable
	}
	return s.dropMigration(id)
}

// sweepMigrations ends every expired migration (expireMigration), and
// removes every folder no record names (a broker stopped between the two).
// Callers hold migrateMu.
func (s *store) sweepMigrations(ctx context.Context, now time.Time) error {
	items, err := s.migrationRecords()
	if err != nil {
		return err
	}
	failed := false
	known := map[string]bool{}
	for id := range s.uploading {
		known[id] = true
	}
	for _, m := range items {
		if m.expired(now) {
			work, cancel := backupContext(ctx, migrateFinishTimeout)
			err := s.expireMigration(work, m)
			cancel()
			if err != nil {
				failed = true
				known[m.ID] = true
			}
			continue
		}
		known[m.ID] = true
	}
	folders, err := s.migrate.Folders()
	if err != nil {
		return err
	}
	for _, id := range folders {
		if !known[id] && s.migrate.Forget(id) != nil {
			failed = true
		}
	}
	if failed {
		return ErrUnavailable
	}
	return nil
}

// expireMigrations sweeps at once and then every interval until ctx ends,
// so a migration nobody finishes still has its key line removed from the
// source on the day it expires, not at the next migration or restart. Each
// expired migration's removal has its own minute.
func (s *store) expireMigrations(ctx context.Context, interval time.Duration) {
	if s.migrate == nil {
		return
	}
	tick := time.NewTicker(interval)
	defer tick.Stop()
	for {
		s.migrateMu.Lock()
		err := s.sweepMigrations(ctx, time.Now().UTC())
		s.migrateMu.Unlock()
		if err != nil {
			fmt.Fprintln(os.Stderr, "sifruno broker: an expired migration could not be ended yet (its key line or folder); the next sweep tries again")
		}
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
		}
	}
}

// migration reads one live migration; an expired one is not found (the
// sweep ends it, removing its key line from the source first). pinned
// requires the admin's confirmed host key.
func (s *store) migration(id string, pinned bool) (migrationRecord, error) {
	m, err := s.anyMigration(id)
	if err != nil {
		return migrationRecord{}, err
	}
	if m.expired(time.Now().UTC()) {
		return migrationRecord{}, ErrNotFound
	}
	if pinned && m.Pinned == "" && m.Via != ViaArchive {
		return migrationRecord{}, &MigrationError{Step: "host_key", Detail: "The old server's host key has not been confirmed yet."}
	}
	return m, nil
}

// anyMigration reads one migration, expired or not.
func (s *store) anyMigration(id string) (migrationRecord, error) {
	if !idPattern.MatchString(id) {
		return migrationRecord{}, ErrInvalid
	}
	if s.migrate == nil {
		return migrationRecord{}, ErrUnavailable
	}
	items, err := s.migrationRecords()
	if err != nil {
		return migrationRecord{}, err
	}
	for _, m := range items {
		if m.ID == id {
			return m, nil
		}
	}
	return migrationRecord{}, ErrNotFound
}

func (s *store) openMigration(ctx context.Context, in MigrationOpenInput, actor string) (Migration, error) {
	if ctx == nil || !validMigrationOpen(in, actor) {
		return Migration{}, ErrInvalid
	}
	if s.migrate == nil {
		return Migration{}, ErrUnavailable
	}
	s.migrateMu.Lock()
	defer s.migrateMu.Unlock()
	now := time.Now().UTC()
	if err := s.sweepMigrations(ctx, now); err != nil {
		return Migration{}, err
	}
	items, err := s.migrationRecords()
	if err != nil {
		return Migration{}, err
	}
	if len(items) >= maxMigrations {
		return Migration{}, ErrConflict
	}
	work, cancel := backupContext(ctx, migrateScanTimeout)
	defer cancel()
	out, err := s.migrate.Scan(work, in.Host, in.Port)
	if err != nil {
		return Migration{}, err
	}
	keys, ok := parseHostKeys(string(out), in.Host, in.Port)
	if !ok {
		return Migration{}, &MigrationError{Step: "connect", Detail: "The old server did not answer with an SSH host key Sifruno can read. Check the address and the SSH port."}
	}
	id, err := randomID()
	if err != nil {
		return Migration{}, err
	}
	// The folder comes first, then the record; a folder no record names
	// (a broker stopped between the two) is removed by the next sweep.
	m := migrationRecord{ID: id, Host: in.Host, Port: in.Port, HostKeys: keys, Via: in.Via, Actor: actor, Reason: in.Reason, CreatedAt: now}
	public, err := s.migrate.Open(id)
	if err != nil {
		_ = s.migrate.Forget(id)
		return Migration{}, err
	}
	m.PublicKey = public
	if err = s.putMigration(m); err != nil {
		_ = s.migrate.Forget(id)
		return Migration{}, err
	}
	return m.view(), nil
}

func (s *store) getMigration(ctx context.Context, id string) (Migration, error) {
	if ctx == nil {
		return Migration{}, ErrInvalid
	}
	s.migrateMu.Lock()
	defer s.migrateMu.Unlock()
	m, err := s.migration(id, false)
	if err != nil {
		return Migration{}, err
	}
	return m.view(), nil
}

// pinMigrationHostKey pins the offered key whose fingerprint the admin
// confirmed against the source's own (ssh-keygen -lf on the old server).
// Until then no command runs there.
func (s *store) pinMigrationHostKey(ctx context.Context, id string, in MigrationPinInput, actor string) (Migration, error) {
	if ctx == nil || !validMigrationPin(in, actor) {
		return Migration{}, ErrInvalid
	}
	s.migrateMu.Lock()
	defer s.migrateMu.Unlock()
	m, err := s.migration(id, false)
	if err != nil {
		return Migration{}, err
	}
	for _, k := range m.HostKeys {
		fp, ok := fingerprint(k)
		if !ok || fp.Fingerprint != in.Fingerprint {
			continue
		}
		if m.Pinned != "" && m.Pinned != k {
			return Migration{}, ErrConflict
		}
		if err = s.migrate.Pin(m.ID, k); err != nil {
			return Migration{}, err
		}
		m.Pinned = k
		if err = s.putMigration(m); err != nil {
			return Migration{}, err
		}
		return m.view(), nil
	}
	return Migration{}, &MigrationError{Step: "host_key", Detail: "That fingerprint is not one the old server offered."}
}

// remote runs one fixed command on the source and reads exit 255, ssh's
// own failure, as a sign-in that did not happen; any other failing exit is
// the step failed names (cpanel_tool for whmapi1 and uapi). A failure's
// output is the command's error output only: what it printed on standard
// output so far can hold credentials, such as the password hashes SHOW
// CREATE USER prints.
func (s *store) remote(ctx context.Context, m migrationRecord, command string, stdin io.Reader, failed string) ([]byte, error) {
	stdout := &limitBuffer{max: cpsource.MaxOutput}
	out, code, err := s.migrate.Remote(ctx, m, command, stdin, stdout, migrateRemoteTimeout)
	switch {
	case err != nil:
		return nil, err
	case code == 255:
		return nil, sshFailure("connect", out)
	case code != 0:
		return nil, migrationFailed(failed, out)
	}
	return stdout.b, nil
}

// cpanelAnswer is one cPanel answer: for an SSH migration whmapi1 or uapi
// run over SSH, for a WHM migration the panel's copy of WHM's own answer
// (D-0005), read by the same parsers. A WHM migration never runs a cPanel
// tool over SSH, and an SSH migration takes no answers from the panel.
func (s *store) cpanelAnswer(ctx context.Context, m migrationRecord, answers *CPanelAnswers, pick func(*CPanelAnswers) json.RawMessage, command string) ([]byte, error) {
	if m.Via != ViaWHM {
		if answers != nil {
			return nil, ErrInvalid
		}
		return s.remote(ctx, m, command, nil, "cpanel_tool")
	}
	if answers == nil {
		return nil, ErrInvalid
	}
	raw := pick(answers)
	if len(raw) == 0 || len(raw) > cpsource.MaxOutput {
		return nil, &MigrationError{Step: "whm_output", Detail: "The panel sent no WHM answer for a step of the copy."}
	}
	return raw, nil
}

func (s *store) sourceAccounts(ctx context.Context, m migrationRecord, answers *CPanelAnswers) ([]cpsource.Account, error) {
	out, err := s.cpanelAnswer(ctx, m, answers, func(a *CPanelAnswers) json.RawMessage { return a.Accounts }, cpsource.ListAccountsCommand())
	if err != nil {
		return nil, err
	}
	items, err := cpsource.ParseAccounts(out)
	if err != nil {
		return nil, &MigrationError{Step: "cpanel_output", Detail: "The old server's list of accounts could not be read (whmapi1 listaccts)."}
	}
	return items, nil
}

func (s *store) migrationAccounts(ctx context.Context, id string) ([]cpsource.Account, error) {
	if ctx == nil {
		return nil, ErrInvalid
	}
	m, err := s.lockedMigration(id)
	if err != nil {
		return nil, err
	}
	if m.Via == ViaArchive {
		return archiveAccounts(m), nil
	}
	if m.Via == ViaServer {
		// Another Linux server lists websites, not accounts.
		return nil, ErrInvalid
	}
	work, cancel := backupContext(ctx, migrateRemoteTimeout)
	defer cancel()
	// A WHM migration's accounts are listed by the panel through WHM.
	return s.sourceAccounts(work, m, nil)
}

// sourceSite reads the source account's main site: its home must end in
// its name and its document root be the home's public_html.
func (s *store) sourceSite(ctx context.Context, m migrationRecord, user, domain string, answers *CPanelAnswers) (cpsource.Account, cpsource.Site, error) {
	accounts, err := s.sourceAccounts(ctx, m, answers)
	if err != nil {
		return cpsource.Account{}, cpsource.Site{}, err
	}
	i := slices.IndexFunc(accounts, func(a cpsource.Account) bool { return a.User == user })
	if i < 0 {
		return cpsource.Account{}, cpsource.Site{}, &MigrationError{Step: "account_missing", Detail: "The old server has no account named " + user + "."}
	}
	account := accounts[i]
	if account.Problem != "" {
		return cpsource.Account{}, cpsource.Site{}, &MigrationError{Step: "source", Detail: account.Problem}
	}
	if domain != "" && account.Domain != domain {
		return cpsource.Account{}, cpsource.Site{}, &MigrationError{Step: "source", Detail: "The account " + user + " on the old server has another main domain than this site."}
	}
	command, err := cpsource.DomainUserDataCommand(account.Domain)
	if err != nil {
		return cpsource.Account{}, cpsource.Site{}, ErrInvalid
	}
	out, err := s.cpanelAnswer(ctx, m, answers, func(a *CPanelAnswers) json.RawMessage { return a.Site }, command)
	if err != nil {
		return cpsource.Account{}, cpsource.Site{}, err
	}
	site, err := cpsource.ParseSite(out, user, account.Domain)
	switch {
	case errors.Is(err, cpsource.ErrNotPublicHTML):
		return cpsource.Account{}, cpsource.Site{}, &MigrationError{Step: "source", Detail: "The site's files are not in the account's public_html folder. This version moves only sites kept in public_html."}
	case err != nil:
		return cpsource.Account{}, cpsource.Site{}, &MigrationError{Step: "cpanel_output", Detail: "The old server's details of the site could not be read (whmapi1 domainuserdata)."}
	}
	return account, site, nil
}

// planMigration reads everything the copy needs from the source account,
// and scans its .htaccess files for the tier.
func (s *store) planMigration(ctx context.Context, id string, in MigrationPlanInput, actor string) (MigrationPlan, error) {
	if ctx == nil || !validMigrationPlan(in, actor) {
		return MigrationPlan{}, ErrInvalid
	}
	if s.backup == nil {
		return MigrationPlan{}, ErrUnavailable
	}
	// The record is read under migrateMu, which is then let go: the reads
	// and the staging scan below may wait for backupMu behind a long
	// backup, and the admin's finish (the key's removal) must not wait.
	m, err := s.lockedMigration(id)
	if err != nil {
		return MigrationPlan{}, err
	}
	work, cancel := backupContext(ctx, 10*time.Minute)
	defer cancel()
	if m.Via == ViaArchive {
		return s.planArchive(work, m, in)
	}
	if m.Via == ViaServer {
		return s.planServer(work, m, in)
	}
	if in.Site != "" {
		return MigrationPlan{}, ErrInvalid
	}
	account, site, err := s.sourceSite(work, m, in.Username, "", in.CPanel)
	if err != nil {
		return MigrationPlan{}, err
	}
	plan := MigrationPlan{Username: account.User, Domain: account.Domain, Aliases: site.Aliases, WWW: site.WWW, DiskUsedMiB: account.DiskUsedMiB, DiskLimitMiB: account.DiskLimitMiB,
		Databases: []cpsource.Database{}, Users: []cpsource.DatabaseUser{}, GrantsSkipped: []string{}, Cron: []cpsource.CronLine{}, CronSkipped: []string{}, Probes: []MigrationProbe{}, TierCauses: []string{},
		Converted: []MigrationFolder{}, TierRefusals: []string{}, TierFix: []string{}, TierWarnings: []string{}}
	out, err := s.cpanelAnswer(work, m, in.CPanel, func(a *CPanelAnswers) json.RawMessage { return a.PHP }, cpsource.VhostPHPCommand())
	if err != nil {
		return MigrationPlan{}, err
	}
	if plan.PHPSource, err = cpsource.ParseVhostPHP(out, account.User, account.Domain); err != nil {
		return MigrationPlan{}, &MigrationError{Step: "cpanel_output", Detail: "The old server's PHP version for the site could not be read (whmapi1 php_get_vhost_versions)."}
	}
	plan.ClientAddress = s.sourceClient(work, m)
	if err = s.planDatabases(work, m, &plan, in.CPanel); err != nil {
		return MigrationPlan{}, err
	}
	if err = s.planCron(work, m, &plan); err != nil {
		return MigrationPlan{}, err
	}
	if err = s.planTier(work, m, site.HomeDir, nil, &plan); err != nil {
		return MigrationPlan{}, err
	}
	return plan, nil
}

// sourceClient reads the address the source sees this server come from,
// from its own sshd (cpsource.ClientAddressCommand). It never stops the
// plan: without it verify fails each folder open to some addresses only,
// so the cutover gate stays closed until a person checks them (D-0002).
func (s *store) sourceClient(ctx context.Context, m migrationRecord) string {
	out, err := s.remote(ctx, m, cpsource.ClientAddressCommand(), nil, "source")
	if err != nil {
		return ""
	}
	address, err := cpsource.ParseClientAddress(out)
	if err != nil {
		return ""
	}
	return address
}

func (s *store) planDatabases(ctx context.Context, m migrationRecord, plan *MigrationPlan, answers *CPanelAnswers) error {
	command, _ := cpsource.DatabasesCommand(plan.Username)
	out, err := s.cpanelAnswer(ctx, m, answers, func(a *CPanelAnswers) json.RawMessage { return a.Databases }, command)
	if err != nil {
		return err
	}
	dbs, err := cpsource.ParseDatabases(out, plan.Username)
	if err != nil {
		return unreadable(err, "databases (uapi Mysql list_databases)")
	}
	command, _ = cpsource.DatabaseUsersCommand(plan.Username)
	if out, err = s.cpanelAnswer(ctx, m, answers, func(a *CPanelAnswers) json.RawMessage { return a.DatabaseUsers }, command); err != nil {
		return err
	}
	users, err := cpsource.ParseDatabaseUsers(out, plan.Username)
	if err != nil {
		return unreadable(err, "database users (uapi Mysql list_users)")
	}
	names := make([]string, 0, len(dbs))
	for _, d := range dbs {
		names = append(names, d.Name)
		for _, u := range d.Users {
			if !slices.Contains(users, u) {
				users = append(users, u)
			}
		}
	}
	plan.Databases = dbs
	if len(users) == 0 {
		return nil
	}
	sql, err := cpsource.UsersSQL(users)
	if err != nil {
		return ErrInvalid
	}
	if out, err = s.remote(ctx, m, cpsource.SQLCommand(), strings.NewReader(sql), "database"); err != nil {
		return err
	}
	items, skipped, err := cpsource.ParseUsers(out, users, names)
	if err != nil {
		return &MigrationError{Step: "database", Detail: "The old server's database users and grants could not be read."}
	}
	plan.Users, plan.GrantsSkipped = items, append(plan.GrantsSkipped, skipped...)
	return nil
}

func unreadable(err error, what string) error {
	if errors.Is(err, cpsource.ErrUnprefixed) {
		return &MigrationError{Step: "source", Detail: installDetail([]byte(err.Error())) + ". Rename it on the old server to start with the account's name and _ first."}
	}
	return &MigrationError{Step: "cpanel_output", Detail: "The old server's " + what + " could not be read."}
}

func (s *store) planCron(ctx context.Context, m migrationRecord, plan *MigrationPlan) error {
	command, _ := cpsource.CrontabCommand(plan.Username)
	stdout := &limitBuffer{max: 256 << 10}
	out, code, err := s.migrate.Remote(ctx, m, command, nil, stdout, migrateRemoteTimeout)
	switch {
	case err != nil:
		return err
	case code == 255:
		return sshFailure("connect", out)
	case code == 1 && bytes.Contains(out, []byte("no crontab for")):
		return nil
	case code != 0:
		return migrationFailed("source", out)
	}
	jobs, skipped, err := cpsource.ParseCrontab(stdout.b)
	if err != nil {
		return &MigrationError{Step: "source", Detail: "The account's scheduled jobs on the old server could not be read."}
	}
	plan.Cron, plan.CronSkipped = jobs, skipped
	return nil
}

// planTier fetches the site's .htaccess files into a root-only staging
// folder, scans them and converts their access rules. Only a Native site,
// converted rules included, may go live on OpenLiteSpeed; the panel refuses
// the others (README, Migration). src is set for a site on another Linux
// server, whose files are its document root.
func (s *store) planTier(ctx context.Context, m migrationRecord, home string, src *serverSource, plan *MigrationPlan) error {
	s.backupMu.Lock()
	defer s.backupMu.Unlock()
	if err := s.cleanBackupLeftovers(ctx); err != nil {
		return err
	}
	op, err := randomID()
	if err != nil {
		return err
	}
	l := backupLeftover{Op: op}
	if err = s.recordLeftover(l); err != nil {
		return err
	}
	defer s.finishLeftover(l)
	var site htaccess.SiteResult
	var homeFile bool
	if src != nil {
		var leftOut []string
		site, leftOut, err = s.migrate.ServerPreflight(ctx, m, *src, l)
		plan.NotCarried = append(plan.NotCarried, leftOutItems(leftOut)...)
	} else {
		site, homeFile, err = s.migrate.Preflight(ctx, m, home, l)
	}
	if err != nil {
		return err
	}
	conv := htaccess.ConvertSite(site)
	plan.Tier, plan.TierCauses = string(htaccess.VerdictNative), []string{}
	if !conv.Native {
		plan.Tier, plan.TierCauses = string(htaccess.VerdictCompat), append([]string{}, site.Causes...)
		plan.TierRefusals = tierRefusals(conv)
		plan.TierAccess, plan.TierFix = tierFix(conv)
		if slices.ContainsFunc(conv.Refused, func(r htaccess.FileRefusal) bool { return r.Cause == htaccess.CauseNotConverted }) {
			plan.TierCauses = append(plan.TierCauses, htaccess.CauseNotConverted)
		}
	}
	if homeFile {
		plan.Tier = string(htaccess.VerdictCompat)
		plan.TierCauses = append(plan.TierCauses, "home_htaccess")
	}
	plan.Htaccess = len(site.Files)
	if plan.Tier == string(htaccess.VerdictNative) {
		plan.Converted = append(migrationFolders(conv.Rules), migrationMoved(conv)...)
		plan.Probes = foldersProbes(conv.Rules)
		plan.TierWarnings = tierWarnings(conv, plan.PHPSource)
	}
	return nil
}

// maxTierLines bounds each list of lines the plan carries.
const maxTierLines = 20

// tierWhere names a line: "<file> line N (<directive>)", the file relative
// to public_html, or "the site" for a refusal of the whole site.
func tierWhere(file string, line int, directive string) string {
	where := "the site"
	if file != "" {
		where = file
		if line > 0 {
			where += fmt.Sprintf(" line %d", line)
		}
		if directive != "" {
			where += " (" + directive + ")"
		}
	}
	return where
}

// tierRefusals says in plain words, at most 20 of them, why a site is not
// Native: each line the converter refused, with its file and directive.
func tierRefusals(conv htaccess.SiteConversion) []string {
	out := []string{}
	for _, r := range conv.Refused {
		if len(out) == maxTierLines {
			break
		}
		out = append(out, installDetail([]byte(tierWhere(r.File, r.Line, r.Directive)+": "+r.Reason)))
	}
	return out
}

// tierFix names the lines a person would change on the old server. When a
// refusal concerns an access rule, OpenLiteSpeed would open what it
// protects, so only those lines are named and access is true; otherwise
// every refused line in a file.
func tierFix(conv htaccess.SiteConversion) (access bool, lines []string) {
	access = slices.ContainsFunc(conv.Refused, func(r htaccess.FileRefusal) bool { return r.Cause == htaccess.CauseAccessControl })
	lines = []string{}
	for _, r := range conv.Refused {
		if r.File == "" || (access && r.Cause != htaccess.CauseAccessControl) || len(lines) == maxTierLines {
			continue
		}
		lines = append(lines, installDetail([]byte(tierWhere(r.File, r.Line, r.Directive))))
	}
	return access, lines
}

// tierWarnings are the lines of a Native site a person checks before
// cutover: what OpenLiteSpeed will not apply (htaccess.FileWarning), a
// memory_limit above the memory a new account's PHP may use, which the
// copy runs with instead (sitePHP), and a PHP handler naming another
// version than the one the plan read for the site, because this server
// runs every folder of a site with that one.
func tierWarnings(conv htaccess.SiteConversion, phpSource string) []string {
	out := []string{}
	add := func(text string) {
		if len(out) < maxTierLines {
			out = append(out, installDetail([]byte(text)))
		}
	}
	for _, w := range conv.Warnings {
		add(tierWhere(w.File, w.Line, w.Directive) + ": " + w.Reason)
	}
	for _, s := range conv.PHPSettings {
		if s.Name != "memory_limit" {
			continue
		}
		memory := DefaultLimits.MemoryMiB
		if mib, ok := olsweb.PHPSizeMiB(s.Value); !ok || mib > memory {
			add(tierWhere(".htaccess", s.Line, s.Name) + fmt.Sprintf(": the old server let the site's PHP use %s of memory (-1 is no limit), but a website's PHP here may use at most its plan's %d MiB, so the copy runs with memory_limit %dM. Check the pages that need the most memory before cutover.", s.Value, memory, memory))
		}
	}
	for _, p := range conv.PHP {
		if p.Package == "" || phpDigits(p.Package) == phpDigits(phpSource) {
			continue
		}
		add(tierWhere(p.File, p.Line, p.Directive) + ": the old server runs " + p.Path + " with PHP " + p.Package + ", but this server runs the whole site with one PHP version, the one the old server names for the site (" + phpSource + "). Check that part of the site before cutover.")
	}
	return out
}

// phpDigits is the version in a PHP package name: "81" in ea-php81.
func phpDigits(pkg string) string {
	i := len(pkg)
	for i > 0 && pkg[i-1] >= '0' && pkg[i-1] <= '9' {
		i--
	}
	return pkg[i:]
}

// beginMigrate checks the account under the broker lock and marks it busy,
// as a restore does: the copy and the import run as the site's user, so a
// delete, suspend, web change or install waits (409) until it ends.
func (s *store) beginMigrate(ctx context.Context, id string, revision uint64) (record, []string, error) {
	if snapshotReentry(ctx, s) {
		return record{}, nil, ErrConflict
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if !idPattern.MatchString(id) {
		return record{}, nil, ErrInvalid
	}
	if s.backup == nil || s.migrate == nil {
		return record{}, nil, ErrUnavailable
	}
	items, err := s.mutationReady(ctx)
	if err != nil {
		return record{}, nil, err
	}
	names := make([]string, 0, len(items))
	for _, r := range items {
		names = append(names, r.Account.Username)
	}
	for _, r := range items {
		if r.Account.ID != id {
			continue
		}
		if r.Account.Revision != revision || r.Account.State != "active" || s.installing[id] {
			return record{}, nil, ErrConflict
		}
		if s.native.Verify(ctx, r) != nil {
			return record{}, nil, ErrConflict
		}
		if s.installing == nil {
			s.installing = map[string]bool{}
		}
		s.installing[id] = true
		return r, names, nil
	}
	return record{}, nil, ErrNotFound
}

// migrateFiles copies the source account of the account's own name into
// its home. The source's details are read again here: the panel names only
// the migration.
func (s *store) migrateFiles(ctx context.Context, id string, in MigrateFilesInput, actor string) (MigrateFilesResult, error) {
	if ctx == nil || !validMigrateFiles(in, actor) {
		return MigrateFilesResult{}, ErrInvalid
	}
	m, err := s.lockedMigration(in.Migration)
	if err != nil {
		return MigrateFilesResult{}, err
	}
	r, _, err := s.beginMigrate(ctx, id, in.ExpectedRevision)
	if err != nil {
		return MigrateFilesResult{}, err
	}
	defer s.endInstall(id)
	work, cancel := backupContext(ctx, backupTimeout)
	defer cancel()
	var home string
	var needMiB int64
	var src *serverSource
	switch {
	case m.Via == ViaArchive:
		if in.CPanel != nil {
			return MigrateFilesResult{}, ErrInvalid
		}
		if err = archiveSite(m, r); err != nil {
			return MigrateFilesResult{}, err
		}
		home, needMiB = m.Archive.Home, mibOf(m.Archive.HomeBytes)
	case m.Via == ViaServer:
		if in.CPanel != nil {
			return MigrateFilesResult{}, ErrInvalid
		}
		server, need, err := s.serverFiles(work, m, r)
		if err != nil {
			return MigrateFilesResult{}, err
		}
		src, needMiB = &server, need
	default:
		account, site, err := s.lockedSourceSite(work, m, r.Account.Username, r.Account.Domain, in.CPanel)
		if err != nil {
			return MigrateFilesResult{}, err
		}
		home, needMiB = site.HomeDir, account.DiskUsedMiB
	}
	s.backupMu.Lock()
	defer s.backupMu.Unlock()
	if err = s.cleanBackupLeftovers(work); err != nil {
		return MigrateFilesResult{}, err
	}
	op, err := randomID()
	if err != nil {
		return MigrateFilesResult{}, err
	}
	l := backupLeftover{Op: op}
	if err = s.recordLeftover(l); err != nil {
		return MigrateFilesResult{}, err
	}
	defer s.finishLeftover(l)
	// Protected folders go live, journaled, before the copy reaches the
	// home: the account is busy for this copy, so setSiteFolders runs under
	// the broker lock without another change in between.
	protect := func(p SiteProtection) error {
		switch err := s.setSiteFolders(work, id, p, actor, in.Reason); {
		case err == nil:
			return nil
		case errors.Is(err, ErrWebRejected):
			return &MigrationError{Step: "tier", Detail: "The web server's configuration test failed with the site's protected folders, so the files were not put into the site."}
		case errors.Is(err, ErrInvalid):
			return &MigrationError{Step: "tier", Detail: "The site's protected folders do not fit this server's limits, so the files were not put into the site."}
		default:
			return err
		}
	}
	var result MigrateFilesResult
	if src != nil {
		result, err = s.migrate.ServerFiles(work, m, *src, r, needMiB, l, protect)
	} else {
		result, err = s.migrate.Files(work, m, home, r, needMiB, l, protect)
	}
	if err != nil {
		return MigrateFilesResult{}, err
	}
	// The copy gives the home the staged folder's ACL, which has no entry
	// for the web server, as a restore does: a live site's access is
	// granted again on held handles.
	if r.Web.enabled() {
		if err = s.native.GrantWebAccess(work, r); err != nil {
			return MigrateFilesResult{}, &MigrationError{Step: "copy", Detail: "The files were copied, but the web server's access to the site's folders could not be set again, so the site may answer 403."}
		}
		// OpenLiteSpeed reads a site's .htaccess, its rewrite rules, only
		// when it restarts, and a protected folders' restart ran before the
		// files were here. One graceful restart with the unchanged site
		// list, while the account is still busy for this copy, makes it
		// read the copied ones before the preview and verify (D-0004).
		s.mu.Lock()
		items, err := s.mutationReady(work)
		if err == nil {
			err = s.applySites(work, items, id)
		}
		s.mu.Unlock()
		if err != nil {
			return MigrateFilesResult{}, &MigrationError{Step: "reload", Detail: "The files are in place, but the web server could not reload to read the site's .htaccess rules, so its rewrites are not in force."}
		}
	}
	// Read while the account is still busy for this copy, so the revision
	// is the one the copy left and no other change's.
	s.mu.Lock()
	r, err = s.recordByID(id)
	s.mu.Unlock()
	if err != nil {
		return MigrateFilesResult{}, err
	}
	result.Revision = r.Account.Revision
	return result, nil
}

// lockedMigration reads a pinned migration under migrateMu.
func (s *store) lockedMigration(id string) (migrationRecord, error) {
	s.migrateMu.Lock()
	defer s.migrateMu.Unlock()
	return s.migration(id, true)
}

// lockedSourceSite reads the source without holding migrateMu, like every
// remote read: a migration's folder removed meanwhile only makes it fail.
func (s *store) lockedSourceSite(ctx context.Context, m migrationRecord, user, domain string, answers *CPanelAnswers) (cpsource.Account, cpsource.Site, error) {
	return s.sourceSite(ctx, m, user, domain, answers)
}

// migrateDatabase copies one database of the source account of the
// account's own name into the database of the same name here, which the
// panel's database service made first: the broker never makes one.
func (s *store) migrateDatabase(ctx context.Context, id string, in MigrateDatabaseInput, actor string) (MigrateDatabaseResult, error) {
	if ctx == nil || !validMigrateDatabase(in, actor) {
		return MigrateDatabaseResult{}, ErrInvalid
	}
	m, err := s.lockedMigration(in.Migration)
	if err != nil {
		return MigrateDatabaseResult{}, err
	}
	r, names, err := s.beginMigrate(ctx, id, in.ExpectedRevision)
	if err != nil {
		return MigrateDatabaseResult{}, err
	}
	defer s.endInstall(id)
	if _, ok := accountDatabases([]string{in.Database}, r.Account.Username, names); !ok {
		return MigrateDatabaseResult{}, ErrInvalid
	}
	work, cancel := backupContext(ctx, backupTimeout)
	defer cancel()
	source, err := s.sourceDatabase(work, m, r, in)
	if err != nil {
		return MigrateDatabaseResult{}, err
	}
	s.backupMu.Lock()
	defer s.backupMu.Unlock()
	if err = s.cleanBackupLeftovers(work); err != nil {
		return MigrateDatabaseResult{}, err
	}
	op, err := randomID()
	if err != nil {
		return MigrateDatabaseResult{}, err
	}
	user, err := restoreUserName()
	if err != nil {
		return MigrateDatabaseResult{}, err
	}
	l := backupLeftover{Op: op, Users: map[string]string{in.Database: user}}
	if err = s.recordLeftover(l); err != nil {
		return MigrateDatabaseResult{}, err
	}
	defer s.finishLeftover(l)
	return s.migrate.Database(work, m, source, in.Database, r, l)
}

// sourceDatabase checks that the source holds the database under the
// account of this name, the old server's list or the backup file's, and
// names it there: the same name, but for another Linux server, whose
// site's wp-config.php names it.
func (s *store) sourceDatabase(ctx context.Context, m migrationRecord, r record, in MigrateDatabaseInput) (string, error) {
	switch m.Via {
	case ViaArchive:
		if in.CPanel != nil {
			return "", ErrInvalid
		}
		if err := archiveSite(m, r); err != nil {
			return "", err
		}
		if !slices.Contains(m.Archive.Databases, in.Database) {
			return "", &MigrationError{Step: "database", Detail: "The backup file holds no database " + in.Database + "."}
		}
		return in.Database, nil
	case ViaServer:
		if in.CPanel != nil {
			return "", ErrInvalid
		}
		return s.serverSourceDatabase(ctx, m, r, in.Database)
	}
	command, err := cpsource.DatabasesCommand(r.Account.Username)
	if err != nil {
		return "", ErrInvalid
	}
	out, err := s.cpanelAnswer(ctx, m, in.CPanel, func(a *CPanelAnswers) json.RawMessage { return a.Databases }, command)
	if err != nil {
		return "", err
	}
	dbs, err := cpsource.ParseDatabases(out, r.Account.Username)
	if err != nil {
		return "", unreadable(err, "databases (uapi Mysql list_databases)")
	}
	if !slices.ContainsFunc(dbs, func(d cpsource.Database) bool { return d.Name == in.Database }) {
		return "", &MigrationError{Step: "database", Detail: "The old server's account " + r.Account.Username + " has no database " + in.Database + "."}
	}
	return in.Database, nil
}

// finishMigration removes the key's line from the source's authorized_keys,
// proves it with a sign-in that is then refused, and removes the local key
// and the record whatever the source answered; a line not proved removed
// is kept as a stale line. An expired migration is finished the same way
// with the key the broker still holds. A migration already ended answers
// what is known of its line: a stale line, never "removed".
func (s *store) finishMigration(ctx context.Context, id string, in MigrationFinishInput, actor string) (MigrationFinishResult, error) {
	if ctx == nil || !validText(in.Reason, 500) || !validText(actor, 120) {
		return MigrationFinishResult{}, ErrInvalid
	}
	s.migrateMu.Lock()
	defer s.migrateMu.Unlock()
	if !idPattern.MatchString(id) {
		return MigrationFinishResult{}, ErrInvalid
	}
	if s.migrate == nil {
		return MigrationFinishResult{}, ErrUnavailable
	}
	m, err := s.anyMigration(id)
	if errors.Is(err, ErrNotFound) {
		stale, found, serr := s.staleKey(id)
		switch {
		case serr != nil:
			return MigrationFinishResult{}, serr
		case found:
			return MigrationFinishResult{Detail: stale.Detail}, nil
		}
		return MigrationFinishResult{}, ErrNotFound
	}
	if err != nil {
		return MigrationFinishResult{}, err
	}
	if m.Via == ViaArchive {
		if err = s.forgetMigration(id); err != nil {
			return MigrationFinishResult{}, err
		}
		return MigrationFinishResult{RemovedFromSource: true, Detail: "The uploaded backup file was deleted from this server."}, nil
	}
	result := MigrationFinishResult{Detail: "The old server's host key was never confirmed, so Sifruno never signed in there. If the key line was added there, it is still there. " + manualRemoval(m)}
	if m.Pinned != "" {
		work, cancel := backupContext(ctx, migrateFinishTimeout)
		result = s.removeSourceKey(work, m)
		cancel()
	}
	if !result.RemovedFromSource {
		if err = s.putStaleKey(m, result.Detail); err != nil {
			return MigrationFinishResult{}, err
		}
	}
	if err = s.forgetMigration(id); err != nil {
		return MigrationFinishResult{}, err
	}
	return result, nil
}

func (s *store) removeSourceKey(ctx context.Context, m migrationRecord) MigrationFinishResult {
	manual := " " + manualRemoval(m)
	command, err := cpsource.RemoveKeyCommand(m.ID)
	if err != nil {
		return MigrationFinishResult{Detail: "The removal could not be built." + manual}
	}
	out, code, err := s.migrate.Remote(ctx, m, command, nil, nil, migrateRemoteTimeout)
	if err != nil || code != 0 {
		return MigrationFinishResult{Detail: "The old server did not remove the key: " + installDetail(out) + "." + manual}
	}
	// The proof: the same key is now refused.
	out, code, err = s.migrate.Remote(ctx, m, "true", nil, nil, migrateRemoteTimeout)
	if err == nil && code == 255 && bytes.Contains(out, []byte("Permission denied")) {
		return MigrationFinishResult{RemovedFromSource: true, Detail: "The old server now refuses the migration key."}
	}
	return MigrationFinishResult{Detail: "The old server ran the removal, but a sign-in with the key was not refused as expected: " + installDetail(out) + "." + manual}
}
