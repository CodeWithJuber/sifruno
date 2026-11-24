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
	"sifruno/internal/cpsource"
	"sifruno/internal/htaccess"
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
	// Database dumps one database on the source into staging and loads it
	// as the site's user through l's temporary MariaDB user, then compares
	// every table's rows.
	Database(ctx context.Context, m migrationRecord, db string, r record, l backupLeftover) (MigrateDatabaseResult, error)
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
	if pinned && m.Pinned == "" {
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
	m := migrationRecord{ID: id, Host: in.Host, Port: in.Port, HostKeys: keys, Actor: actor, Reason: in.Reason, CreatedAt: now}
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
// own failure, as a connection that did not happen. A failure's detail is
// the command's error output only: what it printed on standard output so
// far can hold credentials, such as the password hashes SHOW CREATE USER
// prints.
func (s *store) remote(ctx context.Context, m migrationRecord, command string, stdin io.Reader) ([]byte, error) {
	stdout := &limitBuffer{max: cpsource.MaxOutput}
	out, code, err := s.migrate.Remote(ctx, m, command, stdin, stdout, migrateRemoteTimeout)
	switch {
	case err != nil:
		return nil, err
	case code == 255:
		return nil, migrationFailed("connect", out)
	case code != 0:
		return nil, migrationFailed("source", out)
	}
	return stdout.b, nil
}

func (s *store) sourceAccounts(ctx context.Context, m migrationRecord) ([]cpsource.Account, error) {
	out, err := s.remote(ctx, m, cpsource.ListAccountsCommand(), nil)
	if err != nil {
		return nil, err
	}
	items, err := cpsource.ParseAccounts(out)
	if err != nil {
		return nil, &MigrationError{Step: "source", Detail: "The old server's list of accounts could not be read (whmapi1 listaccts)."}
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
	work, cancel := backupContext(ctx, migrateRemoteTimeout)
	defer cancel()
	return s.sourceAccounts(work, m)
}

// sourceSite reads the source account's main site: its home must end in
// its name and its document root be the home's public_html.
func (s *store) sourceSite(ctx context.Context, m migrationRecord, user, domain string) (cpsource.Account, cpsource.Site, error) {
	accounts, err := s.sourceAccounts(ctx, m)
	if err != nil {
		return cpsource.Account{}, cpsource.Site{}, err
	}
	i := slices.IndexFunc(accounts, func(a cpsource.Account) bool { return a.User == user })
	if i < 0 {
		return cpsource.Account{}, cpsource.Site{}, &MigrationError{Step: "source", Detail: "The old server has no account named " + user + "."}
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
	out, err := s.remote(ctx, m, command, nil)
	if err != nil {
		return cpsource.Account{}, cpsource.Site{}, err
	}
	site, err := cpsource.ParseSite(out, user, account.Domain)
	switch {
	case errors.Is(err, cpsource.ErrNotPublicHTML):
		return cpsource.Account{}, cpsource.Site{}, &MigrationError{Step: "source", Detail: "The site's files are not in the account's public_html folder. This version moves only sites kept in public_html."}
	case err != nil:
		return cpsource.Account{}, cpsource.Site{}, &MigrationError{Step: "source", Detail: "The old server's details of the site could not be read (whmapi1 domainuserdata)."}
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
	account, site, err := s.sourceSite(work, m, in.Username, "")
	if err != nil {
		return MigrationPlan{}, err
	}
	plan := MigrationPlan{Username: account.User, Domain: account.Domain, Aliases: site.Aliases, WWW: site.WWW, DiskUsedMiB: account.DiskUsedMiB, DiskLimitMiB: account.DiskLimitMiB,
		Databases: []cpsource.Database{}, Users: []cpsource.DatabaseUser{}, GrantsSkipped: []string{}, Cron: []cpsource.CronLine{}, CronSkipped: []string{}, Probes: []MigrationProbe{}, TierCauses: []string{},
		Converted: []MigrationFolder{}, TierRefusals: []string{}}
	out, err := s.remote(work, m, cpsource.VhostPHPCommand(), nil)
	if err != nil {
		return MigrationPlan{}, err
	}
	if plan.PHPSource, err = cpsource.ParseVhostPHP(out, account.User, account.Domain); err != nil {
		return MigrationPlan{}, &MigrationError{Step: "source", Detail: "The old server's PHP version for the site could not be read (whmapi1 php_get_vhost_versions)."}
	}
	if err = s.planDatabases(work, m, &plan); err != nil {
		return MigrationPlan{}, err
	}
	if err = s.planCron(work, m, &plan); err != nil {
		return MigrationPlan{}, err
	}
	if err = s.planTier(work, m, site.HomeDir, &plan); err != nil {
		return MigrationPlan{}, err
	}
	return plan, nil
}

func (s *store) planDatabases(ctx context.Context, m migrationRecord, plan *MigrationPlan) error {
	command, _ := cpsource.DatabasesCommand(plan.Username)
	out, err := s.remote(ctx, m, command, nil)
	if err != nil {
		return err
	}
	dbs, err := cpsource.ParseDatabases(out, plan.Username)
	if err != nil {
		return unreadable(err, "databases (uapi Mysql list_databases)")
	}
	command, _ = cpsource.DatabaseUsersCommand(plan.Username)
	if out, err = s.remote(ctx, m, command, nil); err != nil {
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
	if out, err = s.remote(ctx, m, cpsource.SQLCommand(), strings.NewReader(sql)); err != nil {
		return err
	}
	items, skipped, err := cpsource.ParseUsers(out, users, names)
	if err != nil {
		return &MigrationError{Step: "source", Detail: "The old server's database users and grants could not be read."}
	}
	plan.Users, plan.GrantsSkipped = items, append(plan.GrantsSkipped, skipped...)
	return nil
}

func unreadable(err error, what string) error {
	if errors.Is(err, cpsource.ErrUnprefixed) {
		return &MigrationError{Step: "source", Detail: installDetail([]byte(err.Error())) + ". Rename it on the old server to start with the account's name and _ first."}
	}
	return &MigrationError{Step: "source", Detail: "The old server's " + what + " could not be read."}
}

func (s *store) planCron(ctx context.Context, m migrationRecord, plan *MigrationPlan) error {
	command, _ := cpsource.CrontabCommand(plan.Username)
	stdout := &limitBuffer{max: 256 << 10}
	out, code, err := s.migrate.Remote(ctx, m, command, nil, stdout, migrateRemoteTimeout)
	switch {
	case err != nil:
		return err
	case code == 255:
		return migrationFailed("connect", out)
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
// the others (README, Migration).
func (s *store) planTier(ctx context.Context, m migrationRecord, home string, plan *MigrationPlan) error {
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
	site, homeFile, err := s.migrate.Preflight(ctx, m, home, l)
	if err != nil {
		return err
	}
	conv := htaccess.ConvertSite(site)
	plan.Tier, plan.TierCauses = string(htaccess.VerdictNative), []string{}
	if !conv.Native {
		plan.Tier, plan.TierCauses = string(htaccess.VerdictCompat), append([]string{}, site.Causes...)
		plan.TierRefusals = tierRefusals(conv)
	}
	if homeFile {
		plan.Tier = string(htaccess.VerdictCompat)
		plan.TierCauses = append(plan.TierCauses, "home_htaccess")
	}
	plan.Htaccess = len(site.Files)
	if plan.Tier == string(htaccess.VerdictNative) {
		plan.Converted = migrationFolders(conv.Rules)
		plan.Probes = foldersProbes(conv.Rules)
	}
	return nil
}

// tierRefusals says in plain words, at most 20 of them, why a site is not
// Native: each file the converter refused, with its line.
func tierRefusals(conv htaccess.SiteConversion) []string {
	out := []string{}
	for _, r := range conv.Refused {
		if len(out) == 20 {
			break
		}
		where := "the site"
		if r.File != "" {
			where = r.File
			if r.Line > 0 {
				where += fmt.Sprintf(" line %d", r.Line)
			}
		}
		out = append(out, installDetail([]byte(where+": "+r.Reason)))
	}
	return out
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
	account, site, err := s.lockedSourceSite(work, m, r.Account.Username, r.Account.Domain)
	if err != nil {
		return MigrateFilesResult{}, err
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
	result, err := s.migrate.Files(work, m, site.HomeDir, r, account.DiskUsedMiB, l, protect)
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
	}
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
func (s *store) lockedSourceSite(ctx context.Context, m migrationRecord, user, domain string) (cpsource.Account, cpsource.Site, error) {
	return s.sourceSite(ctx, m, user, domain)
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
	// The source must list the database under the account of this name.
	command, err := cpsource.DatabasesCommand(r.Account.Username)
	if err != nil {
		return MigrateDatabaseResult{}, ErrInvalid
	}
	out, err := s.remote(work, m, command, nil)
	if err != nil {
		return MigrateDatabaseResult{}, err
	}
	dbs, err := cpsource.ParseDatabases(out, r.Account.Username)
	if err != nil {
		return MigrateDatabaseResult{}, unreadable(err, "databases (uapi Mysql list_databases)")
	}
	if !slices.ContainsFunc(dbs, func(d cpsource.Database) bool { return d.Name == in.Database }) {
		return MigrateDatabaseResult{}, &MigrationError{Step: "database", Detail: "The old server's account " + r.Account.Username + " has no database " + in.Database + "."}
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
	return s.migrate.Database(work, m, in.Database, r, l)
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
