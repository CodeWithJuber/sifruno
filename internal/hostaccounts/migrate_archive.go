package hostaccounts

import (
	"context"
	"errors"
	"io"
	"path"
	"slices"
	"strings"
	"time"
	"unicode/utf8"

	"sifruno/internal/cpmove"
	"sifruno/internal/cpsource"
	"sifruno/internal/sitemodel"
)

// A migration from a cPanel backup file (docs/migration-design.md): the
// admin uploads cpmove-USER.tar.gz through the panel, which streams it to
// POST /v1/migrations/archive. The broker keeps it root's, 0600, in the
// migration's own folder, for the 24 hours any migration lives, and reads
// it with cpmove.Read, which bounds every size and refuses names outside
// the archive. Every later step reads the file again and takes only what
// it needs: the plan the metadata and the .htaccess files, the copy the
// home, each database step its own dump, the certificate step the
// installed certificate. From the staged copy on, a backup file's move is
// an SSH move's: the same tier check and conversion, cp as the site's user,
// the dump loaded as the site's user. Finishing the migration deletes the
// file. Nothing on any other server is touched.

const (
	// maxArchiveBytes bounds one uploaded backup file.
	maxArchiveBytes = 32 << 30
	// archiveUploadTimeout bounds the upload and its first read.
	archiveUploadTimeout = 2 * time.Hour
)

// validArchive checks what a record says a backup file holds.
func validArchive(a *MigrationArchive) bool {
	if a == nil || !cpsource.UserPattern.MatchString(a.User) || !cpsource.ValidDomain(a.Domain) || a.Bytes <= 0 || a.Bytes > maxArchiveBytes || a.HomeBytes < 0 ||
		len(a.Databases) > cpsource.MaxDatabases || len(a.NotCarried) > sitemodel.MaxNotCarried || !validArchiveHome(a.Home, a.User) {
		return false
	}
	for _, d := range a.Databases {
		if !validDatabaseName(d) || !strings.HasPrefix(d, a.User+"_") {
			return false
		}
	}
	for _, item := range a.NotCarried {
		if !utf8.ValidString(item.Part+item.Text+item.Where) || len(item.Part) > 32 || len(item.Text) > 1024 || len(item.Where) > 1024 {
			return false
		}
	}
	return true
}

// validArchiveHome is the home the backup's old server gave the account:
// an absolute clean path that ends in the account's name, as cPanel's do.
func validArchiveHome(home, user string) bool {
	return strings.HasPrefix(home, "/") && path.Clean(home) == home && path.Base(home) == user && strings.Count(home, "/") >= 2 &&
		resticSafeArgumentSet.MatchString(home) && !strings.Contains(home, ":")
}

func validArchiveOpen(in MigrationArchiveInput, actor string) bool {
	return in.Size > 0 && in.Size <= maxArchiveBytes && validText(in.Reason, 500) && validText(actor, 120)
}

// openArchiveMigration takes an uploaded backup file as a migration's
// source. The upload runs outside migrateMu, so a finish or another
// migration does not wait for it; the id is reserved meanwhile, so the
// sweep does not take its folder for a stray one.
func (s *store) openArchiveMigration(ctx context.Context, in MigrationArchiveInput, body io.Reader, actor string) (Migration, error) {
	if ctx == nil || body == nil || !validArchiveOpen(in, actor) {
		return Migration{}, ErrInvalid
	}
	if s.migrate == nil {
		return Migration{}, ErrUnavailable
	}
	id, err := s.reserveArchive(ctx)
	if err != nil {
		return Migration{}, err
	}
	defer func() {
		s.migrateMu.Lock()
		delete(s.uploading, id)
		s.migrateMu.Unlock()
	}()
	work, cancel := backupContext(ctx, archiveUploadTimeout)
	defer cancel()
	a, err := s.migrate.SaveArchive(work, id, in.Size, body)
	if err != nil {
		_ = s.migrate.Forget(id)
		return Migration{}, err
	}
	if a.Site.DocRoot != "public_html" {
		_ = s.migrate.Forget(id)
		return Migration{}, &MigrationError{Step: "source", Detail: "The website's files are not in the account's public_html folder. This version moves only sites kept in public_html."}
	}
	// The old home's path is where its .htaccess files' AuthUserFile lines
	// point; one this does not take is cPanel's usual.
	home := a.Site.Home
	if !validArchiveHome(home, a.Site.Account) {
		home = "/home/" + a.Site.Account
	}
	archive := &MigrationArchive{User: a.Site.Account, Domain: a.Site.Domain, Databases: []string{}, Bytes: in.Size, HomeBytes: a.HomeBytes, Home: home, NotCarried: slices.Clone(a.Site.NotCarried)}
	for _, d := range a.Site.Databases {
		archive.Databases = append(archive.Databases, d.Name)
	}
	if archive.NotCarried == nil {
		archive.NotCarried = []sitemodel.Item{}
	}
	m := migrationRecord{ID: id, Via: ViaArchive, Actor: actor, Reason: in.Reason, CreatedAt: time.Now().UTC(), Archive: archive}
	s.migrateMu.Lock()
	defer s.migrateMu.Unlock()
	if err := s.putMigration(m); err != nil {
		_ = s.migrate.Forget(id)
		return Migration{}, err
	}
	return m.view(), nil
}

// reserveArchive sweeps, checks the migration count with the uploads in
// progress, and reserves a new id for an upload.
func (s *store) reserveArchive(ctx context.Context) (string, error) {
	s.migrateMu.Lock()
	defer s.migrateMu.Unlock()
	if err := s.sweepMigrations(ctx, time.Now().UTC()); err != nil {
		return "", err
	}
	items, err := s.migrationRecords()
	if err != nil {
		return "", err
	}
	if len(items)+len(s.uploading) >= maxMigrations {
		return "", ErrConflict
	}
	id, err := randomID()
	if err != nil {
		return "", err
	}
	if s.uploading == nil {
		s.uploading = map[string]bool{}
	}
	s.uploading[id] = true
	return id, nil
}

// archiveAccounts is the one account a backup file holds.
func archiveAccounts(m migrationRecord) []cpsource.Account {
	a := m.Archive
	return []cpsource.Account{{User: a.User, Domain: a.Domain, DiskUsedMiB: mibOf(a.HomeBytes)}}
}

func mibOf(n int64) int64 { return (n + 1<<20 - 1) >> 20 }

// planArchive reads the backup file again for the plan: its metadata, and
// its .htaccess files for the tier (planTier, as for a server).
func (s *store) planArchive(ctx context.Context, m migrationRecord, in MigrationPlanInput) (MigrationPlan, error) {
	if in.CPanel != nil {
		return MigrationPlan{}, ErrInvalid
	}
	if in.Username != m.Archive.User {
		return MigrationPlan{}, &MigrationError{Step: "account_missing", Detail: "The backup file holds the account " + m.Archive.User + ", not " + in.Username + "."}
	}
	a, err := s.migrate.ReadArchive(ctx, m)
	if err != nil {
		return MigrationPlan{}, err
	}
	if a.Site.Account != m.Archive.User || a.Site.Domain != m.Archive.Domain {
		return MigrationPlan{}, &MigrationError{Step: "archive", Detail: "The backup file no longer holds what it held when it was uploaded."}
	}
	site := a.Site
	plan := MigrationPlan{Username: site.Account, Domain: site.Domain, Aliases: slices.Clone(site.Aliases), WWW: site.WWW, PHPSource: site.PHP.Source,
		DiskUsedMiB: site.DiskUsedMiB, DiskLimitMiB: site.DiskLimitMiB, Databases: []cpsource.Database{}, Users: slices.Clone(a.Users),
		GrantsSkipped: []string{}, Cron: slices.Clone(site.Cron), CronSkipped: []string{}, Probes: []MigrationProbe{}, TierCauses: []string{},
		Converted: []MigrationFolder{}, TierRefusals: []string{}, NotCarried: slices.Clone(site.NotCarried)}
	for _, d := range site.Databases {
		db := cpsource.Database{Name: d.Name, Users: []string{}}
		for _, u := range a.Users {
			if slices.ContainsFunc(u.Grants, func(g cpsource.Grant) bool { return g.Database == d.Name }) {
				db.Users = append(db.Users, u.Name)
			}
		}
		plan.Databases = append(plan.Databases, db)
	}
	if plan.Aliases == nil {
		plan.Aliases = []string{}
	}
	if plan.Cron == nil {
		plan.Cron = []cpsource.CronLine{}
	}
	if err := s.planTier(ctx, m, m.Archive.Home, nil, &plan); err != nil {
		return MigrationPlan{}, err
	}
	return plan, nil
}

// archiveSite checks that the account is the one the backup file holds,
// with its domain: a backup file's copy goes into that account only.
func archiveSite(m migrationRecord, r record) error {
	if r.Account.Username != m.Archive.User || r.Account.Domain != m.Archive.Domain {
		return &MigrationError{Step: "source", Detail: "The backup file holds the account " + m.Archive.User + " with " + m.Archive.Domain + ", not this site."}
	}
	return nil
}

// archiveCertificate is the backup's installed certificate for the
// domain, in the form the SSH path's answer takes, or ErrNoCertificate.
func (s *store) archiveCertificate(ctx context.Context, m migrationRecord) (cpsource.VhostSSL, error) {
	a, err := s.migrate.ReadArchive(ctx, m)
	if err != nil {
		return cpsource.VhostSSL{}, err
	}
	defer clear(a.KeyPEM)
	if len(a.CertificatePEM) == 0 || len(a.KeyPEM) == 0 {
		return cpsource.VhostSSL{}, cpsource.ErrNoCertificate
	}
	return cpsource.VhostSSL{Certificate: string(a.CertificatePEM), Key: string(a.KeyPEM)}, nil
}

// archiveFailure says in plain words why a backup file cannot be used.
func archiveFailure(err error) error {
	switch {
	case errors.Is(err, cpmove.ErrNotCPMove):
		return &MigrationError{Step: "archive", Detail: "The file is not a cPanel account backup: it has no cp/USER file for the account its top folder names, or its main domain cannot be read."}
	case errors.Is(err, cpmove.ErrLimit):
		return &MigrationError{Step: "archive", Detail: "The backup file holds more than this server takes in one move: a file over 32 GiB, more than 100,000 entries, a name longer than 4096 bytes, more data than this server has free, or more than 64 times its own size once unpacked."}
	case errors.Is(err, sitemodel.ErrInvalid):
		return &MigrationError{Step: "archive", Detail: installDetail([]byte(err.Error())) + "."}
	case errors.Is(err, cpmove.ErrCanceled):
		return &MigrationError{Step: "archive", Detail: "Reading the backup file took longer than this server waits, so it stopped."}
	case errors.Is(err, cpmove.ErrArchive), errors.Is(err, cpmove.ErrUnsupported):
		return &MigrationError{Step: "archive", Detail: "The backup file is damaged or in a form Sifruno does not read. It must be the .tar.gz (or .tar) that cPanel's backup makes, whole, with no name outside its top folder."}
	}
	return ErrUnavailable
}
