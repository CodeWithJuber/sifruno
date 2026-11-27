//go:build linux

package hostaccounts

import (
	"context"
	"errors"
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"strings"
	"time"

	"golang.org/x/sys/unix"
	"sifruno/internal/cpmove"
	"sifruno/internal/cpsource"
)

// archiveName is the backup file in its migration's folder.
const archiveName = "archive"

// SaveArchive writes an uploaded backup file into a new migration folder,
// root's and 0700, as the file root's 0600, then reads it once. The bytes
// come from the panel; nothing in them runs, and the read is cpmove's.
func (m *migrator) SaveArchive(ctx context.Context, id string, size int64, body io.Reader) (*cpmove.Archive, error) {
	if !idPattern.MatchString(id) || size <= 0 || size > maxArchiveBytes || m.prepareDir() != nil || m.e.prepare() != nil {
		return nil, ErrUnavailable
	}
	// The file and what the copy stages from it later.
	if err := m.room(uint64(size) + 64<<20); err != nil {
		return nil, err
	}
	parent, err := openRootDir(m.dir)
	if err != nil {
		return nil, ErrUnavailable
	}
	defer parent.Close()
	if unix.Mkdirat(int(parent.Fd()), id, 0700) != nil {
		return nil, ErrUnavailable
	}
	d, err := openDirectoryAt(int(parent.Fd()), id)
	if err != nil {
		return nil, ErrUnavailable
	}
	defer d.Close()
	if m.e.chown(d, m.e.owner, m.e.owner) != nil || d.Chmod(0700) != nil {
		return nil, ErrUnavailable
	}
	fd, err := unix.Openat(int(d.Fd()), archiveName, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0600)
	if err != nil {
		return nil, ErrUnavailable
	}
	f := os.NewFile(uintptr(fd), archiveName)
	n, err := io.CopyBuffer(f, &contextReader{ctx: ctx, r: io.LimitReader(body, size)}, make([]byte, 1<<20))
	syncErr := f.Sync()
	f.Close()
	switch {
	case ctx.Err() != nil || err != nil || n != size:
		return nil, &MigrationError{Step: "archive", Detail: "The upload of the backup file stopped before its end (the connection ended, or it took longer than two hours), so nothing was kept."}
	case syncErr != nil:
		return nil, ErrUnavailable
	}
	// The first read has its own time, whatever the upload took.
	read, cancel := context.WithTimeout(context.WithoutCancel(ctx), archiveReadTimeout)
	defer cancel()
	return m.readArchive(read, id, nil)
}

// archiveReadTimeout bounds one read of a kept backup file.
const archiveReadTimeout = 30 * time.Minute

// archiveRatio bounds how much a backup file may expand: a site's files and
// dumps compress some tenfold, a file of zeros a thousandfold. Every step
// reads the whole file again, holding the backup lock for the database
// steps, so a file that expands past this is refused instead of costing
// minutes of root's CPU on each step.
const (
	archiveRatio       = 64
	minArchiveExpanded = 1 << 30
)

// ReadArchive reads the migration's backup file again, extracting nothing.
func (m *migrator) ReadArchive(ctx context.Context, rec migrationRecord) (*cpmove.Archive, error) {
	if rec.Via != ViaArchive {
		return nil, ErrInvalid
	}
	return m.readArchive(ctx, rec.ID, nil)
}

// readArchive reads the backup file of migration id; sink takes what is
// extracted (nil: nothing).
func (m *migrator) readArchive(ctx context.Context, id string, sink cpmove.Sink) (*cpmove.Archive, error) {
	d, err := m.folder(id)
	if err != nil {
		return nil, err
	}
	defer d.Close()
	fd, err := unix.Openat(int(d.Fd()), archiveName, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, ErrUnavailable
	}
	f := os.NewFile(uintptr(fd), archiveName)
	defer f.Close()
	info, err := f.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Size() <= 0 || info.Size() > maxArchiveBytes {
		return nil, ErrUnavailable
	}
	if uid, _, perm, err := ownerOfHandle(f); err != nil || uid != m.e.owner || perm != 0600 {
		return nil, ErrUnavailable
	}
	limits := cpmove.DefaultLimits()
	limits.MaxArchiveBytes = info.Size()
	limits.MaxExpandedBytes = min(limits.MaxExpandedBytes, max(minArchiveExpanded, info.Size()*archiveRatio))
	if sink == nil {
		sink = discardSink{}
	}
	a, err := cpmove.Read(ctx, f, limits, sink)
	if err != nil {
		var failed *MigrationError
		if errors.As(err, &failed) {
			return nil, err
		}
		return nil, archiveFailure(err)
	}
	return a, nil
}

// contextReader stops a copy when ctx ends.
type contextReader struct {
	ctx context.Context
	r   io.Reader
}

func (c *contextReader) Read(p []byte) (int, error) {
	if err := c.ctx.Err(); err != nil {
		return 0, err
	}
	return c.r.Read(p)
}

// discardSink reads every member to its end and keeps nothing.
type discardSink struct{}

func (discardSink) Dir(string, fs.FileMode) error { return nil }
func (discardSink) File(_ string, _ fs.FileMode, r io.Reader) error {
	_, err := io.Copy(io.Discard, r)
	return err
}
func (discardSink) Symlink(string, string) error { return nil }

// stageSink writes the members keep picks under root, at the name rename
// gives them, within budget bytes; the rest it reads and drops. A file past
// the budget stops the read with a space error.
type stageSink struct {
	root   cpmove.RootSink
	keep   func(name string, dir bool) (string, bool)
	budget uint64
	used   uint64
	full   bool
}

func (s *stageSink) Dir(name string, mode fs.FileMode) error {
	if to, ok := s.keep(name, true); ok && to != "." {
		return s.root.Dir(to, mode)
	}
	return nil
}

func (s *stageSink) File(name string, mode fs.FileMode, r io.Reader) error {
	to, ok := s.keep(name, false)
	if !ok {
		_, err := io.Copy(io.Discard, r)
		return err
	}
	return s.root.File(to, mode, &budgetReader{s: s, r: r})
}

func (s *stageSink) Symlink(name, target string) error {
	if to, ok := s.keep(name, false); ok {
		return s.root.Symlink(to, target)
	}
	return nil
}

type budgetReader struct {
	s *stageSink
	r io.Reader
}

var errBudget = errors.New("the copy reached the free space this server keeps")

func (b *budgetReader) Read(p []byte) (int, error) {
	n, err := b.r.Read(p)
	b.s.used += uint64(n)
	if b.s.used > b.s.budget {
		b.s.full = true
		return n, errBudget
	}
	return n, err
}

// inHome renames a home member ("home/x") to its place in a staged home
// ("x"); the home itself is ".".
func inHome(name string) (string, bool) {
	if name == "home" {
		return ".", true
	}
	rest, ok := strings.CutPrefix(name, "home/")
	return rest, ok
}

// homeHtaccess keeps what the tier check reads, as the SSH path's
// htaccessArgs does: the folders of public_html and the .htaccess files of
// the home and of public_html's tree.
func homeHtaccess(name string, dir bool) (string, bool) {
	rest, ok := inHome(name)
	if !ok {
		return "", false
	}
	if dir {
		return rest, rest == "." || rest == "public_html" || strings.HasPrefix(rest, "public_html/")
	}
	return rest, path.Base(rest) == ".htaccess" && (rest == ".htaccess" || strings.HasPrefix(rest, "public_html/"))
}

// extractArchive reads the migration's backup file into dir (a fresh
// root-only staging folder) through keep, within the free space margin.
func (m *migrator) extractArchive(ctx context.Context, rec migrationRecord, dir string, most uint64, keep func(string, bool) (string, bool)) error {
	avail, total, _, err := m.e.space(m.e.stage)
	if err != nil {
		return ErrUnavailable
	}
	root, err := os.OpenRoot(dir)
	if err != nil {
		return ErrUnavailable
	}
	defer root.Close()
	sink := &stageSink{root: cpmove.RootSink{Root: root}, keep: keep, budget: min(most, roomLeft(avail, total))}
	_, err = m.readArchive(ctx, rec.ID, sink)
	if sink.full {
		return &MigrationError{Step: "space", Detail: "The copy from the backup file reached the free space this server keeps (or, for a database dump, the 32 GiB one may take), so it was stopped."}
	}
	return err
}

// archivePreflight stages the backup file's .htaccess files and scans
// them, as Preflight does with the old server's.
func (m *migrator) archivePreflight(ctx context.Context, rec migrationRecord, stage *os.File, stagePath string) error {
	if unix.Mkdirat(int(stage.Fd()), "htaccess", 0700) != nil {
		return ErrUnavailable
	}
	return m.extractArchive(ctx, rec, filepath.Join(stagePath, "htaccess"), maxDumpBytes, homeHtaccess)
}

// archiveDatabase loads one database's dump from the backup file into the
// database of the same name here, as the site's user through l's temporary
// MariaDB user, as an SSH move's dump is loaded. A backup file has no live
// database to count against, so each table's source count is the copy's:
// the import itself is the check, and it fails on the first statement
// MariaDB refuses.
func (m *migrator) archiveDatabase(ctx context.Context, rec migrationRecord, db string, r record, l backupLeftover) (MigrateDatabaseResult, error) {
	stage, err := m.e.newStage(l.Op)
	if err != nil {
		return MigrateDatabaseResult{}, err
	}
	defer stage.Close()
	stagePath := filepath.Join(m.e.stage, l.Op)
	if unix.Mkdirat(int(stage.Fd()), "db", 0700) != nil {
		return MigrateDatabaseResult{}, ErrUnavailable
	}
	if err := m.archiveDump(ctx, rec, stagePath, db); err != nil {
		return MigrateDatabaseResult{}, err
	}
	if m.e.chown(stage, m.e.owner, r.Account.GID) != nil || stage.Chmod(0750) != nil {
		return MigrateDatabaseResult{}, ErrUnavailable
	}
	if err := m.e.importDatabase(ctx, r, stage, stagePath, db, l.Users[db]); err != nil {
		var failed *BackupError
		if errors.As(err, &failed) {
			return MigrateDatabaseResult{}, &MigrationError{Step: "import", Detail: failed.Detail}
		}
		return MigrateDatabaseResult{}, err
	}
	// The SSH path refuses a database with views, triggers, routines or
	// events before its dump, because those run as a named MariaDB user.
	// A backup's dump is only known once loaded: the same refusal follows
	// the load, and the failed step's undo drops the database.
	objects, _ := cpsource.ObjectsSQL(db)
	found, err := m.localSQL(ctx)(objects)
	if err != nil {
		return MigrateDatabaseResult{}, err
	}
	if kinds := strings.Fields(string(found)); len(kinds) > 0 {
		return MigrateDatabaseResult{}, &MigrationError{Step: "database", Detail: "The database " + db + " in the backup file has " + strings.Join(uniqueWords(kinds), ", ") + ". This version copies tables and rows only, because those objects run as a named MariaDB user."}
	}
	copied, tables, err := m.count(ctx, db, m.localSQL(ctx))
	if err != nil {
		return MigrateDatabaseResult{}, err
	}
	result := MigrateDatabaseResult{Database: db, Tables: make([]MigrationTable, 0, len(tables))}
	for _, t := range uniqueWords(tables) {
		result.Tables = append(result.Tables, MigrationTable{Table: t, Source: copied[t], Copy: copied[t]})
	}
	return result, nil
}

// archiveDump stages one database's dump from the backup file at
// <stage>/db/<db>.sql, as the SSH path's dump lands there.
func (m *migrator) archiveDump(ctx context.Context, rec migrationRecord, stagePath, db string) error {
	want := "mysql/" + db + ".sql"
	err := m.extractArchive(ctx, rec, filepath.Join(stagePath, "db"), maxDumpBytes, func(name string, dir bool) (string, bool) {
		return db + ".sql", !dir && name == want
	})
	if err != nil {
		return err
	}
	var st unix.Stat_t
	if unix.Lstat(filepath.Join(stagePath, "db", db+".sql"), &st) != nil || st.Mode&unix.S_IFMT != unix.S_IFREG {
		return &MigrationError{Step: "database", Detail: "The backup file holds no dump of " + db + "."}
	}
	return nil
}
