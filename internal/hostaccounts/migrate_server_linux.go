//go:build linux

package hostaccounts

import (
	"context"
	"errors"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"golang.org/x/sys/unix"
	"sifruno/internal/htaccess"
	"sifruno/internal/sitesource"
)

// The Linux engine's half of a migration from another Linux server
// (migrate_server.go): the document root comes over with rsync as its
// owner into the root-only staging folder as public_html, and from there
// placeFiles does what it does for a cPanel copy.

// serverSender is rsync's --rsync-path for a copy from another Linux
// server: the source's rsync as the document root's owner, never as root
// unless root owns the folder (docs/migration-design.md). rsync hands the
// value to the source's shell as it is; every word is fixed or the owner's
// checked name.
func serverSender(owner sitesource.Owner) (string, bool) {
	if owner.UID == 0 {
		return sourceRsyncPath, owner.Name == "root"
	}
	if owner.UID < 0 || owner.Name == "root" || !sitesource.ValidSystemUser(owner.Name) {
		return "", false
	}
	return sourceRunuserPath + " -u " + owner.Name + " -- " + sourceRsyncPath, true
}

// serverWebGroups are the groups a plain server's web server reads files
// through: Apache's on RHEL (apache) and Debian (www-data), nginx's
// (nginx), and nobody. rsync marks them as the cPanel copy marks nobody
// (D-0001).
var serverWebGroups = []string{"nobody", "apache", "www-data", "nginx"}

// serverFetchArgs copies the document root into dest as fetchArgs copies a
// cPanel home: the sender as the owner, the receiver as root, links as
// links, no setuid or setgid bits, no devices, one filesystem, groups
// marked for the old web server's read. An nginx site's .htaccess files are
// left out: nginx never read them.
func serverFetchArgs(rsh, host string, src serverSource, dest string, webMark int) ([]string, bool) {
	sender, ok := serverSender(src.owner)
	if !ok || webMark <= 0 || !sitesource.ValidDocRoot(src.site.DocRoot) {
		return nil, false
	}
	mark := strconv.Itoa(webMark)
	groups := make([]string, 0, len(serverWebGroups)+1)
	for _, g := range serverWebGroups {
		groups = append(groups, g+":"+mark)
	}
	args := []string{"--rsh=" + rsh, "--rsync-path=" + sender, "-rlptg", "--groupmap=" + strings.Join(append(groups, "*:0"), ","), "--sparse", "--chmod=ug-s", "--one-file-system", "--timeout=600"}
	if src.site.Server == "nginx" {
		args = append(args, "--exclude=.htaccess")
	}
	return append(args, "--", host+":"+src.site.DocRoot+"/", dest+"/"), true
}

// serverHtaccessArgs copies only the document root's .htaccess files into
// dest, keeping their folders, as the owner.
func serverHtaccessArgs(rsh, host string, src serverSource, dest string) ([]string, bool) {
	sender, ok := serverSender(src.owner)
	if !ok || !sitesource.ValidDocRoot(src.site.DocRoot) {
		return nil, false
	}
	return []string{"--rsh=" + rsh, "--rsync-path=" + sender, "-rlt", "--prune-empty-dirs", "--one-file-system", "--timeout=300",
		"--include=*/", "--include=.htaccess", "--exclude=*",
		"--", host + ":" + src.site.DocRoot + "/", dest + "/"}, true
}

// serverUnreadable explains rsync's exit 23 on a copy whose sender runs as
// the folder's owner.
func serverUnreadable(src serverSource, out []byte) error {
	return &MigrationError{Step: "fetch", Detail: installDetail([]byte("Some files or folders in " + src.site.DocRoot + " cannot be read by their owner " + src.owner.Name + ", so they were not copied and the copy stopped. Sifruno reads the folder as its owner, never as root. Give them to " + src.owner.Name + ", or remove them, on the old server.")), Output: installDetail(out)}
}

func (m *migrator) ServerPreflight(ctx context.Context, rec migrationRecord, src serverSource, l backupLeftover) (htaccess.SiteResult, []string, error) {
	if m.e.prepare() != nil || m.tools() != nil || rec.Via != ViaServer || !sitesource.ValidDocRoot(src.site.DocRoot) {
		return htaccess.SiteResult{}, nil, ErrUnavailable
	}
	stage, err := m.e.newStage(l.Op)
	if err != nil {
		return htaccess.SiteResult{}, nil, err
	}
	defer stage.Close()
	stagePath := filepath.Join(m.e.stage, l.Op)
	for _, dir := range []string{"found", "htaccess"} {
		if unix.Mkdirat(int(stage.Fd()), dir, 0700) != nil {
			return htaccess.SiteResult{}, nil, ErrUnavailable
		}
	}
	out, code, err := m.rsync(ctx, rec, func(rsh string) ([]string, bool) { return serverHtaccessArgs(rsh, rec.Host, src, stagePath+"/found") }, 10*time.Minute)
	switch {
	case err != nil:
		return htaccess.SiteResult{}, nil, err
	case code == 23:
		return htaccess.SiteResult{}, nil, serverUnreadable(src, out)
	case code != 0 && code != 24:
		return htaccess.SiteResult{}, nil, sshFailure("fetch", out)
	}
	var leftOut []string
	if src.site.Server == "nginx" {
		// nginx never read these; the site's own rules come instead.
		if leftOut, err = htaccessFiles(stagePath + "/found"); err != nil {
			return htaccess.SiteResult{}, nil, ErrUnavailable
		}
		if unix.Mkdirat(int(stage.Fd()), "htaccess/public_html", 0700) != nil {
			return htaccess.SiteResult{}, nil, ErrUnavailable
		}
		public, err := openDirectoryAt(int(stage.Fd()), "htaccess/public_html")
		if err != nil {
			return htaccess.SiteResult{}, nil, ErrUnavailable
		}
		err = writeConverted(public, src.site.Htaccess)
		public.Close()
		if err != nil {
			return htaccess.SiteResult{}, nil, err
		}
	} else if unix.Renameat(int(stage.Fd()), "found", int(stage.Fd()), "htaccess/public_html") != nil {
		return htaccess.SiteResult{}, nil, ErrUnavailable
	}
	site, _, err := scanSite(stagePath + "/htaccess/public_html")
	return site, leftOut, err
}

// htaccessFiles lists the .htaccess files below dir by relative path, at
// most a thousand, following no link.
func htaccessFiles(dir string) ([]string, error) {
	var out []string
	err := filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if len(out) == 1000 {
			return filepath.SkipAll
		}
		if d.Type().IsRegular() && d.Name() == ".htaccess" {
			rel, err := filepath.Rel(dir, p)
			if err != nil {
				return err
			}
			out = append(out, rel)
		}
		return nil
	})
	sort.Strings(out)
	return out, err
}

// writeConverted writes an nginx site's converted rules as .htaccess files
// into the staged public_html: each folder made when the site has none
// there (nginx closed it all the same), reached one folder at a time
// without following a link, and each file new.
func writeConverted(public *os.File, files map[string]string) error {
	folders := make([]string, 0, len(files))
	for folder := range files {
		folders = append(folders, folder)
	}
	sort.Strings(folders)
	for _, folder := range folders {
		dir, err := stagedFolder(public, folder)
		if err != nil {
			return &MigrationError{Step: "copy", Detail: installDetail([]byte("The folder " + folder + " of the copy is a link or not a folder, so nginx's rule for it could not be written."))}
		}
		fd, err := unix.Openat(int(dir.Fd()), ".htaccess", unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0644)
		if dir != public {
			dir.Close()
		}
		if err != nil {
			return &MigrationError{Step: "copy", Detail: installDetail([]byte("nginx's rules for " + folder + "/ could not be written into the copy."))}
		}
		f := os.NewFile(uintptr(fd), ".htaccess")
		_, werr := io.WriteString(f, files[folder])
		cerr := f.Close()
		if werr != nil || cerr != nil {
			return ErrUnavailable
		}
	}
	return nil
}

// stagedFolder opens (making it when missing, 0755) a folder below the
// staged public_html, one part at a time, following no link.
func stagedFolder(public *os.File, folder string) (*os.File, error) {
	if folder == "" {
		return public, nil
	}
	dir := public
	for _, part := range strings.Split(folder, "/") {
		if part == "" || part == "." || part == ".." {
			return nil, ErrInvalid
		}
		if err := unix.Mkdirat(int(dir.Fd()), part, 0755); err != nil && !errors.Is(err, unix.EEXIST) {
			return nil, err
		}
		next, err := openDirectoryAt(int(dir.Fd()), part)
		if dir != public {
			dir.Close()
		}
		if err != nil {
			return nil, err
		}
		if next.Chmod(0755) != nil {
			next.Close()
			return nil, ErrUnavailable
		}
		dir = next
	}
	return dir, nil
}

// rewriteStagedWPConfig points the staged wp-config.php at the database
// and user here (sitesource.RewriteWPConfig), in place, keeping its mode.
// The staging folder is root's alone while this runs, and the file is
// opened without following a link.
func rewriteStagedWPConfig(public *os.File, name, user string) error {
	fd, err := unix.Openat(int(public.Fd()), "wp-config.php", unix.O_RDWR|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	if err != nil {
		return &MigrationError{Step: "copy", Detail: "The copied wp-config.php is missing or is a link, so it could not be pointed at the database here."}
	}
	f := os.NewFile(uintptr(fd), "wp-config.php")
	defer f.Close()
	info, err := f.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Size() > 256<<10 {
		return &MigrationError{Step: "copy", Detail: "The copied wp-config.php is not a plain file of at most 256 KiB, so it could not be pointed at the database here."}
	}
	data, err := io.ReadAll(io.LimitReader(f, 256<<10+1))
	defer clear(data)
	if err != nil {
		return ErrUnavailable
	}
	out, err := sitesource.RewriteWPConfig(data, name, user)
	defer clear(out)
	if err != nil {
		return &MigrationError{Step: "copy", Detail: "The copied wp-config.php no longer names its database plainly, so it could not be pointed at the database here."}
	}
	if f.Truncate(0) != nil {
		return ErrUnavailable
	}
	if _, err := f.WriteAt(out, 0); err != nil || f.Sync() != nil {
		return ErrUnavailable
	}
	return nil
}

func (m *migrator) ServerFiles(ctx context.Context, rec migrationRecord, src serverSource, r record, needMiB int64, l backupLeftover, protect func(SiteProtection) error) (MigrateFilesResult, error) {
	if m.e.prepare() != nil || m.tools() != nil || rec.Via != ViaServer || r.Account.UID <= 0 || r.Account.GID <= 0 || needMiB < 0 || !sitesource.ValidDocRoot(src.site.DocRoot) {
		return MigrateFilesResult{}, ErrUnavailable
	}
	need := uint64(needMiB)<<20 + uint64(needMiB)<<20/10 + 64<<20
	if err := m.room(need); err != nil {
		return MigrateFilesResult{}, err
	}
	stage, err := m.e.newStage(l.Op)
	if err != nil {
		return MigrateFilesResult{}, err
	}
	defer stage.Close()
	stagePath := filepath.Join(m.e.stage, l.Op)
	if unix.Mkdirat(int(stage.Fd()), "files", 0700) != nil {
		return MigrateFilesResult{}, ErrUnavailable
	}
	out, code, full, err := m.watchedRsync(ctx, rec, func(rsh string) ([]string, bool) {
		return serverFetchArgs(rsh, rec.Host, src, stagePath+"/files/public_html", r.Account.GID)
	})
	switch {
	case full:
		return MigrateFilesResult{}, &MigrationError{Step: "space", Detail: "The copy reached the free space this server keeps, so it was stopped. The old website's folder holds more than it reported."}
	case err != nil:
		return MigrateFilesResult{}, err
	case code == 23:
		return MigrateFilesResult{}, serverUnreadable(src, out)
	case code != 0 && code != 24:
		return MigrateFilesResult{}, sshFailure("fetch", out)
	}
	public, err := openDirectoryAt(int(stage.Fd()), "files/public_html")
	if err != nil {
		return MigrateFilesResult{}, &MigrationError{Step: "copy", Detail: "The old website's folder did not arrive as a folder."}
	}
	if src.site.Server == "nginx" {
		err = writeConverted(public, src.site.Htaccess)
	}
	if err == nil && src.dbName != "" {
		err = rewriteStagedWPConfig(public, src.dbName, src.dbUser)
	}
	public.Close()
	if err != nil {
		return MigrateFilesResult{}, err
	}
	return m.placeFiles(ctx, stage, stagePath, src.stagedHome(), r, protect)
}

// watchedRsync runs a copy's rsync while the staging disk is read every 2
// seconds; rsync is stopped, and full is true, before the free space
// margin is crossed.
func (m *migrator) watchedRsync(ctx context.Context, rec migrationRecord, args func(rsh string) ([]string, bool)) ([]byte, int, bool, error) {
	copying, stop := context.WithCancel(ctx)
	full := make(chan bool, 1)
	go func() {
		tick := time.NewTicker(2 * time.Second)
		defer tick.Stop()
		for {
			select {
			case <-copying.Done():
				full <- false
				return
			case <-tick.C:
				if avail, total, _, err := m.e.space(m.e.stage); err == nil && roomLeft(avail, total) == 0 {
					stop()
					full <- true
					return
				}
			}
		}
	}()
	out, code, err := m.rsync(copying, rec, args, backupTimeout)
	stop()
	return out, code, <-full, err
}
