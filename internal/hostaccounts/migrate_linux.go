//go:build linux

package hostaccounts

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"errors"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"sort"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"
	"golang.org/x/sys/unix"
	"sifruno/internal/cpsource"
	"sifruno/internal/htaccess"
)

// migrator is the Linux migrateEngine. It shares the backup engine's
// program runner, staging root, temporary-user import and disk margin: a
// migration's copy is a restore whose source is the old server.
type migrator struct {
	e *resticEngine
	// dir is <state>/migrate, root 0700: one folder per migration with its
	// private key (ssh_key) and the pinned host key (known_hosts).
	dir string
	// prepareDir makes dir; tools checks the programs. They are fields so
	// a test that is not root can run the engine on scratch folders.
	prepareDir func() error
	tools      func() error
}

func newMigrator(stateDir string, e *resticEngine) *migrator {
	m := &migrator{e: e, dir: stateDir + "/migrate", tools: checkMigrateTools}
	m.prepareDir = func() error { return ensureOwnDir(filepath.Dir(m.dir), filepath.Base(m.dir), 0700) }
	return m
}

// checkMigrateTools accepts ssh, ssh-keyscan, rsync, cp and the MariaDB
// client only as root-owned regular executables.
func checkMigrateTools() error {
	for _, p := range []string{sshPath, sshKeyscanPath, rsyncPath, cpPath, xargsPath, chmodPath, mariadbPath} {
		if info, e := trustedFile(p, false); e != nil || info.Mode().Perm()&0001 == 0 {
			return ErrUnavailable
		}
	}
	return nil
}

// migrateEnv holds no secret and points HOME at the broker's own folder, so
// ssh reads nothing of root's.
func (m *migrator) env() []string {
	return []string{"PATH=/usr/bin:/bin", "LANG=C.UTF-8", "HOME=" + m.dir}
}

func (m *migrator) folder(id string) (*os.File, error) {
	if !idPattern.MatchString(id) || m.prepareDir() != nil {
		return nil, ErrUnavailable
	}
	parent, err := openRootDir(m.dir)
	if err != nil {
		return nil, ErrUnavailable
	}
	defer parent.Close()
	d, err := openDirectoryAt(int(parent.Fd()), id)
	if err != nil {
		return nil, ErrUnavailable
	}
	owner, _, perm, err := ownerOfHandle(d)
	if err != nil || owner != m.e.owner || perm != 0700 {
		d.Close()
		return nil, ErrUnavailable
	}
	return d, nil
}

func (m *migrator) Open(id string) (string, error) {
	if !idPattern.MatchString(id) || m.prepareDir() != nil {
		return "", ErrUnavailable
	}
	parent, err := openRootDir(m.dir)
	if err != nil {
		return "", ErrUnavailable
	}
	defer parent.Close()
	if unix.Mkdirat(int(parent.Fd()), id, 0700) != nil {
		return "", ErrUnavailable
	}
	d, err := openDirectoryAt(int(parent.Fd()), id)
	if err != nil {
		return "", ErrUnavailable
	}
	defer d.Close()
	if m.e.chown(d, m.e.owner, m.e.owner) != nil || d.Chmod(0700) != nil {
		return "", ErrUnavailable
	}
	_, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return "", ErrUnavailable
	}
	block, err := ssh.MarshalPrivateKey(private, cpsource.KeyComment(id))
	if err != nil {
		return "", ErrUnavailable
	}
	if m.e.writePrivate(d, "ssh_key", pem.EncodeToMemory(block), m.e.owner, m.e.owner, 0600) != nil {
		return "", ErrUnavailable
	}
	public, err := ssh.NewPublicKey(private.Public())
	if err != nil {
		return "", ErrUnavailable
	}
	return strings.TrimSpace(string(ssh.MarshalAuthorizedKey(public))), nil
}

func (m *migrator) Scan(ctx context.Context, host string, port int) ([]byte, error) {
	if m.tools() != nil || !validMigrationHost(host) {
		return nil, ErrUnavailable
	}
	stdout := &boundedBuffer{max: 8 << 10}
	out, code, err := m.e.run(ctx, backupCommand{path: sshKeyscanPath, args: migrateKeyscanArgs(host, port), env: m.env(), dir: "/", stdout: stdout, limit: migrateScanTimeout})
	if err != nil {
		return nil, migrationFailed("connect", out)
	}
	if code != 0 || len(stdout.b) == 0 {
		return nil, &MigrationError{Step: "connect", Detail: "The old server did not answer on its SSH port. " + installDetail(out)}
	}
	return stdout.b, nil
}

func (m *migrator) Pin(id, key string) error {
	d, err := m.folder(id)
	if err != nil {
		return err
	}
	defer d.Close()
	return m.e.writePrivate(d, "known_hosts", []byte(migrateHostKeyAlias+" "+key+"\n"), m.e.owner, m.e.owner, 0600)
}

func (m *migrator) Remote(ctx context.Context, rec migrationRecord, command string, stdin io.Reader, stdout io.Writer, limit time.Duration) ([]byte, int, error) {
	if m.tools() != nil {
		return nil, -1, ErrUnavailable
	}
	d, err := m.folder(rec.ID)
	if err != nil {
		return nil, -1, err
	}
	d.Close()
	dir := filepath.Join(m.dir, rec.ID)
	args, ok := migrateRemoteArgs(dir, rec, command)
	if !ok {
		return nil, -1, ErrInvalid
	}
	return m.e.run(ctx, backupCommand{path: sshPath, args: args, env: m.env(), dir: dir, stdin: stdin, stdout: stdout, limit: limit})
}

// remoteSQL runs SQL on the source's MariaDB as its root user.
func (m *migrator) remoteSQL(ctx context.Context, rec migrationRecord, sql string) ([]byte, error) {
	stdout := &boundedBuffer{max: cpsource.MaxOutput}
	out, code, err := m.Remote(ctx, rec, cpsource.SQLCommand(), strings.NewReader(sql), stdout, migrateRemoteTimeout)
	switch {
	case err != nil:
		return nil, err
	case code == 255:
		return nil, migrationFailed("connect", out)
	case code != 0:
		// Error output only: standard output may hold what was read so far.
		return nil, migrationFailed("database", out)
	}
	return stdout.b, nil
}

// rsync runs rsync as root, the migration's ssh as its transport; the
// sender on the source runs as the account (senderPath).
func (m *migrator) rsync(ctx context.Context, rec migrationRecord, args func(rsh string) ([]string, bool), limit time.Duration) ([]byte, int, error) {
	d, err := m.folder(rec.ID)
	if err != nil {
		return nil, -1, err
	}
	d.Close()
	rsh, ok := migrateRsh(filepath.Join(m.dir, rec.ID), rec.Port)
	if !ok || !validMigrationHost(rec.Host) {
		return nil, -1, ErrInvalid
	}
	list, ok := args(rsh)
	if !ok {
		return nil, -1, ErrInvalid
	}
	return m.e.run(ctx, backupCommand{path: rsyncPath, args: list, env: m.env(), dir: "/", limit: limit})
}

// unreadable explains rsync's exit 23 on a copy whose sender runs as the
// account: something in the old home is not the account's to read.
func unreadableByAccount(step string, out []byte) error {
	return &MigrationError{Step: step, Detail: "Some files or folders in the old home cannot be read by the account itself, so they were not copied and the copy stopped. Sifruno reads the home as the account, never as root. Give them to the account, or remove them, on the old server. " + installDetail(out)}
}

// validSourceHome is a home folder the source named: a plain absolute path
// (cpsource.ParseSite checked its form; this is the broker's own check).
func validSourceHome(home string) bool {
	return filepath.IsAbs(home) && filepath.Clean(home) == home && resticSafeArgumentSet.MatchString(home) && !strings.Contains(home, ":") && strings.Count(home, "/") >= 2
}

func (m *migrator) Preflight(ctx context.Context, rec migrationRecord, home string, l backupLeftover) (htaccess.SiteResult, bool, error) {
	if m.e.prepare() != nil || m.tools() != nil || !validSourceHome(home) {
		return htaccess.SiteResult{}, false, ErrUnavailable
	}
	stage, err := m.e.newStage(l.Op)
	if err != nil {
		return htaccess.SiteResult{}, false, err
	}
	defer stage.Close()
	stagePath := filepath.Join(m.e.stage, l.Op)
	if unix.Mkdirat(int(stage.Fd()), "htaccess", 0700) != nil {
		return htaccess.SiteResult{}, false, ErrUnavailable
	}
	out, code, err := m.rsync(ctx, rec, func(rsh string) ([]string, bool) { return htaccessArgs(rsh, rec.Host, home, stagePath+"/htaccess") }, 10*time.Minute)
	if err != nil {
		return htaccess.SiteResult{}, false, err
	}
	if code == 23 {
		return htaccess.SiteResult{}, false, unreadableByAccount("fetch", out)
	}
	if code != 0 && code != 24 {
		return htaccess.SiteResult{}, false, migrationFailed("fetch", out)
	}
	files, err := openDirectoryAt(int(stage.Fd()), "htaccess")
	if err != nil {
		return htaccess.SiteResult{}, false, ErrUnavailable
	}
	defer files.Close()
	homeFile := false
	var st unix.Stat_t
	if unix.Fstatat(int(files.Fd()), ".htaccess", &st, unix.AT_SYMLINK_NOFOLLOW) == nil {
		homeFile = true
	}
	// With no .htaccess at all, rsync's --prune-empty-dirs leaves no
	// public_html: nothing for OpenLiteSpeed to ignore.
	if unix.Fstatat(int(files.Fd()), "public_html", &st, unix.AT_SYMLINK_NOFOLLOW) != nil {
		return htaccess.SiteResult{Verdict: htaccess.VerdictNative, Files: []htaccess.FileResult{}}, homeFile, nil
	}
	site, _, err := scanSite(stagePath + "/htaccess/public_html")
	return site, homeFile, err
}

// scanSite runs the .htaccess scan on a staged public_html. The staging
// folder is root's and no tenant can enter it, and the scan never follows a
// link, so root reads only what the copy wrote.
func scanSite(dir string) (htaccess.SiteResult, bool, error) {
	report, err := htaccess.Scan(dir, htaccess.LayoutSingle, htaccess.DefaultLimits())
	if err != nil || len(report.Sites) != 1 {
		return htaccess.SiteResult{}, false, &MigrationError{Step: "tier", Detail: "The site's .htaccess files could not be scanned."}
	}
	return report.Sites[0], false, nil
}

func (m *migrator) room(need uint64) error {
	avail, total, _, err := m.e.space(m.e.stage)
	if err != nil {
		return ErrUnavailable
	}
	if left := roomLeft(avail, total); need > left {
		return &MigrationError{Step: "space", Detail: "The copy needs about " + byteSize(need) + ", but only " + byteSize(left) + " is free on this server beyond the " + byteSize(freeMargin(total)) + " it keeps free."}
	}
	return nil
}

func (m *migrator) Files(ctx context.Context, rec migrationRecord, home string, r record, needMiB int64, l backupLeftover, protect func(SiteProtection) error) (MigrateFilesResult, error) {
	if m.e.prepare() != nil || m.tools() != nil || r.Account.UID <= 0 || r.Account.GID <= 0 || needMiB < 0 || !validSourceHome(home) {
		return MigrateFilesResult{}, ErrUnavailable
	}
	// What the old server counts, a tenth more for blocks, and 64 MiB.
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
	// The old server's figure may be wrong, so the disk is watched while
	// rsync writes, and rsync is stopped before the margin is crossed.
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
	out, code, err := m.rsync(copying, rec, func(rsh string) ([]string, bool) {
		return fetchArgs(rsh, rec.Host, home, stagePath+"/files")
	}, backupTimeout)
	stop()
	if <-full {
		return MigrateFilesResult{}, &MigrationError{Step: "space", Detail: "The copy reached the free space this server keeps, so it was stopped. The old server's account holds more than it reported."}
	}
	if err != nil {
		return MigrateFilesResult{}, err
	}
	// 24 is files that vanished on the source while rsync ran, such as a
	// live site's cache; 23 is what the account may not read; everything
	// else is a failure too.
	if code == 23 {
		return MigrateFilesResult{}, unreadableByAccount("fetch", out)
	}
	if code != 0 && code != 24 {
		return MigrateFilesResult{}, migrationFailed("fetch", out)
	}
	files, err := openDirectoryAt(int(stage.Fd()), "files")
	if err != nil {
		return MigrateFilesResult{}, ErrUnavailable
	}
	defer files.Close()
	public, err := openDirectoryAt(int(files.Fd()), "public_html")
	if err != nil {
		return MigrateFilesResult{}, &MigrationError{Step: "copy", Detail: "The old site's public_html is not a folder (it may be a link), so it cannot be copied over this site's public_html."}
	}
	// Everything staged goes to root and the site's group, as a restore's
	// does (groupStaged): nothing counts against the site's quota until its
	// own copy. The copy gives the home and public_html the staged folders'
	// modes: the ones the broker records for them.
	err = m.e.groupStaged(stage, stagePath+"/files", r.Account.GID)
	if err == nil {
		err = files.Chmod(0750)
	}
	if err == nil {
		err = public.Chmod(0750)
	}
	public.Close()
	if err != nil {
		return MigrateFilesResult{}, ErrUnavailable
	}
	// The panel checked the tier from the source; the files as copied are
	// checked and converted again before they reach the home, so a site
	// whose .htaccess changed meanwhile never goes live on OpenLiteSpeed
	// with a rule it would ignore.
	site, _, err := scanSite(stagePath + "/files/public_html")
	if err != nil {
		return MigrateFilesResult{}, err
	}
	var st unix.Stat_t
	homeFile := unix.Fstatat(int(files.Fd()), ".htaccess", &st, unix.AT_SYMLINK_NOFOLLOW) == nil
	conv := htaccess.ConvertSite(site)
	if !conv.Native || homeFile {
		detail := "The copied site's .htaccess files have rules OpenLiteSpeed does not act on, so the files were not put into the site."
		if refusals := tierRefusals(conv); len(refusals) > 0 {
			detail += " First: " + refusals[0]
		}
		return MigrateFilesResult{}, &MigrationError{Step: "tier", Detail: installDetail([]byte(detail))}
	}
	result := MigrateFilesResult{Folders: migrationFolders(conv.Rules), Probes: foldersProbes(conv.Rules)}
	if len(conv.Rules) > 0 {
		p, err := readProtection(files, home, siteName(r.Account.ID), conv.Rules)
		if err != nil {
			return MigrateFilesResult{}, err
		}
		result.Probes = append(result.Probes, subfolderProbes(stagePath+"/files/public_html", conv.Rules)...)
		result.Probes = append(result.Probes, openFileProbes(stagePath+"/files/public_html", conv.Rules)...)
		// The folders are live before cp makes the files reachable.
		if err := protect(p); err != nil {
			return MigrateFilesResult{}, err
		}
	}
	result.WordPress = regularAt(files, "public_html/wp-config.php") || regularAt(files, "wp-config.php")
	// Only the site's private group may enter the staging folder now.
	if m.e.chown(stage, m.e.owner, r.Account.GID) != nil || stage.Chmod(0750) != nil {
		return MigrateFilesResult{}, ErrUnavailable
	}
	out, code, err = m.e.run(ctx, backupCommand{path: cpPath, args: copyArgs(stagePath+"/files", r.Account.Home), env: siteEnv(r), dir: r.Account.Home, uid: r.Account.UID, gid: r.Account.GID, limit: backupTimeout})
	if err != nil || code != 0 {
		return MigrateFilesResult{}, migrationFailed("copy", out)
	}
	// The old server's modes come back: the group bits staging added go.
	if out, err := m.e.stagedModes(ctx, stage, r); err != nil {
		return MigrateFilesResult{}, &MigrationError{Step: "copy", Detail: "The files were copied, but some kept a group read bit the old server did not give them. " + installDetail(out)}
	}
	return result, nil
}

// readProtection reads each realm's user file from the staged copy and
// returns the site's protected folders with the normalized files. The
// staged files are root's with the site's group (groupStaged), and the
// staging folder stays root-only until after this, so no tenant can change
// what root reads here; the path is walked one folder at a time from
// the staged home's handle, never following a link, and must lie in the
// source home the copy came from.
func readProtection(files *os.File, sourceHome, site string, rules []htaccess.FolderRule) (SiteProtection, error) {
	folders, userFiles := protectionFolders(site, rules)
	p := SiteProtection{Folders: folders, Users: map[string][]byte{}}
	for _, f := range folders {
		if f.Realm == nil {
			continue
		}
		source := userFiles[f.Realm.UserFile]
		data, ok := readStagedFile(files, sourceHome, source)
		if !ok {
			return SiteProtection{}, &MigrationError{Step: "tier", Detail: installDetail([]byte("The password file of the protected folder " + f.Path + " (" + source + ") is not a plain file in the copied home folder, so the files were not put into the site."))}
		}
		normal, _, err := htaccess.NormalizeUserFile(data)
		if err != nil {
			why := err.Error()
			var bad *htaccess.UserFileError
			if errors.As(err, &bad) && bad.User != "" {
				why += ". Set this folder's password for " + bad.User + " again on the old server with a modern hash (bcrypt or apr1, as htpasswd -B or -m makes), or take the password off the folder there and set it again after the move"
			}
			return SiteProtection{}, &MigrationError{Step: "tier", Detail: installDetail([]byte("The password file of the protected folder " + f.Path + " cannot be used here: " + why + "."))}
		}
		p.Users[f.Realm.UserFile] = normal
	}
	return p, nil
}

// readStagedFile reads a regular file of at most htaccess.MaxUserFileBytes
// at an absolute source path inside sourceHome, from the staged home.
func readStagedFile(files *os.File, sourceHome, source string) ([]byte, bool) {
	rel, ok := strings.CutPrefix(source, sourceHome+"/")
	if !ok || rel == "" || filepath.Clean(rel) != rel || strings.HasPrefix(rel, "../") {
		return nil, false
	}
	parts := strings.Split(rel, "/")
	dir := files
	for _, part := range parts[:len(parts)-1] {
		if part == "" || part == "." || part == ".." {
			return nil, false
		}
		next, err := openDirectoryAt(int(dir.Fd()), part)
		if err != nil {
			return nil, false
		}
		if dir != files {
			dir.Close()
		}
		dir = next
	}
	if dir != files {
		defer dir.Close()
	}
	fd, err := unix.Openat(int(dir.Fd()), parts[len(parts)-1], unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, false
	}
	f := os.NewFile(uintptr(fd), "user file")
	defer f.Close()
	info, err := f.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Size() > htaccess.MaxUserFileBytes {
		return nil, false
	}
	data, err := io.ReadAll(io.LimitReader(f, htaccess.MaxUserFileBytes+1))
	if err != nil || len(data) > htaccess.MaxUserFileBytes {
		return nil, false
	}
	return data, true
}

// probeFolderName is a folder name below which open files are looked for:
// no dot (OpenLiteSpeed opens only those, access.go) and nothing a URL
// would need to escape.
var probeFolderName = regexp.MustCompile(`^[A-Za-z0-9_@~-]+$`)

// openFileProbes finds, below each closed folder of the staged public_html,
// up to three real files whose names the folder leaves open, in folders
// whose names have no dot, so verify can ask for them on both sites.
func openFileProbes(public string, rules []htaccess.FolderRule) []MigrationProbe {
	out := []MigrationProbe{}
	root, err := os.OpenRoot(public)
	if err != nil {
		return out
	}
	defer root.Close()
	for _, rule := range rules {
		open := map[string]bool{}
		for _, name := range rule.Allow {
			open[name] = true
		}
		found, seen := 0, 0
		var walk func(rel string, depth int)
		walk = func(rel string, depth int) {
			if found >= 3 || depth > 8 || seen > 5000 {
				return
			}
			d, err := root.Open(rel)
			if err != nil {
				return
			}
			entries, _ := d.ReadDir(1000)
			d.Close()
			sort.Slice(entries, func(i, j int) bool { return entries[i].Name() < entries[j].Name() })
			for _, e := range entries {
				seen++
				child := rel + "/" + e.Name()
				switch t := e.Type(); {
				case t.IsRegular() && open[e.Name()] && found < 3:
					out = append(out, MigrationProbe{Path: "/" + child, Kind: "allow"})
					found++
				// A folder name verify could not put in a URL as it is
				// (a space, ?, %, #) would make it refuse every probe.
				case t.IsDir() && probeFolderName.MatchString(e.Name()):
					walk(child, depth+1)
				}
			}
		}
		if len(open) > 0 {
			walk(strings.Trim(rule.Path, "/"), 0)
		}
	}
	return out
}

// subfolderProbes finds, below each folder closed to every address or
// asking every address for a password, its first real subfolder by name
// in the staged public_html, with the name rules and bounds openFileProbes
// uses, so verify checks that the copy's rule reaches below the folder
// itself. It expects the folder's own status (D-0002). A subfolder named
// like a file the folder leaves open is passed over.
func subfolderProbes(public string, rules []htaccess.FolderRule) []MigrationProbe {
	out := []MigrationProbe{}
	root, err := os.OpenRoot(public)
	if err != nil {
		return out
	}
	defer root.Close()
	for _, rule := range rules {
		kind := closedKind(rule)
		if kind == "" {
			continue
		}
		rel := strings.Trim(rule.Path, "/")
		d, err := root.Open(rel)
		if err != nil {
			continue
		}
		entries, _ := d.ReadDir(1000)
		d.Close()
		sort.Slice(entries, func(i, j int) bool { return entries[i].Name() < entries[j].Name() })
		for _, e := range entries {
			if e.Type().IsDir() && probeFolderName.MatchString(e.Name()) && !slices.Contains(rule.Allow, e.Name()) {
				out = append(out, MigrationProbe{Path: "/" + rel + "/" + e.Name() + "/", Kind: kind})
				break
			}
		}
	}
	return out
}

// regularAt reports a regular file at a relative path, following no link.
func regularAt(dir *os.File, name string) bool {
	parent, base := filepath.Split(name)
	d := dir
	if parent != "" {
		sub, err := openDirectoryAt(int(dir.Fd()), strings.TrimSuffix(parent, "/"))
		if err != nil {
			return false
		}
		defer sub.Close()
		d = sub
	}
	var st unix.Stat_t
	return unix.Fstatat(int(d.Fd()), base, &st, unix.AT_SYMLINK_NOFOLLOW) == nil && st.Mode&unix.S_IFMT == unix.S_IFREG
}

func (m *migrator) Database(ctx context.Context, rec migrationRecord, db string, r record, l backupLeftover) (MigrateDatabaseResult, error) {
	if m.e.prepare() != nil || m.tools() != nil || r.Account.UID <= 0 || r.Account.GID <= 0 || !validDatabaseName(db) || l.Users[db] == "" {
		return MigrateDatabaseResult{}, ErrUnavailable
	}
	out, code, err := m.e.rootSQL(ctx, databaseExistsSQL(db))
	if err != nil || code != 0 {
		return MigrateDatabaseResult{}, migrationFailed("database", out)
	}
	if strings.TrimSpace(string(out)) != "1" {
		return MigrateDatabaseResult{}, &MigrationError{Step: "database", Detail: "The database " + db + " does not exist on this server yet, so it cannot be copied into."}
	}
	objects, _ := cpsource.ObjectsSQL(db)
	found, err := m.remoteSQL(ctx, rec, objects)
	if err != nil {
		return MigrateDatabaseResult{}, err
	}
	if kinds := strings.Fields(string(found)); len(kinds) > 0 {
		return MigrateDatabaseResult{}, &MigrationError{Step: "database", Detail: "The database " + db + " on the old server has " + strings.Join(uniqueWords(kinds), ", ") + ". This version copies tables and rows only, because those objects run as a named MariaDB user."}
	}
	stage, err := m.e.newStage(l.Op)
	if err != nil {
		return MigrateDatabaseResult{}, err
	}
	defer stage.Close()
	stagePath := filepath.Join(m.e.stage, l.Op)
	if unix.Mkdirat(int(stage.Fd()), "db", 0700) != nil {
		return MigrateDatabaseResult{}, ErrUnavailable
	}
	dumps, err := openDirectoryAt(int(stage.Fd()), "db")
	if err != nil {
		return MigrateDatabaseResult{}, ErrUnavailable
	}
	fd, err := unix.Openat(int(dumps.Fd()), db+".sql", unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0600)
	dumps.Close()
	if err != nil {
		return MigrateDatabaseResult{}, ErrUnavailable
	}
	file := os.NewFile(uintptr(fd), db+".sql")
	avail, total, _, err := m.e.space(m.e.stage)
	if err != nil {
		file.Close()
		return MigrateDatabaseResult{}, ErrUnavailable
	}
	capped := &cappedWriter{w: file, max: min(uint64(maxDumpBytes), roomLeft(avail, total))}
	command, _ := cpsource.DumpCommand(db)
	out, code, err = m.Remote(ctx, rec, command, nil, capped, backupTimeout)
	syncErr := file.Sync()
	file.Close()
	switch {
	case capped.over:
		return MigrateDatabaseResult{}, &MigrationError{Step: "space", Detail: "The dump of " + db + " grew past the free space this server keeps, so it was stopped."}
	case err != nil:
		return MigrateDatabaseResult{}, err
	case code == 255:
		return MigrateDatabaseResult{}, migrationFailed("connect", out)
	case code != 0 || syncErr != nil:
		return MigrateDatabaseResult{}, migrationFailed("dump", out)
	}
	// The source's rows are counted after its dump; a site that changed
	// meanwhile shows up as a difference, which the panel reports.
	source, sourceTables, err := m.count(ctx, db, func(sql string) ([]byte, error) { return m.remoteSQL(ctx, rec, sql) })
	if err != nil {
		return MigrateDatabaseResult{}, err
	}
	if m.e.chown(stage, m.e.owner, r.Account.GID) != nil || stage.Chmod(0750) != nil {
		return MigrateDatabaseResult{}, ErrUnavailable
	}
	if err = m.e.importDatabase(ctx, r, stage, stagePath, db, l.Users[db]); err != nil {
		var failed *BackupError
		if errors.As(err, &failed) {
			return MigrateDatabaseResult{}, &MigrationError{Step: "import", Detail: failed.Detail}
		}
		return MigrateDatabaseResult{}, err
	}
	copied, copiedTables, err := m.count(ctx, db, func(sql string) ([]byte, error) {
		stdout := &boundedBuffer{max: cpsource.MaxOutput}
		out, code, err := m.e.run(ctx, backupCommand{path: mariadbPath, args: rootSQLArgs(), env: []string{"PATH=/usr/bin:/bin", "LANG=C.UTF-8", "HOME=" + m.e.dir}, dir: m.e.dir, stdin: strings.NewReader(sql), stdout: stdout, limit: 10 * time.Minute})
		if err != nil || code != 0 {
			return nil, migrationFailed("compare", out)
		}
		return stdout.b, nil
	})
	if err != nil {
		return MigrateDatabaseResult{}, err
	}
	names := uniqueWords(append(sourceTables, copiedTables...))
	result := MigrateDatabaseResult{Database: db, Tables: make([]MigrationTable, 0, len(names))}
	for _, t := range names {
		src, inSource := source[t]
		cp, inCopy := copied[t]
		if !inSource {
			src = -1
		}
		if !inCopy {
			cp = -1
		}
		result.Tables = append(result.Tables, MigrationTable{Table: t, Source: src, Copy: cp})
	}
	sort.Slice(result.Tables, func(i, j int) bool { return result.Tables[i].Table < result.Tables[j].Table })
	return result, nil
}

// count lists the database's tables and counts each one's rows through
// query (the source's or this server's MariaDB).
func (m *migrator) count(ctx context.Context, db string, query func(string) ([]byte, error)) (map[string]int64, []string, error) {
	sql, _ := cpsource.TablesSQL(db)
	out, err := query(sql)
	if err != nil {
		return nil, nil, err
	}
	tables, err := cpsource.ParseTables(out)
	if err != nil {
		return nil, nil, &MigrationError{Step: "compare", Detail: "The tables of " + db + " could not be listed (a table name past 64 bytes or with a control character)."}
	}
	if len(tables) == 0 {
		return map[string]int64{}, tables, nil
	}
	sql, err = cpsource.CountsSQL(db, tables)
	if err != nil {
		return nil, nil, ErrInvalid
	}
	if out, err = query(sql); err != nil {
		return nil, nil, err
	}
	counts, err := cpsource.ParseCounts(out, tables)
	if err != nil {
		return nil, nil, &MigrationError{Step: "compare", Detail: "The row counts of " + db + " could not be read."}
	}
	return counts, tables, nil
}

func (m *migrator) Forget(id string) error {
	if !idPattern.MatchString(id) {
		return ErrInvalid
	}
	if err := os.RemoveAll(filepath.Join(m.dir, id)); err != nil {
		return ErrUnavailable
	}
	return nil
}

func (m *migrator) Folders() ([]string, error) {
	entries, err := os.ReadDir(m.dir)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, ErrUnavailable
	}
	var out []string
	for _, e := range entries {
		if idPattern.MatchString(e.Name()) {
			out = append(out, e.Name())
		}
	}
	return out, nil
}
