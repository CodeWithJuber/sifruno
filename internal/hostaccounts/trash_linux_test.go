//go:build linux

package hostaccounts

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// me is the test's own user, which owns the trash in these tests; the
// broker's is root.
func me() fileOwner { return fileOwner{uint32(os.Getuid()), uint32(os.Getgid())} }

// trashFixture is a homes folder, held open, with r's home in it: owned by
// the test's user, which stands for the account.
func trashFixture(t *testing.T) (string, *os.File, record) {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "homes")
	if os.Mkdir(dir, 0755) != nil {
		t.Fatal("fixture")
	}
	homes, err := openDirectoryAt(unix.AT_FDCWD, dir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { homes.Close() })
	id, err := randomID()
	if err != nil {
		t.Fatal(err)
	}
	r := record{Account: Account{ID: id, Username: "trashacct", UID: os.Getuid(), GID: os.Getgid(), Home: filepath.Join(dir, "trashacct")}}
	if os.Mkdir(r.Account.Home, 0750) != nil || os.WriteFile(filepath.Join(r.Account.Home, "index.php"), []byte("x"), 0644) != nil {
		t.Fatal("fixture")
	}
	var st unix.Stat_t
	if unix.Lstat(r.Account.Home, &st) != nil {
		t.Fatal("fixture")
	}
	r.Ownership.Home = fileIdentity{uint64(st.Dev), st.Ino}
	return dir, homes, r
}

// The trash must be the broker's own folder and the home the recorded one:
// each refusal moves nothing. A home already moved counts as moved.
func TestDetachHomeRefusals(t *testing.T) {
	dir, homes, r := trashFixture(t)
	trashPath := filepath.Join(dir, trashName)
	if _, err := trashIn(homes, false, me()); !errors.Is(err, errNoTrash) {
		t.Fatalf("no trash: %v", err)
	}
	refused := func(name string, setUp func() error, owner fileOwner) {
		t.Helper()
		if err := setUp(); err != nil {
			t.Fatal(err)
		}
		if trash, err := trashIn(homes, true, owner); err != ErrRecovery {
			if trash != nil {
				trash.Close()
			}
			t.Fatalf("%s: %v", name, err)
		}
		if err := os.RemoveAll(trashPath); err != nil {
			t.Fatal(err)
		}
	}
	elsewhere := t.TempDir()
	refused("a link", func() error { return os.Symlink(elsewhere, trashPath) }, me())
	refused("a file", func() error { return os.WriteFile(trashPath, nil, 0600) }, me())
	refused("mode 0755", func() error { return errors.Join(os.Mkdir(trashPath, 0755), os.Chmod(trashPath, 0755)) }, me())
	refused("another owner", func() error { return os.Mkdir(trashPath, 0700) }, fileOwner{me().uid + 1, me().gid})
	if _, err := os.Lstat(filepath.Join(elsewhere, r.Account.ID)); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("something was moved through the link")
	}

	trash, err := trashIn(homes, true, me())
	if err != nil {
		t.Fatalf("the trash was not made: %v", err)
	}
	defer trash.Close()
	var st unix.Stat_t
	if unix.Lstat(trashPath, &st) != nil || st.Mode&07777 != 0700 || st.Uid != me().uid {
		t.Fatalf("the trash made: %o %d", st.Mode, st.Uid)
	}
	for name, change := range map[string]func(*record){
		"another inode": func(r *record) { r.Ownership.Home.Ino++ },
		"another owner": func(r *record) { r.Account.UID++ },
		"another group": func(r *record) { r.Account.GID++ },
	} {
		other := r
		change(&other)
		if err := detachHome(homes, trash, other); err != ErrRecovery {
			t.Fatalf("%s: %v", name, err)
		}
	}
	if os.Mkdir(filepath.Join(trashPath, r.Account.ID), 0700) != nil {
		t.Fatal("fixture")
	}
	if err := detachHome(homes, trash, r); err != ErrRecovery {
		t.Fatalf("an entry with the ID in the trash: %v", err)
	}
	if os.Remove(filepath.Join(trashPath, r.Account.ID)) != nil {
		t.Fatal("fixture")
	}
	if _, err := os.Stat(filepath.Join(r.Account.Home, "index.php")); err != nil {
		t.Fatal("a refused move moved the home")
	}
	if err := detachHome(homes, trash, r); err != nil {
		t.Fatal(err)
	}
	var moved unix.Stat_t
	if unix.Lstat(filepath.Join(trashPath, r.Account.ID), &moved) != nil || !homeIs(moved, r) {
		t.Fatal("the home in the trash is not the recorded one")
	}
	if _, err := os.Lstat(r.Account.Home); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("the home is still in the homes folder")
	}
	if err := detachHome(homes, trash, r); err != nil {
		t.Fatalf("a home moved already: %v", err)
	}
	// A link where the home was is never followed nor moved.
	if os.Symlink(elsewhere, r.Account.Home) != nil {
		t.Fatal("fixture")
	}
	if err := detachHome(homes, trash, r); err != ErrRecovery {
		t.Fatalf("a link named as the home: %v", err)
	}
}

// buildTree makes, below the folder parent holds, a chain of depth folders
// named "d", each with files regular files, a link to outside and a link to
// a file there, through handles, so no path grows past PATH_MAX.
func buildTree(t *testing.T, parent int, depth, files int, outside string) {
	t.Helper()
	cur, err := unix.Dup(parent)
	if err != nil {
		t.Fatal(err)
	}
	for level := 0; level < depth; level++ {
		for i := 0; i < files; i++ {
			fd, err := unix.Openat(cur, "f"+strconv.Itoa(i), unix.O_CREAT|unix.O_EXCL|unix.O_WRONLY|unix.O_CLOEXEC, 0600)
			if err != nil {
				t.Fatal(err)
			}
			unix.Close(fd)
		}
		if unix.Symlinkat(outside, cur, "out") != nil || unix.Symlinkat(filepath.Join(outside, "keep"), cur, "keep") != nil {
			t.Fatal("fixture")
		}
		if unix.Mkdirat(cur, "d", 0700) != nil {
			t.Fatal("fixture")
		}
		next, err := unix.Openat(cur, "d", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
		if err != nil {
			t.Fatal(err)
		}
		unix.Close(cur)
		cur = next
	}
	unix.Close(cur)
}

// trashWithTree is a homes folder whose trash holds one entry, named as an
// account ID, with a tree of depth levels in it, and a folder outside it
// that the tree links to.
func trashWithTree(t *testing.T, depth, files int) (dir, id, outside string) {
	t.Helper()
	dir, homes, _ := trashFixture(t)
	trash, err := trashIn(homes, true, me())
	if err != nil {
		t.Fatal(err)
	}
	defer trash.Close()
	outside = t.TempDir()
	if os.WriteFile(filepath.Join(outside, "keep"), []byte("keep"), 0600) != nil {
		t.Fatal("fixture")
	}
	if id, err = randomID(); err != nil {
		t.Fatal(err)
	}
	if unix.Mkdirat(int(trash.Fd()), id, 0750) != nil {
		t.Fatal("fixture")
	}
	entry, err := openDirectoryAt(int(trash.Fd()), id)
	if err != nil {
		t.Fatal(err)
	}
	defer entry.Close()
	buildTree(t, int(entry.Fd()), depth, files, outside)
	// A hard link to a file outside: removing it removes only that name.
	if os.Link(filepath.Join(outside, "keep"), filepath.Join(dir, trashName, id, "hard")) != nil {
		t.Fatal("fixture")
	}
	return dir, id, outside
}

// testRemover is the remover of the trash in dir as the test's user, with
// no authority check (a temporary folder is not root's).
func testRemover(dir string) *trashRemover {
	t := newTrashRemover(dir)
	t.owner, t.guard = me(), func(string) error { return nil }
	return t
}

func openFiles(t *testing.T) int {
	entries, err := os.ReadDir("/proc/self/fd")
	if err != nil {
		t.Error(err)
	}
	return len(entries)
}

func trashEntries(t *testing.T, dir string) []string {
	t.Helper()
	entries, err := os.ReadDir(filepath.Join(dir, trashName))
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, e := range entries {
		names = append(names, e.Name())
	}
	return names
}

// A deep, wide home (about 20,000 files, 2,500 folders deep) is removed
// with a bounded number of open descriptors at any depth, and no link in
// it is followed: what it links to outside the trash stays.
func TestTrashRemoverTakesADeepTreeWithFewHandles(t *testing.T) {
	const depth, files = 2500, 8
	dir, _, outside := trashWithTree(t, depth, files)
	remover := testRemover(dir)
	baseline := openFiles(t)
	most, calls := 0, 0
	remover.stat = func(fd int, name string) (entryStat, error) {
		if calls++; calls%97 == 0 {
			most = max(most, openFiles(t)-baseline)
		}
		return statEntry(fd, name)
	}
	if left := remover.drain(t.Context()); left {
		t.Fatal("entries were left")
	}
	if calls < depth*files {
		t.Fatalf("only %d entries were read", calls)
	}
	if names := trashEntries(t, dir); len(names) != 0 {
		t.Fatalf("the trash still holds %v", names)
	}
	if most > 5 {
		t.Fatalf("the walk held %d descriptors more than before it", most)
	}
	if b, err := os.ReadFile(filepath.Join(outside, "keep")); err != nil || string(b) != "keep" {
		t.Fatal("a file the tree linked to was removed or changed")
	}
}

// A removal stopped by its context leaves what is left in the trash, and
// the next run removes the rest.
func TestTrashRemoverStopsAndResumes(t *testing.T) {
	dir, id, _ := trashWithTree(t, 300, 4)
	remover := testRemover(dir)
	ctx, cancel := context.WithCancel(t.Context())
	calls := 0
	remover.stat = func(fd int, name string) (entryStat, error) {
		if calls++; calls == 500 {
			cancel()
		}
		return statEntry(fd, name)
	}
	if left := remover.drain(ctx); !left {
		t.Fatal("a stopped removal said nothing is left")
	}
	if names := trashEntries(t, dir); len(names) != 1 || names[0] != id {
		t.Fatalf("after the stop: %v", names)
	}
	stopped := calls
	if stopped > 501 {
		t.Fatalf("the removal went on for %d entries after its context ended", stopped-500)
	}
	remover.stat = statEntry
	if left := remover.drain(t.Context()); left {
		t.Fatal("the resumed removal left entries")
	}
	if names := trashEntries(t, dir); len(names) != 0 {
		t.Fatalf("after the resume: %v", names)
	}
}

// A folder on another device or mount is never entered: it and the folders
// above it stay, everything else in the entry goes, and the entry is left,
// logged by its account ID only, for the remover to try again later. Other
// entries are removed, and one not named as an account ID is left alone.
func TestTrashRemoverSkipsAMount(t *testing.T) {
	logged := captureRecoveryLog(t)
	dir, id, _ := trashWithTree(t, 3, 2)
	mounted := filepath.Join(dir, trashName, id, "d", "d", "tenant-secret-name")
	if os.Mkdir(mounted, 0700) != nil || os.WriteFile(filepath.Join(mounted, "inside"), nil, 0600) != nil {
		t.Fatal("fixture")
	}
	other, err := randomID()
	if err != nil {
		t.Fatal(err)
	}
	if os.MkdirAll(filepath.Join(dir, trashName, other, "a", "b"), 0700) != nil || os.Mkdir(filepath.Join(dir, trashName, "not-an-id"), 0700) != nil {
		t.Fatal("fixture")
	}
	remover := testRemover(dir)
	remover.stat = func(fd int, name string) (entryStat, error) {
		st, err := statEntry(fd, name)
		if name == "tenant-secret-name" {
			st.dev++
		}
		return st, err
	}
	if left := remover.drain(t.Context()); !left {
		t.Fatal("a mount left in the trash was not reported as left")
	}
	if _, err := os.Stat(filepath.Join(mounted, "inside")); err != nil {
		t.Fatal("the remover entered a folder on another device")
	}
	for path, want := range map[string]string{filepath.Join(dir, trashName, id): "d", filepath.Join(dir, trashName, id, "d"): "d", filepath.Join(dir, trashName, id, "d", "d"): "tenant-secret-name"} {
		entries, err := os.ReadDir(path)
		if err != nil || len(entries) != 1 || entries[0].Name() != want {
			t.Fatalf("%s holds %v, want only %s: %v", path, entries, want, err)
		}
	}
	names := trashEntries(t, dir)
	if len(names) != 2 || !strings.Contains(strings.Join(names, " "), id) || !strings.Contains(strings.Join(names, " "), "not-an-id") {
		t.Fatalf("the trash holds %v", names)
	}
	log := logged.String()
	if !strings.Contains(log, "sifruno broker: cleanup: account="+id+` step="empty the trash: a folder on another device or mount is left in it"`) || strings.Contains(log, "tenant-secret-name") || strings.Contains(log, "not-an-id") {
		t.Fatalf("log %q", log)
	}
}

// The remover runs outside the store lock: while it is held in the middle
// of a home, a create (whose Plan reads the same trash) and a delete (which
// wakes it) go ahead; let go, it empties the trash. Run with -race too.
func TestCreateProceedsWhileTheRemoverIsHeld(t *testing.T) {
	dir, _, _ := trashWithTree(t, 50, 4)
	s, f, _ := setupStore(t)
	f.planUsed = func() (map[int]bool, error) {
		homes, err := openDirectoryAt(unix.AT_FDCWD, dir)
		if err != nil {
			return nil, err
		}
		defer homes.Close()
		return trashOwners(homes, me())
	}
	remover := testRemover(dir)
	s.trashWake = remover.wake
	held, release := make(chan struct{}), make(chan struct{})
	var once sync.Once
	remover.stat = func(fd int, name string) (entryStat, error) {
		once.Do(func() { close(held); <-release })
		return statEntry(fd, name)
	}
	ctx, cancel := context.WithCancel(t.Context())
	stopped := make(chan struct{})
	go func() { remover.run(ctx); close(stopped) }()
	defer func() { cancel(); <-stopped }()
	<-held
	done := make(chan error, 1)
	go func() {
		a, err := s.create(t.Context(), CreateInput{Username: "heldacct", Domain: "held.test", Reason: "While the remover is held"}, "test operator")
		if err == nil {
			_, err = s.delete(t.Context(), a.ID, DeleteInput{ExpectedRevision: a.Revision, Reason: "Wake it"}, "test operator")
		}
		done <- err
	}()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(20 * time.Second):
		t.Fatal("the create waited for the remover")
	}
	close(release)
	for deadline := time.Now().Add(20 * time.Second); len(trashEntries(t, dir)) != 0; {
		if time.Now().After(deadline) {
			t.Fatalf("the trash was not emptied: %v", trashEntries(t, dir))
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// Root-only: Plan does not give out an ID that owns an entry of the trash,
// and gives it again once the remover has emptied the trash. Run on the dev
// VM with: go test -c ./internal/hostaccounts && sudo ./hostaccounts.test
// -test.run RootOnly
func TestRootOnlyPlanSkipsATrashedUID(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("needs root: reads passwd and group and chowns a trash entry")
	}
	n := rootTestSystem(t)
	name := "sfplan" + strconv.Itoa(os.Getpid())
	uid, gid, err := n.Plan(t.Context(), name)
	if err != nil {
		t.Fatal(err)
	}
	homes, err := openDirectoryAt(unix.AT_FDCWD, n.opts.HomesDir)
	if err != nil {
		t.Fatal(err)
	}
	defer homes.Close()
	trash, err := trashIn(homes, true, rootOwner)
	if err != nil {
		t.Fatal(err)
	}
	defer trash.Close()
	id, err := randomID()
	if err != nil {
		t.Fatal(err)
	}
	if unix.Mkdirat(int(trash.Fd()), id, 0750) != nil || unix.Fchownat(int(trash.Fd()), id, uid, gid, unix.AT_SYMLINK_NOFOLLOW) != nil {
		t.Fatal("fixture")
	}
	if next, _, err := n.Plan(t.Context(), name); err != nil || next == uid {
		t.Fatalf("Plan gave out %d, which owns a trash entry: %v", next, err)
	}
	if left := newTrashRemover(n.opts.HomesDir).drain(t.Context()); left {
		t.Fatal("the remover left the entry")
	}
	if again, _, err := n.Plan(t.Context(), name); err != nil || again != uid {
		t.Fatalf("Plan after the trash was emptied: %d, want %d: %v", again, uid, err)
	}
}

// Every entry's owner is a used ID while the entry is in the trash: Plan
// skips them, so a new account never starts with a deleted one's files on
// its quota.
func TestTrashOwnersAreUsedIDs(t *testing.T) {
	dir, _, _ := trashWithTree(t, 2, 1)
	homes, err := openDirectoryAt(unix.AT_FDCWD, dir)
	if err != nil {
		t.Fatal(err)
	}
	defer homes.Close()
	ids, err := trashOwners(homes, me())
	if err != nil || !ids[os.Getuid()] || !ids[os.Getgid()] || len(ids) > 2 {
		t.Fatalf("trash owners %v %v", ids, err)
	}
	if _, err := trashOwners(homes, fileOwner{me().uid + 1, me().gid}); err != ErrRecovery {
		t.Fatalf("a trash that is not the broker's: %v", err)
	}
	empty, _, _ := trashFixture(t)
	bare, err := openDirectoryAt(unix.AT_FDCWD, empty)
	if err != nil {
		t.Fatal(err)
	}
	defer bare.Close()
	if ids, err := trashOwners(bare, me()); err != nil || len(ids) != 0 {
		t.Fatalf("no trash: %v %v", ids, err)
	}
}
