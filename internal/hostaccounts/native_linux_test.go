//go:build linux

package hostaccounts

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// Checks the exact production argv against shadow useradd's VALID comment
// contract (no colon/newline). This does not execute or certify shadow-utils.
func TestUseraddGeneratedCommentContract(t *testing.T) {
	s, _, _ := setupStore(t)
	createFixture(t, s)
	items, e := s.records()
	if e != nil || len(items) != 1 {
		t.Fatal("record observation", e)
	}
	args := useraddArgs(items[0], "/root/fixture/empty-skel")
	count := 0
	groups := 0
	for i, arg := range args {
		if strings.HasPrefix(arg, "CREATE_MAIL_SPOOL") {
			t.Fatal("unsupported login.defs override")
		}
		if arg == "--groups" {
			groups++
			if i+1 >= len(args) || args[i+1] != "" {
				t.Fatal("supplementary groups not pinned empty")
			}
		}
		if arg == "--comment" {
			count++
			if i+1 >= len(args) || args[i+1] != items[0].Tag || strings.ContainsAny(args[i+1], ":\n\r\x00") {
				t.Fatal("invalid production comment argv")
			}
		}
	}
	if count != 1 || groups != 1 {
		t.Fatal("missing or duplicated comment option")
	}
}

func TestPrivateGroupOnlyContract(t *testing.T) {
	if !privateGroupOnly([]nativeGroup{{"fixtureacct", 20000, ""}, {"wheel", 10, "root"}}, "fixtureacct", 20000) {
		t.Fatal("private primary group refused")
	}
	for name, input := range map[string][]nativeGroup{
		"missing": {}, "wronggid": {{"fixtureacct", 20001, ""}},
		"duplicate":            {{"fixtureacct", 20000, ""}, {"fixtureacct", 20000, ""}},
		"aliasgid":             {{"fixtureacct", 20000, ""}, {"other", 20000, ""}},
		"privateforeignmember": {{"fixtureacct", 20000, "other"}},
		"supplementary":        {{"fixtureacct", 20000, ""}, {"wheel", 10, "root,fixtureacct"}},
	} {
		t.Run(name, func(t *testing.T) {
			if privateGroupOnly(input, "fixtureacct", 20000) {
				t.Fatal("changed authority accepted")
			}
		})
	}
}

// Literal dialect fixtures; actual passwd observations require the guest run.
func TestLockedStatusDialect(t *testing.T) {
	for _, token := range []string{"L", "LK"} {
		if !lockedStatus(token) {
			t.Fatal("locked dialect rejected")
		}
	}
	for _, token := range []string{"", "P", "NP", "PS", "L ", "locked", "LK\n"} {
		if lockedStatus(token) {
			t.Fatal("unknown dialect accepted")
		}
	}
}

func TestDirectoryHandleRejectsSymlinkAndPinsMutation(t *testing.T) {
	parent := t.TempDir()
	original := filepath.Join(parent, "public_html")
	target := filepath.Join(parent, "target")
	if os.Mkdir(original, 0750) != nil || os.Mkdir(target, 0700) != nil {
		t.Fatal("fixture")
	}
	handle, e := openDirectoryAt(unix.AT_FDCWD, original)
	if e != nil {
		t.Fatal(e)
	}
	defer handle.Close()
	id, e := heldIdentity(handle, os.Getuid(), os.Getgid(), 0750)
	if e != nil {
		t.Fatal(e)
	}
	moved := filepath.Join(parent, "moved")
	if os.Rename(original, moved) != nil || os.Symlink(target, original) != nil {
		t.Fatal("fixture swap")
	}
	if f, e := openDirectoryAt(unix.AT_FDCWD, original); e == nil {
		f.Close()
		t.Fatal("followed symlink")
	}
	if handle.Chmod(0710) != nil {
		t.Fatal("held chmod")
	}
	pinned, e := heldIdentity(handle, os.Getuid(), os.Getgid(), 0710)
	if e != nil || pinned != id {
		t.Fatal("identity changed")
	}
	info, e := os.Stat(target)
	if e != nil || info.Mode().Perm() != 0700 {
		t.Fatal("symlink target changed")
	}
}

// What the account's own user can do in its home shows in VerifySiteFiles
// only; the home's object and owner, which the account checks and delete
// read, stay the same. Runs as any user: the fixture is the caller's own.
func TestSiteFilesAreTheTenantsToChange(t *testing.T) {
	homes := t.TempDir()
	home := filepath.Join(homes, "webacct")
	public := filepath.Join(home, "public_html")
	if os.Mkdir(home, 0750) != nil || os.Chmod(home, 0750) != nil || os.Mkdir(public, 0750) != nil || os.Chmod(public, 0750) != nil {
		t.Fatal("fixture")
	}
	uid, gid := os.Getuid(), os.Getgid()
	homeID, e1 := dirIdentity(home, uid, gid, 0750)
	publicID, e2 := dirIdentity(public, uid, gid, 0750)
	if e1 != nil || e2 != nil {
		t.Fatal("fixture identity")
	}
	n := &linuxSystem{opts: BrokerOptions{HomesDir: homes}}
	r := record{Account: Account{Username: "webacct", Home: home, PublicHTML: public, UID: uid, GID: gid}, Ownership: ownership{Home: homeID, Public: publicID}}
	if e := n.VerifySiteFiles(r); e != nil {
		t.Fatalf("the recorded folders: %v", e)
	}
	accountHome := func() {
		t.Helper()
		if id, e := dirIdentity(home, uid, gid, 0); e != nil || id != homeID {
			t.Fatal("the home's identity, which only root can change, moved")
		}
	}
	for name, change := range map[string]struct{ do, undo func() error }{
		"home mode":          {func() error { return os.Chmod(home, 0755) }, func() error { return os.Chmod(home, 0750) }},
		"public_html mode":   {func() error { return os.Chmod(public, 0700) }, func() error { return os.Chmod(public, 0750) }},
		"public_html moved":  {func() error { return os.Rename(public, public+".old") }, func() error { return os.Rename(public+".old", public) }},
		"public_html linked": {func() error { return errors.Join(os.Rename(public, public+".old"), os.Symlink(public+".old", public)) }, func() error { return errors.Join(os.Remove(public), os.Rename(public+".old", public)) }},
		"public_html new": {func() error {
			return errors.Join(os.Rename(public, public+".old"), os.Mkdir(public, 0750), os.Chmod(public, 0750))
		}, func() error {
			return errors.Join(os.Remove(public), os.Rename(public+".old", public))
		}},
	} {
		if e := change.do(); e != nil {
			t.Fatalf("%s: %v", name, e)
		}
		if n.VerifySiteFiles(r) == nil {
			t.Fatalf("%s: the site folder check passed", name)
		}
		accountHome()
		if e := change.undo(); e != nil {
			t.Fatalf("%s undo: %v", name, e)
		}
		if e := n.VerifySiteFiles(r); e != nil {
			t.Fatalf("%s put back: %v", name, e)
		}
	}
}

// Literal expected argv is independent of production assembly. Managed
// accounts are regular users so shadow allocates their subordinate ID ranges;
// the explicitly allocated private IDs, the empty supplementary groups, the
// empty skeleton, the nologin shell and the locked password must all stay.
func TestManagedAccountUseraddExactArgv(t *testing.T) {
	for _, ids := range [][2]int{{20000, 20001}, {60000, 59999}} {
		r := record{Account: Account{Username: "fixtureacct", UID: ids[0], GID: ids[1], Home: "/srv/fixtureacct"}, Tag: "fixture-tag"}
		uid, gid := "20000", "20001"
		if ids[0] == 60000 {
			uid, gid = "60000", "59999"
		}
		want := []string{"--uid", uid, "--gid", gid, "--no-user-group", "--groups", "", "--create-home", "--home-dir", "/srv/fixtureacct", "--skel", "/root/fixture/empty-skel", "--shell", "/usr/sbin/nologin", "--comment", "fixture-tag", "--password", "!", "--expiredate", "", "--", "fixtureacct"}
		got := useraddArgs(r, "/root/fixture/empty-skel")
		if !reflect.DeepEqual(got, want) {
			t.Fatalf("useradd argv = %#v; want %#v", got, want)
		}
		for _, arg := range got {
			// System-account mode and a zero subordinate count are exactly what
			// kept rootless containers from working on these accounts.
			if arg == "--system" || arg == "-r" || strings.HasPrefix(arg, "SUB_UID_COUNT") || strings.HasPrefix(arg, "SUB_GID_COUNT") {
				t.Fatalf("argv still disables subordinate IDs: %q", arg)
			}
		}
	}
}

// The indexed identity check must give the same verdict as the original
// rules: privateGroupOnly over the raw group list plus the passwd conditions.
func TestIndexedIdentityMatchesListRules(t *testing.T) {
	r := record{Account: Account{Username: "fixtureacct", UID: 20000, GID: 20000, Home: "/home/fixtureacct"}, Tag: "sifruno-managed-x"}
	good := nativeUser{"fixtureacct", 20000, 20000, "/home/fixtureacct", nologin, "sifruno-managed-x"}
	root := nativeUser{"root", 0, 0, "/root", "/bin/bash", "root"}
	own := nativeGroup{"fixtureacct", 20000, ""}
	wheel := nativeGroup{"wheel", 10, "root"}
	cases := map[string]struct {
		users  []nativeUser
		groups []nativeGroup
		want   bool
	}{
		"managed":             {[]nativeUser{root, good}, []nativeGroup{wheel, own}, true},
		"missing user":        {[]nativeUser{root}, []nativeGroup{wheel, own}, false},
		"duplicate name":      {[]nativeUser{root, good, good}, []nativeGroup{wheel, own}, false},
		"shared uid":          {[]nativeUser{root, good, {"alias", 20000, 20000, "/home/alias", nologin, "x"}}, []nativeGroup{wheel, own}, false},
		"wrong uid":           {[]nativeUser{root, {"fixtureacct", 20001, 20000, "/home/fixtureacct", nologin, "sifruno-managed-x"}}, []nativeGroup{wheel, own}, false},
		"wrong gid":           {[]nativeUser{root, {"fixtureacct", 20000, 20001, "/home/fixtureacct", nologin, "sifruno-managed-x"}}, []nativeGroup{wheel, own}, false},
		"wrong home":          {[]nativeUser{root, {"fixtureacct", 20000, 20000, "/srv/other", nologin, "sifruno-managed-x"}}, []nativeGroup{wheel, own}, false},
		"real shell":          {[]nativeUser{root, {"fixtureacct", 20000, 20000, "/home/fixtureacct", "/bin/bash", "sifruno-managed-x"}}, []nativeGroup{wheel, own}, false},
		"wrong tag":           {[]nativeUser{root, {"fixtureacct", 20000, 20000, "/home/fixtureacct", nologin, "other"}}, []nativeGroup{wheel, own}, false},
		"missing group":       {[]nativeUser{root, good}, []nativeGroup{wheel}, false},
		"duplicate group":     {[]nativeUser{root, good}, []nativeGroup{wheel, own, own}, false},
		"group gid differs":   {[]nativeUser{root, good}, []nativeGroup{wheel, {"fixtureacct", 20001, ""}}, false},
		"group alias gid":     {[]nativeUser{root, good}, []nativeGroup{wheel, own, {"other", 20000, ""}}, false},
		"group has members":   {[]nativeUser{root, good}, []nativeGroup{wheel, {"fixtureacct", 20000, "root"}}, false},
		"supplementary group": {[]nativeUser{root, good}, []nativeGroup{{"wheel", 10, "root,fixtureacct"}, own}, false},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			_, indexed := indexAccounts(c.users, c.groups).managedIdentity(r)
			if indexed != c.want {
				t.Fatalf("indexed verdict %v, want %v", indexed, c.want)
			}
			// Re-derive the verdict from the list form the original code used.
			found, clash := 0, false
			var user nativeUser
			for _, u := range c.users {
				if u.Username != r.Account.Username && u.UID == r.Account.UID {
					clash = true
				}
				if u.Username == r.Account.Username {
					found++
					user = u
				}
			}
			listed := !clash && found == 1 && user.UID == r.Account.UID && user.GID == r.Account.GID && user.Home == r.Account.Home && user.Shell == nologin && user.Tag == r.Tag && privateGroupOnly(c.groups, r.Account.Username, r.Account.GID)
			if listed != indexed {
				t.Fatalf("list rules say %v, index says %v", listed, indexed)
			}
		})
	}
}

// removeRegular is the only unlink the broker performs outside a home. It
// must take a regular single-link file of the expected owner and nothing else.
func TestRemoveRegularOnlyTakesTheExpectedFile(t *testing.T) {
	dir := t.TempDir()
	uid := os.Getuid()
	file := filepath.Join(dir, "spool")
	if os.WriteFile(file, []byte("x"), 0600) != nil {
		t.Fatal("fixture")
	}
	if e := removeRegular(file, uid+1, false); e != ErrRecovery {
		t.Fatalf("foreign owner: %v", e)
	}
	if _, e := os.Lstat(file); e != nil {
		t.Fatal("foreign-owned file was removed")
	}
	target := filepath.Join(dir, "target")
	link := filepath.Join(dir, "link")
	hard := filepath.Join(dir, "hard")
	sub := filepath.Join(dir, "sub")
	if os.WriteFile(target, []byte("keep"), 0600) != nil || os.Symlink(target, link) != nil || os.Link(target, hard) != nil || os.Mkdir(sub, 0700) != nil {
		t.Fatal("fixture")
	}
	for name, path := range map[string]string{"symlink": link, "hard link": hard, "directory": sub} {
		if e := removeRegular(path, uid, false); e != ErrRecovery {
			t.Fatalf("%s: %v", name, e)
		}
	}
	if b, e := os.ReadFile(target); e != nil || string(b) != "keep" {
		t.Fatal("link target changed")
	}
	if e := removeRegular(file, uid, false); e != nil {
		t.Fatal(e)
	}
	if _, e := os.Lstat(file); !os.IsNotExist(e) {
		t.Fatal("expected file not removed")
	}
	if e := removeRegular(file, uid, false); e != nil {
		t.Fatalf("second removal must be a completed removal: %v", e)
	}
	if e := removeRegular(filepath.Join(dir, "missing-parent", "x"), uid, false); e != nil {
		t.Fatalf("missing parent: %v", e)
	}
	if e := removeRegular(filepath.Join(target, "x"), uid, false); e != nil {
		t.Fatalf("non-directory parent: %v", e)
	}
}

// Without the installer's root-owned 0711 key directory there is no SFTP key
// surface: the broker reports unavailable and writes nothing. The successful
// path needs root and is exercised by the root-only test below on the dev VM.
func TestSSHKeysNeedThePreparedDirectory(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("covered by the root test")
	}
	dir := filepath.Join(t.TempDir(), "authorized_keys")
	if os.Mkdir(dir, 0711) != nil {
		t.Fatal("fixture")
	}
	n := &linuxSystem{sshDir: dir, mailDir: t.TempDir()}
	r := record{Account: Account{ID: strings.Repeat("a", 32), Username: "fixtureacct", UID: 20000, GID: 20000}}
	if e := n.SetSSHKeys(t.Context(), r, []string{testEd25519Line(t, "laptop")}); e != ErrUnavailable {
		t.Fatalf("unprepared directory: %v", e)
	}
	if entries, e := os.ReadDir(dir); e != nil || len(entries) != 0 {
		t.Fatal("wrote into an unadmitted directory")
	}
}

// Root-only: the real file effects of the key operation. Run on the dev VM
// with: go test -c ./internal/hostaccounts && sudo ./hostaccounts.test -test.run RootOnly
func TestRootOnlySSHKeyFileLifecycle(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("needs root: checks ownership, group and mode of the installed file")
	}
	base, e := os.MkdirTemp("/etc", "sifruno-test-")
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { os.RemoveAll(base) })
	dir := filepath.Join(base, "authorized_keys")
	mail := filepath.Join(base, "mail")
	if os.Chmod(base, 0755) != nil || os.Mkdir(dir, 0711) != nil || os.Chmod(dir, 0711) != nil || os.Mkdir(mail, 0775) != nil {
		t.Fatal("fixture")
	}
	n := &linuxSystem{sshDir: dir, mailDir: mail}
	const gid = 54321
	r := record{Account: Account{ID: strings.Repeat("b", 32), Username: "fixtureacct", UID: 54321, GID: gid}}
	first, second := testEd25519Line(t, "laptop"), testEd25519Line(t, "ci")
	if e := n.SetSSHKeys(t.Context(), r, []string{first}); e != nil {
		t.Fatal(e)
	}
	target := filepath.Join(dir, "fixtureacct")
	check := func(want []string) {
		t.Helper()
		info, e := os.Lstat(target)
		if e != nil {
			t.Fatal(e)
		}
		st := info.Sys().(*syscall.Stat_t)
		if !info.Mode().IsRegular() || info.Mode().Perm() != 0640 || st.Uid != 0 || st.Gid != gid {
			t.Fatalf("installed file is %v uid %d gid %d", info.Mode(), st.Uid, st.Gid)
		}
		got, e := os.ReadFile(target)
		if e != nil || string(got) != string(renderAuthorizedKeys(want)) {
			t.Fatalf("content mismatch: %q", got)
		}
		entries, _ := os.ReadDir(dir)
		if len(entries) != 1 {
			t.Fatalf("temporary file left behind: %v", entries)
		}
	}
	check([]string{first})
	if e := n.SetSSHKeys(t.Context(), r, []string{second, first}); e != nil {
		t.Fatal(e)
	}
	check([]string{second, first})
	// A group-writable key directory is not the installer's contract.
	if os.Chmod(dir, 0775) != nil {
		t.Fatal("fixture")
	}
	if e := n.SetSSHKeys(t.Context(), r, []string{first}); e != ErrUnavailable {
		t.Fatalf("loosened directory: %v", e)
	}
	check([]string{second, first})
	if os.Chmod(dir, 0711) != nil {
		t.Fatal("fixture")
	}
	if e := n.VerifySSHKeys(r, []string{second, first}); e != nil {
		t.Fatalf("installed set not recognised: %v", e)
	}
	if e := n.VerifySSHKeys(r, []string{first}); e != ErrRecovery {
		t.Fatalf("different set accepted: %v", e)
	}
	// A spool the account owns goes with the account; so do the key file and
	// a temporary file left by a write that crashed before its rename.
	spool := filepath.Join(mail, "fixtureacct")
	leftover := filepath.Join(dir, ".new-"+r.Account.ID)
	if os.WriteFile(spool, nil, 0660) != nil || os.Chown(spool, r.Account.UID, 12) != nil || os.WriteFile(leftover, []byte("x"), 0600) != nil {
		t.Fatal("fixture")
	}
	if e := n.removeAccountFiles(r); e != nil {
		t.Fatal(e)
	}
	if e := n.VerifySSHKeys(r, nil); e != nil {
		t.Fatalf("absent file is not the empty set: %v", e)
	}
	for _, path := range []string{target, spool, leftover} {
		if _, e := os.Lstat(path); !os.IsNotExist(e) {
			t.Fatalf("%s survived account removal", path)
		}
	}
	if e := n.SetSSHKeys(t.Context(), r, nil); e != nil {
		t.Fatalf("removing an absent key file: %v", e)
	}
}

// The kill runs only as an account the broker made, as passwd and group
// show it now. Each refused case is otherwise consistent, so the named rule
// is what refuses it.
func TestAccountCredentialOnlyForTheAccount(t *testing.T) {
	root := nativeUser{"root", 0, 0, "/root", "/bin/bash", "root"}
	account := func(uid, gid int) (record, *accountDatabase) {
		r := record{Account: Account{Username: "fixtureacct", UID: uid, GID: gid, Home: "/home/fixtureacct"}, Tag: "sifruno-managed-x"}
		user := nativeUser{"fixtureacct", uid, gid, "/home/fixtureacct", nologin, "sifruno-managed-x"}
		return r, indexAccounts([]nativeUser{user}, []nativeGroup{{"fixtureacct", gid, ""}})
	}
	r, db := account(20000, 20000)
	cred, err := accountCredential(db, r, 2000)
	if err != nil || cred.Uid != 20000 || cred.Gid != 20000 || cred.Groups == nil || len(cred.Groups) != 0 || cred.NoSetGroups {
		t.Fatalf("the account's own credential: %+v %v", cred, err)
	}
	for _, ids := range [][2]int{{0, 0}, {1, 1}, {999, 999}, {1000, 1000}, {19999, 19999}, {60001, 60001}, {65534, 65534}, {20000, 20001}} {
		r, db := account(ids[0], ids[1])
		if cred, err := accountCredential(db, r, 2000); !errors.Is(err, ErrRecovery) || cred != nil {
			t.Errorf("UID %d GID %d: %+v %v", ids[0], ids[1], cred, err)
		}
	}
	if cred, err := accountCredential(db, r, 20000); !errors.Is(err, ErrRecovery) || cred != nil {
		t.Errorf("the controller's UID: %+v %v", cred, err)
	}
	other := nativeUser{"otheracct", 20001, 20001, "/home/otheracct", nologin, "sifruno-managed-y"}
	for name, db := range map[string]*accountDatabase{
		"passwd names another UID": indexAccounts([]nativeUser{root, {"fixtureacct", 20001, 20001, "/home/fixtureacct", nologin, "sifruno-managed-x"}}, []nativeGroup{{"fixtureacct", 20001, ""}}),
		"another user on the UID":  indexAccounts([]nativeUser{root, {"fixtureacct", 20000, 20000, "/home/fixtureacct", nologin, "sifruno-managed-x"}, {"alias", 20000, 20000, "/home/alias", nologin, "x"}}, []nativeGroup{{"fixtureacct", 20000, ""}}),
		"user gone":                indexAccounts([]nativeUser{root, other}, []nativeGroup{{"otheracct", 20001, ""}}),
		"another tag":              indexAccounts([]nativeUser{root, {"fixtureacct", 20000, 20000, "/home/fixtureacct", nologin, "other"}}, []nativeGroup{{"fixtureacct", 20000, ""}}),
		"a login shell":            indexAccounts([]nativeUser{root, {"fixtureacct", 20000, 20000, "/home/fixtureacct", "/bin/bash", "sifruno-managed-x"}}, []nativeGroup{{"fixtureacct", 20000, ""}}),
		"a supplementary group":    indexAccounts([]nativeUser{root, {"fixtureacct", 20000, 20000, "/home/fixtureacct", nologin, "sifruno-managed-x"}}, []nativeGroup{{"fixtureacct", 20000, ""}, {"wheel", 10, "fixtureacct"}}),
	} {
		if cred, err := accountCredential(db, r, 2000); !errors.Is(err, ErrRecovery) || cred != nil {
			t.Errorf("%s: %+v %v", name, cred, err)
		}
	}
}

// The exact kill process: argv, credential, directory, environment, input.
// signalAs refuses root and every ID outside the range before it looks at
// the binary, and runs nothing without the binary checked at start.
func TestKillRunsAsTheAccountOnly(t *testing.T) {
	cred := &syscall.Credential{Uid: 20000, Gid: 20000, Groups: []uint32{}}
	cmd := killCommand(t.Context(), cred)
	if cmd.Path != "/usr/bin/kill" || !reflect.DeepEqual(cmd.Args, []string{"/usr/bin/kill", "-s", "KILL", "--", "-1"}) {
		t.Fatalf("kill argv %q %q", cmd.Path, cmd.Args)
	}
	if cmd.Dir != "/" || !reflect.DeepEqual(cmd.Env, []string{"LANG=C", "LC_ALL=C"}) || cmd.Stdin != nil {
		t.Fatalf("kill runs in %q with %q and input %v", cmd.Dir, cmd.Env, cmd.Stdin)
	}
	attr := cmd.SysProcAttr
	if attr == nil || attr.Credential != cred || attr.Credential.NoSetGroups || len(attr.Credential.Groups) != 0 || attr.Pdeathsig != syscall.SIGKILL || attr.Chroot != "" || attr.Setsid || attr.Setpgid || attr.AmbientCaps != nil || attr.UidMappings != nil {
		t.Fatalf("kill process attributes %+v", attr)
	}
	n := &linuxSystem{}
	for _, c := range []*syscall.Credential{
		nil,
		{Uid: 0, Gid: 0, Groups: []uint32{}},
		{Uid: 999, Gid: 999, Groups: []uint32{}},
		{Uid: 60001, Gid: 60001, Groups: []uint32{}},
		{Uid: 20000, Gid: 0, Groups: []uint32{}},
		{Uid: 20000, Gid: 20000, Groups: []uint32{0}},
		{Uid: 20000, Gid: 20000, NoSetGroups: true},
	} {
		if err := n.signalAs(t.Context(), c); !errors.Is(err, ErrRecovery) {
			t.Errorf("credential %+v: %v", c, err)
		}
	}
	if err := n.signalAs(t.Context(), cred); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("kill without the binary checked at start: %v", err)
	}
}

func TestProcessStatusUIDs(t *testing.T) {
	status := "Name:\tsleep\nState:\tS (sleeping)\nTgid:\t4242\nUid:\t20000\t20001\t20002\t20003\nGid:\t20000\t20000\t20000\t20000\n"
	if ids, ok := statusUIDs([]byte(status)); !ok || ids != [4]uint32{20000, 20001, 20002, 20003} {
		t.Fatalf("Uid line read as %v %v", ids, ok)
	}
	for _, bad := range []string{"Name:\tsleep\n", "Uid:\t1\t2\n", "Uid:\tx\t1\t1\t1\n", "Uid:\t-1\t1\t1\t1\n", "Uid:\t4294967296\t1\t1\t1\n"} {
		if ids, ok := statusUIDs([]byte(bad)); ok {
			t.Errorf("%q read as %v", bad, ids)
		}
	}
	self, err := os.ReadFile("/proc/self/status")
	if err != nil {
		t.Fatal(err)
	}
	if ids, ok := statusUIDs(self); !ok || ids[0] != uint32(os.Getuid()) || ids[1] != uint32(os.Geteuid()) {
		t.Fatalf("this process's IDs read as %v %v", ids, ok)
	}
	if running, err := accountRunning(uint32(os.Getuid())); err != nil || !running {
		t.Fatalf("this process is not seen: %v %v", running, err)
	}
	for name, want := range map[string]bool{"1": true, "4242": true, "self": false, "": false, "12a": false, "12345678901": false} {
		if pidName(name) != want {
			t.Errorf("pidName(%q) != %v", name, want)
		}
	}
}

// The broker's helper ends every process of one throwaway account, forks
// included, and no process of another. Two users are made with the fixed
// shadow tools and removed afterwards.
func TestRootOnlyEndProcessesTakesOnlyTheAccount(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("needs root: makes two users and runs processes as them")
	}
	kill, err := trustedFile(killPath, false)
	if err != nil {
		t.Fatalf("%s: %v", killPath, err)
	}
	users, err := systemUsers()
	if err != nil {
		t.Fatal(err)
	}
	groups, err := systemGroups()
	if err != nil {
		t.Fatal(err)
	}
	used := map[int]bool{}
	for _, u := range users {
		used[u.UID] = true
	}
	for _, g := range groups {
		used[g.GID] = true
	}
	var ids []int
	for id := lastAccountID; id > lastAccountID-1000 && len(ids) < 2; id-- {
		if !used[id] {
			ids = append(ids, id)
		}
	}
	if len(ids) != 2 {
		t.Fatal("no free IDs for the throwaway users")
	}
	shadow := func(path string, args ...string) {
		t.Helper()
		if out, err := exec.Command(path, args...).CombinedOutput(); err != nil {
			t.Fatalf("%s %q: %v\n%s", path, args, err, out)
		}
	}
	account := func(id int) record {
		name := "sfend" + strconv.Itoa(id)
		r := record{Account: Account{Username: name, UID: id, GID: id, Home: "/nonexistent/" + name}, Tag: "sifruno-test-" + name}
		shadow("/usr/sbin/groupadd", "--gid", strconv.Itoa(id), "--", name)
		t.Cleanup(func() { _ = exec.Command("/usr/sbin/groupdel", "--", name).Run() })
		shadow("/usr/sbin/useradd", "--uid", strconv.Itoa(id), "--gid", strconv.Itoa(id), "--no-user-group", "--groups", "", "--no-create-home", "--home-dir", r.Account.Home, "--shell", nologin, "--comment", r.Tag, "--", name)
		t.Cleanup(func() {
			_ = exec.Command("/usr/sbin/userdel", "--", name).Run()
			_ = os.Remove(filepath.Join(mailSpoolDir, name))
		})
		return r
	}
	start := func(r record, script string) (*exec.Cmd, chan error) {
		t.Helper()
		cmd := exec.Command("/bin/sh", "-c", script)
		cmd.Dir = "/"
		cmd.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{Uid: uint32(r.Account.UID), Gid: uint32(r.Account.GID), Groups: []uint32{}}}
		if err := cmd.Start(); err != nil {
			t.Fatal(err)
		}
		// Reaped at once, as a login's or a worker's parent does, so the
		// ended process does not stay as a zombie.
		done := make(chan error, 1)
		go func() { done <- cmd.Wait() }()
		return cmd, done
	}
	a, b := account(ids[0]), account(ids[1])
	_, aDone := start(a, "sleep 300 & sleep 300 & exec sleep 300")
	bCmd, bDone := start(b, "exec sleep 300")
	t.Cleanup(func() { _ = bCmd.Process.Kill(); <-bDone })
	deadline := time.Now().Add(5 * time.Second)
	for {
		if running, err := accountRunning(uint32(a.Account.UID)); err == nil && running {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("the first user's processes did not start")
		}
		time.Sleep(10 * time.Millisecond)
	}

	n := &linuxSystem{opts: BrokerOptions{ControllerUID: 1}, tools: map[string]os.FileInfo{killPath: kill}}
	if err := n.EndProcesses(t.Context(), a); err != nil {
		t.Fatalf("end the first user's processes: %v", err)
	}
	select {
	case err := <-aDone:
		if err == nil {
			t.Fatal("the first user's process exited by itself")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the first user's process still runs")
	}
	if running, err := accountRunning(uint32(a.Account.UID)); err != nil || running {
		t.Fatalf("a process of the first user is left: %v %v", running, err)
	}
	if running, err := accountRunning(uint32(b.Account.UID)); err != nil || !running {
		t.Fatalf("the other user's process ended: %v %v", running, err)
	}

	// A record whose name passwd gives another UID is refused, and the other
	// user's process still runs.
	wrong := a
	wrong.Account.UID, wrong.Account.GID = b.Account.UID, b.Account.GID
	if err := n.EndProcesses(t.Context(), wrong); !errors.Is(err, ErrRecovery) {
		t.Fatalf("a record that does not match passwd: %v", err)
	}
	select {
	case <-bDone:
		t.Fatal("the other user's process ended")
	case <-time.After(300 * time.Millisecond):
	}
}
