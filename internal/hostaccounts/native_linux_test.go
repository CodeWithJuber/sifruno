//go:build linux

package hostaccounts

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

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

// Literal expected argv is independent of production assembly. System identity
// semantics must not drop the explicitly allocated private IDs or home guards.
func TestServiceAccountUseraddExactArgv(t *testing.T) {
	for _, ids := range [][2]int{{20000, 20001}, {60000, 59999}} {
		r := record{Account: Account{Username: "fixtureacct", UID: ids[0], GID: ids[1], Home: "/srv/fixtureacct"}, Tag: "fixture-tag"}
		uid, gid := "20000", "20001"
		if ids[0] == 60000 {
			uid, gid = "60000", "59999"
		}
		want := []string{"--system", "-K", "SUB_UID_COUNT=0", "-K", "SUB_GID_COUNT=0", "--uid", uid, "--gid", gid, "--no-user-group", "--groups", "", "--create-home", "--home-dir", "/srv/fixtureacct", "--skel", "/root/fixture/empty-skel", "--shell", "/usr/sbin/nologin", "--comment", "fixture-tag", "--password", "!", "--expiredate", "", "--", "fixtureacct"}
		if got := useraddArgs(r, "/root/fixture/empty-skel"); !reflect.DeepEqual(got, want) {
			t.Fatalf("useradd argv = %#v; want %#v", got, want)
		}
	}
}
