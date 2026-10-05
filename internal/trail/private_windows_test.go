//go:build windows

package trail

import (
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/sys/windows"
)

func TestWindowsStoreAndKeyHaveRestrictedACL(t *testing.T) {
	s, root := fixture(t)
	put(t, root, "config.txt", "original")
	change := checkpoint(t, s, root, "config.txt")
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{s.dir, filepath.Join(s.dir, "key"), filepath.Join(s.dir, "events.jsonl"), filepath.Join(s.dir, "changes", change.ID+".enc")} {
		sd, err := windows.GetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION)
		if err != nil {
			t.Fatal(err)
		}
		sddl := sd.String()
		if strings.Count(sddl, "(A;") != 2 || !strings.Contains(sddl, ";;;SY)") || !strings.Contains(sddl, ";;;"+user.User.Sid.String()+")") {
			t.Fatalf("private ACL on %s has unexpected identities", filepath.Base(path))
		}
		if path == s.dir {
			control, _, err := sd.Control()
			if err != nil {
				t.Fatal(err)
			}
			if control&windows.SE_DACL_PROTECTED == 0 {
				t.Fatal("private store inherits parent ACL")
			}
		}
	}
}

func TestWindowsReopenRepairsProtectedInheritedKeyACL(t *testing.T) {
	s, _ := fixture(t)
	keyPath := filepath.Join(s.dir, "key")
	sd, err := windows.SecurityDescriptorFromString("D:P(A;;FA;;;WD)")
	if err != nil {
		t.Fatal(err)
	}
	dacl, _, err := sd.DACL()
	if err != nil {
		t.Fatal(err)
	}
	if err = windows.SetNamedSecurityInfo(keyPath, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION, nil, nil, dacl, nil); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(s.dir); err != nil {
		t.Fatal(err)
	}
	actual, err := windows.GetNamedSecurityInfo(keyPath, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(actual.String(), ";;;WD)") {
		t.Fatal("protected key ACL still permits other identities")
	}
}
