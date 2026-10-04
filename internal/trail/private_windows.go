//go:build windows

package trail

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"

	"golang.org/x/sys/windows"
)

// Windows chmod(0700) does not restrict inherited ACLs. Protect the private
// store with an inheritable DACL for this process identity and SYSTEM only.
func protectStore(path string) error {
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		return fmt.Errorf("private trail identity: %w", err)
	}
	sd, err := windows.SecurityDescriptorFromString("D:P(A;OICI;FA;;;" + user.User.Sid.String() + ")(A;OICI;FA;;;SY)")
	if err != nil {
		return fmt.Errorf("private trail permissions: %w", err)
	}
	dacl, _, err := sd.DACL()
	if err != nil {
		return fmt.Errorf("private trail permissions: %w", err)
	}
	return windows.SetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION, nil, nil, dacl, nil)
}

// Existing files can have protected ACLs that refuse inheritance from the
// parent. Apply the same policy to every entry while holding the process lock.
func protectExistingEntries(path string) error {
	return filepath.WalkDir(path, func(name string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if entry.Type()&os.ModeSymlink != 0 || (!entry.IsDir() && !entry.Type().IsRegular()) {
			return errors.New("invalid entry in private trail store")
		}
		return protectStore(name)
	})
}

// Windows does not expose portable directory fsync via os.File. File content
// and the event journal are fsynced; power-loss directory durability still
// depends on the filesystem. Interrupted commits are detected on next open.
func syncDirectory(string) error               { return nil }
func syncRootDirectory(*os.Root, string) error { return nil }
