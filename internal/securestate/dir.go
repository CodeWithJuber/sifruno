package securestate

import (
	"errors"
	"os"
	"path/filepath"
)

// Dir creates a private application-owned state directory. Never point it at
// shared project roots: permission hardening applies to this exact directory.
func Dir(path string) (string, error) {
	path, err := filepath.Abs(path)
	if err != nil {
		return "", err
	}
	if path == filepath.VolumeName(path)+string(os.PathSeparator) {
		return "", errors.New("state cannot be a filesystem root")
	}
	if err = CheckPath(path); err != nil {
		return "", err
	}
	if err = os.MkdirAll(path, 0700); err != nil {
		return "", err
	}
	info, err := os.Lstat(path)
	if err != nil {
		return "", err
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return "", errors.New("state must be a real private directory")
	}
	marker := filepath.Join(path, ".sifruno-state")
	if err = CheckPath(marker); err != nil {
		return "", err
	}
	if _, err = os.Lstat(marker); errors.Is(err, os.ErrNotExist) {
		items, e := os.ReadDir(path)
		if e != nil {
			return "", e
		}
		if len(items) > 0 {
			return "", errors.New("refusing to change permissions on a nonempty directory without a Sifruno state marker")
		}
		if err = os.WriteFile(marker, []byte("private Sifruno application state\n"), 0600); err != nil {
			return "", err
		}
	} else if err != nil {
		return "", err
	}
	raw, err := os.ReadFile(marker)
	if err != nil {
		return "", err
	}
	if string(raw) != "private Sifruno application state\n" {
		return "", errors.New("invalid Sifruno state marker")
	}
	if err = protect(path); err != nil {
		return "", err
	}
	return path, nil
}

// CheckPath rejects existing symlinks in a private state path and its parents.
// The state is owned by one OS identity; it is not a sandbox against that owner.
func CheckPath(path string) error {
	path, err := filepath.Abs(path)
	if err != nil {
		return err
	}
	for {
		info, e := os.Lstat(path)
		if e == nil && info.Mode()&os.ModeSymlink != 0 {
			return errors.New("private state cannot follow symlinks")
		}
		if e != nil && !errors.Is(e, os.ErrNotExist) {
			return e
		}
		parent := filepath.Dir(path)
		if parent == path {
			break
		}
		path = parent
	}
	return nil
}
