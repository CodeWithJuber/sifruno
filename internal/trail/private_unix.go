//go:build !windows

package trail

import "os"

func protectStore(path string) error { return os.Chmod(path, 0700) }

// A private parent directory prevents unprivileged access to existing files.
func protectExistingEntries(string) error { return nil }

func syncDirectory(path string) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	return f.Sync()
}

func syncRootDirectory(r *os.Root, path string) error {
	f, err := r.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	return f.Sync()
}

func replaceRootedFile(r *os.Root, source, destination string) error {
	return r.Rename(source, destination)
}
