package trail

import (
	"errors"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
)

const maxManifest = maxFile*maxFiles*2 + (1 << 20)

var changeIDPattern = regexp.MustCompile(`^[a-f0-9]{32}$`)
var hashPattern = regexp.MustCompile(`^[a-f0-9]{64}$`)

// Check existing components before opening a declared root or private store
// path. Rooted operations additionally prevent escapes during file access.
func rejectLinks(path string) error {
	abs, err := filepath.Abs(path)
	if err != nil {
		return err
	}
	current := filepath.VolumeName(abs) + string(filepath.Separator)
	for _, part := range strings.Split(strings.TrimPrefix(abs, current), string(filepath.Separator)) {
		if part == "" {
			continue
		}
		current = filepath.Join(current, part)
		info, err := os.Lstat(current)
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		if err != nil {
			return err
		}
		if info.Mode()&os.ModeSymlink != 0 {
			return errors.New("symlinks are excluded from trail roots and store paths")
		}
	}
	return nil
}

func pathKey(p string) string {
	if runtime.GOOS == "windows" {
		return strings.ToLower(p)
	}
	return p
}

// Validate decrypted structure as well as its cryptographic envelope. This
// prevents corrupt shapes from causing indexing panics or unsafe restoration.
func validateChange(c Change) error {
	if !filepath.IsAbs(c.Root) || c.Created.IsZero() || len(c.Before) == 0 || len(c.Before) > maxFiles {
		return errors.New("invalid checkpoint scope")
	}
	if c.Parent != "" && !changeIDPattern.MatchString(c.Parent) {
		return errors.New("invalid checkpoint parent")
	}
	if strings.TrimSpace(c.Reason) == "" || strings.TrimSpace(c.Actor) == "" || len(c.Reason) > 500 || len(c.Actor) > 100 {
		return errors.New("invalid checkpoint metadata")
	}
	if c.State == "checkpointed" {
		if len(c.After) != 0 {
			return errors.New("unsealed checkpoint has after images")
		}
	} else if c.State != "applied" && c.State != "recovering" && c.State != "rolled_back" {
		return errors.New("invalid checkpoint state")
	} else if len(c.After) != len(c.Before) {
		return errors.New("checkpoint before and after scope differs")
	}
	seen := map[string]bool{}
	for n, img := range c.Before {
		p, err := safePath(img.Path)
		if err != nil || p != img.Path || seen[pathKey(p)] {
			return errors.New("invalid or duplicate checkpoint path")
		}
		seen[pathKey(p)] = true
		if img.Exists {
			if len(img.Data) > maxFile || img.Mode > 0777 || img.Hash != digest(img.Data) {
				return errors.New("checkpoint before image integrity failed")
			}
		} else if img.Hash != "absent" || img.Mode != 0 || len(img.Data) != 0 {
			return errors.New("invalid absent before image")
		}
		if c.State != "checkpointed" {
			after := c.After[n]
			if after.Path != p || len(after.Data) != 0 || after.Mode > 0777 || (after.Exists && !hashPattern.MatchString(after.Hash)) || (!after.Exists && (after.Hash != "absent" || after.Mode != 0)) {
				return errors.New("invalid checkpoint after image")
			}
		}
	}
	return nil
}
