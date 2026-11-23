package acme

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
)

const challengeFileMode = 0o644 // the web server reads it as another user

// The token comes from the certificate authority, so it is checked before it
// names a file: base64url only (RFC 8555 section 8.3), which has no slash or
// dot.
var tokenPattern = regexp.MustCompile(`^[A-Za-z0-9_-]{1,256}$`)

// challengeFiles answers HTTP-01 challenges with one file per token,
// <dir>/<token>, holding the key authorization. One directory serves every
// site: tokens are random, so sites never share a file.
type challengeFiles struct{ dir string }

// Present writes <dir>/<token> (0644) atomically.
func (c challengeFiles) Present(_ context.Context, _, token, keyAuth string) error {
	if !tokenPattern.MatchString(token) {
		return errors.New("acme: the certificate authority sent a challenge token that is not base64url")
	}
	if err := c.checkDir(); err != nil {
		return err
	}
	f, err := os.CreateTemp(c.dir, ".token-")
	if err != nil {
		return fmt.Errorf("acme: writing the challenge answer: %w", err)
	}
	name := f.Name()
	err = f.Chmod(challengeFileMode)
	if err == nil {
		_, err = f.WriteString(keyAuth)
	}
	if err == nil {
		err = f.Sync()
	}
	if closeErr := f.Close(); err == nil {
		err = closeErr
	}
	if err == nil {
		err = os.Rename(name, filepath.Join(c.dir, token))
	}
	if err != nil {
		_ = os.Remove(name)
		return fmt.Errorf("acme: writing the challenge answer: %w", err)
	}
	return nil
}

// CleanUp removes <dir>/<token>; one already gone is fine.
func (c challengeFiles) CleanUp(_ context.Context, _, token, _ string) error {
	if !tokenPattern.MatchString(token) {
		return errors.New("acme: the certificate authority sent a challenge token that is not base64url")
	}
	if err := os.Remove(filepath.Join(c.dir, token)); err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("acme: removing the challenge answer: %w", err)
	}
	return nil
}

// checkDir makes sure the directory is there and is a real directory; the
// panel does not make it, because provisioning sets its owner and mode.
func (c challengeFiles) checkDir() error {
	info, err := os.Lstat(c.dir)
	if errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("acme: the challenge directory %s is missing; provisioning creates it", c.dir)
	}
	if err != nil {
		return fmt.Errorf("acme: the challenge directory: %w", err)
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("acme: %s must be a real directory", c.dir)
	}
	return nil
}
