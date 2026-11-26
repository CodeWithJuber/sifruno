package acme

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"sync"
	"time"

	"sifruno/internal/securestate"
)

const (
	recordsFile     = "certificates.json"
	recordsVersion  = 1
	maxRecordsBytes = 4 << 20
	privateFileMode = 0o600
)

// record is one site the panel has tried to get a certificate for.
// NotAfter is zero until a certificate is installed.
type record struct {
	AccountID   string    `json:"account_id"`
	Domain      string    `json:"domain"`
	NotAfter    time.Time `json:"not_after"`
	LastAttempt time.Time `json:"last_attempt"`
	LastResult  string    `json:"last_result"`
	// Waiting are the site's aliases its last look left out of the
	// certificate because they did not reach this server.
	Waiting []string `json:"waiting,omitempty"`
	// Copied says the installed certificate, valid until NotAfter, is the
	// one copied from the site's old server when it moved here; the next
	// certificate the panel installs clears it.
	Copied bool `json:"copied,omitempty"`
}

type recordsData struct {
	Version int      `json:"version"`
	Sites   []record `json:"sites"`
}

// records is the panel's own small list of the certificates it got, in one
// private file replaced atomically on every change. Memory is the authority
// while the panel runs: a failed write is logged and the next write saves
// everything.
type records struct {
	path string
	log  io.Writer
	mu   sync.Mutex
	list []record
}

// openRecords reads the list. A file that cannot be used is renamed to
// certificates.json.corrupt-<UTC time>, one line names it, and the list
// starts empty: the sites are found again when the wizard or a person adds
// them.
func openRecords(dir string, log io.Writer) (*records, error) {
	r := &records{path: filepath.Join(dir, recordsFile), log: log}
	if err := securestate.CheckPath(r.path); err != nil {
		return nil, err
	}
	raw, err := readPrivate(r.path, maxRecordsBytes)
	if errors.Is(err, os.ErrNotExist) {
		return r, nil
	}
	var data recordsData
	if err == nil {
		dec := json.NewDecoder(bytes.NewReader(raw))
		dec.DisallowUnknownFields()
		if dec.Decode(&data) != nil || dec.More() || data.Version != recordsVersion {
			err = errors.New("not a version 1 certificate list")
		}
	}
	if err != nil {
		aside := r.path + ".corrupt-" + time.Now().UTC().Format("20060102T150405Z")
		// CheckPath refused a symlink, so this changes the file itself.
		rerr := os.Chmod(r.path, privateFileMode)
		if rerr == nil {
			rerr = os.Rename(r.path, aside)
		}
		if rerr != nil {
			return nil, fmt.Errorf("acme: %s could not be used (%v), and moving it aside failed: %w", r.path, err, rerr)
		}
		fmt.Fprintf(log, "acme: %s could not be used (%v); moved it to %s and started with no certificates on record\n", r.path, err, aside)
		return r, nil
	}
	r.list = data.Sites
	return r, nil
}

func (r *records) get(accountID string) (record, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, x := range r.list {
		if x.AccountID == accountID {
			return x, true
		}
	}
	return record{}, false
}

func (r *records) all() []record {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]record(nil), r.list...)
}

// change applies fn to the account's record, making it first if need be,
// and saves the list.
func (r *records) change(accountID string, fn func(*record)) {
	r.mu.Lock()
	defer r.mu.Unlock()
	i := -1
	for k := range r.list {
		if r.list[k].AccountID == accountID {
			i = k
			break
		}
	}
	if i < 0 {
		r.list = append(r.list, record{AccountID: accountID})
		i = len(r.list) - 1
	}
	fn(&r.list[i])
	r.saveLocked()
}

// attempt records a new attempt before it starts, so a panel that stops
// mid-way does not try again at once.
func (r *records) attempt(accountID, domain string, now time.Time) {
	r.change(accountID, func(x *record) {
		if x.Domain != domain {
			x.NotAfter = time.Time{}
		}
		x.Domain, x.LastAttempt, x.LastResult = domain, now.UTC(), "trying"
	})
}

// waiting records the site's aliases that did not reach this server, and
// saves the list only when that changed.
func (r *records) waiting(accountID, domain string, waiting []string) {
	if x, ok := r.get(accountID); ok && x.Domain == domain && slices.Equal(x.Waiting, waiting) {
		return
	}
	r.change(accountID, func(x *record) {
		if x.Domain != domain {
			x.Domain, x.NotAfter = domain, time.Time{}
		}
		x.Waiting = slices.Clone(waiting)
		if len(x.Waiting) == 0 {
			x.Waiting = nil
		}
	})
}

func (r *records) failed(accountID string, err error) {
	result := "failed"
	for _, kind := range []error{ErrValidation, ErrRateLimited, ErrInstall, ErrAuthority} {
		if errors.Is(err, kind) {
			result = kind.Error()
			break
		}
	}
	r.change(accountID, func(x *record) { x.LastResult = result })
}

func (r *records) installed(accountID string, notAfter time.Time) {
	r.change(accountID, func(x *record) { x.NotAfter, x.LastResult, x.Copied = notAfter.UTC(), "installed", false })
}

// copied records a certificate copied from the site's old server, valid
// until notAfter, as the one installed for domain.
func (r *records) copied(accountID, domain string, notAfter time.Time) {
	r.change(accountID, func(x *record) {
		if x.Domain != domain {
			x.Waiting = nil
		}
		x.Domain, x.NotAfter, x.LastResult, x.Copied = domain, notAfter.UTC(), "copied", true
	})
}

func (r *records) forget(accountID string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	for i := range r.list {
		if r.list[i].AccountID == accountID {
			r.list = append(r.list[:i], r.list[i+1:]...)
			r.saveLocked()
			return
		}
	}
}

func (r *records) saveLocked() {
	list := r.list
	if list == nil {
		list = []record{}
	}
	raw, err := json.Marshal(recordsData{Version: recordsVersion, Sites: list})
	if err == nil {
		err = writePrivate(r.path, append(raw, '\n'))
	}
	if err != nil {
		fmt.Fprintf(r.log, "acme: saving %s failed: %v\n", r.path, err)
	}
}

// privateDir makes dir (0700) and checks that it is a real directory
// reached without symlinks.
func privateDir(dir string) (string, error) {
	dir, err := filepath.Abs(dir)
	if err != nil {
		return "", err
	}
	if err = securestate.CheckPath(dir); err != nil {
		return "", err
	}
	if err = os.MkdirAll(dir, stateDirMode); err != nil {
		return "", err
	}
	info, err := os.Lstat(dir)
	if err != nil {
		return "", err
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return "", errors.New("acme: the state directory must be a real directory")
	}
	return dir, os.Chmod(dir, stateDirMode)
}

// readPrivate reads a private file of at most limit bytes and refuses one
// that others can read or write.
func readPrivate(path string, limit int64) ([]byte, error) {
	if err := securestate.CheckPath(path); err != nil {
		return nil, err
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() || info.Mode().Perm()&0o077 != 0 {
		return nil, fmt.Errorf("acme: %s must be a regular file with mode 0600, not %v", path, info.Mode())
	}
	raw, err := io.ReadAll(io.LimitReader(f, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(raw)) > limit {
		return nil, fmt.Errorf("acme: %s is larger than %d bytes", path, limit)
	}
	return raw, nil
}

// writePrivate replaces path atomically with a 0600 file: a temporary file in
// the same directory, synced, renamed over the old one, then the directory
// synced.
func writePrivate(path string, data []byte) error {
	if err := securestate.CheckPath(path); err != nil {
		return err
	}
	dir := filepath.Dir(path)
	f, err := os.CreateTemp(dir, "."+filepath.Base(path)+".tmp-")
	if err != nil {
		return err
	}
	name := f.Name()
	err = f.Chmod(privateFileMode)
	if err == nil {
		_, err = f.Write(data)
	}
	if err == nil {
		err = f.Sync()
	}
	if closeErr := f.Close(); err == nil {
		err = closeErr
	}
	if err == nil {
		err = os.Rename(name, path)
	}
	if err != nil {
		_ = os.Remove(name)
		return err
	}
	if runtime.GOOS != "windows" {
		if d, derr := os.Open(dir); derr == nil {
			_ = d.Sync()
			_ = d.Close()
		}
	}
	return nil
}
