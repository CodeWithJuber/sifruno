// Package wizard runs the "create a WordPress site" wizard as a panel job:
// a hosting account, its live site, its certificate, a database and
// WordPress, one step after another, outside the request that asked for it.
// Every root action is one of the account broker's typed operations;
// databases go through dbhost. The job record is the job log: it is kept in
// the panel's private state directory and never holds a password.
package wizard

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"sync"
	"time"

	"sifruno/internal/securestate"
)

// Job is one wizard run as the API shows it and the store keeps it.
type Job struct {
	ID         string   `json:"id"`
	Kind       string   `json:"kind"`
	Domain     string   `json:"domain"`
	Username   string   `json:"username"`
	PHPVersion string   `json:"php_version"` // from the request; "" in a job saved before it was recorded
	State      string   `json:"state"`
	Steps      []Step   `json:"steps"`
	Error      *Failure `json:"error"`
	Result     *Result  `json:"result"`
	Actor      string   `json:"actor"`
	CreatedAt  string   `json:"created_at"`
	UpdatedAt  string   `json:"updated_at"`
	// RemovedAt is when the site this job made was deleted from its page,
	// RFC 3339. Such a job is kept as a record but no longer names a site.
	RemovedAt string `json:"removed_at,omitempty"`
	// DeleteRevision is the hosting account's revision when a delete from
	// the site's page last asked the account service to delete it; 0 if none
	// has. Once that account is gone, Websites lists the site as partly
	// deleted with this revision until a second delete removes the rest.
	DeleteRevision uint64 `json:"delete_revision,omitempty"`
}

// namesSite reports whether the job stands for a site Websites lists: it
// succeeded, and the site was not deleted since.
func (j Job) namesSite() bool { return j.State == StateSucceeded && j.RemovedAt == "" }

// Step is one part of the job. StartedAt and FinishedAt are RFC 3339 or
// empty. "undone" means the job removed what the step created after a later
// step failed. "skipped" means the step did not run because an earlier one
// failed, or, for "ssl", that the site has no certificate yet and uses http.
type Step struct {
	Name       string `json:"name"`
	Title      string `json:"title"`
	State      string `json:"state"`
	Message    string `json:"message"`
	StartedAt  string `json:"started_at"`
	FinishedAt string `json:"finished_at"`
}

// Failure says what went wrong in plain words; Technical holds the broker's
// step detail or the error text, printable ASCII without secrets.
type Failure struct {
	Step      string `json:"step"`
	What      string `json:"what"`
	Why       string `json:"why"`
	Next      string `json:"next"`
	Technical string `json:"technical"`
}

// Result is where the new site is.
type Result struct {
	URL              string `json:"url"`
	AdminURL         string `json:"admin_url"`
	WordPressVersion string `json:"wordpress_version"`
	AccountID        string `json:"account_id"`
}

const (
	KindWordPress = "wordpress"

	StateRunning   = "running"
	StateSucceeded = "succeeded"
	StateFailed    = "failed"

	StepPending = "pending"
	StepRunning = "running"
	StepDone    = "done"
	StepFailed  = "failed"
	StepUndone  = "undone"
	StepSkipped = "skipped"
)

// Step names, in the order they run.
const (
	StepAccount   = "account"
	StepWeb       = "web"
	StepSSL       = "ssl"
	StepDatabase  = "database"
	StepWordPress = "wordpress"
)

var stepTitles = []struct{ name, title string }{
	{StepAccount, "Create the hosting account"},
	{StepWeb, "Put the site live with PHP"},
	{StepSSL, "Turn on https"},
	{StepDatabase, "Create the database"},
	{StepWordPress, "Install WordPress"},
}

// Restart texts, as the contract fixes them.
const (
	restartWhat = "The panel restarted while this website was being created."
	restartWhy  = "The panel stopped before the job finished, so it does not know how far the last step got."
	restartNext = "Check Websites and Accounts, remove what was left, then create it again."
)

const (
	maxJobs        = 50      // the newest 50 jobs that did not succeed
	maxSucceeded   = 2000    // succeeded jobs name the sites: as many as the broker has accounts
	maxListed      = 20      // GET /jobs answers at most 20
	maxStoreBytes  = 8 << 20 // a full store is about 2.5 MiB
	storeFile      = "jobs.json"
	storeFileMode  = 0o600
	storeDirMode   = 0o700
	storeVersion   = 1
	timestampStyle = time.RFC3339
)

var jobIDPattern = regexp.MustCompile(`^[0-9a-f]{32}$`)

// ValidID reports whether id has the shape of a job ID.
func ValidID(id string) bool { return jobIDPattern.MatchString(id) }

func newJobID() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	return hex.EncodeToString(b[:]), nil
}

func timestamp(t time.Time) string { return t.UTC().Format(timestampStyle) }

func newJob(id, domain, actor string, now time.Time) Job {
	steps := make([]Step, len(stepTitles))
	for i, s := range stepTitles {
		steps[i] = Step{Name: s.name, Title: s.title, State: StepPending}
	}
	at := timestamp(now)
	return Job{ID: id, Kind: KindWordPress, Domain: domain, State: StateRunning, Steps: steps, Actor: actor, CreatedAt: at, UpdatedAt: at}
}

// clone copies a job so callers never share its slices or pointers.
func (j Job) clone() Job {
	j.Steps = append([]Step(nil), j.Steps...)
	if j.Error != nil {
		e := *j.Error
		j.Error = &e
	}
	if j.Result != nil {
		r := *j.Result
		j.Result = &r
	}
	return j
}

// Store keeps the newest jobs in one private JSON file, replaced atomically
// on every change. Memory is the authority while the panel runs: a failed
// write leaves memory current and the next write saves everything.
type Store struct {
	dir  string
	mu   sync.Mutex
	jobs []Job // oldest first
}

type storeData struct {
	Version int   `json:"version"`
	Jobs    []Job `json:"jobs"`
}

// logOutput takes the store's and the runner's one-line reports. It is
// stderr, where the panel's other start-up messages go.
var logOutput io.Writer = os.Stderr

// OpenStore opens or creates the job store in dir (made 0700). A job still
// "running" in the file belonged to a panel that stopped mid-run: it becomes
// "failed" with the restart message, and nothing is undone automatically.
// A job file that cannot be read or used (damaged, too large, another
// version, an invalid job) does not stop the panel: it is renamed to
// jobs.json.corrupt-<UTC time>, one line on stderr names it, and the store
// starts empty.
func OpenStore(dir string) (*Store, error) {
	dir, err := filepath.Abs(dir)
	if err != nil {
		return nil, err
	}
	if err = securestate.CheckPath(dir); err != nil {
		return nil, err
	}
	if err = os.MkdirAll(dir, storeDirMode); err != nil {
		return nil, err
	}
	info, err := os.Lstat(dir)
	if err != nil {
		return nil, err
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return nil, errors.New("website job store must be a real directory")
	}
	if err = os.Chmod(dir, storeDirMode); err != nil {
		return nil, err
	}
	s := &Store{dir: dir}
	path := filepath.Join(dir, storeFile)
	if err = securestate.CheckPath(path); err != nil {
		return nil, err
	}
	jobs, err := readStore(path)
	if errors.Is(err, os.ErrNotExist) {
		return s, nil
	}
	if err != nil {
		// The job log is for people; a damaged one is kept for them to read,
		// not allowed to keep the panel from starting.
		aside, aerr := setAside(path)
		if aerr != nil {
			return nil, fmt.Errorf("%v, and moving it aside failed: %w", err, aerr)
		}
		fmt.Fprintf(logOutput, "website jobs: %s could not be used (%v); moved it to %s and started with no jobs\n", path, err, aside)
		return s, nil
	}
	s.jobs = jobs
	changed := false
	now := timestamp(time.Now())
	for i := range s.jobs {
		if s.jobs[i].State == StateRunning {
			s.jobs[i] = interrupted(s.jobs[i], now)
			changed = true
		}
	}
	if s.trimLocked() {
		changed = true
	}
	if changed {
		if err = s.writeLocked(); err != nil {
			return nil, err
		}
	}
	return s, nil
}

// readStore reads and checks the job file. A missing file is os.ErrNotExist;
// any other error means the file cannot be used as it is.
func readStore(path string) ([]Job, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	raw, err := io.ReadAll(io.LimitReader(f, maxStoreBytes+1))
	f.Close()
	if err != nil {
		return nil, err
	}
	if len(raw) > maxStoreBytes {
		return nil, errors.New("website job store is too large")
	}
	var data storeData
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err = dec.Decode(&data); err != nil || dec.More() {
		return nil, errors.New("website job store is not valid JSON")
	}
	if data.Version != storeVersion {
		return nil, fmt.Errorf("website job store version %d is not supported", data.Version)
	}
	for _, j := range data.Jobs {
		// A job from before the "ssl" step has one step fewer; it is kept.
		if !ValidID(j.ID) || (len(j.Steps) != len(stepTitles) && len(j.Steps) != len(stepTitles)-1) {
			return nil, errors.New("website job store holds an invalid job")
		}
	}
	return data.Jobs, nil
}

// setAside renames a job file that cannot be used to
// jobs.json.corrupt-<UTC time> in the same directory, private, and never over
// an earlier one. It returns the new path.
func setAside(path string) (string, error) {
	aside := path + ".corrupt-" + time.Now().UTC().Format("20060102T150405Z")
	if _, err := os.Lstat(aside); err == nil {
		return "", fmt.Errorf("%s already exists", aside)
	} else if !errors.Is(err, os.ErrNotExist) {
		return "", err
	}
	// CheckPath refused a symlink, so this changes the file itself.
	if err := os.Chmod(path, storeFileMode); err != nil {
		return "", err
	}
	if err := os.Rename(path, aside); err != nil {
		return "", err
	}
	syncDir(filepath.Dir(path))
	return aside, nil
}

// interrupted marks a job the panel stopped in the middle of.
func interrupted(j Job, now string) Job {
	j = j.clone()
	failed := ""
	for i := range j.Steps {
		switch j.Steps[i].State {
		case StepRunning:
			j.Steps[i].State = StepFailed
			j.Steps[i].Message = restartWhat
			j.Steps[i].FinishedAt = now
			failed = j.Steps[i].Name
		case StepPending:
			if failed == "" {
				// Stopped between steps: the step that was next is the one
				// that did not happen.
				j.Steps[i].State = StepFailed
				j.Steps[i].Message = restartWhat
				j.Steps[i].FinishedAt = now
				failed = j.Steps[i].Name
				continue
			}
			j.Steps[i].State = StepSkipped
		}
	}
	j.State = StateFailed
	j.Error = &Failure{Step: failed, What: restartWhat, Why: restartWhy, Next: restartNext, Technical: "job was running when the panel stopped; nothing was undone"}
	j.UpdatedAt = now
	return j
}

// put adds or replaces a job and saves the store.
func (s *Store) put(j Job) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	j = j.clone()
	replaced := false
	for i := range s.jobs {
		if s.jobs[i].ID == j.ID {
			s.jobs[i] = j
			replaced = true
			break
		}
	}
	if !replaced {
		s.jobs = append(s.jobs, j)
	}
	s.trimLocked()
	return s.writeLocked()
}

// trimLocked drops the oldest jobs past the limits and reports whether it
// dropped any. Succeeded jobs are what Websites lists, so they have their own,
// larger limit; the job of a site deleted since counts with the others, so
// deleted sites do not use up that limit. A running job is never dropped.
func (s *Store) trimLocked() bool {
	succeeded, other := 0, 0
	for _, j := range s.jobs {
		switch {
		case j.namesSite():
			succeeded++
		case j.State == StateRunning:
		default:
			other++
		}
	}
	dropped := false
	kept := s.jobs[:0]
	for _, j := range s.jobs { // oldest first
		switch {
		case j.namesSite() && succeeded > maxSucceeded:
			succeeded--
			dropped = true
		case !j.namesSite() && j.State != StateRunning && other > maxJobs:
			other--
			dropped = true
		default:
			kept = append(kept, j)
		}
	}
	s.jobs = kept
	return dropped
}

// markRemoved records that the site of this account was deleted: every job
// that made it gets RemovedAt, and the store is saved.
func (s *Store) markRemoved(accountID, at string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	changed := false
	for i := range s.jobs {
		if j := &s.jobs[i]; j.namesSite() && j.Result != nil && j.Result.AccountID == accountID {
			j.RemovedAt, j.UpdatedAt = at, at
			changed = true
		}
	}
	if !changed {
		return nil
	}
	s.trimLocked()
	return s.writeLocked()
}

// markDeleting records, before the account service is asked to delete the
// site of this account, the revision it is asked at: every job that names
// the site gets DeleteRevision, and the store is saved.
func (s *Store) markDeleting(accountID string, revision uint64, at string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	changed := false
	for i := range s.jobs {
		if j := &s.jobs[i]; j.namesSite() && j.Result != nil && j.Result.AccountID == accountID && j.DeleteRevision != revision {
			j.DeleteRevision, j.UpdatedAt = revision, at
			changed = true
		}
	}
	if !changed {
		return nil
	}
	return s.writeLocked()
}

// forget removes a job from memory only: used when its first save failed,
// so the file never held it.
func (s *Store) forget(id string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for i := range s.jobs {
		if s.jobs[i].ID == id {
			s.jobs = append(s.jobs[:i], s.jobs[i+1:]...)
			return
		}
	}
}

// Get returns a copy of one job.
func (s *Store) Get(id string) (Job, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, j := range s.jobs {
		if j.ID == id {
			return j.clone(), true
		}
	}
	return Job{}, false
}

// sites returns copies of every kept job that names a site with its
// account, newest first.
func (s *Store) sites() []Job {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := []Job{}
	for i := len(s.jobs) - 1; i >= 0; i-- {
		if j := s.jobs[i]; j.namesSite() && j.Result != nil && j.Result.AccountID != "" {
			out = append(out, j.clone())
		}
	}
	return out
}

// List returns copies of the newest jobs, newest first, at most limit.
func (s *Store) List(limit int) []Job {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := []Job{}
	for i := len(s.jobs) - 1; i >= 0 && len(out) < limit; i-- {
		out = append(out, s.jobs[i].clone())
	}
	return out
}

// writeLocked replaces the file atomically: a private temporary file in the
// same directory, synced, renamed over the old one, then the directory synced.
func (s *Store) writeLocked() error {
	jobs := s.jobs
	if jobs == nil {
		jobs = []Job{}
	}
	raw, err := json.Marshal(storeData{Version: storeVersion, Jobs: jobs})
	if err != nil {
		return err
	}
	if len(raw) > maxStoreBytes {
		return errors.New("website job store is too large")
	}
	path := filepath.Join(s.dir, storeFile)
	if err = securestate.CheckPath(path); err != nil {
		return err
	}
	f, err := os.CreateTemp(s.dir, "."+storeFile+".tmp-")
	if err != nil {
		return err
	}
	name := f.Name()
	err = f.Chmod(storeFileMode)
	if err == nil {
		_, err = f.Write(append(raw, '\n'))
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
	syncDir(s.dir)
	return nil
}

// syncDir makes the rename durable where the platform supports it; a failure
// only risks losing the newest write after a power cut, not a corrupt file.
func syncDir(dir string) {
	if runtime.GOOS == "windows" {
		return
	}
	if d, err := os.Open(dir); err == nil {
		_ = d.Sync()
		_ = d.Close()
	}
}
