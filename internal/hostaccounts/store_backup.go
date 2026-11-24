package hostaccounts

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"time"

	bolt "go.etcd.io/bbolt"
)

// Backups are not written to the accounts' operation journal. A journal
// holds 256 rows per account, about 127 operations, and a nightly backup
// would fill it in four months. A backup and a drill change no account and
// no tenant file; a restore changes only the tenant's own files and
// databases, with the tenant's rights, as a WordPress install does, and the
// panel's job log records who asked. What a restore or drill leaves behind
// as root (its staging folder and its temporary MariaDB user) is recorded
// here before it is made and removed afterwards; whatever an interruption
// left is removed before the next backup operation runs.
var backupBucket = []byte("hostbroker-backup-v1")

const maxBackupLeftovers = 32

// backupEngine runs restic and the database tools. The Linux engine is the
// real one; tests use a fake.
type backupEngine interface {
	// Status makes the broker's key pair and repository password if they
	// do not exist yet, and returns the public key; ready says restic
	// matches its pin and the tools it needs are in place.
	Status(ctx context.Context) (publicKey string, ready bool, err error)
	// Password reads the repository password, to show it once.
	Password() (string, error)
	// SetTarget opens the target's repository with the broker's password,
	// or makes one there, before the target's host keys replace the old.
	SetTarget(ctx context.Context, t BackupTarget) (initialized bool, err error)
	Backup(ctx context.Context, t BackupTarget, r record, dbs []string) (Snapshot, error)
	Snapshots(ctx context.Context, t BackupTarget, r record) ([]Snapshot, error)
	Restore(ctx context.Context, t BackupTarget, r record, in RestoreInput, l backupLeftover) error
	Drill(ctx context.Context, t BackupTarget, r record, l backupLeftover, now time.Time) (DrillResult, error)
	Prune(ctx context.Context, t BackupTarget) (PruneResult, error)
	// Cleanup drops the leftover's temporary MariaDB users and removes its
	// staging folder; it must be safe to repeat.
	Cleanup(ctx context.Context, l backupLeftover) error
}

// storedTarget is the configured target and whether the repository
// password was shown.
type storedTarget struct {
	Target        BackupTarget `json:"target"`
	PasswordShown bool         `json:"password_shown"`
	Actor         string       `json:"actor"`
	Reason        string       `json:"reason"`
	UpdatedAt     time.Time    `json:"updated_at"`
}

// backupLeftover names one restore's or drill's root-side state: its
// staging folder (Op) and the temporary MariaDB users, one per database.
type backupLeftover struct {
	Op    string            `json:"op"`
	Users map[string]string `json:"users,omitempty"`
}

func (l backupLeftover) valid() bool {
	if !idPattern.MatchString(l.Op) || len(l.Users) > maxBackupDatabases {
		return false
	}
	for db, user := range l.Users {
		if !restoreUserPattern.MatchString(user) || !validDatabaseName(db) {
			return false
		}
	}
	return true
}

func (s *store) readBackup(key string, out any) (bool, error) {
	found := false
	err := s.db.View(func(tx *bolt.Tx) error {
		b := tx.Bucket(backupBucket)
		if b == nil {
			return nil
		}
		raw := b.Get([]byte(key))
		if raw == nil {
			return nil
		}
		found = true
		return json.Unmarshal(raw, out)
	})
	if err != nil {
		return false, ErrUnavailable
	}
	return found, nil
}

func (s *store) writeBackup(key string, value any) error {
	raw, err := json.Marshal(value)
	if err != nil {
		return ErrUnavailable
	}
	if s.db.Update(func(tx *bolt.Tx) error {
		b, e := tx.CreateBucketIfNotExists(backupBucket)
		if e != nil {
			return e
		}
		return b.Put([]byte(key), raw)
	}) != nil {
		return ErrUnavailable
	}
	return nil
}

func (s *store) target() (storedTarget, bool, error) {
	var t storedTarget
	found, err := s.readBackup("target", &t)
	if err != nil || found && !validStoredTarget(t.Target) {
		return storedTarget{}, false, ErrUnavailable
	}
	return t, found, nil
}

func (s *store) leftovers() ([]backupLeftover, error) {
	var items []backupLeftover
	if _, err := s.readBackup("leftovers", &items); err != nil || len(items) > maxBackupLeftovers {
		return nil, ErrUnavailable
	}
	for _, l := range items {
		if !l.valid() {
			return nil, ErrUnavailable
		}
	}
	return items, nil
}

// cleanBackupLeftovers removes what earlier restores and drills left; one
// that still cannot be removed stays listed for the next run.
func (s *store) cleanBackupLeftovers(ctx context.Context) error {
	items, err := s.leftovers()
	if err != nil {
		return err
	}
	kept := []backupLeftover{}
	for _, l := range items {
		if s.backup.Cleanup(ctx, l) != nil {
			kept = append(kept, l)
		}
	}
	if len(kept) == len(items) {
		return nil
	}
	return s.writeBackup("leftovers", kept)
}

// recordLeftover lists a restore's or drill's root-side state before any of
// it is made.
func (s *store) recordLeftover(l backupLeftover) error {
	items, err := s.leftovers()
	if err != nil {
		return err
	}
	if len(items) >= maxBackupLeftovers {
		return ErrUnavailable
	}
	return s.writeBackup("leftovers", append(items, l))
}

// finishLeftover removes the state and then its entry; if the removal
// fails, the entry stays for the next run.
func (s *store) finishLeftover(l backupLeftover) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	if s.backup.Cleanup(ctx, l) != nil {
		return
	}
	items, err := s.leftovers()
	if err != nil {
		return
	}
	kept := []backupLeftover{}
	for _, item := range items {
		if item.Op != l.Op {
			kept = append(kept, item)
		}
	}
	_ = s.writeBackup("leftovers", kept)
}

func restoreUserName() (string, error) {
	var b [8]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", ErrUnavailable
	}
	return "sifruno_rst_" + hex.EncodeToString(b[:]), nil
}

// backupAccount looks the account up under the broker lock; the backup
// itself runs outside it, one backup operation at a time.
func (s *store) backupReady(ctx context.Context, id string) (record, []string, error) {
	if snapshotReentry(ctx, s) {
		return record{}, nil, ErrConflict
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if !idPattern.MatchString(id) {
		return record{}, nil, ErrInvalid
	}
	if s.backup == nil {
		return record{}, nil, ErrUnavailable
	}
	items, err := s.mutationReady(ctx)
	if err != nil {
		return record{}, nil, err
	}
	names := make([]string, 0, len(items))
	for _, r := range items {
		names = append(names, r.Account.Username)
	}
	for _, r := range items {
		if r.Account.ID == id {
			return r, names, nil
		}
	}
	return record{}, nil, ErrNotFound
}

func (s *store) configuredTarget() (BackupTarget, error) {
	t, found, err := s.target()
	if err != nil {
		return BackupTarget{}, err
	}
	if !found {
		return BackupTarget{}, &BackupError{Step: "target", Detail: "no backup storage is set up"}
	}
	return t.Target, nil
}

func backupContext(ctx context.Context, limit time.Duration) (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.WithoutCancel(ctx), limit)
}

func (s *store) backupStatus(ctx context.Context) (BackupStatus, error) {
	if ctx == nil {
		return BackupStatus{}, ErrInvalid
	}
	if s.backup == nil {
		return BackupStatus{}, ErrUnavailable
	}
	s.backupMu.Lock()
	defer s.backupMu.Unlock()
	key, ready, err := s.backup.Status(ctx)
	if err != nil {
		return BackupStatus{}, err
	}
	t, found, err := s.target()
	if err != nil {
		return BackupStatus{}, err
	}
	status := BackupStatus{Ready: ready, PublicKey: key, Configured: found}
	if found {
		target := t.Target
		status.Target = &target
	}
	return status, nil
}

func (s *store) setBackupTarget(ctx context.Context, in BackupTargetInput, actor string) (BackupTargetResult, error) {
	if ctx == nil {
		return BackupTargetResult{}, ErrInvalid
	}
	t, ok := validBackupTarget(in, actor)
	if !ok {
		return BackupTargetResult{}, ErrInvalid
	}
	if s.backup == nil {
		return BackupTargetResult{}, ErrUnavailable
	}
	s.backupMu.Lock()
	defer s.backupMu.Unlock()
	work, cancel := backupContext(ctx, backupTargetTimeout)
	defer cancel()
	if _, _, err := s.backup.Status(work); err != nil {
		return BackupTargetResult{}, err
	}
	if err := s.cleanBackupLeftovers(work); err != nil {
		return BackupTargetResult{}, err
	}
	old, _, err := s.target()
	if err != nil {
		return BackupTargetResult{}, err
	}
	initialized, err := s.backup.SetTarget(work, t)
	if err != nil {
		return BackupTargetResult{}, err
	}
	result := BackupTargetResult{Initialized: initialized}
	if !old.PasswordShown {
		if result.Password, err = s.backup.Password(); err != nil {
			return BackupTargetResult{}, err
		}
	}
	// The password counts as shown once this answer is written: it is not
	// kept anywhere the panel can ask for it again.
	if err = s.writeBackup("target", storedTarget{Target: t, PasswordShown: true, Actor: actor, Reason: in.Reason, UpdatedAt: time.Now().UTC()}); err != nil {
		return BackupTargetResult{}, err
	}
	key, ready, err := s.backup.Status(work)
	if err != nil {
		return BackupTargetResult{}, err
	}
	result.Status = BackupStatus{Ready: ready, PublicKey: key, Configured: true, Target: &t}
	return result, nil
}

func (s *store) backupAccount(ctx context.Context, id string, in BackupInput, actor string) (Snapshot, error) {
	if ctx == nil {
		return Snapshot{}, ErrInvalid
	}
	if !validBackupInput(in, actor) {
		return Snapshot{}, ErrInvalid
	}
	r, names, err := s.backupReady(ctx, id)
	if err != nil {
		return Snapshot{}, err
	}
	dbs, ok := accountDatabases(in.Databases, r.Account.Username, names)
	if !ok {
		return Snapshot{}, ErrInvalid
	}
	if r.Account.State == "recovery_required" || s.native.VerifyIdentity(r) != nil {
		return Snapshot{}, ErrConflict
	}
	s.backupMu.Lock()
	defer s.backupMu.Unlock()
	work, cancel := backupContext(ctx, backupTimeout)
	defer cancel()
	t, err := s.configuredTarget()
	if err != nil {
		return Snapshot{}, err
	}
	if err = s.cleanBackupLeftovers(work); err != nil {
		return Snapshot{}, err
	}
	return s.backup.Backup(work, t, r, dbs)
}

// listBackups does not wait for a running backup: restic lists without a
// lock.
func (s *store) listBackups(ctx context.Context, id string) ([]Snapshot, error) {
	if ctx == nil {
		return nil, ErrInvalid
	}
	r, _, err := s.backupReady(ctx, id)
	if err != nil {
		return nil, err
	}
	t, err := s.configuredTarget()
	if err != nil {
		return nil, err
	}
	work, cancel := backupContext(ctx, backupListTimeout)
	defer cancel()
	return s.backup.Snapshots(work, t, r)
}

func (s *store) restoreAccount(ctx context.Context, id string, in RestoreInput, actor string) (RestoreResult, error) {
	if ctx == nil {
		return RestoreResult{}, ErrInvalid
	}
	if !validRestoreInput(in, actor) {
		return RestoreResult{}, ErrInvalid
	}
	r, dbs, err := s.beginRestore(ctx, id, in)
	if err != nil {
		return RestoreResult{}, err
	}
	defer s.endInstall(id)
	in.Databases = dbs
	s.backupMu.Lock()
	defer s.backupMu.Unlock()
	work, cancel := backupContext(ctx, backupTimeout)
	defer cancel()
	t, err := s.configuredTarget()
	if err != nil {
		return RestoreResult{}, err
	}
	if err = s.cleanBackupLeftovers(work); err != nil {
		return RestoreResult{}, err
	}
	op, err := randomID()
	if err != nil {
		return RestoreResult{}, err
	}
	l := backupLeftover{Op: op, Users: map[string]string{}}
	for _, db := range dbs {
		if l.Users[db], err = restoreUserName(); err != nil {
			return RestoreResult{}, err
		}
	}
	if err = s.recordLeftover(l); err != nil {
		return RestoreResult{}, err
	}
	defer s.finishLeftover(l)
	if err = s.backup.Restore(work, t, r, in, l); err != nil {
		return RestoreResult{}, err
	}
	return RestoreResult{Snapshot: in.Snapshot, Files: in.Files, Databases: dbs}, nil
}

// beginRestore checks the account under the broker lock and marks it busy:
// the copy and the import run as the site user, so a delete, suspend, web
// change or WordPress install waits (409) until the restore ends.
func (s *store) beginRestore(ctx context.Context, id string, in RestoreInput) (record, []string, error) {
	if snapshotReentry(ctx, s) {
		return record{}, nil, ErrConflict
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if !idPattern.MatchString(id) {
		return record{}, nil, ErrInvalid
	}
	if s.backup == nil {
		return record{}, nil, ErrUnavailable
	}
	items, err := s.mutationReady(ctx)
	if err != nil {
		return record{}, nil, err
	}
	names := make([]string, 0, len(items))
	for _, r := range items {
		names = append(names, r.Account.Username)
	}
	for _, r := range items {
		if r.Account.ID != id {
			continue
		}
		dbs, ok := accountDatabases(in.Databases, r.Account.Username, names)
		if !ok {
			return record{}, nil, ErrInvalid
		}
		if r.Account.Revision != in.ExpectedRevision || r.Account.State != "active" && r.Account.State != "suspended" || s.installing[id] {
			return record{}, nil, ErrConflict
		}
		if s.native.Verify(ctx, r) != nil {
			return record{}, nil, ErrConflict
		}
		if s.installing == nil {
			s.installing = map[string]bool{}
		}
		s.installing[id] = true
		return r, dbs, nil
	}
	return record{}, nil, ErrNotFound
}

// drillAccount restores the account's latest snapshot into a root-only
// staging folder, compares it with the snapshot and checks part of the
// repository. It never touches the account. A drill that cannot run, or
// finds a difference, answers Passed false with the step.
func (s *store) drillAccount(ctx context.Context, id string, in DrillInput, actor string) (DrillResult, error) {
	if ctx == nil {
		return DrillResult{}, ErrInvalid
	}
	if !validText(in.Reason, 500) || !validText(actor, 120) {
		return DrillResult{}, ErrInvalid
	}
	r, _, err := s.backupReady(ctx, id)
	if err != nil {
		return DrillResult{}, err
	}
	s.backupMu.Lock()
	defer s.backupMu.Unlock()
	work, cancel := backupContext(ctx, backupTimeout)
	defer cancel()
	now := time.Now().UTC()
	failed := func(err error) (DrillResult, error) {
		var step *BackupError
		if !errors.As(err, &step) {
			return DrillResult{}, err
		}
		return DrillResult{AccountID: id, CheckedAt: now, Subset: drillSubset(now), Step: step.Step, Detail: step.Detail}, nil
	}
	t, err := s.configuredTarget()
	if err != nil {
		return failed(err)
	}
	if err = s.cleanBackupLeftovers(work); err != nil {
		return DrillResult{}, err
	}
	op, err := randomID()
	if err != nil {
		return DrillResult{}, err
	}
	l := backupLeftover{Op: op}
	if err = s.recordLeftover(l); err != nil {
		return DrillResult{}, err
	}
	defer s.finishLeftover(l)
	result, err := s.backup.Drill(work, t, r, l, now)
	if err != nil {
		return failed(err)
	}
	return result, nil
}

func (s *store) pruneBackups(ctx context.Context, in PruneInput, actor string) (PruneResult, error) {
	if ctx == nil {
		return PruneResult{}, ErrInvalid
	}
	if !validText(in.Reason, 500) || !validText(actor, 120) {
		return PruneResult{}, ErrInvalid
	}
	if s.backup == nil {
		return PruneResult{}, ErrUnavailable
	}
	s.backupMu.Lock()
	defer s.backupMu.Unlock()
	work, cancel := backupContext(ctx, backupTimeout)
	defer cancel()
	t, err := s.configuredTarget()
	if err != nil {
		return PruneResult{}, err
	}
	if err = s.cleanBackupLeftovers(work); err != nil {
		return PruneResult{}, err
	}
	return s.backup.Prune(work, t)
}
