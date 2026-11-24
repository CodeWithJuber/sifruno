package hostaccounts

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	bolt "go.etcd.io/bbolt"
)

// cronBucket holds each account's scheduled jobs, keyed by account ID: a
// map from a job set's digest to its jobs. It holds the installed set (the
// record's Cron) and, while a cron operation is unfinished, the set it
// installs (its pending target), so the record itself stays small.
var cronBucket = []byte("hostaccounts-cron-v1")

// maxCronSetsValue bounds one account's entry: two sets of at most
// maxCronLines of job text, which JSON may write six bytes to the byte.
const maxCronSetsValue = 512 << 10

// siteToolsSystem is the native side of scheduled jobs, logs and usage.
type siteToolsSystem interface {
	// SetCron makes the account's crontab exactly content, written beside
	// its target and renamed; nil removes it. It writes nothing in the home.
	// An error means the installed crontab was not changed: the rename or
	// unlink is its last step, and nothing after it can fail.
	SetCron(ctx context.Context, r record, content []byte) error
	// VerifyCron is nil when the installed crontab is exactly content (for
	// nil: there is none), ErrRecovery when it differs (the account's user
	// can rewrite its own crontab with cronie's setuid crontab),
	// ErrConflict when the object there is one SetCron would not replace,
	// and ErrUnavailable when the crontab directory cannot be used.
	VerifyCron(r record, content []byte) error
	// TailLog reads the end of a site's access or error log.
	TailLog(ctx context.Context, site, kind string) (LogTail, error)
	// QuotaUsage reads the XFS user quota of these account UIDs.
	QuotaUsage(ctx context.Context, uids []int) (map[int]quotaUsage, error)
	// SiteLogDir opens a site's log directory for the traffic counter, or
	// answers errNoLogs when it does not exist yet. The caller closes it.
	SiteLogDir(site string) (siteLogDir, error)
	// LoadUsageState, SaveUsageState and RemoveUsageState keep a site's
	// traffic counter in a root-only file of its own; Load answers nil for
	// none.
	LoadUsageState(id string) ([]byte, error)
	SaveUsageState(id string, b []byte) error
	RemoveUsageState(id string) error
}

// siteLogDir is a log directory the caller must close.
type siteLogDir interface {
	logDir
	Close() error
}

func (s *store) cronSets(id string) (map[string][]CronJob, error) {
	sets := map[string][]CronJob{}
	err := s.db.View(func(tx *bolt.Tx) error {
		b := tx.Bucket(cronBucket)
		if b == nil {
			return nil
		}
		v := b.Get([]byte(id))
		if v == nil {
			return nil
		}
		if len(v) > maxCronSetsValue || json.Unmarshal(v, &sets) != nil {
			return ErrRecovery
		}
		return nil
	})
	if err != nil {
		return nil, ErrRecovery
	}
	return sets, nil
}

func (s *store) putCronSets(id string, sets map[string][]CronJob) error {
	raw, err := json.Marshal(sets)
	if err != nil || len(raw) > maxCronSetsValue {
		return ErrUnavailable
	}
	return s.db.Update(func(tx *bolt.Tx) error {
		b, e := tx.CreateBucketIfNotExists(cronBucket)
		if e != nil {
			return e
		}
		if len(sets) == 0 {
			return b.Delete([]byte(id))
		}
		return b.Put([]byte(id), raw)
	})
}

// cronJobs is the job set an account's records name by digest: none for
// the empty set, otherwise the stored set, which must still be admissible
// and hash to the same digest.
func (s *store) cronJobs(id, digest string) ([]CronJob, error) {
	if digest == "" || digest == emptyCronDigest {
		return nil, nil
	}
	sets, err := s.cronSets(id)
	if err != nil {
		return nil, err
	}
	jobs, ok := sets[digest]
	if !ok || len(jobs) == 0 || !validCronJobs(jobs) || cronDigest(jobs) != digest {
		return nil, ErrRecovery
	}
	return jobs, nil
}

// installedCron is the record's value for a job set: its digest, or empty
// for no jobs.
func installedCron(jobs []CronJob) string {
	if len(jobs) == 0 {
		return ""
	}
	return cronDigest(jobs)
}

// settleCron keeps only the installed set once an operation is done. A
// failure leaves an extra set behind, which nothing reads.
func (s *store) settleCron(id string, jobs []CronJob) {
	sets := map[string][]CronJob{}
	if len(jobs) > 0 {
		sets[cronDigest(jobs)] = jobs
	}
	_ = s.putCronSets(id, sets)
}

func cronResult(a Account, jobs []CronJob) CronResult {
	now := time.Now()
	return CronResult{Account: a, Jobs: cronEntries(jobs, now), ServerTime: now.Format(time.RFC3339)}
}

// recordByID finds one account's record. The caller holds mu.
func (s *store) recordByID(id string) (record, error) {
	items, err := s.records()
	if err != nil {
		return record{}, err
	}
	for _, r := range items {
		if r.Account.ID == id {
			return r, nil
		}
	}
	return record{}, ErrNotFound
}

// cron lists an account's installed jobs with their next runs. It reads the
// broker's own records only and changes nothing, so neither another
// account's unfinished operation nor the account's own stops it; with the
// account's own pending, the state reads recovery_required.
func (s *store) cron(ctx context.Context, id string) (CronResult, error) {
	if snapshotReentry(ctx, s) {
		return CronResult{}, ErrConflict
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if ctx == nil || !idPattern.MatchString(id) {
		return CronResult{}, ErrInvalid
	}
	if s.healthy() != nil {
		return CronResult{}, ErrUnavailable
	}
	r, err := s.recordByID(id)
	if err != nil {
		return CronResult{}, err
	}
	jobs, err := s.cronJobs(id, r.Cron)
	if err != nil {
		return CronResult{}, ErrRecovery
	}
	a := r.Account
	if r.Pending != nil {
		a.State = "recovery_required"
	}
	return cronResult(a, jobs), nil
}

// setCron replaces an account's scheduled jobs. The checks come first and
// change nothing: the input, every other account settled (mutationReady),
// the revision, the account's identity (only what root controls: the
// crontab is outside the home, so a tenant's own folders cannot stop it)
// and a usable crontab directory with nothing at the crontab's name that
// the write would refuse. Then the new set is stored, the intent journaled,
// and the crontab written. A write that failed changed nothing (SetCron's
// rename is its last step), so it ends rejected, unchanged (503
// unavailable); nothing the account's own user does can leave the change
// pending. Only a crash or a failed journal write does, and the next start
// finishes it from the stored set.
func (s *store) setCron(ctx context.Context, id string, in CronInput, actor string) (CronResult, error) {
	if snapshotReentry(ctx, s) {
		return CronResult{}, ErrConflict
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if !idPattern.MatchString(id) || !validCronInput(in, actor) {
		return CronResult{}, ErrInvalid
	}
	items, err := s.mutationReady(ctx)
	if err != nil {
		return CronResult{}, err
	}
	var r record
	found := false
	for _, item := range items {
		if item.Account.ID == id {
			r, found = item, true
			break
		}
	}
	if !found {
		return CronResult{}, ErrNotFound
	}
	if r.Account.Revision != in.ExpectedRevision {
		return CronResult{}, ErrConflict
	}
	current, err := s.cronJobs(id, r.Cron)
	if err != nil {
		return CronResult{}, ErrRecovery
	}
	next := append([]CronJob(nil), in.Jobs...)
	digest := cronDigest(next)
	// An unchanged set is a no-op only while the installed crontab still
	// holds it; one edited outside the broker is rewritten through the
	// journaled path, which also moves the revision on.
	switch e := s.native.VerifyCron(r, renderCrontab(current)); {
	case errors.Is(e, ErrUnavailable), errors.Is(e, ErrConflict), errors.Is(e, ErrInvalid):
		return CronResult{}, e
	case e == nil && digest == cronDigest(current):
		return cronResult(r.Account, current), nil
	}
	if r.Account.Revision == ^uint64(0) {
		return CronResult{}, ErrRecovery
	}
	// Two history rows, with room left as historyRoom leaves it for the
	// operations a tenant can reach.
	if !historyRoom(r, operationRows, false) {
		return CronResult{}, ErrConflict
	}
	if s.native.VerifyAccount(ctx, r) != nil {
		return CronResult{}, ErrConflict
	}
	sets := map[string][]CronJob{}
	if len(current) > 0 {
		sets[r.Cron] = current
	}
	if len(next) > 0 {
		sets[digest] = next
	}
	if s.putCronSets(id, sets) != nil {
		return CronResult{}, ErrUnavailable
	}
	operationID, e := randomID()
	if e != nil {
		return CronResult{}, e
	}
	r.Pending = &pending{Action: "cron", Target: digest, Actor: actor, Reason: in.Reason, OperationID: operationID}
	before := r.Account
	after := r.Account
	after.Revision++
	r, err = s.appendEvent(r, operationEvent{OperationID: operationID, Action: "cron", Status: "intended", Actor: actor, Reason: in.Reason, Before: &before, After: after})
	if err != nil {
		return CronResult{}, ErrRecovery
	}
	if e := s.native.SetCron(ctx, r, renderCrontab(next)); e != nil {
		operation := *r.Pending
		r.Pending = nil
		if _, e := s.resultEvent(r, operation, "rejected"); e != nil {
			return CronResult{}, ErrRecovery
		}
		return CronResult{}, ErrUnavailable
	}
	operation := *r.Pending
	r.Pending = nil
	r.Cron = installedCron(next)
	r.Account.Revision++
	r.Account.UpdatedAt = time.Now().UTC()
	r.Actor, r.Reason = actor, in.Reason
	if _, e := s.resultEvent(r, operation, "succeeded"); e != nil {
		return CronResult{}, ErrRecovery
	}
	s.settleCron(id, next)
	return cronResult(r.Account, next), nil
}

// reconcileCron finishes an interrupted cron operation at start: the set
// was stored before the intent, and writing it is idempotent. Only what
// root controls is checked, so a tenant cannot keep it pending. A missing
// set, a failed check or write stay pending for the next start or a
// person: the broker does not guess. Only a failed journal write is an
// error.
func (s *store) reconcileCron(ctx context.Context, r record) error {
	jobs, err := s.cronJobs(r.Account.ID, r.Pending.Target)
	if err != nil {
		return nil
	}
	current := r
	current.Pending = nil
	if s.native.VerifyAccount(ctx, current) != nil || s.native.SetCron(ctx, r, renderCrontab(jobs)) != nil {
		return nil
	}
	operation := *r.Pending
	r.Pending = nil
	r.Cron = installedCron(jobs)
	r.Account.Revision++
	r.Account.UpdatedAt = time.Now().UTC()
	r.Actor, r.Reason = operation.Actor, operation.Reason
	if _, e := s.resultEvent(r, operation, "reconciled"); e != nil {
		return ErrRecovery
	}
	s.settleCron(r.Account.ID, jobs)
	return nil
}

// ---- Logs and usage ---------------------------------------------------------

// Logs and usage only read: root-owned logs outside every home, and quota
// numbers. They depend on nothing an operation changes halfway, so no
// pending record, the account's own included, stops them, and they hold
// the broker lock only to read the records. They need the web operation:
// it admits xfs_quota and knows the web server's user, which owns the logs.

// siteLog returns the end of a site's access or error log.
func (s *store) siteLog(ctx context.Context, id, kind string) (LogTail, error) {
	if snapshotReentry(ctx, s) {
		return LogTail{}, ErrConflict
	}
	if ctx == nil || !idPattern.MatchString(id) || logFileNames[kind] == "" {
		return LogTail{}, ErrInvalid
	}
	if _, err := s.usageTargets(id); err != nil {
		return LogTail{}, err
	}
	return s.native.TailLog(ctx, siteName(id), kind)
}

type usageTarget struct {
	id  string
	uid int
}

// usageTargets lists the accounts a usage read covers: one, or all.
func (s *store) usageTargets(only string) ([]usageTarget, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.healthy() != nil || s.web == nil {
		return nil, ErrUnavailable
	}
	items, err := s.records()
	if err != nil {
		return nil, err
	}
	out := []usageTarget{}
	for _, r := range items {
		if only == "" || r.Account.ID == only {
			out = append(out, usageTarget{id: r.Account.ID, uid: r.Account.UID})
		}
	}
	if only != "" && len(out) == 0 {
		return nil, ErrNotFound
	}
	return out, nil
}

// siteUsage is one account's usage, with the whole traffic budget.
func (s *store) siteUsage(ctx context.Context, id string) (SiteUsage, error) {
	if ctx == nil || !idPattern.MatchString(id) {
		return SiteUsage{}, ErrInvalid
	}
	items, err := s.usage(ctx, id)
	if err != nil {
		return SiteUsage{}, err
	}
	return items[0], nil
}

// usageAll is every account's usage, the traffic budget shared out.
func (s *store) usageAll(ctx context.Context) ([]SiteUsage, error) {
	if ctx == nil {
		return nil, ErrInvalid
	}
	return s.usage(ctx, "")
}

// minSiteBudget is the least traffic budget one site gets in a read of
// every site, so a site with a long backlog cannot starve the others.
const minSiteBudget = 4 << 20

// usage reads disk use with one xfs_quota run and brings each site's
// traffic counter up to date within the budget. Usage reads run one at a
// time (usageMu), outside mu; a counter is saved under mu, and only while
// its account still exists, so a delete meanwhile, which removes the
// counter under mu, leaves none behind.
func (s *store) usage(ctx context.Context, only string) ([]SiteUsage, error) {
	if snapshotReentry(ctx, s) {
		return nil, ErrConflict
	}
	s.usageMu.Lock()
	defer s.usageMu.Unlock()
	targets, err := s.usageTargets(only)
	if err != nil {
		return nil, err
	}
	uids := make([]int, len(targets))
	for i, t := range targets {
		uids[i] = t.uid
	}
	quotas, err := s.native.QuotaUsage(ctx, uids)
	if err != nil {
		return nil, ErrUnavailable
	}
	now := time.Now()
	left := int64(trafficBudget)
	share := max(left/int64(max(len(targets), 1)), minSiteBudget)
	saved := map[string][]byte{}
	out := make([]SiteUsage, 0, len(targets))
	for _, t := range targets {
		q := quotas[t.uid]
		u := SiteUsage{AccountID: t.id, DiskUsedKiB: q.UsedKiB, DiskLimitKiB: q.HardKiB, TrafficMonth: now.Format("2006-01")}
		raw, _ := s.native.LoadUsageState(t.id)
		st, _ := decodeTrafficState(raw)
		dir, err := s.native.SiteLogDir(siteName(t.id))
		switch {
		case errors.Is(err, errNoLogs):
			u.TrafficComplete = true
		case err != nil:
		default:
			next, read, complete, cerr := countTraffic(st, dir, now, min(share, left))
			_ = dir.Close()
			left -= read
			st, u.TrafficComplete = next, complete && cerr == nil
			if b, e := json.Marshal(next); e == nil && string(b) != string(raw) {
				saved[t.id] = b
			}
		}
		if st.Month == u.TrafficMonth {
			u.TrafficBytes = st.Bytes
		}
		out = append(out, u)
	}
	if len(saved) > 0 {
		// The writes run outside mu, so a read of many sites does not hold
		// every other request; a delete meanwhile removes its counter under
		// mu, and the second look removes one this read wrote after it.
		before := s.accountIDs()
		for id, b := range saved {
			if before[id] {
				_ = s.native.SaveUsageState(id, b)
			}
		}
		s.mu.Lock()
		if items, err := s.records(); err == nil {
			now := make(map[string]bool, len(items))
			for _, r := range items {
				now[r.Account.ID] = true
			}
			for id := range saved {
				if before[id] && !now[id] {
					_ = s.native.RemoveUsageState(id)
				}
			}
		}
		s.mu.Unlock()
	}
	return out, nil
}

// accountIDs is the set of accounts the broker holds now, empty when the
// records cannot be read.
func (s *store) accountIDs() map[string]bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	ids := map[string]bool{}
	if items, err := s.records(); err == nil {
		for _, r := range items {
			ids[r.Account.ID] = true
		}
	}
	return ids
}

// removeUsageState takes a deleted account's traffic counter away. Like
// removeSiteCache it cannot change the delete's answer: a counter left
// behind is a small root-only file under an ID no account gets again.
func (s *store) removeUsageState(id string) {
	_ = s.native.RemoveUsageState(id)
}
