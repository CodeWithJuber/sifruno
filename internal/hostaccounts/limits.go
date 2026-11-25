package hostaccounts

import (
	"context"
	"errors"
	"fmt"
	"strconv"
)

// AccountLimits bound what all of an account's processes may use together,
// wherever they start: an SFTP session, a cron job, the site's PHP. The
// broker writes them as a systemd drop-in for the account's user slice,
// /etc/systemd/system/user-<uid>.slice.d/50-sifruno-limits.conf, and renders
// the memory and process numbers into the site's lsphp app (see webSites).
// The installer's pam_limits file bounds nproc for every account UID too
// (README, Resource limits).
type AccountLimits struct {
	// Processes is the slice's TasksMax: tasks (each thread counts) of the
	// whole account. The site's lsphp app gets it as procHardLimit, raised to
	// the floor OpenLiteSpeed keeps (olsweb.ProcessFloor).
	Processes int `json:"processes"`
	// MemoryMiB is the slice's MemoryMax: memory of the whole account, page
	// cache included; past it the kernel's OOM killer acts inside the slice.
	// The lsphp app gets it as memHardLimit (RLIMIT_AS of each process).
	MemoryMiB int `json:"memory_mib"`
	// CPUPercent is the slice's CPUQuota: 100 is one CPU's full time.
	CPUPercent int `json:"cpu_percent"`
}

// DefaultLimits are a new account's limits, and those of an account made
// before limits were recorded. They suit one server with a few hundred to
// two thousand small sites: a small PHP site runs about five tasks (lsphp
// and its 4 children), an SFTP session two or three, WP-CLI one or two, so
// 100 tasks leave room for bursts while a fork loop stops early; 1 GiB
// holds 4 PHP workers at PHP's usual 128 MiB memory_limit, the opcache and
// page cache; one CPU keeps one busy site from taking a many-core server.
// They are caps, not reservations: the sum may exceed the server.
var DefaultLimits = AccountLimits{Processes: 100, MemoryMiB: 1024, CPUPercent: 100}

// Bounds a plan's limits must stay within. The lowest process count still
// runs a site's PHP, an SFTP session and WP-CLI at once; the memory bounds
// are those olsweb accepts for an lsphp app.
const (
	minLimitProcesses  = 32
	maxLimitProcesses  = 4096
	minLimitMemoryMiB  = 256
	maxLimitMemoryMiB  = 65536
	minLimitCPUPercent = 10
	maxLimitCPUPercent = 6400
)

// limitsDropIn is the broker's file in an account's slice drop-in directory.
// systemd parses every drop-in of user-<uid>.slice by file name, so 50-
// comes after the vendor's user-.slice.d/10-defaults.conf (TasksMax=33%).
const limitsDropIn = "50-sifruno-limits.conf"

func (l AccountLimits) given() bool { return l != AccountLimits{} }

func validLimits(l AccountLimits) bool {
	return l.Processes >= minLimitProcesses && l.Processes <= maxLimitProcesses &&
		l.MemoryMiB >= minLimitMemoryMiB && l.MemoryMiB <= maxLimitMemoryMiB &&
		l.CPUPercent >= minLimitCPUPercent && l.CPUPercent <= maxLimitCPUPercent
}

// limitsOf is the limits an account has: its recorded ones, or the defaults
// for an account recorded before limits were.
func limitsOf(a Account) AccountLimits {
	if a.Limits.given() {
		return a.Limits
	}
	return DefaultLimits
}

// recordLimits is what the record's account should run with now: a plan
// change in flight counts as done, as a web change in flight does in
// webSites.
func recordLimits(r record) AccountLimits {
	if r.Pending != nil && r.Pending.Action == "plan" && r.LimitsNext.given() {
		return r.LimitsNext
	}
	return limitsOf(r.Account)
}

// validLimitUID admits only a UID the broker allocates to accounts: never
// root, a system user or anything outside the account range.
func validLimitUID(uid int) bool { return uid >= firstAccountID && uid <= lastAccountID }

// sliceDropInDir is the drop-in directory of the account's user slice,
// relative to /etc/systemd/system, built only from a UID in the account
// range.
func sliceDropInDir(uid int) (string, error) {
	if !validLimitUID(uid) {
		return "", ErrInvalid
	}
	return "user-" + strconv.Itoa(uid) + ".slice.d", nil
}

// renderSliceLimits is the drop-in's whole content.
func renderSliceLimits(l AccountLimits) ([]byte, error) {
	if !validLimits(l) {
		return nil, ErrInvalid
	}
	return fmt.Appendf(nil, "# Written by the Sifruno broker for one hosting account. Do not edit:\n# the broker rewrites it when the account's plan changes and at its start.\n[Slice]\nTasksMax=%d\nMemoryMax=%dM\nCPUQuota=%d%%\n", l.Processes, l.MemoryMiB, l.CPUPercent), nil
}

// errLimitsRejected is the store's answer when an account's slice drop-in
// could not be written or systemd not reloaded: the old drop-in went back
// and the plan change ends rejected with the account unchanged.
var errLimitsRejected = errors.New("account limits not applied")

// applyPlanLimits applies a pending plan change's limits, items[i] being its
// record: the account's slice drop-in first, then, for a live site whose
// limits changed, the site list, so its PHP gets them. A drop-in that cannot
// be written or loaded answers errLimitsRejected, a site list whose config
// fails its test ErrWebRejected; either way the old drop-in is put back.
// Any other site list failure is returned as is and leaves the new drop-in.
// It runs under the web operation's own limit, not the caller's.
func (s *store) applyPlanLimits(ctx context.Context, items []record, i int, old, next AccountLimits) error {
	uid := items[i].Account.UID
	applyCtx, cancel := webContext(ctx)
	defer cancel()
	if s.native.ApplyLimits(applyCtx, uid, next) != nil {
		s.restoreLimits(ctx, uid, old)
		return errLimitsRejected
	}
	if !items[i].Web.enabled() || next == old {
		return nil
	}
	e := s.applySites(ctx, items, items[i].Account.ID)
	if errors.Is(e, ErrWebRejected) {
		s.restoreLimits(ctx, uid, old)
	}
	return e
}

// restoreLimits puts an account's recorded limits back after a rejected
// plan change. Its own failure does not change the answer: the drop-in is
// root's file for this account's slice alone, systemd keeps the limits it
// last loaded, and the broker writes every account's recorded limits again
// at its next start (syncLimitsAtStart) and at the account's next plan
// change, so one account's drop-in never holds up another account. It has
// its own limit: a site list that took most of the previous one must not
// leave it no time.
func (s *store) restoreLimits(ctx context.Context, uid int, old AccountLimits) {
	restoreCtx, cancel := webContext(ctx)
	defer cancel()
	_ = s.native.ApplyLimits(restoreCtx, uid, old)
}

// syncLimitsAtStart writes every account's recorded limits to its slice
// drop-in, removes the drop-ins of UIDs no account holds (a delete whose
// removal failed), and reloads systemd once if anything changed. It runs
// once before the broker's socket accepts requests, so accounts made before
// limits were recorded get DefaultLimits and a drop-in changed outside the
// broker is put right. It changes no record, so nothing is journaled.
func (s *store) syncLimitsAtStart(ctx context.Context) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	items, err := s.records()
	if err != nil {
		return err
	}
	want := make(map[int]AccountLimits, len(items))
	for _, r := range items {
		want[r.Account.UID] = recordLimits(r)
	}
	return s.native.SyncLimits(ctx, want)
}
