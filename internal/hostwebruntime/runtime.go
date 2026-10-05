// Package hostwebruntime implements an unactivated, root-installed Linux
// stop/start executor. It creates no accounts, mounts, certificates or services.
package hostwebruntime

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"path"
	"regexp"
	"sort"
	"time"

	"sifruno/internal/hostaccounts"
	"sifruno/internal/hostweb"
	"sifruno/internal/hostwebgeneration"
)

var (
	ErrInvalid     = errors.New("invalid web runtime input")
	ErrUnavailable = errors.New("native Linux web runtime unavailable")
	ErrConflict    = errors.New("web runtime identity changed")
	ErrRecovery    = errors.New("web runtime recovery required")
	ErrLimit       = errors.New("web runtime bound reached")
)

const (
	MaxGenerations     = 16
	MaxRuntimeAccounts = 8
	MaxMetadataBytes   = 512 << 10
	MaxProcesses       = 1 + 2*MaxRuntimeAccounts
	MaxGroupMembers    = 64
	OperationTimeout   = 25 * time.Second
	CleanupTimeout     = 3 * time.Second
)

// Options is a trusted installation input, never an operator HTTP request.
// Root already exists, is private/root-owned and contains every writable
// profile root. Binaries/modules are separately admitted read-only inputs.
type Options struct {
	Root    string
	Profile hostweb.Profile
}

type processPin struct {
	Role, AccountID              string
	PID                          int
	Start, Boot                  string
	Executable                   string
	ExecutableSHA256             string
	Config                       string
	Namespace                    uint64
	ExecutableDev, ExecutableIno uint64
}

type transaction struct {
	OperationID   string
	Revision      uint64
	Before, After hostwebgeneration.Generation
	Target        hostwebgeneration.Generation
	ApplyIntent   *hostwebgeneration.ApplyCompletionBinding `json:",omitempty"`
}

type record struct {
	Version         int
	Revision        uint64
	LastOperation   string
	Current         hostwebgeneration.Generation
	Pending         *transaction
	Processes       []processPin
	InputsSHA256    string
	BootID          string                 `json:",omitempty"`
	Repair          *nativeRepair          `json:",omitempty"`
	CompletedRepair *nativeCompletion      `json:",omitempty"`
	CompletedApply  *nativeApplyCompletion `json:",omitempty"`
}

var idPattern = regexp.MustCompile(`^[a-f0-9]{32}$`)
var hex64 = regexp.MustCompile(`^[a-f0-9]{64}$`)
var decimal = regexp.MustCompile(`^[1-9][0-9]{0,19}$`)
var bootPattern = regexp.MustCompile(`^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$`)

func hash(data []byte) string { v := sha256.Sum256(data); return hex.EncodeToString(v[:]) }
func digest(v any) string     { data, _ := json.Marshal(v); return hash(data) }
func inside(root, p string) bool {
	return p != root && path.IsAbs(p) && path.Clean(p) == p && len(p) <= 240 && len(root) > 1 && len(p) > len(root) && p[:len(root)+1] == root+"/"
}
func copyGeneration(g hostwebgeneration.Generation) hostwebgeneration.Generation {
	g.Accounts = append([]hostaccounts.Account{}, g.Accounts...)
	g.Bundle.Files = append([]hostweb.File(nil), g.Bundle.Files...)
	for i := range g.Bundle.Files {
		g.Bundle.Files[i].Data = append([]byte(nil), g.Bundle.Files[i].Data...)
	}
	return g
}

func validateOptions(o Options) error {
	if o.Root == "/" || !path.IsAbs(o.Root) || path.Clean(o.Root) != o.Root || len(o.Root) > 160 {
		return ErrInvalid
	}
	p := o.Profile
	for _, v := range []string{p.ManagedRoot, p.ManagedHomeRoot, p.FrontChroot, p.BackendChrootRoot, p.RuntimeRoot, p.TLSRoot} {
		if !inside(o.Root, v) {
			return ErrInvalid
		}
	}
	// This first executor supports only an explicit loopback listener. Exposure
	// and TLS termination are separate installation/peer-boundary decisions.
	if p.FrontendIP != "127.0.0.1" || p.FrontendPort == 0 || p.BackendPort != hostweb.DefaultBackendPort || p.FrontUID == 0 || p.FrontGID == 0 || p.ControllerUID == 0 {
		return ErrInvalid
	}
	_, err := hostweb.Compile(p, nil)
	if err != nil {
		return ErrInvalid
	}
	return nil
}

func validateGeneration(p hostweb.Profile, g hostwebgeneration.Generation, bootstrap bool) error {
	if (g.ID == "") != bootstrap || (!bootstrap && !idPattern.MatchString(g.ID)) || (bootstrap && !g.Denied) || len(g.Accounts) > MaxRuntimeAccounts {
		return ErrInvalid
	}
	accounts := append([]hostaccounts.Account{}, g.Accounts...)
	sort.Slice(accounts, func(i, j int) bool { return accounts[i].ID < accounts[j].ID })
	// Stored canonical ordering is part of the account digest/CAS contract.
	for i, a := range accounts {
		if a != g.Accounts[i] || a.CreatedAt.IsZero() || a.UpdatedAt.Before(a.CreatedAt) {
			return ErrInvalid
		}
	}
	if digest(p) != g.ProfileSHA256 || digest(accounts) != g.SnapshotSHA256 {
		return ErrInvalid
	}
	render := append([]hostaccounts.Account{}, accounts...)
	if g.Denied {
		for i := range render {
			render[i].State = "suspended"
		}
	}
	want, err := hostweb.Compile(p, render)
	if err != nil || g.Bundle.Validate() != nil || !equalBundle(want, g.Bundle) {
		return ErrInvalid
	}
	return nil
}

func equalBundle(a, b hostweb.Bundle) bool {
	if a.Profile != b.Profile || a.SHA256 != b.SHA256 || len(a.Files) != len(b.Files) {
		return false
	}
	for i, x := range a.Files {
		y := b.Files[i]
		if x.Path != y.Path || x.Mode != y.Mode || x.SHA256 != y.SHA256 || !bytes.Equal(x.Data, y.Data) {
			return false
		}
	}
	return true
}
func generationPath(g hostwebgeneration.Generation) string {
	if g.ID == "" {
		return "generations/bootstrap-" + g.SnapshotSHA256
	}
	return "generations/" + g.ID
}
func bounded(ctx context.Context) (context.Context, context.CancelFunc, error) {
	if ctx == nil {
		return nil, nil, ErrInvalid
	}
	if err := ctx.Err(); err != nil {
		return nil, nil, err
	}
	c, cancel := context.WithTimeout(ctx, OperationTimeout)
	return c, cancel, nil
}

func validateRecord(p hostweb.Profile, r record) error {
	if r.Version != 1 || validateGeneration(p, r.Current, r.Current.ID == "") != nil || len(r.Processes) > MaxProcesses {
		return ErrRecovery
	}
	if r.Revision > 0 && !idPattern.MatchString(r.LastOperation) || r.Revision == 0 && r.LastOperation != "" {
		return ErrRecovery
	}
	if r.Pending != nil {
		t := r.Pending
		causal := t.Revision == r.Revision || t.Revision != ^uint64(0) && t.Revision+1 == r.Revision && r.LastOperation == t.OperationID && r.Current.Identity() == t.After.Identity()
		if !causal || t.Revision == ^uint64(0) || t.Before.ID == t.After.ID || !idPattern.MatchString(t.OperationID) || validateGeneration(p, t.Before, t.Before.ID == "") != nil || validateGeneration(p, t.After, false) != nil || validateGeneration(p, t.Target, t.Target.ID == "") != nil {
			return ErrRecovery
		}
		if !t.Target.Denied && t.Target.Identity() != t.After.Identity() && (t.Target.Identity() != t.Before.Identity() || t.Before.SnapshotSHA256 != t.After.SnapshotSHA256) {
			return ErrRecovery
		}
		if r.Current.Identity() != t.Before.Identity() && r.Current.Identity() != t.After.Identity() && r.Current.Identity() != t.Target.Identity() {
			return ErrRecovery
		}
	}
	allowed := map[string]string{}
	add := func(g hostwebgeneration.Generation) {
		base := path.Join(p.ManagedRoot, generationPath(g))
		allowed[path.Join(base, "apache/front.conf")] = "front:"
		for _, a := range g.Accounts {
			if a.State == "active" && !g.Denied {
				allowed[path.Join(base, "apache/backends/"+a.ID+".conf")] = "backend:" + a.ID
				allowed[path.Join(base, "fpm/"+a.ID+".conf")] = "fpm:" + a.ID
			}
		}
	}
	add(r.Current)
	if r.Pending != nil {
		add(r.Pending.Before)
		add(r.Pending.After)
		add(r.Pending.Target)
	}
	if r.Repair != nil {
		add(r.Repair.Request.Target)
		for _, g := range r.Repair.Retained {
			add(g)
		}
	}
	seen := map[string]bool{}
	seenPID := map[int]bool{}
	seenNS := map[uint64]bool{}
	for _, v := range r.Processes {
		key := v.Role + ":" + v.AccountID
		if seen[key] || seenPID[v.PID] || seenNS[v.Namespace] || v.PID <= 1 || !decimal.MatchString(v.Start) || !bootPattern.MatchString(v.Boot) || !hex64.MatchString(v.ExecutableSHA256) || v.Namespace == 0 || v.ExecutableIno == 0 || allowed[v.Config] != key {
			return ErrRecovery
		}
		seen[key] = true
		seenPID[v.PID] = true
		seenNS[v.Namespace] = true
		if v.Role == "front" {
			if v.AccountID != "" || v.Executable != p.ApacheBinary {
				return ErrRecovery
			}
		} else if (v.Role == "backend" || v.Role == "fpm") && idPattern.MatchString(v.AccountID) {
			if v.Role == "backend" && v.Executable != p.ApacheBinary || v.Role == "fpm" && v.Executable != p.FPMBinary {
				return ErrRecovery
			}
		} else {
			return ErrRecovery
		}
		if !inside(p.ManagedRoot, v.Config) {
			return ErrRecovery
		}
	}
	return validateRecoveryRecord(p, r)
}
