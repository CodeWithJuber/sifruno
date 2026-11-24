package hostaccounts

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	bolt "go.etcd.io/bbolt"
	"sifruno/internal/olsweb"
	"sifruno/internal/securestate"
)

type fileIdentity struct {
	Dev uint64 `json:"dev"`
	Ino uint64 `json:"ino"`
}
type ownership struct {
	Home   fileIdentity `json:"home"`
	Public fileIdentity `json:"public"`
	Marker fileIdentity `json:"marker"`
}
type pending struct {
	Action      string `json:"action"`
	Target      string `json:"target"`
	Actor       string `json:"actor"`
	Reason      string `json:"reason"`
	OperationID string `json:"operation_id"`
}
type record struct {
	Version         int       `json:"version"`
	Account         Account   `json:"account"`
	Tag             string    `json:"tag"`
	Ownership       ownership `json:"ownership"`
	Pending         *pending  `json:"pending,omitempty"`
	Actor           string    `json:"actor"`
	Reason          string    `json:"reason"`
	HistorySequence uint64    `json:"history_sequence"`
	// HistoryStart is the sequence of the checkpoint a compacted history
	// starts at (journal.go); 0 for a history never compacted, which starts
	// at the create, sequence 1. Left out when 0, so a record written before
	// compaction existed reads the same.
	HistoryStart uint64 `json:"history_start,omitempty"`
	// SSHKeys is the installed canonical key set, one key per line. SSHKeysNext
	// is the set an unfinished ssh_keys operation is installing; it is durable
	// before the key file is touched so a restart can finish the same write.
	// Both are strings so a record stays comparable for snapshot leases.
	SSHKeys     string `json:"ssh_keys,omitempty"`
	SSHKeysNext string `json:"ssh_keys_next,omitempty"`
	// Web is the live site's settings (empty: no site). WebNext is what an
	// unfinished web operation applies, durable before anything changes.
	Web     WebState `json:"web"`
	WebNext WebState `json:"web_next"`
	// TLS is the site's installed certificate (empty: none); Account.Certificate
	// always equals it. TLSNext is what an unfinished certificate operation
	// installs; its files were staged before the intent was journaled.
	TLS     CertificateState `json:"tls"`
	TLSNext CertificateState `json:"tls_next"`
	// LimitsNext is what an unfinished plan operation applies (empty: the
	// limits stay), durable before the slice drop-in changes.
	LimitsNext AccountLimits `json:"limits_next,omitzero"`
	// Cron is the digest of the installed scheduled jobs (empty: none). The
	// jobs are in the cron bucket under that digest, so a record stays
	// small; an unfinished cron operation's jobs are there too, under its
	// pending target, before the crontab changes (store_sitetools.go).
	Cron string `json:"cron,omitempty"`
	// Domains is the live site's aliases and redirects in canonical form
	// (empty: none; see encodeSiteDomains). DomainsNext is what an
	// unfinished domains operation installs, durable before the config
	// changes. Strings, so a record stays comparable.
	Domains     string `json:"domains,omitempty"`
	DomainsNext string `json:"domains_next,omitempty"`
	// Folders is a migrated site's protected folders in canonical form
	// (empty: none; see encodeFolders in folders.go). FoldersNext is what an
	// unfinished folders operation installs, durable before the config
	// changes and after its realm user files were written.
	Folders     string `json:"folders,omitempty"`
	FoldersNext string `json:"folders_next,omitempty"`
}

// maxRecordBytes bounds one stored record: the account, the SFTP keys, two
// sets of site domains (the recorded one and one being installed) and two
// sets of protected folders; only one operation is pending at a time.
const maxRecordBytes = 224 << 10

type nativeSystem interface {
	// siteToolsSystem writes crontabs and reads logs, quotas and traffic
	// counters (sitetools_linux.go).
	siteToolsSystem
	Plan(context.Context, string) (int, int, error)
	Create(context.Context, record, func(ownership) error) (ownership, error)
	RecoverCreate(context.Context, record, func(ownership) error) (ownership, error)
	// VerifyAccountIdentity checks, from files alone, what only root can
	// change: the passwd and group identity, the home directory object and
	// its owner, and the ownership marker. VerifyAccount adds the
	// password-lock and expiry observation. A failure of either is a
	// conflict that stops every mutation.
	VerifyAccountIdentity(record) error
	VerifyAccount(context.Context, record) error
	// VerifySiteFiles checks what the account's own user can change: the
	// home's mode and the public_html recorded at create. A failure concerns
	// that account alone.
	VerifySiteFiles(record) error
	// VerifyIdentity is VerifyAccountIdentity and VerifySiteFiles; Verify
	// adds the lock and expiry observation. Operations that write into the
	// tenant's folders use these.
	VerifyIdentity(record) error
	Verify(context.Context, record) error
	// SetSSHKeys installs exactly this canonical key set; empty removes it.
	SetSSHKeys(context.Context, record, []string) error
	// VerifySSHKeys reports whether the installed key file holds exactly this
	// set (for the empty set: that no file exists).
	VerifySSHKeys(record, []string) error
	// GrantWebAccess lets the web server read the account's site, on the
	// home and public_html recorded at create; it is idempotent and touches
	// nothing else.
	GrantWebAccess(context.Context, record) error
	// AdoptPublicHTML returns the identity of the account's current
	// public_html, opened without following links from the recorded home,
	// after setting both to mode 0750 through those handles. ErrConflict:
	// public_html is missing, a link, not a directory, not the account's,
	// or on another filesystem; nothing changed.
	AdoptPublicHTML(context.Context, record) (fileIdentity, error)
	// InstallPlaceholder writes the placeholder index.php into the live
	// site's public_html as the account's user, only if the folder is
	// empty, and reports whether it wrote it; it changes only the tenant's
	// files.
	InstallPlaceholder(context.Context, record) (bool, error)
	// ApplyWeb sets the account's quota and installs the full site list:
	// written, tested, reloaded. A failed test restores the old files and
	// the previous quota and returns ErrWebRejected. It must be safe to
	// repeat, and it does not depend on the tenant's files. tenantBroken
	// names vhosts whose test reports must not decide the change (see
	// store.tenantBroken); the same holds for ApplySites and
	// ApplyCertificate.
	ApplyWeb(ctx context.Context, r record, previous, next WebState, sites []olsweb.Site, tenantBroken map[string]bool) error
	// ApplySites installs the full site list only, tested and reloaded.
	ApplySites(ctx context.Context, sites []olsweb.Site, tenantBroken map[string]bool) error
	// StageCertificate writes a checked chain and key as the site's staged
	// pair, root-only, where OpenLiteSpeed does not read them; with both
	// empty it removes the staged pair. It touches no tenant file.
	StageCertificate(ctx context.Context, r record, chainPEM, keyPEM []byte) error
	// ApplyCertificate installs the staged pair, which must be the one named
	// by next, as the site's live certificate files and installs the full
	// site list: written, tested, reloaded. A failed test restores the old
	// files and returns ErrWebRejected. It must be safe to repeat.
	ApplyCertificate(ctx context.Context, r record, next CertificateState, sites []olsweb.Site, tenantBroken map[string]bool) error
	// InstallWordPress runs WP-CLI as the account's user into its live
	// site; it changes only the tenant's files.
	InstallWordPress(context.Context, record, WordPressInput) (WordPressResult, error)
	// RunFiles runs the file helper (FilesHelper) as the account's user,
	// in its home, in a transient unit in the account's slice: stdin is its
	// request, its answer goes to stdout. It returns nil only when the
	// helper exited 0. Root opens nothing in the home.
	RunFiles(ctx context.Context, r record, stdin io.Reader, stdout io.Writer) error
	// Delete removes the managed system identity and owned home after
	// ownership verification; it must be safe to retry after a crash. It
	// ends the account's processes first. errAccountBusy: userdel still
	// refused the user as busy, and nothing changed. errNothingRemoved: it
	// stopped for another reason before userdel ran, and nothing changed.
	Delete(context.Context, record) error
	// EndProcesses ends every process that runs as the account's user, by
	// signalling as that user, never as root. errAccountBusy: some were
	// still running after its last pass. It changes no record.
	EndProcesses(context.Context, record) error
	SetState(context.Context, record, string) error
	// ApplyLimits writes the account's user slice drop-in with these limits
	// and reloads systemd. The UID must be in the account range and not the
	// controller's. It touches no tenant file and is safe to repeat.
	ApplyLimits(ctx context.Context, uid int, l AccountLimits) error
	// VerifyLimits reports whether the drop-in holds exactly these limits.
	VerifyLimits(uid int, l AccountLimits) error
	// RemoveLimits removes the account's drop-in and reloads systemd.
	RemoveLimits(ctx context.Context, uid int) error
	// RemoveSiteCache removes a deleted site's LSCache store and everything
	// in it, without following a link. A store that is not there is no
	// error.
	RemoveSiteCache(ctx context.Context, id string) error
	// WriteSiteRealms makes the site's directory in olsweb.RealmRoot hold
	// exactly these realm user files (path: bytes), root's own and readable
	// by the web server user alone, written without following a link.
	WriteSiteRealms(ctx context.Context, site string, files map[string][]byte) error
	// RemoveSiteRealms removes the site's directory in olsweb.RealmRoot and
	// everything in it, without following a link. None there is no error.
	RemoveSiteRealms(ctx context.Context, site string) error
	// SyncLimits makes the drop-ins match want, one per account UID, removes
	// the broker's drop-in of every other account-range UID, and reloads
	// systemd once if anything changed.
	SyncLimits(ctx context.Context, want map[int]AccountLimits) error
	GuardState(string) error
	GuardHomes([]record) error
}
type store struct {
	mu     sync.Mutex
	db     *bolt.DB
	opts   BrokerOptions
	web    *WebOptions // nil: the web operation is off
	native nativeSystem
	closed bool
	// installing holds accounts with a WordPress install or a restore
	// running outside the lock; delete refuses them while their user's
	// processes run.
	installing map[string]bool
	// fileRuns counts each account's file operations running outside the
	// lock (store_files.go); they never make the account busy.
	fileRuns map[string]int
	// backup runs restic and the database tools (nil: off). backupMu lets
	// one backup operation run at a time, outside mu, so a long backup
	// holds no other account.
	backup   backupEngine
	backupMu sync.Mutex
	// backupKeyMu guards making the backup key and password, so reading
	// the backup status never waits for backupMu.
	backupKeyMu sync.Mutex
	// migrate holds migrations' keys and runs their programs (nil: off).
	// migrateMu lets one migration operation read or change migration
	// records and the source at a time; a copy holds it only while it
	// reads the source, then takes backupMu, as a restore does.
	migrate   migrateEngine
	migrateMu sync.Mutex
	// usageMu lets one usage read run at a time, outside mu: it reads logs,
	// which takes a moment, and keeps each site's traffic counter.
	usageMu sync.Mutex
	// auditAfter is the ID of the last account the rotating full check
	// reached. Keying the rotation on an ID, not a position, keeps it fair
	// while accounts are created and deleted between requests.
	auditAfter string
	// compactAt is the number of rows at which a settled account's history
	// is compacted: historyCompactAt; 0 (tests only) turns compaction off
	// to exercise the limits behind it.
	compactAt uint64
}

// auditBatch is how many accounts each refresh verifies in full (identity
// plus the password-lock and expiry observation, two processes per account).
// Every account still gets the file-only identity check on every refresh.
// Full verification of all accounts on every request is what limited the
// broker to about a hundred accounts; a rotating batch keeps drift detection
// while the cost per request stays fixed.
const auditBatch = 16

// The broker gives each account one ID, its UID and its GID, from this range
// (Plan). A record outside it is refused as damaged, and no process runs with
// an account's credential outside it.
const (
	firstAccountID = 20000
	lastAccountID  = 60000
)

// errAccountBusy is the native answer when processes of the account were
// still running after the broker ended them; for a delete, userdel refused
// the user and nothing changed.
var errAccountBusy = errors.New("account processes still running")

// errNothingRemoved is the native answer when a delete stopped for another
// reason before userdel changed anything (a /proc read or kill failed, or
// time ran out) and the account was put back as it was.
var errNothingRemoved = errors.New("delete stopped before anything was removed")

var accountBucket = []byte("hostaccounts-v1")
var configBucket = []byte("hostbroker-config-v1")

func openStore(ctx context.Context, opts BrokerOptions, system nativeSystem) (*store, error) {
	if ctx == nil || system == nil {
		return nil, ErrInvalid
	}
	if ensureBrokerDir(opts.StateDir) != nil {
		return nil, ErrUnavailable
	}
	dir, err := securestate.Dir(opts.StateDir)
	if err != nil {
		return nil, ErrUnavailable
	}
	opts.StateDir = dir
	if system.GuardState(dir) != nil {
		return nil, ErrUnavailable
	}
	db, err := bolt.Open(filepath.Join(dir, "hostaccounts.db"), 0600, &bolt.Options{Timeout: time.Second})
	if err != nil {
		return nil, ErrUnavailable
	}
	s := &store{db: db, opts: opts, native: system, compactAt: historyCompactAt}
	ok := false
	defer func() {
		if !ok {
			db.Close()
		}
	}()
	err = db.Update(func(tx *bolt.Tx) error {
		b, e := tx.CreateBucketIfNotExists(accountBucket)
		if e != nil {
			return e
		}
		if b.Stats().KeyN > MaxAccounts {
			return ErrRecovery
		}
		cfg, e := tx.CreateBucketIfNotExists(configBucket)
		if e != nil {
			return e
		}
		if _, e = tx.CreateBucketIfNotExists(historyBucket); e != nil {
			return e
		}
		want, _ := json.Marshal(opts)
		if old := cfg.Get([]byte("options")); old != nil {
			var actual BrokerOptions
			if json.Unmarshal(old, &actual) != nil || actual != opts {
				return ErrRecovery
			}
		} else {
			if b.Stats().KeyN != 0 {
				return ErrRecovery
			}
			if e = cfg.Put([]byte("options"), want); e != nil {
				return e
			}
		}
		return nil
	})
	if err != nil {
		return nil, ErrRecovery
	}
	if system.GuardState(dir) != nil {
		return nil, ErrUnavailable
	}
	if err = s.refresh(ctx, true); err != nil {
		return nil, err
	}
	ok = true
	return s, nil
}
func (s *store) close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil
	}
	s.closed = true
	if s.db.Close() != nil {
		return ErrUnavailable
	}
	return nil
}
func (s *store) healthy() error {
	if s.closed || s.native.GuardState(s.opts.StateDir) != nil {
		return ErrUnavailable
	}
	return nil
}
func (s *store) records() ([]record, error) {
	out := []record{}
	err := s.db.View(func(tx *bolt.Tx) error {
		b := tx.Bucket(accountBucket)
		if b == nil {
			return ErrRecovery
		}
		return b.ForEach(func(key, value []byte) error {
			if len(out) >= MaxAccounts || value == nil || len(value) > maxRecordBytes {
				return ErrRecovery
			}
			var r record
			if json.Unmarshal(value, &r) != nil || r.Version != 1 || !idPattern.MatchString(r.Account.ID) || string(key) != r.Account.ID || !validUsername(r.Account.Username) || !validDomain(r.Account.Domain) || r.Account.UID < firstAccountID || r.Account.UID > lastAccountID || r.Account.GID != r.Account.UID || r.Account.Revision == 0 || r.Tag != "sifruno-managed-"+r.Account.ID || r.Account.Home != filepath.Join(s.opts.HomesDir, r.Account.Username) || r.Account.PublicHTML != filepath.Join(r.Account.Home, "public_html") || r.Account.CreatedAt.IsZero() || r.Account.UpdatedAt.IsZero() || (r.Account.State != "active" && r.Account.State != "suspended" && r.Account.State != "recovery_required") {
				return ErrRecovery
			}
			if r.Pending != nil {
				validAction := r.Pending.Action == "create" || r.Pending.Action == "state" || r.Pending.Action == "conflict" || r.Pending.Action == "plan" || r.Pending.Action == "delete" || r.Pending.Action == "ssh_keys" || r.Pending.Action == "web" || r.Pending.Action == "certificate" || r.Pending.Action == "adopt" || r.Pending.Action == "cron" || r.Pending.Action == "domains" || r.Pending.Action == "folders"
				validTarget := false
				switch r.Pending.Action {
				case "create", "state", "conflict":
					validTarget = r.Pending.Target == "active" || r.Pending.Target == "suspended"
				case "plan":
					validTarget = validText(r.Pending.Target, 64)
				case "delete":
					validTarget = r.Pending.Target == ""
				case "ssh_keys":
					validTarget = sshDigestPattern.MatchString(r.Pending.Target) && canonicalSSHKeys(r.SSHKeysNext) && r.Pending.Target == sshKeysDigest(splitSSHKeys(r.SSHKeysNext))
				case "web":
					validTarget = webDigestPattern.MatchString(r.Pending.Target) && validWebState(r.WebNext) && r.Pending.Target == webDigest(r.WebNext)
				case "certificate":
					validTarget = certificateDigestPattern.MatchString(r.Pending.Target) && validCertificateState(r.TLSNext) && r.Pending.Target == certificateDigest(r.TLSNext)
				case "adopt":
					_, validTarget = parsePublicTarget(r.Pending.Target)
				case "cron":
					validTarget = cronDigestPattern.MatchString(r.Pending.Target)
				case "domains":
					validTarget = domainsDigestPattern.MatchString(r.Pending.Target) && validStoredDomains(r.Account.Domain, r.DomainsNext) && r.Pending.Target == domainsDigest(r.DomainsNext)
				case "folders":
					validTarget = foldersDigestPattern.MatchString(r.Pending.Target) && r.FoldersNext != "" && validStoredFolders(r.Account.ID, r.FoldersNext) && r.Pending.Target == foldersDigest(r.FoldersNext)
				}
				if !idPattern.MatchString(r.Pending.OperationID) || !validText(r.Pending.Actor, 120) || !validText(r.Pending.Reason, 500) || !validAction || !validTarget {
					return ErrRecovery
				}
			}
			if !canonicalSSHKeys(r.SSHKeys) || (r.SSHKeysNext != "" && (r.Pending == nil || r.Pending.Action != "ssh_keys")) {
				return ErrRecovery
			}
			if (r.Web.enabled() && !validWebState(r.Web)) || (!r.Web.enabled() && r.Web != WebState{}) || (r.WebNext != WebState{} && (r.Pending == nil || r.Pending.Action != "web")) || r.Account.Web != (WebState{}) || r.Account.SiteFolderChanged {
				return ErrRecovery
			}
			if (r.TLS.installed() && !validCertificateState(r.TLS)) || (!r.TLS.installed() && r.TLS != CertificateState{}) || r.Account.Certificate != r.TLS || (r.TLSNext != CertificateState{} && (r.Pending == nil || r.Pending.Action != "certificate")) {
				return ErrRecovery
			}
			if (r.Account.Limits.given() && !validLimits(r.Account.Limits)) || (r.LimitsNext.given() && (!validLimits(r.LimitsNext) || r.Pending == nil || r.Pending.Action != "plan")) {
				return ErrRecovery
			}
			if r.Cron != "" && (!cronDigestPattern.MatchString(r.Cron) || r.Cron == emptyCronDigest) {
				return ErrRecovery
			}
			// Like Web, the list fills SiteDomains in; a stored account never
			// carries it.
			if !validStoredDomains(r.Account.Domain, r.Domains) || (r.DomainsNext != "" && (r.Pending == nil || r.Pending.Action != "domains")) || r.Account.SiteDomains != nil {
				return ErrRecovery
			}
			if !validStoredFolders(r.Account.ID, r.Folders) || (r.FoldersNext != "" && (r.Pending == nil || r.Pending.Action != "folders")) {
				return ErrRecovery
			}
			if verifyHistory(tx, r) != nil {
				return ErrRecovery
			}
			out = append(out, r)
			return nil
		})
	})
	if err != nil {
		return nil, ErrRecovery
	}
	return out, nil
}
func (s *store) save(r record) error {
	b, err := json.Marshal(r)
	if err != nil {
		return ErrRecovery
	}
	// As appendEvent: records() would refuse it, and with it every account.
	if len(b) > maxRecordBytes {
		return ErrInvalid
	}
	if s.db.Update(func(tx *bolt.Tx) error { return tx.Bucket(accountBucket).Put([]byte(r.Account.ID), b) }) != nil {
		return ErrRecovery
	}
	return nil
}
func (s *store) refresh(ctx context.Context, reconcile bool) error {
	items, err := s.records()
	if err != nil {
		return err
	}
	if s.native.GuardHomes(items) != nil {
		return ErrRecovery
	}
	seenNames, seenDomains, seenUID := map[string]bool{}, map[string]bool{}, map[int]bool{}
	audited, last := s.nextAudit(items)
	for i, r := range items {
		if seenNames[r.Account.Username] || seenDomains[r.Account.Domain] || seenUID[r.Account.UID] {
			return ErrRecovery
		}
		seenNames[r.Account.Username] = true
		seenDomains[r.Account.Domain] = true
		seenUID[r.Account.UID] = true
		if ctx.Err() != nil {
			return ErrUnavailable
		}
		if r.Pending != nil {
			if !reconcile || r.Pending.Action == "conflict" {
				continue
			}
			if r.Pending.Action == "create" {
				owned, e := s.native.RecoverCreate(ctx, r, func(owned ownership) error { r.Ownership = owned; return s.save(r) })
				if e != nil {
					continue
				}
				r.Ownership = owned
			} else if r.Pending.Action == "web" {
				// Finish the interrupted web write: the settings were durable
				// before anything changed, and applying them is idempotent. A
				// config that now fails its test ends as rejected, unchanged;
				// any other failure stays pending for the next start.
				operation := *r.Pending
				applyCtx, cancel := webContext(ctx)
				e := s.native.ApplyWeb(applyCtx, r, r.Web, r.WebNext, webSites(items, ""), s.tenantBroken(items, r.Account.ID))
				cancel()
				switch {
				case errors.Is(e, ErrWebRejected):
					r.Pending, r.WebNext = nil, WebState{}
					if _, e := s.resultEvent(r, operation, "rejected"); e != nil {
						return ErrRecovery
					}
					continue
				case e != nil:
					continue
				}
				r.Web, r.WebNext = r.WebNext, WebState{}
				r.Account.Revision++
				r.Account.UpdatedAt = time.Now().UTC()
				r.Actor, r.Reason = r.Pending.Actor, r.Pending.Reason
				r.Pending = nil
				if _, e := s.resultEvent(r, operation, "reconciled"); e != nil {
					return ErrRecovery
				}
				continue
			} else if r.Pending.Action == "certificate" {
				// Finish the interrupted install from the staged pair, which
				// was durable before the intent: installing it is idempotent.
				// A config that now fails its test ends as rejected, unchanged;
				// any other failure, a missing or different staged pair
				// included, stays pending for the next start.
				operation := *r.Pending
				applyCtx, cancel := webContext(ctx)
				e := s.native.ApplyCertificate(applyCtx, r, r.TLSNext, webSites(items, ""), s.tenantBroken(items, r.Account.ID))
				cancel()
				switch {
				case errors.Is(e, ErrWebRejected):
					r.Pending, r.TLSNext = nil, CertificateState{}
					if _, e := s.resultEvent(r, operation, "rejected"); e != nil {
						return ErrRecovery
					}
					s.discardStagedCertificate(r)
					continue
				case e != nil:
					continue
				}
				r.TLS, r.TLSNext = r.TLSNext, CertificateState{}
				r.Account.Certificate = r.TLS
				r.Account.Revision++
				r.Account.UpdatedAt = time.Now().UTC()
				r.Actor, r.Reason = r.Pending.Actor, r.Pending.Reason
				r.Pending = nil
				if _, e := s.resultEvent(r, operation, "reconciled"); e != nil {
					return ErrRecovery
				}
				s.discardStagedCertificate(r)
				continue
			} else if r.Pending.Action == "ssh_keys" {
				// Finish the interrupted key write: the target set was durable
				// before the file was touched, and installing it is idempotent.
				// The key file is outside the home, so only what root controls
				// is checked: the tenant's own folders cannot hold it pending.
				current := r
				current.Pending = nil
				if s.native.VerifyAccount(ctx, current) != nil || s.native.SetSSHKeys(ctx, r, splitSSHKeys(r.SSHKeysNext)) != nil {
					continue
				}
				operation := *r.Pending
				r.SSHKeys, r.SSHKeysNext = r.SSHKeysNext, ""
				r.Account.Revision++
				r.Account.UpdatedAt = time.Now().UTC()
				r.Actor, r.Reason = r.Pending.Actor, r.Pending.Reason
				r.Pending = nil
				if _, e := s.resultEvent(r, operation, "reconciled"); e != nil {
					return ErrRecovery
				}
				continue
			} else if r.Pending.Action == "cron" {
				// Finish the interrupted crontab write from the journaled set
				// (store_sitetools.go); a failure stays pending.
				if s.reconcileCron(ctx, r) != nil {
					return ErrRecovery
				}
				continue
			} else if r.Pending.Action == "adopt" {
				// Metadata only: record the directory the intent named.
				if s.finishAdopt(r) != nil {
					return ErrRecovery
				}
				continue
			} else if r.Pending.Action == "domains" {
				if s.finishDomains(ctx, items, r) != nil {
					return ErrRecovery
				}
				continue
			} else if r.Pending.Action == "folders" {
				if s.finishFolders(ctx, items, r) != nil {
					return ErrRecovery
				}
				continue
			} else if r.Pending.Action == "plan" {
				// Finish the interrupted plan change: its limits were durable
				// before the slice drop-in changed, and applying them is
				// idempotent. Only what root controls is checked, so a
				// tenant's own folders cannot keep it pending. A drop-in or
				// site list that cannot take the new limits ends it rejected,
				// unchanged; any other failure stays pending for the next
				// start. A plan change journaled by an earlier broker has no
				// limits and keeps the account's.
				current := r
				current.Pending = nil
				if s.native.VerifyAccount(ctx, current) != nil {
					continue
				}
				operation := *r.Pending
				switch e := s.applyPlanLimits(ctx, items, i, limitsOf(r.Account), recordLimits(r)); {
				case errors.Is(e, errLimitsRejected) || errors.Is(e, ErrWebRejected):
					r.Pending, r.LimitsNext = nil, AccountLimits{}
					if _, e := s.resultEvent(r, operation, "rejected"); e != nil {
						return ErrRecovery
					}
					continue
				case e != nil:
					continue
				}
				r.Account.Plan = operation.Target
				if r.LimitsNext.given() {
					r.Account.Limits = r.LimitsNext
				}
				r.LimitsNext = AccountLimits{}
				r.Account.Revision++
				r.Account.UpdatedAt = time.Now().UTC()
				r.Actor, r.Reason = operation.Actor, operation.Reason
				r.Pending = nil
				if _, e := s.resultEvent(r, operation, "reconciled"); e != nil {
					return ErrRecovery
				}
				continue
			} else if s.native.VerifyAccount(ctx, targetRecord(r, r.Pending.Target)) != nil {
				// A state change whose account verifies in its old state
				// changed nothing: the broker stopped before the account
				// changed, or after a rejected site list put it back and
				// before that was journaled. It ends rejected, unchanged,
				// so it does not block every account. Like the state change
				// itself, this checks only what root controls.
				current := r
				current.Pending = nil
				if r.Pending.Action == "state" && s.native.VerifyAccount(ctx, current) == nil {
					operation := *r.Pending
					r.Pending = nil
					if _, e := s.resultEvent(r, operation, "rejected"); e != nil {
						return ErrRecovery
					}
				}
				continue
			}
			if r.Pending.Action == "delete" {
				operation := *r.Pending
				if r.Web.enabled() {
					switch e := s.applySitesWithout(ctx, items, r.Account.ID); {
					case errors.Is(e, ErrWebRejected):
						r.Pending = nil
						if _, e := s.resultEvent(r, operation, "rejected"); e != nil {
							return ErrRecovery
						}
						continue
					case e != nil:
						continue
					}
				}
				if e := s.native.Delete(ctx, r); e != nil {
					// A delete that stopped before userdel changed anything (a
					// busy user, a failed /proc read, time run out) ends
					// rejected, as in delete: the site goes back and nothing
					// else changed. Any other failure keeps the record and
					// retries on the next refresh; an uncertain destructive
					// effect is never force-closed.
					if errors.Is(e, errAccountBusy) || errors.Is(e, errNothingRemoved) {
						live := append([]record(nil), items...)
						live[i].Pending = nil
						if r.Web.enabled() && s.applySites(ctx, live, "") != nil {
							continue
						}
						r.Pending = nil
						if _, e := s.resultEvent(r, operation, "rejected"); e != nil {
							return ErrRecovery
						}
					}
					continue
				}
				s.removeLimits(ctx, r.Account.UID)
				s.removeSiteCache(ctx, r.Account.ID)
				s.removeSiteRealms(ctx, r.Account.ID)
				if _, e := s.resultEvent(r, operation, "reconciled"); e != nil {
					return ErrRecovery
				}
				if e := s.purge(r.Account.ID); e != nil {
					return ErrRecovery
				}
				s.removeUsageState(r.Account.ID)
				continue
			}
			if r.Pending.Action == "state" && r.Web.enabled() {
				// Finish the interrupted suspend or resume of a live site: the
				// account is in its new state (verified above), and installing
				// the site list is idempotent. A config that now fails its
				// test puts the account back and ends as rejected, unchanged;
				// any other failure stays pending for the next start.
				switch e := s.applySites(ctx, items, r.Account.ID); {
				case errors.Is(e, ErrWebRejected):
					if s.undoState(ctx, r) != nil {
						continue
					}
					operation := *r.Pending
					r.Pending = nil
					if _, e := s.resultEvent(r, operation, "rejected"); e != nil {
						return ErrRecovery
					}
					continue
				case e != nil:
					continue
				}
			}
			operation := *r.Pending
			r.Account.State = r.Pending.Target
			r.Account.UpdatedAt = time.Now().UTC()
			if r.Pending.Action == "state" {
				r.Account.Revision++
			}
			r.Actor, r.Reason = r.Pending.Actor, r.Pending.Reason
			r.Pending = nil
			if _, e := s.resultEvent(r, operation, "reconciled"); e != nil {
				return ErrRecovery
			}
			continue
		}
		// Only what root controls makes a conflict, which stops every
		// mutation. A tenant's own changes to its home or public_html are
		// not checked here: they concern that account alone, which the
		// account list shows (SiteFolderChanged) and the operations that
		// write into those folders check for themselves.
		var e error
		if audited(i) {
			e = s.native.VerifyAccount(ctx, r)
		} else {
			e = s.native.VerifyAccountIdentity(r)
		}
		if e != nil {
			if errors.Is(e, ErrUnavailable) {
				return ErrUnavailable
			}
			before := r.Account
			r.Pending = &pending{Action: "conflict", Target: r.Account.State, Actor: "broker-reconcile", Reason: "Managed operating system identity changed"}
			r, e = s.beginOperation(r, &before)
			if e != nil {
				return ErrRecovery
			}
			if _, e = s.resultEvent(r, *r.Pending, "recovery_required"); e != nil {
				return ErrRecovery
			}
		}
	}
	s.auditAfter = last
	return nil
}
func targetRecord(r record, state string) record { r.Account.State = state; return r }

// nextAudit picks this refresh's full-verification batch: the auditBatch
// accounts after the last one audited, in ID order, wrapping around. It
// returns the ID to resume after; refresh stores it only once the whole
// pass has run, so an aborted pass is repeated rather than skipped. With
// auditBatch accounts or fewer every account is in the batch, which is the
// behaviour the broker had before the account bound was raised.
func (s *store) nextAudit(items []record) (func(int) bool, string) {
	n := len(items)
	if n <= auditBatch {
		return func(int) bool { return true }, ""
	}
	start := sort.Search(n, func(i int) bool { return items[i].Account.ID > s.auditAfter })
	if start == n {
		start = 0
	}
	last := items[(start+auditBatch-1)%n].Account.ID
	return func(i int) bool { return (i-start+n)%n < auditBatch }, last
}

// A stored key set is the canonical lines joined by newlines; the empty
// string is the empty set.
func joinSSHKeys(canonical []string) string { return strings.Join(canonical, "\n") }
func splitSSHKeys(stored string) []string {
	if stored == "" {
		return nil
	}
	return strings.Split(stored, "\n")
}

// canonicalSSHKeys reports whether a stored set is exactly what
// normalizeSSHKeys would produce, so a record never carries a line the
// admission rules would refuse.
func canonicalSSHKeys(stored string) bool {
	canonical, _, ok := normalizeSSHKeys(splitSSHKeys(stored))
	return ok && joinSSHKeys(canonical) == stored
}

func (s *store) sshKeys(ctx context.Context, id string) (SSHKeysResult, error) {
	if snapshotReentry(ctx, s) {
		return SSHKeysResult{}, ErrConflict
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	if ctx == nil || !idPattern.MatchString(id) {
		return SSHKeysResult{}, ErrInvalid
	}
	if s.healthy() != nil {
		return SSHKeysResult{}, ErrUnavailable
	}
	if s.refresh(ctx, false) != nil {
		return SSHKeysResult{}, ErrRecovery
	}
	items, err := s.records()
	if err != nil {
		return SSHKeysResult{}, err
	}
	for _, r := range items {
		if r.Account.ID != id {
			continue
		}
		_, keys, ok := normalizeSSHKeys(splitSSHKeys(r.SSHKeys))
		if !ok {
			return SSHKeysResult{}, ErrRecovery
		}
		a := r.Account
		if r.Pending != nil {
			a.State = "recovery_required"
		}
		return SSHKeysResult{Account: a, Keys: keys}, nil
	}
	return SSHKeysResult{}, ErrNotFound
}

// setSSHKeys replaces the account's SFTP key set. The intent and the target
// set are journaled before the key file changes, the touched account is
// verified in full first, and an interrupted write is finished by refresh.
func (s *store) setSSHKeys(ctx context.Context, id string, in SSHKeysInput, actor string) (SSHKeysResult, error) {
	if snapshotReentry(ctx, s) {
		return SSHKeysResult{}, ErrConflict
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	canonical, keys, ok := normalizeSSHKeys(in.Keys)
	if !idPattern.MatchString(id) || !ok || in.ExpectedRevision == 0 || !validText(in.Reason, 500) || !validText(actor, 120) {
		return SSHKeysResult{}, ErrInvalid
	}
	items, err := s.mutationReady(ctx)
	if err != nil {
		return SSHKeysResult{}, err
	}
	var r record
	found := false
	for _, item := range items {
		if item.Account.ID == id {
			r = item
			found = true
			break
		}
	}
	if !found {
		return SSHKeysResult{}, ErrNotFound
	}
	if r.Account.Revision != in.ExpectedRevision {
		return SSHKeysResult{}, ErrConflict
	}
	// An unchanged set is a no-op only while the installed file still holds
	// it. A file edited or removed outside the broker is rewritten through
	// the ordinary journaled path, which also moves the revision on.
	if r.SSHKeys == joinSSHKeys(canonical) && s.native.VerifySSHKeys(r, canonical) == nil {
		return SSHKeysResult{Account: r.Account, Keys: keys}, nil
	}
	if r.Account.Revision == ^uint64(0) {
		return SSHKeysResult{}, ErrRecovery
	}
	// Two history rows, with room left as historyRoom leaves it for the
	// operations a tenant can reach, so the result can always be journaled.
	if !historyRoom(r, operationRows, false) {
		return SSHKeysResult{}, ErrConflict
	}
	current := r
	r.Pending = &pending{Action: "ssh_keys", Target: sshKeysDigest(canonical), Actor: actor, Reason: in.Reason}
	r.SSHKeysNext = joinSSHKeys(canonical)
	before := r.Account
	operationID, e := randomID()
	if e != nil {
		return SSHKeysResult{}, e
	}
	r.Pending.OperationID = operationID
	after := r.Account
	after.Revision++
	intent := operationEvent{OperationID: operationID, Action: "ssh_keys", Status: "intended", Actor: actor, Reason: in.Reason, Before: &before, After: after}
	r, err = s.appendEvent(r, intent)
	if err != nil {
		return SSHKeysResult{}, ErrRecovery
	}
	// The key file is outside the home, so this checks only what root
	// controls: a tenant who changed its own folders can still get keys to
	// put them right, and cannot leave this operation pending.
	if s.native.VerifyAccount(ctx, current) != nil || s.native.SetSSHKeys(ctx, r, canonical) != nil {
		_, _ = s.resultEvent(r, *r.Pending, "recovery_required")
		return SSHKeysResult{}, ErrRecovery
	}
	r.SSHKeys, r.SSHKeysNext = joinSSHKeys(canonical), ""
	r.Account.Revision++
	r.Account.UpdatedAt = time.Now().UTC()
	r.Actor, r.Reason = actor, in.Reason
	operation := *r.Pending
	r.Pending = nil
	if _, e := s.resultEvent(r, operation, "succeeded"); e != nil {
		return SSHKeysResult{}, ErrRecovery
	}
	return SSHKeysResult{Account: r.Account, Keys: keys}, nil
}

// purge removes the account record key after a completed delete. Operation
// history rows are retained under the history bucket for audit; the account
// inventory no longer lists the identity.
func (s *store) purge(id string) error {
	if !idPattern.MatchString(id) {
		return ErrRecovery
	}
	if s.db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket(accountBucket)
		if b == nil {
			return ErrRecovery
		}
		if c := tx.Bucket(cronBucket); c != nil {
			if e := c.Delete([]byte(id)); e != nil {
				return e
			}
		}
		return b.Delete([]byte(id))
	}) != nil {
		return ErrRecovery
	}
	return nil
}

func (s *store) setPlan(ctx context.Context, id string, in PlanInput, actor string) (Account, error) {
	if snapshotReentry(ctx, s) {
		return Account{}, ErrConflict
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	if !idPattern.MatchString(id) || !validPlan(in, actor) {
		return Account{}, ErrInvalid
	}
	items, err := s.mutationReady(ctx)
	if err != nil {
		return Account{}, err
	}
	index := -1
	for i, item := range items {
		if item.Account.ID == id {
			index = i
			break
		}
	}
	if index < 0 {
		return Account{}, ErrNotFound
	}
	r := items[index]
	if r.Account.Revision != in.ExpectedRevision {
		return Account{}, ErrConflict
	}
	old := limitsOf(r.Account)
	next := old
	if in.Limits.given() {
		next = in.Limits
	}
	// An unchanged plan is a no-op only while the slice drop-in still holds
	// its limits. A drop-in edited or removed outside the broker, or an
	// account recorded before limits were, goes through the ordinary
	// journaled path, which writes the drop-in and moves the revision on.
	if r.Account.Plan == in.Plan && r.Account.Limits == next && s.native.VerifyLimits(r.Account.UID, next) == nil {
		return r.Account, nil
	}
	if r.Account.Revision == ^uint64(0) {
		return Account{}, ErrRecovery
	}
	// New limits reach a live site's PHP through the site list, which needs
	// the web operation, and would restart PHP under a running WordPress
	// install: both are refused before anything is journaled. Two history
	// rows, with room left as historyRoom leaves it for the operations a
	// tenant can reach.
	render := r.Web.enabled() && next != old
	if render && s.web == nil {
		return Account{}, ErrUnavailable
	}
	if (render && s.installing[id]) || !historyRoom(r, operationRows, false) {
		return Account{}, ErrConflict
	}
	r.Pending = &pending{Action: "plan", Target: in.Plan, Actor: actor, Reason: in.Reason}
	r.LimitsNext = next
	before := r.Account
	operationID, e := randomID()
	if e != nil {
		return Account{}, e
	}
	r.Pending.OperationID = operationID
	after := r.Account
	after.Plan = in.Plan
	after.Limits = next
	after.Revision++
	intent := operationEvent{OperationID: operationID, Action: "plan", Status: "intended", Actor: actor, Reason: in.Reason, Before: &before, After: after}
	r, err = s.appendEvent(r, intent)
	if err != nil {
		return Account{}, ErrRecovery
	}
	live := append([]record(nil), items...)
	live[index] = r
	switch e := s.applyPlanLimits(ctx, live, index, old, next); {
	case errors.Is(e, errLimitsRejected), errors.Is(e, ErrWebRejected):
		// The old drop-in and site list went back: the account is
		// unchanged and nothing holds up any other account.
		operation := *r.Pending
		r.Pending, r.LimitsNext = nil, AccountLimits{}
		if _, e := s.resultEvent(r, operation, "rejected"); e != nil {
			return Account{}, ErrRecovery
		}
		if errors.Is(e, ErrWebRejected) {
			return Account{}, ErrWebRejected
		}
		return Account{}, ErrUnavailable
	case e != nil:
		_, _ = s.resultEvent(r, *r.Pending, "recovery_required")
		return Account{}, ErrRecovery
	}
	r.Account.Plan = in.Plan
	r.Account.Limits, r.LimitsNext = next, AccountLimits{}
	r.Account.Revision++
	r.Account.UpdatedAt = time.Now().UTC()
	r.Actor, r.Reason = actor, in.Reason
	operation := *r.Pending
	r.Pending = nil
	if _, e := s.resultEvent(r, operation, "succeeded"); e != nil {
		return Account{}, ErrRecovery
	}
	return r.Account, nil
}

func (s *store) delete(ctx context.Context, id string, in DeleteInput, actor string) (Account, error) {
	if snapshotReentry(ctx, s) {
		return Account{}, ErrConflict
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	if !idPattern.MatchString(id) || !validDelete(in, actor) {
		return Account{}, ErrInvalid
	}
	items, err := s.mutationReady(ctx)
	if err != nil {
		return Account{}, err
	}
	var r record
	found := false
	for _, item := range items {
		if item.Account.ID == id {
			r = item
			found = true
			break
		}
	}
	if !found {
		return Account{}, ErrNotFound
	}
	// A running WordPress install keeps the user's processes alive, and
	// userdel refuses a user with running processes.
	if r.Account.Revision != in.ExpectedRevision || s.installing[id] {
		return Account{}, ErrConflict
	}
	// The delete's rows come out of the operator's room, which the
	// operations a tenant can reach leave free, so its result can always be
	// journaled.
	if !historyRoom(r, operationRows, true) {
		return Account{}, ErrConflict
	}
	r.Pending = &pending{Action: "delete", Target: "", Actor: actor, Reason: in.Reason}
	operationID, e := randomID()
	if e != nil {
		return Account{}, e
	}
	r.Pending.OperationID = operationID
	before := r.Account
	intent := operationEvent{OperationID: operationID, Action: "delete", Status: "intended", Actor: actor, Reason: in.Reason, Before: &before, After: r.Account}
	r, err = s.appendEvent(r, intent)
	if err != nil {
		return Account{}, ErrRecovery
	}
	// A live site leaves OpenLiteSpeed's config before its user and home go,
	// so the server never points at a missing user. If the config without it
	// fails its test, the old files went back and nothing changed: the delete
	// ends rejected and blocks nothing.
	if r.Web.enabled() {
		switch e := s.applySitesWithout(ctx, items, r.Account.ID); {
		case errors.Is(e, ErrWebRejected):
			operation := *r.Pending
			r.Pending = nil
			if _, e := s.resultEvent(r, operation, "rejected"); e != nil {
				return Account{}, ErrRecovery
			}
			return Account{}, ErrWebRejected
		case e != nil:
			_, _ = s.resultEvent(r, *r.Pending, "recovery_required")
			return Account{}, ErrRecovery
		}
	}
	// After the intent is journaled the removal runs on its own limit, so a
	// caller that gives up (or a slow site rewrite before it) does not leave
	// a half-removed user for recovery.
	removeCtx, cancel := webContext(ctx)
	e = s.native.Delete(removeCtx, r)
	cancel()
	if errors.Is(e, errAccountBusy) || errors.Is(e, errNothingRemoved) {
		// The native delete stopped before userdel changed anything and put
		// the account back: a process of the account was still running
		// after the broker ended them, or ending them failed or ran out of
		// time. The site goes back into the config (items lists the account
		// without its pending delete; applySites has its own limit) and the
		// delete ends rejected, the account unchanged: what the tenant does
		// holds up this delete only. If the site cannot go back, the delete
		// stays pending.
		if r.Web.enabled() && s.applySites(ctx, items, "") != nil {
			_, _ = s.resultEvent(r, *r.Pending, "recovery_required")
			return Account{}, ErrRecovery
		}
		operation := *r.Pending
		r.Pending = nil
		if _, err := s.resultEvent(r, operation, "rejected"); err != nil {
			return Account{}, ErrRecovery
		}
		if errors.Is(e, errAccountBusy) {
			return Account{}, ErrDeleteBusy
		}
		return Account{}, ErrDeleteStopped
	}
	if e != nil {
		_, _ = s.resultEvent(r, *r.Pending, "recovery_required")
		return Account{}, ErrRecovery
	}
	s.removeLimits(ctx, r.Account.UID)
	s.removeSiteCache(ctx, r.Account.ID)
	s.removeSiteRealms(ctx, r.Account.ID)
	operation := *r.Pending
	r.Pending = nil
	if _, e := s.resultEvent(r, operation, "succeeded"); e != nil {
		return Account{}, ErrRecovery
	}
	if e := s.purge(r.Account.ID); e != nil {
		return Account{}, ErrRecovery
	}
	s.removeUsageState(r.Account.ID)
	return before, nil
}

// removeLimits takes a deleted account's slice drop-in away once its user
// and processes are gone. The delete has succeeded by then and cannot be
// undone, so a failure does not change its answer: the drop-in names a UID
// no account holds, which the broker's next start removes
// (syncLimitsAtStart) and the next create of that UID rewrites.
func (s *store) removeLimits(ctx context.Context, uid int) {
	removeCtx, cancel := webContext(ctx)
	defer cancel()
	_ = s.native.RemoveLimits(removeCtx, uid)
}

// removeSiteCache takes a deleted site's LSCache store away, with the web
// operation on, once the site has left OpenLiteSpeed's config and its user
// is gone. Like removeLimits it cannot change the delete's answer: a store
// left behind holds only cached pages of a site no config names, under a
// name no new account gets, since account IDs are random.
func (s *store) removeSiteCache(ctx context.Context, id string) {
	if s.web == nil {
		return
	}
	removeCtx, cancel := webContext(ctx)
	defer cancel()
	_ = s.native.RemoveSiteCache(removeCtx, id)
}
func (s *store) capability(ctx context.Context) (Capability, error) {
	if snapshotReentry(ctx, s) {
		return Capability{}, ErrConflict
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	if ctx == nil {
		return Capability{}, ErrInvalid
	}
	if s.healthy() != nil {
		return unavailable("broker_state_unavailable"), nil
	}
	if s.refresh(ctx, false) != nil {
		return unavailable("broker_state_unavailable"), nil
	}
	items, err := s.records()
	if err != nil {
		return unavailable("broker_recovery_required"), nil
	}
	for _, r := range items {
		if r.Pending != nil {
			return Capability{Reason: "managed_account_recovery_required", Backend: "linux_shadow_utils", Restrictions: restrictions()}, nil
		}
	}
	return Capability{Available: true, Backend: "linux_shadow_utils", Restrictions: restrictions()}, nil
}
func (s *store) list(ctx context.Context) ([]Account, error) {
	if snapshotReentry(ctx, s) {
		return nil, ErrConflict
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	if ctx == nil {
		return nil, ErrInvalid
	}
	if s.healthy() != nil {
		return nil, ErrUnavailable
	}
	if s.refresh(ctx, false) != nil {
		return nil, ErrRecovery
	}
	items, err := s.records()
	if err != nil {
		return nil, err
	}
	out := make([]Account, 0, len(items))
	for _, r := range items {
		a := r.Account
		if r.Pending != nil {
			a.State = "recovery_required"
		}
		// The settings applied now; an unfinished web or plan change is not
		// shown. An account recorded before limits were runs with the
		// defaults, which the broker's start wrote to its slice.
		a.Web = r.Web
		a.Limits = limitsOf(r.Account)
		a.SiteDomains = siteDomainsSummary(r)
		a.SiteFolderChanged = r.Pending == nil && s.native.VerifySiteFiles(r) != nil
		out = append(out, a)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Username < out[j].Username })
	return out, nil
}

// mutationReady refreshes and refuses every mutation while any account has
// a pending record. Each is the broker's own: an operation it journaled and
// has not finished, or a conflict over what only root can change. An
// unfinished operation may have half-applied the OpenLiteSpeed config, which
// every web change rewrites from every account's record, or a native change
// the next start must finish from a known state, so nothing else may change
// first. A tenant's folders cannot leave one behind: they make no conflict,
// and the checks made after an intent is journaled read only what root
// controls (a create's run before its user can act). Nor can a tenant's
// running processes: delete ends them, and if userdel still refuses the
// user, or ending them fails or runs out of its budget, the delete ends
// rejected (README, Processes).
func (s *store) mutationReady(ctx context.Context) ([]record, error) {
	if ctx == nil {
		return nil, ErrInvalid
	}
	if ctx.Err() != nil {
		return nil, ErrUnavailable
	}
	if s.healthy() != nil {
		return nil, ErrUnavailable
	}
	if s.refresh(ctx, false) != nil {
		return nil, ErrRecovery
	}
	items, e := s.records()
	if e != nil {
		return nil, e
	}
	for _, r := range items {
		if r.Pending != nil {
			return nil, ErrRecovery
		}
	}
	// Every account is settled: a long history is compacted before the
	// operation adds to it (journal.go).
	return s.compactHistories(items), nil
}
func planOrDefault(plan string) string {
	if plan == "" {
		return "default"
	}
	return plan
}

func (s *store) create(ctx context.Context, in CreateInput, actor string) (Account, error) {
	if snapshotReentry(ctx, s) {
		return Account{}, ErrConflict
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	if !validCreate(in, actor) {
		return Account{}, ErrInvalid
	}
	items, err := s.mutationReady(ctx)
	if err != nil {
		return Account{}, err
	}
	if len(items) >= MaxAccounts {
		return Account{}, ErrConflict
	}
	for _, r := range items {
		if r.Account.Username == in.Username || r.Account.Domain == in.Domain {
			return Account{}, ErrConflict
		}
	}
	// A domain may belong to one account only: another's alias, or the www.
	// form of another's domain, which OpenLiteSpeed maps as the same name.
	if domainTaken(items, "", in.Domain) {
		return Account{}, ErrConflict
	}
	uid, gid, err := s.native.Plan(ctx, in.Username)
	if err != nil {
		return Account{}, err
	}
	if uid < firstAccountID || uid > lastAccountID || gid != uid || uid == int(s.opts.ControllerUID) {
		return Account{}, ErrRecovery
	}
	for _, r := range items {
		if r.Account.UID == uid || r.Account.GID == gid {
			return Account{}, ErrRecovery
		}
	}
	// The slow root steps (the slice limits, which may reload systemd, then
	// useradd and the home) run on the web operation's own limit, not the
	// caller's: a systemd reload alone can outlast a request on a busy host,
	// and once the intent is journaled a caller that gives up must not leave
	// a half-made user for recovery.
	rootCtx, cancel := webContext(ctx)
	defer cancel()
	// The account's limits are in place before its user exists, so nothing
	// it runs ever starts without them. A failure refuses the create before
	// anything is journaled: the drop-in names only this unused UID, and the
	// next create of it, or the broker's next start, rewrites it.
	if s.native.ApplyLimits(rootCtx, uid, DefaultLimits) != nil {
		return Account{}, ErrUnavailable
	}
	var id [16]byte
	if _, err = rand.Read(id[:]); err != nil {
		return Account{}, ErrUnavailable
	}
	key := hex.EncodeToString(id[:])
	now := time.Now().UTC()
	home := filepath.Join(s.opts.HomesDir, in.Username)
	r := record{Version: 1, Tag: "sifruno-managed-" + key, Account: Account{ID: key, Username: in.Username, Domain: in.Domain, Plan: planOrDefault(in.Plan), Limits: DefaultLimits, Home: home, PublicHTML: filepath.Join(home, "public_html"), State: "recovery_required", UID: uid, GID: gid, Revision: 1, CreatedAt: now, UpdatedAt: now}, Pending: &pending{Action: "create", Target: "active", Actor: actor, Reason: in.Reason}}
	r, err = s.beginOperation(r, nil)
	if err != nil {
		return Account{}, ErrRecovery
	}
	owned, err := s.native.Create(rootCtx, r, func(owned ownership) error { r.Ownership = owned; return s.save(r) })
	if err != nil {
		_, _ = s.resultEvent(r, *r.Pending, "recovery_required")
		return Account{}, ErrRecovery
	}
	r.Ownership = owned
	r.Account.State = "active"
	r.Account.UpdatedAt = time.Now().UTC()
	r.Actor, r.Reason = actor, in.Reason
	operation := *r.Pending
	if s.native.Verify(rootCtx, r) != nil {
		_, _ = s.resultEvent(r, operation, "recovery_required")
		return Account{}, ErrRecovery
	}
	r.Pending = nil
	if _, e := s.resultEvent(r, operation, "succeeded"); e != nil {
		return Account{}, ErrRecovery
	}
	return r.Account, nil
}
func (s *store) setState(ctx context.Context, id string, in StateInput, actor string) (Account, error) {
	if snapshotReentry(ctx, s) {
		return Account{}, ErrConflict
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	if !idPattern.MatchString(id) || !validState(in, actor) {
		return Account{}, ErrInvalid
	}
	items, err := s.mutationReady(ctx)
	if err != nil {
		return Account{}, err
	}
	index := -1
	for i, item := range items {
		if item.Account.ID == id {
			index = i
			break
		}
	}
	if index < 0 {
		return Account{}, ErrNotFound
	}
	r := items[index]
	// A running WordPress install would keep going as a suspended user.
	if r.Account.Revision != in.ExpectedRevision || s.installing[id] {
		return Account{}, ErrConflict
	}
	// A suspend of a suspended account with a live site installs the site
	// list again, journaled like any change, so an operator can enforce a
	// suspension made before the site list followed the account.
	if r.Account.State == in.State && !(in.State == "suspended" && r.Web.enabled()) {
		// A suspend of a suspended account ends its processes again.
		if in.State == "suspended" && s.native.EndProcesses(ctx, r) != nil {
			return Account{}, ErrUnavailable
		}
		return withWeb(r), nil
	}
	if r.Account.Revision == ^uint64(0) {
		return Account{}, ErrRecovery
	}
	// A live site changes with its account, which needs the web operation:
	// refused here, before anything is journaled.
	if r.Web.enabled() && s.web == nil {
		return Account{}, ErrUnavailable
	}
	r.Pending = &pending{Action: "state", Target: in.State, Actor: actor, Reason: in.Reason}
	before := r.Account
	r, err = s.beginOperation(r, &before)
	if err != nil {
		return Account{}, ErrRecovery
	}
	if s.native.SetState(ctx, r, in.State) != nil {
		_, _ = s.resultEvent(r, *r.Pending, "recovery_required")
		return Account{}, ErrRecovery
	}
	// Only what root controls: the tenant's own folders cannot make a
	// suspend of its account, or any state change, stay pending.
	next := targetRecord(r, in.State)
	if s.native.VerifyAccount(ctx, next) != nil {
		_, _ = s.resultEvent(r, *r.Pending, "recovery_required")
		return Account{}, ErrRecovery
	}
	// A live site follows its account: suspended, OpenLiteSpeed refuses every
	// request for it; active again, it serves. The site list is installed
	// under the web operation's own limit, with this account as the pending
	// change leaves it. If the config fails its test the old files went
	// back, so the account goes back too and the change ends rejected:
	// nothing changed. Any other failure stays pending for the next start.
	if r.Web.enabled() {
		live := append([]record(nil), items...)
		live[index] = r
		switch e := s.applySites(ctx, live, id); {
		case errors.Is(e, ErrWebRejected):
			if s.undoState(ctx, r) != nil {
				_, _ = s.resultEvent(r, *r.Pending, "recovery_required")
				return Account{}, ErrRecovery
			}
			operation := *r.Pending
			r.Pending = nil
			if _, e := s.resultEvent(r, operation, "rejected"); e != nil {
				return Account{}, ErrRecovery
			}
			return Account{}, ErrWebRejected
		case e != nil:
			_, _ = s.resultEvent(r, *r.Pending, "recovery_required")
			return Account{}, ErrRecovery
		}
	}
	next.Account.Revision++
	next.Account.UpdatedAt = time.Now().UTC()
	next.Actor, next.Reason = actor, in.Reason
	operation := *next.Pending
	next.Pending = nil
	if _, e := s.resultEvent(next, operation, "succeeded"); e != nil {
		return Account{}, ErrRecovery
	}
	// A suspended account's processes end too: SFTP sessions, PHP workers,
	// cron jobs. This runs with the tenant's own rights and changes no
	// record, so it is not journaled. The suspension stands either way (no
	// login, cron job or PHP request starts for it); if some processes did
	// not end, the answer is 503 and a suspend again ends them again.
	if in.State == "suspended" && s.native.EndProcesses(ctx, next) != nil {
		return Account{}, ErrUnavailable
	}
	return withWeb(next), nil
}

// withWeb is a record's account as the account list shows it: with the live
// site's settings and its domains, which the stored account and the journal
// never carry, and the limits in force.
func withWeb(r record) Account {
	a := r.Account
	a.Web = r.Web
	a.Limits = limitsOf(r.Account)
	a.SiteDomains = siteDomainsSummary(r)
	return a
}

// A fresh dedicated broker directory has its own marker in addition to the
// shared private-state guard. No unrelated nonempty directory can be adopted.
func ensureBrokerDir(path string) error {
	if securestate.CheckPath(path) != nil {
		return ErrUnavailable
	}
	if _, e := securestate.Dir(path); e != nil {
		return ErrUnavailable
	}
	marker := filepath.Join(path, ".sifruno-hostbroker")
	if _, e := os.Lstat(marker); errors.Is(e, os.ErrNotExist) {
		entries, e := os.ReadDir(path)
		if e != nil || len(entries) != 1 || entries[0].Name() != ".sifruno-state" {
			return ErrUnavailable
		}
		f, e := os.OpenFile(marker, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
		if e != nil {
			return ErrUnavailable
		}
		_, e = f.Write([]byte("native Linux account broker v1\n"))
		if e == nil {
			e = f.Sync()
		}
		c := f.Close()
		if e != nil || c != nil {
			return ErrUnavailable
		}
	} else if e != nil {
		return ErrUnavailable
	}
	raw, e := os.ReadFile(marker)
	if e != nil || string(raw) != "native Linux account broker v1\n" {
		return ErrUnavailable
	}
	return nil
}
