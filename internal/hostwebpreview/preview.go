// Package hostwebpreview composes the compiler with a broker-owned snapshot.
// It never installs generated files or observes/activates runtime processes.
package hostwebpreview

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"sort"

	"sifruno/internal/hostaccounts"
	"sifruno/internal/hostweb"
)

type service struct {
	profile  hostweb.Profile
	provider hostaccounts.SnapshotProvider
	valid    bool
}

// New binds a trusted startup profile. It has no request-configurable inputs.
// Unsupported profiles fail closed at Preview without invoking the provider.
func New(profile hostweb.Profile, provider hostaccounts.SnapshotProvider) hostaccounts.WebPreviewService {
	_, err := hostweb.Compile(profile, nil)
	return &service{profile: profile, provider: provider, valid: err == nil && provider != nil && profile.Name == hostweb.RestrictedChrootV1 && profile.ControllerUID != 0}
}

// BrokerProfile is a named compilation profile, not an installed-host claim.
// Only the admitted homes path and controller UID vary with broker startup.
func BrokerProfile(opts hostaccounts.BrokerOptions) hostweb.Profile {
	return hostweb.Profile{Name: hostweb.RestrictedChrootV1, ManagedRoot: "/var/lib/sifruno/hostweb", ManagedHomeRoot: opts.HomesDir, FrontChroot: "/var/lib/sifruno/front-jail", ApacheModuleRoot: "/usr/lib64/httpd/modules", BackendChrootRoot: "/var/lib/sifruno/backend-jails", RuntimeRoot: "/run/sifruno/hostweb", ApacheBinary: "/usr/sbin/httpd", FPMBinary: "/usr/sbin/php-fpm", TLSRoot: "/etc/sifruno/tls", CAFile: "/etc/sifruno/tls/ca.pem", FrontendIP: hostweb.DefaultFrontendIP, FrontendPort: hostweb.DefaultFrontendPort, BackendPort: hostweb.DefaultBackendPort, FrontUID: hostweb.DefaultFrontUID, FrontGID: hostweb.DefaultFrontGID, ControllerUID: opts.ControllerUID}
}
func digest(v any) string {
	b, _ := json.Marshal(v)
	s := sha256.Sum256(b)
	return hex.EncodeToString(s[:])
}
func (s *service) Preview(ctx context.Context) (hostaccounts.WebPreview, error) {
	if ctx == nil {
		return hostaccounts.WebPreview{}, hostaccounts.ErrInvalid
	}
	if !s.valid || ctx.Err() != nil {
		return hostaccounts.WebPreview{}, hostaccounts.ErrUnavailable
	}
	var out hostaccounts.WebPreview
	err := s.provider.WithSnapshot(ctx, func(lease hostaccounts.SnapshotLease) error {
		if lease == nil || lease.Context() == nil || lease.Context().Err() != nil {
			return hostaccounts.ErrUnavailable
		}
		if err := lease.Verify(lease.Context()); err != nil {
			return err
		}
		accounts := append([]hostaccounts.Account{}, lease.Accounts()...)
		bundle, err := hostweb.Compile(s.profile, accounts)
		if err != nil {
			return hostaccounts.ErrUnavailable
		}
		sort.Slice(accounts, func(i, j int) bool { return accounts[i].ID < accounts[j].ID })
		next := hostaccounts.WebPreview{Profile: s.profile.Name, ProfileSHA256: digest(s.profile), SnapshotSHA256: digest(accounts), BundleSHA256: bundle.SHA256, Accounts: len(accounts), Files: make([]hostaccounts.WebPreviewFile, 0, len(bundle.Files))}
		for _, a := range accounts {
			if a.State == "active" {
				next.ActiveAccounts++
			} else {
				next.SuspendedAccounts++
			}
		}
		for _, f := range bundle.Files {
			next.Files = append(next.Files, hostaccounts.WebPreviewFile{Path: f.Path, Mode: uint32(f.Mode.Perm()), Bytes: len(f.Data), SHA256: f.SHA256})
		}
		if err := lease.Verify(lease.Context()); err != nil {
			return err
		}
		if err := lease.Context().Err(); err != nil {
			return err
		}
		out = next
		return nil
	})
	// WithSnapshot performs another verification after callback return. Never
	// expose the buffered candidate if this fails, including recovery bookkeeping.
	if err != nil {
		return hostaccounts.WebPreview{}, err
	}
	if ctx.Err() != nil || out.Files == nil {
		return hostaccounts.WebPreview{}, hostaccounts.ErrUnavailable
	}
	return out, nil
}
