package hostaccounts

import (
	"context"
	"errors"
	"time"
)

// setCertificate installs a certificate for an account's live site.
//
// Everything about the input is checked before anything is journaled: its
// form (400), whether its names are the site's domains, the account's own
// among them, and it is valid now (422 certificate_rejected), and the
// account's state and revision (409). Then the
// canonical chain and key are staged root-only beside the site's live files,
// so the intent never names a certificate the broker cannot finish
// installing. After the intent is journaled, the staged pair becomes the
// live files and the config is written, tested and reloaded under its own
// limit, or everything is restored and journaled as rejected, which leaves
// the account unchanged.
func (s *store) setCertificate(ctx context.Context, id string, in CertificateInput, actor string) (CertificateResult, error) {
	if snapshotReentry(ctx, s) {
		return CertificateResult{}, ErrConflict
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	if !idPattern.MatchString(id) || !validCertificateInput(in, actor) {
		return CertificateResult{}, ErrInvalid
	}
	bundle, err := parseCertificate(in.CertPEM, in.KeyPEM)
	if err != nil {
		return CertificateResult{}, ErrInvalid
	}
	// The leaf names the account's domain and may name its aliases; every
	// name must be one of them.
	return s.installCertificate(ctx, id, in.ExpectedRevision, bundle, bundle.fits, actor, in.Reason)
}

// installCertificate installs a checked bundle on the account's live site
// at its expected revision: fits says whether the leaf fits the site's
// domains (the account's own first) now. Callers hold s.mu.
func (s *store) installCertificate(ctx context.Context, id string, revision uint64, bundle certificateBundle, fits func(domains []string, primary string, now time.Time) error, actor, reason string) (CertificateResult, error) {
	if !idPattern.MatchString(id) || revision == 0 || !validText(reason, 500) || !validText(actor, 120) {
		return CertificateResult{}, ErrInvalid
	}
	if s.web == nil {
		return CertificateResult{}, ErrUnavailable
	}
	items, err := s.mutationReady(ctx)
	if err != nil {
		return CertificateResult{}, err
	}
	index := -1
	for i, item := range items {
		if item.Account.ID == id {
			index = i
			break
		}
	}
	if index < 0 {
		return CertificateResult{}, ErrNotFound
	}
	r := items[index]
	// An account busy with a WordPress install is left alone, as the web
	// operation leaves it.
	if r.Account.Revision != revision || r.Account.State != "active" || !r.Web.enabled() || s.installing[id] {
		return CertificateResult{}, ErrConflict
	}
	// No operation is pending, so the recorded aliases are the ones served.
	domains := append([]string{r.Account.Domain}, recordSiteDomains(r).Aliases...)
	if fits(domains, r.Account.Domain, time.Now()) != nil {
		return CertificateResult{}, ErrCertificateRejected
	}
	if r.Account.Revision == ^uint64(0) {
		return CertificateResult{}, recovery("certificate", r, "revision at its limit", ErrConflict)
	}
	// Two history rows, with room left as historyRoom leaves it for the
	// operations a tenant can reach, so the result can always be journaled.
	if !historyRoom(r, operationRows, false) {
		return CertificateResult{}, ErrConflict
	}
	if s.native.Verify(ctx, r) != nil {
		return CertificateResult{}, ErrConflict
	}
	if s.native.StageCertificate(ctx, r, bundle.chainPEM, bundle.keyPEM) != nil {
		return CertificateResult{}, ErrUnavailable
	}
	next := bundle.state
	r.Pending = &pending{Action: "certificate", Target: certificateDigest(next), Actor: actor, Reason: reason}
	r.TLSNext = next
	nextItems := append([]record(nil), items...)
	nextItems[index] = r
	sites := webSites(nextItems, "")
	operationID, e := randomID()
	if e != nil {
		return CertificateResult{}, e
	}
	r.Pending.OperationID = operationID
	before := r.Account
	after := r.Account
	after.Revision++
	after.Certificate = next
	intent := operationEvent{OperationID: operationID, Action: "certificate", Status: "intended", Actor: actor, Reason: reason, Before: &before, After: after}
	r, err = s.appendEvent(r, intent)
	if err != nil {
		return CertificateResult{}, ErrRecovery
	}
	applyCtx, cancel := webContext(ctx)
	defer cancel()
	switch e := s.native.ApplyCertificate(applyCtx, r, next, sites, s.tenantBroken(nextItems, id)); {
	case errors.Is(e, ErrWebRejected):
		operation := *r.Pending
		r.Pending, r.TLSNext = nil, CertificateState{}
		if _, e := s.resultEvent(r, operation, "rejected"); e != nil {
			return CertificateResult{}, ErrRecovery
		}
		s.discardStagedCertificate(r)
		return CertificateResult{}, ErrWebRejected
	case e != nil:
		s.recoveryRequired(r, *r.Pending, "install", e)
		return CertificateResult{}, ErrRecovery
	}
	r.TLS, r.TLSNext = next, CertificateState{}
	r.Account.Certificate = next
	r.Account.Revision++
	r.Account.UpdatedAt = time.Now().UTC()
	r.Actor, r.Reason = actor, reason
	operation := *r.Pending
	r.Pending = nil
	if _, e := s.resultEvent(r, operation, "succeeded"); e != nil {
		return CertificateResult{}, ErrRecovery
	}
	s.discardStagedCertificate(r)
	return CertificateResult{Account: r.Account, Certificate: next}, nil
}

// discardStagedCertificate removes a staged pair once its operation is
// journaled as finished. A failure leaves root-only files that the next
// staging replaces and a delete removes, so it is not an error.
func (s *store) discardStagedCertificate(r record) {
	_ = s.native.StageCertificate(context.Background(), r, nil, nil)
}
