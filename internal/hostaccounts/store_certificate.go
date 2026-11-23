package hostaccounts

import (
	"context"
	"errors"
	"time"
)

// setCertificate installs a certificate for an account's live site.
//
// Everything about the input is checked before anything is journaled: its
// form (400), whether it names the account's domain and is valid now (422
// certificate_rejected), and the account's state and revision (409). Then the
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
	if r.Account.Revision != in.ExpectedRevision || r.Account.State != "active" || !r.Web.enabled() || s.installing[id] {
		return CertificateResult{}, ErrConflict
	}
	if bundle.fits(r.Account.Domain, time.Now()) != nil {
		return CertificateResult{}, ErrCertificateRejected
	}
	if r.Account.Revision == ^uint64(0) {
		return CertificateResult{}, ErrRecovery
	}
	// Two history rows, with room left as beginOperation leaves it, so the
	// result can always be journaled.
	if r.HistorySequence > MaxHistoryRows-3 {
		return CertificateResult{}, ErrConflict
	}
	if s.native.Verify(ctx, r) != nil {
		return CertificateResult{}, ErrConflict
	}
	if s.native.StageCertificate(ctx, r, bundle.chainPEM, bundle.keyPEM) != nil {
		return CertificateResult{}, ErrUnavailable
	}
	next := bundle.state
	r.Pending = &pending{Action: "certificate", Target: certificateDigest(next), Actor: actor, Reason: in.Reason}
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
	intent := operationEvent{OperationID: operationID, Action: "certificate", Status: "intended", Actor: actor, Reason: in.Reason, Before: &before, After: after}
	r, err = s.appendEvent(r, intent)
	if err != nil {
		return CertificateResult{}, ErrRecovery
	}
	applyCtx, cancel := webContext(ctx)
	defer cancel()
	switch e := s.native.ApplyCertificate(applyCtx, r, next, sites); {
	case errors.Is(e, ErrWebRejected):
		operation := *r.Pending
		r.Pending, r.TLSNext = nil, CertificateState{}
		if _, e := s.resultEvent(r, operation, "rejected"); e != nil {
			return CertificateResult{}, ErrRecovery
		}
		s.discardStagedCertificate(r)
		return CertificateResult{}, ErrWebRejected
	case e != nil:
		_, _ = s.resultEvent(r, *r.Pending, "recovery_required")
		return CertificateResult{}, ErrRecovery
	}
	r.TLS, r.TLSNext = next, CertificateState{}
	r.Account.Certificate = next
	r.Account.Revision++
	r.Account.UpdatedAt = time.Now().UTC()
	r.Actor, r.Reason = actor, in.Reason
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
