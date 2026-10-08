package sites

import (
	"math"
	"time"
)

// DomainInput changes only this native site's local HTTP host routing.
// It does not configure DNS, TLS, native accounts, or external servers.
type DomainInput struct {
	Domain           string `json:"domain"`
	ExpectedRevision uint64 `json:"expected_revision"`
}

func (s *Store) ChangeDomain(id string, input DomainInput, actor string) (Site, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !validActor(actor) {
		return Site{}, ErrInvalid
	}
	domain, err := canonicalDomain(input.Domain)
	if err != nil {
		return Site{}, err
	}
	r, err := s.checked(id)
	if err != nil {
		return Site{}, err
	}
	if r.Site.Revision != input.ExpectedRevision || r.Site.Revision == math.MaxUint64 {
		return Site{}, ErrConflict
	}
	if _, err = s.snapshot(r); err != nil {
		return Site{}, err
	}
	records, err := s.records()
	if err != nil {
		return Site{}, err
	}
	for _, other := range records {
		// A pending site's domain remains reserved while recovery is required.
		if other.Site.ID != id && other.Site.Domain == domain {
			return Site{}, ErrConflict
		}
	}
	if r.Site.Domain == domain {
		return r.Site, nil
	}
	next := r
	next.Site.Domain = domain
	next.Site.Revision++
	next.Site.UpdatedAt = time.Now().UTC()
	if err = s.change(r, next, nil, "domain", actor); err != nil {
		return Site{}, err
	}
	return next.Site, nil
}
