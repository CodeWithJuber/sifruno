package sites

import (
	"math"
	"time"
)

// NameInput changes the display name only; routing and saved content stay intact.
type NameInput struct {
	Name             string `json:"name"`
	ExpectedRevision uint64 `json:"expected_revision"`
}

func (s *Store) ChangeName(id string, input NameInput, actor string) (Site, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !validActor(actor) || !validName(input.Name) {
		return Site{}, ErrInvalid
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
	if r.Site.Name == input.Name {
		return r.Site, nil
	}
	next := r
	next.Site.Name = input.Name
	next.Site.Revision++
	next.Site.UpdatedAt = time.Now().UTC()
	if err = s.change(r, next, nil, "name", actor); err != nil {
		return Site{}, err
	}
	return next.Site, nil
}
