package accesspolicy

import (
	"errors"

	bolt "go.etcd.io/bbolt"
)

// AuthorizeAt validates and checks one database read snapshot. The expected
// version must match that snapshot; no previously loaded Policy is reused.
// Reads already in flight may observe the snapshot preceding a replacement.
// This is not authentication, an execution lock, or cancellation of later work.
func (s *Store) AuthorizeAt(expected StoreVersion, actor ActorID, action Action, resource Resource) (bool, error) {
	if !s.usable() {
		return false, ErrStore
	}
	allowed := false
	err := s.db.View(func(tx *bolt.Tx) error {
		policy, current, err := readSnapshot(tx)
		if err != nil {
			return err
		}
		if expected != current {
			return ErrConflict
		}
		allowed = policy.Authorize(actor, action, resource)
		return nil
	})
	if err != nil {
		if errors.Is(err, ErrConflict) {
			return false, ErrConflict
		}
		return false, ErrStore
	}
	return allowed, nil
}
