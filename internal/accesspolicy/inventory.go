package accesspolicy

import (
	"errors"
	"sort"

	bolt "go.etcd.io/bbolt"
)

// VisibleAccountsAt returns the sorted account IDs that an independently
// authenticated actor may ReadAccount in one validated database snapshot.
// It does not grant ListAccounts or permission for a later operation. An
// overlapping replacement may commit while a read uses the preceding snapshot.
// Successful results are independently owned and nonnil, even when empty;
// every error returns nil. Identity authentication remains the caller's duty.
func (s *Store) VisibleAccountsAt(expected StoreVersion, actor ActorID) ([]AccountID, error) {
	if !s.usable() {
		return nil, ErrStore
	}
	var visible []AccountID
	err := s.db.View(func(tx *bolt.Tx) error {
		policy, current, err := readSnapshot(tx)
		if err != nil {
			return err
		}
		if expected != current {
			return ErrConflict
		}
		if _, registered := policy.actors[actor]; !registered {
			return ErrDenied
		}
		visible = make([]AccountID, 0)
		for id := range policy.accounts {
			if policy.Authorize(actor, ReadAccount, AccountResource(id)) {
				visible = append(visible, id)
			}
		}
		sort.Slice(visible, func(i, j int) bool { return visible[i].String() < visible[j].String() })
		visible = visible[:len(visible):len(visible)]
		return nil
	})
	if err != nil {
		if errors.Is(err, ErrConflict) || errors.Is(err, ErrDenied) {
			return nil, err
		}
		return nil, ErrStore
	}
	return visible, nil
}
