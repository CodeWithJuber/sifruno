package trail

import (
	"errors"
	"os"
)

// VerifyCurrent binds an applied checkpoint to its current scoped file images.
// Historical checkpoints superseded by legitimate later writes do not match;
// callers must retain the latest sealed checkpoint for each managed scope.
// External writers must be quiesced, as with Checkpoint and Rollback.
func (s *Store) VerifyCurrent(changeID string) error {
	if err := s.acquire(); err != nil {
		return err
	}
	defer s.release()
	if _, err := s.verifyLocked(); err != nil {
		return err
	}
	change, err := s.read(changeID)
	if err != nil {
		return err
	}
	if change.State != "applied" {
		return errors.New("current verification requires an applied checkpoint")
	}
	if err = rejectLinks(change.Root); err != nil {
		return err
	}
	root, err := os.OpenRoot(change.Root)
	if err != nil {
		return err
	}
	defer root.Close()
	for _, expected := range change.After {
		actual, err := readImage(root, expected.Path, false)
		if err != nil {
			return err
		}
		if !same(expected, actual) {
			return errors.New("managed files differ from the applied checkpoint")
		}
	}
	return nil
}
