package mailhost

import (
	"context"
	"os"
	"path/filepath"
)

// PurgeAccount removes every mailbox of a terminated account and the
// account's mail root. Mirrors removeacct's post-steps. Per-mailbox
// failures are collected, never hidden.
func (s *LocalService) PurgeAccount(ctx context.Context, account string, domains []string) (purged int, errs []string) {
	boxes, err := s.ListMailboxes(ctx, account)
	if err != nil {
		return 0, []string{err.Error()}
	}
	for _, b := range boxes {
		if err := s.DeleteMailbox(ctx, account, b.Email); err != nil {
			errs = append(errs, b.Email+": "+err.Error())
			continue
		}
		purged++
	}
	for _, d := range domains {
		if err := os.Remove(s.valiasesPath(d)); err != nil && !os.IsNotExist(err) {
			errs = append(errs, "valiases "+d+": "+err.Error())
		}
	}
	if err := os.RemoveAll(filepath.Join(s.Homes, account)); err != nil {
		errs = append(errs, "mail root: "+err.Error())
	}
	// autoresponders of the terminated account (batch 3)
	if err := os.Remove(s.arPath(account)); err != nil && !os.IsNotExist(err) {
		errs = append(errs, "autorespond: "+err.Error())
	}
	return purged, errs
}
