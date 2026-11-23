package acme

import (
	"testing"
	"time"
)

// A refused install takes two rows of the account's journal, so the panel
// waits a week before it tries that site again; other failures wait 6 hours.
func TestRefusedInstallWaitsAWeek(t *testing.T) {
	now := time.Date(2026, 11, 23, 12, 0, 0, 0, time.UTC)
	refused := record{LastAttempt: now.Add(-24 * time.Hour), LastResult: ErrInstall.Error()}
	if due(time.Time{}, refused.LastAttempt.Add(retryWait(refused)), now) {
		t.Fatal("a site whose install was refused a day ago was tried again")
	}
	refused.LastAttempt = now.Add(-8 * 24 * time.Hour)
	if !due(time.Time{}, refused.LastAttempt.Add(retryWait(refused)), now) {
		t.Fatal("a site whose install was refused 8 days ago was not tried again")
	}
	dns := record{LastAttempt: now.Add(-7 * time.Hour), LastResult: ErrValidation.Error()}
	if !due(time.Time{}, dns.LastAttempt.Add(retryWait(dns)), now) {
		t.Fatal("a site that failed validation 7 hours ago was not tried again")
	}
}
