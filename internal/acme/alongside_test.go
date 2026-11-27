package acme

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"testing"
	"time"
)

// The panel's own certificate has a manager beside the websites': the same
// issuer, so the same certificate authority account, its own records, and
// one attempt at a time across both.
func TestAlongsideSharesTheIssuerAndTakesTurns(t *testing.T) {
	f := newManagerFixture(t)
	installer := &installerFake{notAfter: f.now.Add(90 * 24 * time.Hour)}
	dir := filepath.Join(t.TempDir(), "panel")
	panel, err := f.m.Alongside(installer, &sitesFake{}, dir)
	if err != nil {
		t.Fatal(err)
	}
	panel.log, panel.records.log, panel.now = f.log, f.log, f.m.now
	// While the websites' manager has its turn, the panel's attempt waits.
	f.m.busy <- struct{}{}
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	_, _, err = panel.Secure(ctx, "panel", "panel.example.com", 0)
	cancel()
	if !errors.Is(err, context.DeadlineExceeded) || len(f.issuer.domains) != 0 {
		t.Fatalf("an attempt did not wait for the other manager's: %v, issued %q", err, f.issuer.domains)
	}
	<-f.m.busy
	if _, _, err = panel.Secure(context.Background(), "panel", "panel.example.com", 0); err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(f.issuer.domains, []string{"panel.example.com"}) || len(installer.calls) != 1 || len(f.installer.calls) != 0 {
		t.Fatalf("issued %q, panel installs %q, website installs %q", f.issuer.domains, installer.calls, f.installer.calls)
	}
	// Each keeps its own records.
	if _, ok := f.m.records.get("panel"); ok {
		t.Fatal("the websites' records name the panel")
	}
	if r, ok := panel.records.get("panel"); !ok || r.LastResult != "installed" {
		t.Fatalf("panel record %+v", r)
	}
	if info, err := os.Lstat(filepath.Join(dir, recordsFile)); err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("panel records %v %v", info, err)
	}
	// Two managers on one records file would overwrite each other's.
	if _, err = f.m.Alongside(installer, &sitesFake{}, f.dir); err == nil {
		t.Fatal("a manager alongside was given the same records folder")
	}
}

// Reaches asks the issuer's probe; an issuer without one counts every name
// as reaching, as for aliases.
func TestManagerReachesAsksTheIssuer(t *testing.T) {
	f := newManagerFixture(t)
	f.issuer.unreachable = map[string]bool{"far.example.com": true}
	ctx := context.Background()
	if !f.m.Reaches(ctx, "panel.example.com") || f.m.Reaches(ctx, "far.example.com") {
		t.Fatalf("probes %q", f.issuer.probes)
	}
	plain, err := NewManager(plainIssuer{}, f.installer, f.sites, filepath.Join(t.TempDir(), "plain"))
	if err != nil {
		t.Fatal(err)
	}
	if !plain.Reaches(ctx, "far.example.com") {
		t.Fatal("an issuer without a probe counted a name as not reaching")
	}
}

type plainIssuer struct{}

func (plainIssuer) Issue(context.Context, []string) (Certificate, error) {
	return Certificate{}, errors.New("not used")
}
