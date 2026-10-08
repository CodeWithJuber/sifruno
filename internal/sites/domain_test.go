package sites

import (
	"errors"
	"math"
	"os"
	"path/filepath"
	"reflect"
	"sync"
	"testing"
)

func TestChangeDomainRoutingReopenAndPriorBackupRestore(t *testing.T) {
	s, journal, base := fixture(t)
	site := makeSite(t, s)
	original, err := s.ReadFile(site.ID, "index.html")
	if err != nil {
		t.Fatal(err)
	}
	backup, err := s.Backup(site.ID, site.Revision, "local-operator")
	if err != nil {
		t.Fatal(err)
	}
	site, err = s.Get(site.ID)
	if err != nil {
		t.Fatal(err)
	}
	files, err := s.Files(site.ID)
	if err != nil {
		t.Fatal(err)
	}
	before := site
	site, err = s.ChangeDomain(site.ID, DomainInput{Domain: "BÜCHER.test", ExpectedRevision: site.Revision}, "local-operator")
	if err != nil || site.Domain != "xn--bcher-kva.test" || site.Revision != before.Revision+1 || !site.UpdatedAt.After(before.UpdatedAt) {
		t.Fatal("canonical domain mutation", site, err)
	}
	expected := before
	expected.Domain, expected.Revision, expected.UpdatedAt = site.Domain, site.Revision, site.UpdatedAt
	if site != expected {
		t.Fatal("domain change altered unrelated metadata", site)
	}
	if actual, err := s.Files(site.ID); err != nil || !reflect.DeepEqual(actual, files) {
		t.Fatal("domain change altered files", err)
	}
	if backups, err := s.Backups(site.ID); err != nil || len(backups) != 1 || backups[0] != backup {
		t.Fatal("domain change altered backups", err)
	}
	if w := served(s, before.Domain, "/", "GET"); w.Code != 404 {
		t.Fatal("old domain still routed", w.Code)
	}
	for _, host := range []string{site.Domain, site.PreviewHost} {
		if w := served(s, host, "/", "GET"); w.Code != 200 || w.Body.String() != original.Content {
			t.Fatal("new domain or stable preview lost bytes", host, w.Code)
		}
	}
	if err = s.Close(); err != nil {
		t.Fatal(err)
	}
	again, err := Open(filepath.Join(base, "sites"), journal)
	if err != nil {
		t.Fatal("reopen changed domain", err)
	}
	defer again.Close()
	if actual, err := again.Get(site.ID); err != nil || actual != site {
		t.Fatal("domain not durable", actual, err)
	}
	site, err = again.WriteFile(site.ID, WriteInput{Path: original.Path, Content: "changed after domain", ExpectedSHA256: original.SHA256, ExpectedRevision: site.Revision}, "local-operator")
	if err != nil {
		t.Fatal(err)
	}
	site, err = again.Restore(site.ID, RestoreInput{BackupID: backup.ID, ExpectedRevision: site.Revision}, "local-operator")
	if err != nil || site.Domain != expected.Domain || site.PreviewHost != before.PreviewHost {
		t.Fatal("prior backup restored old domain metadata", site, err)
	}
	if w := served(again, site.Domain, "/", "GET"); w.Code != 200 || w.Body.String() != original.Content {
		t.Fatal("prior backup bytes missing on new domain", w.Code)
	}
	if w := served(again, before.Domain, "/", "GET"); w.Code != 404 {
		t.Fatal("restore revived old route", w.Code)
	}
	if journal.Verify() != nil {
		t.Fatal("signed domain history invalid")
	}
}

func TestChangeDomainNoOpAndRefusals(t *testing.T) {
	s, journal, base := fixture(t)
	site := makeSite(t, s)
	entries, err := journal.List()
	if err != nil {
		t.Fatal(err)
	}
	if got, err := s.ChangeDomain(site.ID, DomainInput{Domain: "EXAMPLE.TEST", ExpectedRevision: site.Revision}, "local-operator"); err != nil || got != site {
		t.Fatal("same canonical domain changed metadata", got, err)
	}
	if actual, err := journal.List(); err != nil || !reflect.DeepEqual(actual, entries) {
		t.Fatal("no-op added journal entries", err)
	}
	for _, row := range []struct {
		input DomainInput
		actor string
		want  error
	}{
		{DomainInput{Domain: site.Domain, ExpectedRevision: 0}, "local-operator", ErrConflict},
		{DomainInput{Domain: "other.test", ExpectedRevision: site.Revision + 1}, "local-operator", ErrConflict},
		{DomainInput{Domain: "http://other.test/path", ExpectedRevision: site.Revision}, "local-operator", ErrInvalid},
		{DomainInput{Domain: "other.test", ExpectedRevision: site.Revision}, "root", ErrInvalid},
	} {
		if got, err := s.ChangeDomain(site.ID, row.input, row.actor); got != (Site{}) || !errors.Is(err, row.want) {
			t.Fatal("domain refusal", got, err)
		}
	}
	other, err := s.Create(CreateInput{Name: "Reservation", Domain: "reserved.test"}, "local-operator")
	if err != nil {
		t.Fatal(err)
	}
	r, err := s.load(other.ID)
	if err != nil {
		t.Fatal(err)
	}
	r.Pending = &pendingChange{Action: "interrupted", Checkpoints: []string{}}
	if err = s.save(r); err != nil {
		t.Fatal(err)
	}
	if got, err := s.ChangeDomain(site.ID, DomainInput{Domain: "RESERVED.test", ExpectedRevision: site.Revision}, "local-operator"); got != (Site{}) || !errors.Is(err, ErrConflict) {
		t.Fatal("pending domain reservation ignored", got, err)
	}
	if got, err := s.ChangeDomain(other.ID, DomainInput{Domain: "available.test", ExpectedRevision: other.Revision}, "local-operator"); got != (Site{}) || !errors.Is(err, ErrUnavailable) {
		t.Fatal("recovery-required mutation accepted", got, err)
	}
	if actual, err := s.Get(site.ID); err != nil || actual != site {
		t.Fatal("refusal changed target", actual, err)
	}
	// Even a same-domain request must validate the actual saved files.
	path := filepath.Join(base, "sites", "data", site.ID, "content", "index.html")
	if err = os.WriteFile(path, []byte("unexpected external content"), 0600); err != nil {
		t.Fatal(err)
	}
	if got, err := s.ChangeDomain(site.ID, DomainInput{Domain: site.Domain, ExpectedRevision: site.Revision}, "local-operator"); got != (Site{}) || err == nil {
		t.Fatal("no-op skipped file validation", got, err)
	}
}

func TestChangeDomainSuspendedAndRevisionExhaustion(t *testing.T) {
	s, _, _ := fixture(t)
	site := makeSite(t, s)
	site, err := s.SetState(site.ID, StateInput{State: "suspended", ExpectedRevision: site.Revision}, "local-operator")
	if err != nil {
		t.Fatal(err)
	}
	old := site.Domain
	site, err = s.ChangeDomain(site.ID, DomainInput{Domain: "suspended.test", ExpectedRevision: site.Revision}, "local-operator")
	if err != nil || site.State != "suspended" || served(s, old, "/", "GET").Code != 404 || served(s, site.Domain, "/", "GET").Code != 503 || served(s, site.PreviewHost, "/", "GET").Code != 503 {
		t.Fatal("domain mutation changed suspended routing", site, err)
	}
	r, err := s.load(site.ID)
	if err != nil {
		t.Fatal(err)
	}
	next := r
	next.Site.Revision = math.MaxUint64
	if err = s.change(r, next, nil, "test revision exhaustion", "local-operator"); err != nil {
		t.Fatal(err)
	}
	for _, domain := range []string{site.Domain, "overflow.test"} {
		if got, err := s.ChangeDomain(site.ID, DomainInput{Domain: domain, ExpectedRevision: math.MaxUint64}, "local-operator"); got != (Site{}) || !errors.Is(err, ErrConflict) {
			t.Fatal("exhausted revision accepted", got, err)
		}
	}
}

func TestChangeDomainConcurrentReservation(t *testing.T) {
	s, _, _ := fixture(t)
	first := makeSite(t, s)
	second, err := s.Create(CreateInput{Name: "Second", Domain: "second.test"}, "local-operator")
	if err != nil {
		t.Fatal(err)
	}
	start := make(chan struct{})
	type result struct {
		site Site
		err  error
	}
	results := make(chan result, 2)
	var wg sync.WaitGroup
	for _, site := range []Site{first, second} {
		wg.Add(1)
		go func(site Site) {
			defer wg.Done()
			<-start
			got, err := s.ChangeDomain(site.ID, DomainInput{Domain: "SHARED.test", ExpectedRevision: site.Revision}, "local-operator")
			results <- result{got, err}
		}(site)
	}
	close(start)
	wg.Wait()
	close(results)
	var winner Site
	success, conflicts := 0, 0
	for got := range results {
		if got.err == nil {
			winner = got.site
			success++
		} else if errors.Is(got.err, ErrConflict) && got.site == (Site{}) {
			conflicts++
		} else {
			t.Fatal(got.err)
		}
	}
	if success != 1 || conflicts != 1 {
		t.Fatal("domain reservation was not serialized", success, conflicts)
	}
	file, err := s.ReadFile(winner.ID, "index.html")
	if err != nil {
		t.Fatal(err)
	}
	if w := served(s, "shared.test", "/", "GET"); w.Code != 200 || w.Body.String() != file.Content {
		t.Fatal("canonical host did not route only to winner", w.Code)
	}
	for _, old := range []Site{first, second} {
		actual, err := s.Get(old.ID)
		if err != nil || (old.ID != winner.ID && actual != old) || (old.ID == winner.ID && actual.Domain != "shared.test") {
			t.Fatal("losing or winning record incorrect", actual, err)
		}
	}
}
