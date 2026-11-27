package hostaccounts

import (
	"context"
	"errors"
	"strings"
	"testing"

	"sifruno/internal/olsweb"
)

const fixtureUserFile = "alice:$apr1$x1Y2z3$abcdefghijklmnopqrstuv\n"

func fixtureProtection(id string) SiteProtection {
	site := siteName(id)
	return SiteProtection{
		Folders: []olsweb.Folder{
			{Path: "/members/", Hosts: olsweb.HostsAll, Realm: &olsweb.FolderRealm{Name: "Members only", UserFile: olsweb.RealmFile(site, 1)}},
			{Path: "/wp-content/plugins/akismet/", Hosts: olsweb.HostsNone, Allow: []string{"akismet.css", "form.js"}},
		},
		Users: map[string][]byte{olsweb.RealmFile(site, 1): []byte(fixtureUserFile)},
	}
}

// busy marks the account busy, as migrateFiles does around the copy.
func busy(s *store, id string) func() {
	s.mu.Lock()
	if s.installing == nil {
		s.installing = map[string]bool{}
	}
	s.installing[id] = true
	s.mu.Unlock()
	return func() { s.endInstall(id) }
}

func TestSiteFoldersGoLiveBeforeAndJournal(t *testing.T) {
	s, f := webStore(t)
	live := liveFixture(t, s)
	ctx := context.Background()
	p := fixtureProtection(live.Account.ID)
	// Only while a copy holds the account busy.
	if err := s.setSiteFolders(ctx, live.Account.ID, p, "test operator", "Move a website here"); !errors.Is(err, ErrConflict) {
		t.Fatalf("not busy: %v", err)
	}
	done := busy(s, live.Account.ID)
	defer done()
	if err := s.setSiteFolders(ctx, live.Account.ID, p, "test operator", "Move a website here"); err != nil {
		t.Fatal(err)
	}
	r := recordFor(t, s, live.Account.ID)
	if r.Pending != nil || r.Folders == "" || r.FoldersNext != "" || r.Account.Revision != live.Account.Revision+1 {
		t.Fatalf("record %+v", r)
	}
	if h := historyActions(t, s, live.Account.ID); h[len(h)-1] != "folders:succeeded" {
		t.Fatalf("journal %v", h)
	}
	site := siteOf(t, f.sites, live.Account.ID)
	if len(site.Folders) != 2 || site.Folders[0].Realm == nil {
		t.Fatalf("site %+v", site)
	}
	if got := f.realms[siteName(live.Account.ID)][olsweb.RealmFile(siteName(live.Account.ID), 1)]; string(got) != fixtureUserFile {
		t.Fatalf("realm file %q", got)
	}
	// The same set again changes nothing; another set is refused.
	if err := s.setSiteFolders(ctx, live.Account.ID, p, "test operator", "again"); err != nil {
		t.Fatal(err)
	}
	other := fixtureProtection(live.Account.ID)
	other.Folders = other.Folders[1:]
	other.Users = map[string][]byte{}
	if err := s.setSiteFolders(ctx, live.Account.ID, other, "test operator", "x"); !errors.Is(err, ErrConflict) {
		t.Fatalf("a second set: %v", err)
	}
	// Later web changes keep the folders in the rendered site.
	done()
	r = recordFor(t, s, live.Account.ID)
	if _, err := s.setWeb(ctx, live.Account.ID, WebInput{PHPVersion: "8.4", QuotaMiB: 200, ExpectedRevision: r.Account.Revision, Reason: "x"}, "test operator"); err != nil {
		t.Fatal(err)
	}
	if site := siteOf(t, f.sites, live.Account.ID); len(site.Folders) != 2 {
		t.Fatalf("folders lost: %+v", site)
	}
	// Delete takes the realm files away.
	r = recordFor(t, s, live.Account.ID)
	if _, err := s.delete(ctx, live.Account.ID, DeleteInput{ExpectedRevision: r.Account.Revision, Reason: "Closed"}, "test operator"); err != nil {
		t.Fatal(err)
	}
	if _, ok := f.realms[siteName(live.Account.ID)]; ok || len(f.realmsRemoved) == 0 {
		t.Fatalf("realm files outlived the delete: %v", f.realmsRemoved)
	}
}

// TestSiteFoldersWithoutRealm: closed folders and address lists need no
// user file, so none is written and the folders still go live.
func TestSiteFoldersWithoutRealm(t *testing.T) {
	s, f := webStore(t)
	live := liveFixture(t, s)
	ctx := context.Background()
	defer busy(s, live.Account.ID)()
	p := SiteProtection{Folders: []olsweb.Folder{
		{Path: "/internal/", Hosts: olsweb.HostsOnly, Networks: []string{"192.0.2.0/24"}},
		{Path: "/wp-content/plugins/akismet/", Hosts: olsweb.HostsNone, Allow: []string{"akismet.css", "form.js"}},
	}, Users: map[string][]byte{}}
	if err := s.setSiteFolders(ctx, live.Account.ID, p, "test operator", "Move a website here"); err != nil {
		t.Fatal(err)
	}
	if r := recordFor(t, s, live.Account.ID); r.Folders == "" || r.Pending != nil {
		t.Fatalf("record %+v", r)
	}
	if _, ok := f.realms[siteName(live.Account.ID)]; ok {
		t.Fatal("user files written for folders without a realm")
	}
	if site := siteOf(t, f.sites, live.Account.ID); len(site.Folders) != 2 {
		t.Fatalf("site %+v", site)
	}
}

// TestSiteNamesRedirectsAndErrorPages: a migrated WordPress site's root
// .htaccess converts to names closed at the root, redirects and error
// pages, with no folder and no user file; they go live and stay in the
// rendered site.
func TestSiteNamesRedirectsAndErrorPages(t *testing.T) {
	s, f := webStore(t)
	live := liveFixture(t, s)
	ctx := context.Background()
	defer busy(s, live.Account.ID)()
	p := SiteProtection{
		Folders:    []olsweb.Folder{{Path: "/", Hosts: olsweb.HostsAll, Deny: &olsweb.DenyNames{Names: []string{"wp-config.php", "xmlrpc.php"}}}},
		Users:      map[string][]byte{},
		Redirects:  []olsweb.HtaccessRedirect{{Prefix: "/old-page", Target: "https://example.com/new-page", Status: 301}, {Pattern: "^/blog/(.*)$", Target: "/news/$1", Status: 302}},
		ErrorPages: []olsweb.ErrorPage{{Status: 404, URL: "/404.html"}},
	}
	if err := s.setSiteFolders(ctx, live.Account.ID, p, "test operator", "Move a website here"); err != nil {
		t.Fatal(err)
	}
	site := siteOf(t, f.sites, live.Account.ID)
	if len(site.Folders) != 1 || site.Folders[0].Deny == nil || len(site.HtaccessRedirects) != 2 || site.HtaccessRedirects[1].Pattern == "" || len(site.ErrorPages) != 1 {
		t.Fatalf("site %+v", site)
	}
	if _, ok := f.realms[siteName(live.Account.ID)]; ok {
		t.Fatal("user files written without a realm")
	}
}

// Redirects alone, without a folder, are a set of their own.
func TestSiteRedirectsWithoutFolders(t *testing.T) {
	s, f := webStore(t)
	live := liveFixture(t, s)
	defer busy(s, live.Account.ID)()
	p := SiteProtection{Users: map[string][]byte{}, Redirects: []olsweb.HtaccessRedirect{{Prefix: "/", Target: "https://new.example.com/", Status: 301}}}
	if err := s.setSiteFolders(context.Background(), live.Account.ID, p, "test operator", "Move a website here"); err != nil {
		t.Fatal(err)
	}
	if site := siteOf(t, f.sites, live.Account.ID); len(site.Folders) != 0 || len(site.HtaccessRedirects) != 1 {
		t.Fatalf("site %+v", site)
	}
}

func TestSiteFoldersRefusals(t *testing.T) {
	s, f := webStore(t)
	live := liveFixture(t, s)
	ctx := context.Background()
	defer busy(s, live.Account.ID)()
	site := siteName(live.Account.ID)
	bad := map[string]SiteProtection{
		"no folders":        {},
		"missing user file": {Folders: fixtureProtection(live.Account.ID).Folders, Users: map[string][]byte{}},
		"extra user file":   {Folders: fixtureProtection(live.Account.ID).Folders[1:], Users: map[string][]byte{olsweb.RealmFile(site, 1): []byte(fixtureUserFile)}},
		"plain password":    {Folders: fixtureProtection(live.Account.ID).Folders, Users: map[string][]byte{olsweb.RealmFile(site, 1): []byte("alice:secret\n")}},
		"not normalized":    {Folders: fixtureProtection(live.Account.ID).Folders, Users: map[string][]byte{olsweb.RealmFile(site, 1): []byte("# c\n" + fixtureUserFile)}},
		"other site file":   {Folders: []olsweb.Folder{{Path: "/m/", Hosts: olsweb.HostsAll, Realm: &olsweb.FolderRealm{Name: "m", UserFile: olsweb.RealmFile("uother", 1)}}}, Users: map[string][]byte{olsweb.RealmFile("uother", 1): []byte(fixtureUserFile)}},
		"open folder":       {Folders: []olsweb.Folder{{Path: "/m/", Hosts: olsweb.HostsAll}}},
		"root folder rule":  {Folders: []olsweb.Folder{{Path: "/", Hosts: olsweb.HostsNone}}},
		"bad deny name":     {Folders: []olsweb.Folder{{Path: "/", Hosts: olsweb.HostsAll, Deny: &olsweb.DenyNames{Names: []string{"a|b"}}}}},
		"bad redirect":      {Redirects: []olsweb.HtaccessRedirect{{Prefix: "/a", Target: "/b%{HTTP_HOST}", Status: 301}}},
		"redirect status":   {Redirects: []olsweb.HtaccessRedirect{{Prefix: "/a", Target: "/b", Status: 307}}},
		"bad error page":    {ErrorPages: []olsweb.ErrorPage{{Status: 404, URL: "https://example.com/404"}}},
	}
	for name, p := range bad {
		if err := s.setSiteFolders(ctx, live.Account.ID, p, "test operator", "x"); !errors.Is(err, ErrInvalid) {
			t.Errorf("%s: %v", name, err)
		}
	}
	if len(f.realms) != 0 || recordFor(t, s, live.Account.ID).Folders != "" {
		t.Fatal("a refusal wrote something")
	}
}

func TestSiteFoldersRejectedConfigChangesNothing(t *testing.T) {
	s, f := webStore(t)
	live := liveFixture(t, s)
	ctx := context.Background()
	defer busy(s, live.Account.ID)()
	f.failure = "sites-reject"
	if err := s.setSiteFolders(ctx, live.Account.ID, fixtureProtection(live.Account.ID), "test operator", "x"); !errors.Is(err, ErrWebRejected) {
		t.Fatalf("rejected config: %v", err)
	}
	r := recordFor(t, s, live.Account.ID)
	if r.Pending != nil || r.Folders != "" || r.FoldersNext != "" || r.Account != live.Account {
		t.Fatalf("a rejected change left %+v", r)
	}
	if _, ok := f.realms[siteName(live.Account.ID)]; ok {
		t.Fatal("a rejected change left its realm files")
	}
	if h := historyActions(t, s, live.Account.ID); h[len(h)-1] != "folders:rejected" {
		t.Fatalf("journal %v", h)
	}
}

func TestSiteFoldersInterruptedApplyIsFinishedByRefresh(t *testing.T) {
	s, f := webStore(t)
	live := liveFixture(t, s)
	ctx := context.Background()
	done := busy(s, live.Account.ID)
	f.failure = "sites"
	if err := s.setSiteFolders(ctx, live.Account.ID, fixtureProtection(live.Account.ID), "test operator", "x"); !errors.Is(err, ErrRecovery) {
		t.Fatalf("failed apply: %v", err)
	}
	done()
	r := recordFor(t, s, live.Account.ID)
	if r.Pending == nil || r.Pending.Action != "folders" || r.FoldersNext == "" || r.Folders != "" {
		t.Fatalf("pending folders op not durable: %+v", r)
	}
	f.failure = ""
	s.mu.Lock()
	err := s.refresh(ctx, true)
	s.mu.Unlock()
	if err != nil {
		t.Fatal(err)
	}
	r = recordFor(t, s, live.Account.ID)
	if r.Pending != nil || r.FoldersNext != "" || r.Folders == "" || r.Account.Revision != live.Account.Revision+1 {
		t.Fatalf("refresh did not finish the folders op: %+v", r)
	}
	if h := historyActions(t, s, live.Account.ID); h[len(h)-1] != "folders:reconciled" {
		t.Fatalf("journal %v", h)
	}
	if site := siteOf(t, f.sites, live.Account.ID); len(site.Folders) != 2 {
		t.Fatalf("site %+v", site)
	}
}

// TestMigrateFilesProtectsTheSiteFirst: the copy's protection goes live
// through the journaled folders operation before the engine copies, and a
// config that refuses it stops the copy with a tier error.
func TestMigrateFilesProtectsTheSiteFirst(t *testing.T) {
	s, f, _ := migrateStore(t)
	native := s.native.(*fakeNative)
	s.web = &WebOptions{ServerUser: "nobody"}
	ctx := context.Background()
	m := pinnedMigration(t, s)
	live := liveFixture(t, s)
	f.protection = fixtureProtection(live.Account.ID)
	got, err := s.migrateFiles(ctx, live.Account.ID, MigrateFilesInput{Migration: m.ID, ExpectedRevision: live.Account.Revision, Reason: "Move a website here"}, "test operator")
	if err != nil {
		t.Fatal(err)
	}
	r := recordFor(t, s, live.Account.ID)
	if r.Folders == "" || len(siteOf(t, native.sites, live.Account.ID).Folders) != 2 || len(s.installing) != 0 {
		t.Fatalf("record %+v", r)
	}
	// The folders raised the revision; the panel's next step needs it.
	if r.Account.Revision != live.Account.Revision+1 || got.Revision != r.Account.Revision {
		t.Fatalf("revision: answered %d, stored %d, before %d", got.Revision, r.Account.Revision, live.Account.Revision)
	}

	s2, f2, _ := migrateStore(t)
	native2 := s2.native.(*fakeNative)
	s2.web = &WebOptions{ServerUser: "nobody"}
	m2 := pinnedMigration(t, s2)
	live2 := liveFixture(t, s2)
	f2.protection = fixtureProtection(live2.Account.ID)
	native2.failure = "sites-reject"
	_, err = s2.migrateFiles(ctx, live2.Account.ID, MigrateFilesInput{Migration: m2.ID, ExpectedRevision: live2.Account.Revision, Reason: "Move a website here"}, "test operator")
	var failed *MigrationError
	if !errors.As(err, &failed) || failed.Step != "tier" {
		t.Fatalf("a refused config: %v", err)
	}
	if recordFor(t, s2, live2.Account.ID).Folders != "" {
		t.Fatal("refused folders were recorded")
	}
}

func TestSiteFoldersStoredFormIsChecked(t *testing.T) {
	id := strings.Repeat("a", 32)
	p := fixtureProtection(id)
	f := siteFolders{Folders: p.Folders, Users: map[string]string{olsweb.RealmFile(siteName(id), 1): strings.Repeat("0", 64)}}
	encoded := encodeFolders(f)
	if !validStoredFolders(id, encoded) || !validStoredFolders(id, "") {
		t.Fatal("a valid set was refused")
	}
	for name, bad := range map[string]string{
		"other account": strings.Repeat("b", 32),
		"bad id":        "x",
	} {
		if validStoredFolders(bad, encoded) {
			t.Errorf("%s: accepted", name)
		}
	}
	noDigest := siteFolders{Folders: p.Folders, Users: map[string]string{}}
	badRedirect := siteFolders{Users: map[string]string{}, Redirects: []olsweb.HtaccessRedirect{{Prefix: "/a", Target: "/b$1", Status: 301}}}
	for name, bad := range map[string]string{
		"spaces":       strings.Replace(encoded, `{"folders"`, `{ "folders"`, 1),
		"unknown":      strings.Replace(encoded, `{"folders"`, `{"x":1,"folders"`, 1),
		"no digest":    encodeFolders(noDigest),
		"too big":      encoded + strings.Repeat(" ", maxFoldersBytes),
		"bad redirect": encodeFolders(badRedirect),
		"empty":        `{"folders":null,"users":{}}`,
	} {
		if validStoredFolders(id, bad) {
			t.Errorf("%s: accepted", name)
		}
	}
	// A set from before the redirects keeps its stored form.
	if strings.Contains(encoded, "redirects") || strings.Contains(encoded, "error_pages") || strings.Contains(encoded, "deny") {
		t.Fatalf("an older set's form changed: %s", encoded)
	}
	moved := siteFolders{Users: map[string]string{}, Redirects: []olsweb.HtaccessRedirect{{Prefix: "/a", Target: "/b", Status: 301}}, ErrorPages: []olsweb.ErrorPage{{Status: 404, URL: "/404.html"}}}
	if !validStoredFolders(id, encodeFolders(moved)) {
		t.Fatal("redirects without folders were refused")
	}
}
