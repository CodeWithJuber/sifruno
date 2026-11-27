package htaccess

import (
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func writeTree(t *testing.T, root string, files map[string]string) {
	t.Helper()
	for rel, content := range files {
		path := filepath.Join(root, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
}

func mkdirs(t *testing.T, root string, dirs ...string) {
	t.Helper()
	for _, d := range dirs {
		if err := os.MkdirAll(filepath.Join(root, filepath.FromSlash(d)), 0o755); err != nil {
			t.Fatal(err)
		}
	}
}

func symlink(t *testing.T, target, link string) {
	t.Helper()
	if err := os.Symlink(target, link); err != nil {
		t.Skipf("symbolic links unavailable: %v", err)
	}
}

func scan(t *testing.T, root string, layout Layout, limits Limits) Report {
	t.Helper()
	r, err := Scan(root, layout, limits)
	if err != nil {
		t.Fatal(err)
	}
	return r
}

type siteSummary struct {
	Name    string
	Verdict Verdict
	Causes  []string
	Links   []string
	Files   []string
}

func summarize(r Report) []siteSummary {
	var out []siteSummary
	for _, s := range r.Sites {
		sum := siteSummary{Name: s.Name, Verdict: s.Verdict, Causes: s.Causes, Links: s.SymlinkedDirs}
		for _, f := range s.Files {
			sum.Files = append(sum.Files, f.Path+" "+f.URLPath+" "+string(f.Verdict))
		}
		out = append(out, sum)
	}
	return out
}

func TestScanSingleNestedProtection(t *testing.T) {
	root := t.TempDir()
	writeTree(t, root, map[string]string{
		".htaccess":               wordpressBlock,
		"members/.htaccess":       passwordProtected,
		"members/area/index.html": "x",
		"assets/htaccess.txt":     "Deny from all\n",
		"assets/.htaccess.bak":    "Deny from all\n",
	})
	r := scan(t, root, LayoutSingle, DefaultLimits())
	want := []siteSummary{{Name: ".", Verdict: VerdictCompat, Causes: []string{CauseAccessControl}, Files: []string{
		".htaccess / native",
		"members/.htaccess /members/ compat",
	}}}
	if got := summarize(r); !reflect.DeepEqual(got, want) {
		t.Fatalf("sites %+v, want %+v", got, want)
	}
	rules := r.Sites[0].Files[1].AccessRules
	if len(rules) != 1 || rules[0].Path != "/members/" || rules[0].Kind != AccessPassword || rules[0].ExpectStatus != 401 {
		t.Fatalf("access rules %+v", rules)
	}
	if f := r.Sites[0].Files[1].Findings[0]; f.File != "members/.htaccess" || f.Access.Path != "/members/" {
		t.Fatalf("finding %+v", f)
	}
	tt := r.Totals
	if tt.Sites != 1 || tt.Files != 2 || tt.CompatSitesNestedOnly != 1 || tt.CompatSitesByCauseSet["access_control"] != 1 ||
		tt.DirectivesByCategory[CategoryRewrite] != 7 || tt.DirectivesByCategory[CategoryAccessControl] != 4 || r.Truncated {
		t.Fatalf("totals %+v", tt)
	}
}

func TestScanDirLayout(t *testing.T) {
	root := t.TempDir()
	writeTree(t, root, map[string]string{
		"alpha/.htaccess":       wordpressBlock,
		"beta/.htaccess":        cachePluginBlocks,
		"gamma/index.html":      "no htaccess",
		"delta/.htaccess":       "FooBar on\nWeird.Thing x\n",
		"notes.txt":             "a file at the root is not a site",
		".hidden/.htaccess":     "Deny from all\n",
		"beta/blog/.htaccess":   wordpressBlock,
		"alpha/deep/.htaccess2": "Deny from all\n",
	})
	r := scan(t, root, LayoutDir, DefaultLimits())
	// The blog copy keeps "RewriteBase /", which does not name /blog/, so it
	// is convertible rather than native; see the Unverified list in doc.go.
	want := []siteSummary{
		{Name: "alpha", Verdict: VerdictNative, Files: []string{"alpha/.htaccess / native"}},
		{Name: "beta", Verdict: VerdictConvertible, Files: []string{"beta/.htaccess / convertible", "beta/blog/.htaccess /blog/ convertible"}},
		{Name: "delta", Verdict: VerdictCompat, Causes: []string{CauseUnknown}, Files: []string{"delta/.htaccess / compat"}},
		{Name: "gamma", Verdict: VerdictNative},
	}
	if got := summarize(r); !reflect.DeepEqual(got, want) {
		t.Fatalf("sites %+v, want %+v", got, want)
	}
	tt := r.Totals
	wantVerdicts := map[Verdict]int{VerdictNative: 2, VerdictConvertible: 1, VerdictCompat: 1}
	if tt.Sites != 4 || !reflect.DeepEqual(tt.SitesByVerdict, wantVerdicts) || tt.SitesWithoutHtaccess != 1 || tt.Files != 4 {
		t.Fatalf("totals %+v", tt)
	}
	wantUnknown := []NameCount{{"(not a directive name)", 1}, {"foobar", 1}}
	if !reflect.DeepEqual(tt.TopUnknown, wantUnknown) {
		t.Fatalf("top unknown %+v", tt.TopUnknown)
	}
}

func TestScanSymlinksInsideSite(t *testing.T) {
	for _, tc := range []struct {
		name    string
		setup   func(t *testing.T, root string)
		verdict Verdict
		links   []string
	}{
		{"directory outside the site", func(t *testing.T, root string) {
			mkdirs(t, root, "other")
			symlink(t, "../other", filepath.Join(root, "site", "shared"))
		}, VerdictCompat, []string{"site/shared"}},
		{"absolute link to /etc", func(t *testing.T, root string) {
			symlink(t, "/etc", filepath.Join(root, "site", "etc"))
		}, VerdictCompat, []string{"site/etc"}},
		{"sibling directory inside the site", func(t *testing.T, root string) {
			mkdirs(t, root, "site/real")
			symlink(t, "real", filepath.Join(root, "site", "alias"))
		}, VerdictCompat, []string{"site/alias"}},
		{"dangling link", func(t *testing.T, root string) {
			symlink(t, "missing", filepath.Join(root, "site", "gone"))
		}, VerdictCompat, []string{"site/gone"}},
		{"link to a regular file", func(t *testing.T, root string) {
			writeTree(t, root, map[string]string{"site/real.txt": "x"})
			symlink(t, "real.txt", filepath.Join(root, "site", "copy.txt"))
		}, VerdictNative, nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			root := t.TempDir()
			writeTree(t, root, map[string]string{"site/.htaccess": wordpressBlock})
			tc.setup(t, root)
			r := scan(t, root, LayoutDir, DefaultLimits())
			var site SiteResult
			for _, s := range r.Sites {
				if s.Name == "site" {
					site = s
				}
			}
			if site.Verdict != tc.verdict || !reflect.DeepEqual(site.SymlinkedDirs, tc.links) {
				t.Fatalf("site %+v", site)
			}
			if tc.verdict == VerdictCompat {
				if !reflect.DeepEqual(site.Causes, []string{CauseSymlinkNotFollowed}) || r.Totals.SymlinkedDirsNotFollowed != 1 || r.Totals.CompatSitesByCause[CauseSymlinkNotFollowed] != 1 {
					t.Fatalf("site %+v totals %+v", site, r.Totals)
				}
			}
		})
	}
}

func TestScanCPanelLayout(t *testing.T) {
	root := t.TempDir()
	writeTree(t, root, map[string]string{
		"alice/public_html/.htaccess":             wordpressBlock,
		"alice/public_html/members/.htaccess":     passwordProtected,
		"alice/.htaccess":                         "Deny from all\n",
		"bob/public_html/.htaccess":               "php_value memory_limit 256M\n",
		"bob/public_html/addon.example/.htaccess": wordpressBlock,
		"dave/public_html":                        "a file, not a docroot",
		"frank/public_html/index.html":            "x",
	})
	mkdirs(t, root, "carol/mail", ".cpanel", "virtfs", "erin")
	symlink(t, "../alice/public_html", filepath.Join(root, "erin", "public_html"))
	r := scan(t, root, LayoutCPanel, DefaultLimits())
	want := []siteSummary{
		{Name: "alice/public_html", Verdict: VerdictCompat, Causes: []string{CauseAccessControl}, Files: []string{
			"alice/public_html/.htaccess / native",
			"alice/public_html/members/.htaccess /members/ compat",
		}},
		{Name: "bob/public_html", Verdict: VerdictConvertible, Files: []string{
			"bob/public_html/.htaccess / native",
			"bob/public_html/addon.example/.htaccess /addon.example/ convertible",
		}},
		{Name: "erin/public_html", Verdict: VerdictCompat, Causes: []string{CauseSymlinkNotFollowed}, Links: []string{"erin/public_html"}},
		{Name: "frank/public_html", Verdict: VerdictNative},
	}
	if got := summarize(r); !reflect.DeepEqual(got, want) {
		t.Fatalf("sites %+v, want %+v", got, want)
	}
	tt := r.Totals
	if tt.Sites != 4 || tt.AccountsWithoutDocroot != 3 || tt.SymlinkedDirsNotFollowed != 1 || tt.CompatSitesNestedOnly != 1 ||
		tt.CompatSitesByCause[CauseAccessControl] != 1 || tt.CompatSitesByCause[CauseSymlinkNotFollowed] != 1 || tt.SitesWithoutHtaccess != 2 {
		t.Fatalf("totals %+v", tt)
	}
}

func TestScanIrregularHtaccess(t *testing.T) {
	root := t.TempDir()
	writeTree(t, root, map[string]string{
		"linked/real.conf": "RewriteEngine On\n",
		"big/.htaccess":    "# " + string(make([]byte, MaxFileBytes)),
		"dirnamed/x":       "x",
		"plain/.htaccess":  "RewriteEngine On\n",
	})
	symlink(t, "real.conf", filepath.Join(root, "linked", ".htaccess"))
	mkdirs(t, root, "dirnamed/.htaccess")
	r := scan(t, root, LayoutDir, DefaultLimits())
	causes := map[string][]string{}
	for _, s := range r.Sites {
		causes[s.Name] = s.Causes
	}
	want := map[string][]string{
		"big":      {CauseOversizeFile},
		"dirnamed": {CauseIrregularFile},
		"linked":   {CauseIrregularFile},
		"plain":    nil,
	}
	if !reflect.DeepEqual(causes, want) {
		t.Fatalf("causes %v", causes)
	}
	if r.Totals.UnreadableFiles != 3 || r.Totals.Files != 4 {
		t.Fatalf("totals %+v", r.Totals)
	}
}

func TestScanLimitsTruncate(t *testing.T) {
	root := t.TempDir()
	writeTree(t, root, map[string]string{
		"a/.htaccess":       wordpressBlock,
		"a/x/y/z/.htaccess": wordpressBlock,
		"b/.htaccess":       wordpressBlock,
	})
	for _, tc := range []struct {
		name   string
		limits Limits
		sites  int
		causes []string
		full   bool
	}{
		{"depth", Limits{MaxDepth: 2, MaxFilesPerSite: 10, MaxEntriesPerSite: 100, MaxSites: 10}, 2, []string{CauseScanTruncated}, false},
		{"files", Limits{MaxDepth: 10, MaxFilesPerSite: 1, MaxEntriesPerSite: 100, MaxSites: 10}, 2, []string{CauseScanTruncated}, false},
		{"entries", Limits{MaxDepth: 10, MaxFilesPerSite: 10, MaxEntriesPerSite: 3, MaxSites: 10}, 2, []string{CauseScanTruncated}, false},
		{"sites", Limits{MaxDepth: 10, MaxFilesPerSite: 10, MaxEntriesPerSite: 100, MaxSites: 1}, 1, nil, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := scan(t, root, LayoutDir, tc.limits)
			if len(r.Sites) != tc.sites || !r.Truncated || r.Sites[0].Name != "a" || !reflect.DeepEqual(r.Sites[0].Causes, tc.causes) || r.SitesLimitReached != tc.full {
				t.Fatalf("report %+v", summarize(r))
			}
			if !tc.full && (r.Totals.TruncatedSites != 1 || r.Sites[0].Verdict != VerdictCompat) {
				t.Fatalf("totals %+v", r.Totals)
			}
		})
	}
}

func TestScanRejectsBadRoots(t *testing.T) {
	root := t.TempDir()
	file := filepath.Join(root, "file")
	writeTree(t, root, map[string]string{"file": "x"})
	for _, dir := range []string{filepath.Join(root, "missing"), file} {
		if _, err := Scan(dir, LayoutSingle, DefaultLimits()); !errors.Is(err, ErrRoot) {
			t.Fatalf("%s: %v", dir, err)
		}
	}
	if _, err := Scan(root, Layout("flat"), DefaultLimits()); !errors.Is(err, ErrInvalidOptions) {
		t.Fatalf("layout: %v", err)
	}
	if _, err := Scan(root, LayoutSingle, Limits{}); !errors.Is(err, ErrInvalidOptions) {
		t.Fatalf("limits: %v", err)
	}
}
