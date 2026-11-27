package olsweb

import (
	"errors"
	"fmt"
	"regexp"
	"strings"
	"testing"
)

func folderSite(folders ...Folder) Server {
	return Server{Listeners: []Listener{{Name: "http", Address: "*", Port: 80}}, Sites: []Site{{
		Name: "blog", Username: "blogowner", Group: "blogowner", Domains: []string{"example.com"},
		DocRoot: "/home/blogowner/public_html", PHPVersion: "8.3", Folders: folders,
	}}}
}

func TestFolderValidation(t *testing.T) {
	realm := func(n int) *FolderRealm { return &FolderRealm{Name: "Staff", UserFile: RealmFile("blog", n)} }
	ok := [][]Folder{
		{{Path: "/a/", Hosts: HostsNone}},
		{{Path: "/a/", Hosts: HostsNone, Allow: []string{"a.css", "b.js"}}, {Path: "/b/", Hosts: HostsAll, Realm: realm(2)}},
		{{Path: "/a.b/c~d@e_f-g/", Hosts: HostsOnly, Networks: []string{"192.0.2.0/24", "2001:db8::1/128"}}},
		{{Path: "/a/", Hosts: HostsExcept, Networks: []string{"10.0.0.0/8"}, Realm: &FolderRealm{Name: "A b", UserFile: RealmFile("blog", 1), Users: []string{"a", "b"}}}},
	}
	for i, folders := range ok {
		if err := Validate(folderSite(folders...)); err != nil {
			t.Errorf("ok[%d]: %v", i, err)
		}
	}
	bad := map[string][]Folder{
		"root":              {{Path: "/", Hosts: HostsNone}},
		"no slash":          {{Path: "/a", Hosts: HostsNone}},
		"hidden":            {{Path: "/.well-known/", Hosts: HostsNone}},
		"dot dot":           {{Path: "/a/../", Hosts: HostsNone}},
		"space":             {{Path: "/a b/", Hosts: HostsNone}},
		"regex char":        {{Path: "/a(b)/", Hosts: HostsNone}},
		"unsorted":          {{Path: "/b/", Hosts: HostsNone}, {Path: "/a/", Hosts: HostsNone}},
		"twice":             {{Path: "/a/", Hosts: HostsNone}, {Path: "/a/", Hosts: HostsNone}},
		"nested":            {{Path: "/a/", Hosts: HostsNone}, {Path: "/a/b/", Hosts: HostsNone}},
		"open":              {{Path: "/a/", Hosts: HostsAll}},
		"kind":              {{Path: "/a/", Hosts: "some"}},
		"networks on none":  {{Path: "/a/", Hosts: HostsNone, Networks: []string{"10.0.0.0/8"}}},
		"only without list": {{Path: "/a/", Hosts: HostsOnly}},
		"host bits":         {{Path: "/a/", Hosts: HostsOnly, Networks: []string{"10.0.0.1/8"}}},
		"zero bits":         {{Path: "/a/", Hosts: HostsOnly, Networks: []string{"0.0.0.0/0"}}},
		"not canonical":     {{Path: "/a/", Hosts: HostsOnly, Networks: []string{"2001:DB8::/32"}}},
		"unsorted networks": {{Path: "/a/", Hosts: HostsOnly, Networks: []string{"192.0.2.0/24", "10.0.0.0/8"}}},
		"allow on only":     {{Path: "/a/", Hosts: HostsOnly, Networks: []string{"10.0.0.0/8"}, Allow: []string{"a.css"}}},
		"allow script":      {{Path: "/a/", Hosts: HostsNone, Allow: []string{"index.php"}}},
		"allow no suffix":   {{Path: "/a/", Hosts: HostsNone, Allow: []string{"README"}}},
		"allow pipe":        {{Path: "/a/", Hosts: HostsNone, Allow: []string{"a|b.css"}}},
		"realm on none":     {{Path: "/a/", Hosts: HostsNone, Realm: realm(1)}},
		"realm name brace":  {{Path: "/a/", Hosts: HostsAll, Realm: &FolderRealm{Name: "a{", UserFile: RealmFile("blog", 1)}}},
		"realm name spaces": {{Path: "/a/", Hosts: HostsAll, Realm: &FolderRealm{Name: "a  b", UserFile: RealmFile("blog", 1)}}},
		"realm other file":  {{Path: "/a/", Hosts: HostsAll, Realm: &FolderRealm{Name: "a", UserFile: "/home/blogowner/.htpasswd"}}},
		"realm other site":  {{Path: "/a/", Hosts: HostsAll, Realm: &FolderRealm{Name: "a", UserFile: RealmFile("shop", 1)}}},
		"realm wrong index": {{Path: "/a/", Hosts: HostsAll, Realm: realm(2)}},
		"realm user":        {{Path: "/a/", Hosts: HostsAll, Realm: &FolderRealm{Name: "a", UserFile: RealmFile("blog", 1), Users: []string{"a b"}}}},
	}
	for name, folders := range bad {
		t.Run(name, func(t *testing.T) {
			err := Validate(folderSite(folders...))
			var fe *FieldError
			if !errors.As(err, &fe) || !strings.Contains(fe.Field, "folders") {
				t.Fatalf("got %v", err)
			}
		})
	}
}

// TestExceptFolderNeedsIPv4Listeners: a deny list would miss IPv4 clients
// that an IPv6 listener sees as ::ffff: addresses, so it is refused there;
// an allow list fails closed and is kept.
func TestExceptFolderNeedsIPv4Listeners(t *testing.T) {
	except := Folder{Path: "/a/", Hosts: HostsExcept, Networks: []string{"203.0.113.0/24"}}
	only := Folder{Path: "/a/", Hosts: HostsOnly, Networks: []string{"203.0.113.0/24"}}
	s := folderSite(except)
	if err := Validate(s); err != nil {
		t.Fatalf("IPv4 listener: %v", err)
	}
	s.Listeners = append(s.Listeners, Listener{Name: "http6", Address: "::", Port: 8080})
	var fe *FieldError
	if err := Validate(s); !errors.As(err, &fe) || fe.Field != "sites[0].folders[0].hosts" {
		t.Fatalf("IPv6 listener: %v", err)
	}
	s.Sites[0].Folders = []Folder{only}
	if err := Validate(s); err != nil {
		t.Fatalf("allow list with an IPv6 listener: %v", err)
	}
}

func TestFolderPattern(t *testing.T) {
	cases := map[string]Folder{
		`(?s)^/a[.]b/c/.*`: {Path: "/a.b/c/", Hosts: HostsNone},
		`(?s)^/p/(?!(?:[^/.]+/)*(?:a[.]css|b-c@2x[.]png)(?!.)).*`: {Path: "/p/", Hosts: HostsNone, Allow: []string{"a.css", "b-c@2x.png"}},
	}
	for want, f := range cases {
		if got := folderPattern(f); got != want {
			t.Errorf("got %s want %s", got, want)
		}
	}
}

func TestDenyFolderValidation(t *testing.T) {
	names := &DenyNames{Names: []string{".user.ini", "wp-config.php", "xmlrpc.php"}, Endings: []string{".sql", "~"}}
	ok := [][]Folder{
		{{Path: "/", Hosts: HostsAll, Deny: names}},
		{{Path: "/", Hosts: HostsAll, Deny: names}, {Path: "/a/", Hosts: HostsNone}, {Path: "/a/b/", Hosts: HostsAll, Deny: names}},
		{{Path: "/a/", Hosts: HostsOnly, Networks: []string{"192.0.2.0/24"}, Deny: names}},
		{{Path: "/a/", Hosts: HostsAll, Realm: &FolderRealm{Name: "a", UserFile: RealmFile("blog", 1)}, Deny: &DenyNames{Names: []string{".htpasswd"}}}},
	}
	for i, folders := range ok {
		if err := Validate(folderSite(folders...)); err != nil {
			t.Errorf("ok[%d]: %v", i, err)
		}
	}
	bad := map[string][]Folder{
		"root folder rule":  {{Path: "/", Hosts: HostsOnly, Networks: []string{"192.0.2.0/24"}, Deny: names}},
		"root without deny": {{Path: "/", Hosts: HostsAll}},
		"empty":             {{Path: "/a/", Hosts: HostsAll, Deny: &DenyNames{}}},
		"closed folder":     {{Path: "/a/", Hosts: HostsNone, Deny: names}},
		"unsorted":          {{Path: "/a/", Hosts: HostsAll, Deny: &DenyNames{Names: []string{"b", "a"}}}},
		"twice":             {{Path: "/a/", Hosts: HostsAll, Deny: &DenyNames{Endings: []string{".sql", ".sql"}}}},
		"slash":             {{Path: "/a/", Hosts: HostsAll, Deny: &DenyNames{Names: []string{"a/b"}}}},
		"regex char":        {{Path: "/a/", Hosts: HostsAll, Deny: &DenyNames{Names: []string{"a|b"}}}},
		"plus":              {{Path: "/a/", Hosts: HostsAll, Deny: &DenyNames{Endings: []string{"+"}}}},
		"dot dot":           {{Path: "/a/", Hosts: HostsAll, Deny: &DenyNames{Names: []string{".."}}}},
		"brace":             {{Path: "/a/", Hosts: HostsAll, Deny: &DenyNames{Names: []string{"a{"}}}},
		"nested folders":    {{Path: "/", Hosts: HostsAll, Deny: names}, {Path: "/a/", Hosts: HostsNone}, {Path: "/a/b/", Hosts: HostsNone}},
	}
	for name, folders := range bad {
		t.Run(name, func(t *testing.T) {
			err := Validate(folderSite(folders...))
			var fe *FieldError
			if !errors.As(err, &fe) || !strings.Contains(fe.Field, "folders") {
				t.Fatalf("got %v", err)
			}
		})
	}
}

// goDenyPattern is denyPattern's regex for Go's engine, which has no
// lookahead: (?!.) at the end is \z, and the challenge path's lookahead is
// left out and checked on its own.
func goDenyPattern(p string) *regexp.Regexp {
	p = strings.Replace(p, "(?!"+acmeToken+")", "", 1)
	return regexp.MustCompile(strings.TrimSuffix(p, "(?!.)") + `\z`)
}

func TestDenyPattern(t *testing.T) {
	root := Folder{Path: "/", Hosts: HostsAll, Deny: &DenyNames{Names: []string{".user.ini", "wp-config.php", "xmlrpc.php"}, Endings: []string{".sql"}}}
	want := `(?s)^/(?![.]well-known/acme-challenge/[-_A-Za-z0-9]+(?!.))(?:(?:.*/)?(?:[.]user[.]ini|wp-config[.]php|xmlrpc[.]php|[^/]*[.]sql)(?:/.*)?)[[:cntrl:]]?(?!.)`
	if got := denyPattern(root); got != want {
		t.Fatalf("got  %s\nwant %s", got, want)
	}
	re := goDenyPattern(denyPattern(root))
	for path, closed := range map[string]bool{
		"/wp-config.php": true, "/blog/wp-config.php": true, "/xmlrpc.php/x": true, "/xmlrpc.php/": true,
		"/a/.user.ini": true, "/dump.sql": true, "/x/y/.sql": true, "/wp-config.php\n": true,
		"/wp-config.php.bak": false, "/my-wp-config.php": false, "/index.php": false, "/": false,
		"/dump.sql.gz": false, "/wp-config.phpx": false, "/wp-admin/": false, "/sql": false,
	} {
		if re.MatchString(path) != closed {
			t.Errorf("%q: closed %v, want %v", path, !closed, closed)
		}
	}
	// The challenge path is left out only for a bare token at the root.
	token := regexp.MustCompile("^/" + strings.TrimSuffix(acmeToken, "(?!.)") + `\z`)
	for path, left := range map[string]bool{
		"/.well-known/acme-challenge/AbC-_09": true, "/.well-known/acme-challenge/a.sql": false,
		"/.well-known/acme-challenge/../wp-config.php": false, "/.well-known/acme-challenge/a/b": false,
	} {
		if token.MatchString(path) != left {
			t.Errorf("%q: left out %v", path, !left)
		}
	}
	if strings.Contains(denyPattern(Folder{Path: "/a/", Hosts: HostsAll, Deny: root.Deny}), "acme") {
		t.Error("a folder below the root leaves the challenge path out")
	}
	// Names that include an index file close each folder's own address.
	uploads := Folder{Path: "/wp-content/uploads/", Hosts: HostsAll, Deny: &DenyNames{Endings: []string{".php"}}}
	re = goDenyPattern(denyPattern(uploads))
	for path, closed := range map[string]bool{
		"/wp-content/uploads/": true, "/wp-content/uploads/2026/": true, "/wp-content/uploads/a.php": true,
		"/wp-content/uploads/a.php/b.jpg": true, "/wp-content/uploads/a.jpg": false, "/wp-content/": false,
	} {
		if re.MatchString(path) != closed {
			t.Errorf("%q: closed %v, want %v", path, !closed, closed)
		}
	}
}

// The names' contexts come before every folder's, so the first regex
// context that matches is a names context whenever one matches.
func TestNamesContextsComeFirst(t *testing.T) {
	s := folderSite(
		Folder{Path: "/", Hosts: HostsAll, Deny: &DenyNames{Names: []string{"wp-config.php"}}},
		Folder{Path: "/a/", Hosts: HostsOnly, Networks: []string{"192.0.2.0/24"}, Deny: &DenyNames{Names: []string{"secret.json"}}},
	)
	files, err := Render(s)
	if err != nil {
		t.Fatal(err)
	}
	vh := string(files[VhostConfigPath("blog")])
	var contexts []string
	for _, line := range strings.Split(vh, "\n") {
		if strings.HasPrefix(line, "context exp:") {
			contexts = append(contexts, line)
		}
	}
	if len(contexts) != 3 || !strings.Contains(contexts[0], "wp-config") || !strings.Contains(contexts[1], "secret") || !strings.HasPrefix(contexts[2], "context exp:(?s)^/a/.*") {
		t.Fatalf("contexts %q", contexts)
	}
	if _, err := confShape(files[VhostConfigPath("blog")]); err != nil {
		t.Fatal(err)
	}
}

func TestSuspendedSiteHasNoFolders(t *testing.T) {
	s := folderSite(Folder{Path: "/a/", Hosts: HostsAll, Realm: &FolderRealm{Name: "a", UserFile: RealmFile("blog", 1)}})
	s.Sites[0].Suspended = true
	files, err := Render(s)
	if err != nil {
		t.Fatal(err)
	}
	if vh := string(files[VhostConfigPath("blog")]); strings.Contains(vh, "realm") || strings.Contains(vh, "exp:") {
		t.Fatalf("suspended vhost names a folder:\n%s", vh)
	}
}

// FuzzFolder feeds arbitrary folder values through the validator. A refusal
// must be a FieldError. An accepted folder must render with exactly the
// structure of a reference folder of the same kind with placeholder values,
// so no value adds a line, opens or closes a block or starts a heredoc.
func FuzzFolder(f *testing.F) {
	f.Add("/members/", "all", "", "", "Members only", "alice", false)
	f.Add("/wp-content/plugins/akismet/", "none", "", "akismet.css", "", "", false)
	f.Add("/internal/", "only", "192.0.2.0/24", "", "", "", false)
	f.Add("/staff/", "except", "2001:db8::/32", "", "Staff", "", true)
	f.Add("/a{/", "none", "", "a.css\n}", "x\ny", "u v", true)
	f.Fuzz(func(t *testing.T, path, hosts, network, name, realmName, user string, withRealm bool) {
		folder := Folder{Path: path, Hosts: hosts}
		if network != "" {
			folder.Networks = []string{network}
		}
		if name != "" {
			folder.Allow = []string{name}
		}
		if withRealm || realmName != "" {
			folder.Realm = &FolderRealm{Name: realmName, UserFile: RealmFile("blog", 1)}
			if user != "" {
				folder.Realm.Users = []string{user}
			}
		}
		in := folderSite(folder)
		err := Validate(in)
		if err != nil {
			var fe *FieldError
			if !errors.As(err, &fe) || fe.Field == "" {
				t.Fatalf("refusal is not a named FieldError: %v", err)
			}
			return
		}
		got, err := Render(in)
		if err != nil {
			t.Fatalf("validated folder failed to render: %v", err)
		}
		ref := Folder{Path: "/qqpath/", Hosts: hosts}
		if network != "" {
			if strings.Contains(network, ":") {
				ref.Networks = []string{"2001:db8::/32"}
			} else {
				ref.Networks = []string{"192.0.2.0/24"}
			}
		}
		if name != "" {
			ref.Allow = []string{"qq.css"}
		}
		if folder.Realm != nil {
			ref.Realm = &FolderRealm{Name: "Qq", UserFile: RealmFile("blog", 1)}
			if user != "" {
				ref.Realm.Users = []string{"qquser"}
			}
		}
		want, err := Render(folderSite(ref))
		if err != nil {
			t.Fatalf("reference failed: %v", err)
		}
		checkAnchoring(t, folder)
		path0 := VhostConfigPath("blog")
		gotShape, err := confShape(got[path0])
		if err != nil {
			t.Fatalf("%v\n%s", err, got[path0])
		}
		wantShape, err := confShape(want[path0])
		if err != nil {
			t.Fatalf("reference: %v", err)
		}
		if fmt.Sprint(gotShape) != fmt.Sprint(wantShape) {
			t.Fatalf("structure differs from the reference\n%s", got[path0])
		}
	})
}

// checkAnchoring checks what the rendered regex covers, with Go's regexp on
// its prefix (Go has no lookahead): it matches the folder and everything
// below it, and neither a sibling whose name only starts the same
// (/privateX/), the folder without its slash, nor the same name deeper
// (/pub/private/). The lookahead, when there is one, holds exactly the
// open names.
func checkAnchoring(t *testing.T, f Folder) {
	t.Helper()
	pattern := folderPattern(f)
	prefix, look, hasLook := strings.Cut(pattern, "(?!")
	prefix = strings.TrimSuffix(prefix, ".*")
	re, err := regexp.Compile(prefix)
	if err != nil {
		t.Fatalf("%s: %v", pattern, err)
	}
	trimmed := strings.TrimSuffix(f.Path, "/")
	for _, uri := range []string{f.Path, f.Path + "x", f.Path + "a/b.php", f.Path + "x\n"} {
		if !re.MatchString(uri) {
			t.Fatalf("%s does not cover %q", pattern, uri)
		}
	}
	for _, uri := range []string{trimmed + "X/", trimmed + "-x/y", trimmed, "/pub" + f.Path, "/pub" + f.Path + "x", strings.ToUpper(f.Path[:2]) + f.Path[2:] + "\x00"} {
		if uri == f.Path || strings.HasPrefix(uri, f.Path) {
			continue
		}
		if re.MatchString(uri) {
			t.Fatalf("%s covers %q, outside %s", pattern, uri, f.Path)
		}
	}
	if hasLook != (len(f.Allow) > 0) {
		t.Fatalf("%s: lookahead and allow list disagree", pattern)
	}
	if hasLook {
		names := make([]string, len(f.Allow))
		for i, n := range f.Allow {
			names[i] = regexQuote(n)
		}
		want := "(?:[^/.]+/)*(?:" + strings.Join(names, "|") + ")(?!.)).*"
		if look != want {
			t.Fatalf("lookahead %q, want %q", look, want)
		}
	}
}
