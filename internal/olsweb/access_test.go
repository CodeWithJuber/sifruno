package olsweb

import (
	"errors"
	"fmt"
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
