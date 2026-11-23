package olsweb

import (
	"reflect"
	"strconv"
	"testing"
)

func TestMakePlan(t *testing.T) {
	before := baseServer()
	prev, err := Render(before)
	if err != nil {
		t.Fatal(err)
	}
	after := baseServer()
	after.Sites[0].PHPVersion = "8.4"                         // blog changes
	after.Sites = append(after.Sites[:1], after.Sites[2:]...) // legacy goes away
	after.Sites = append(after.Sites, Site{Name: "fresh", Username: "freshuser", Group: "freshuser", Domains: []string{"fresh.example.com"}, DocRoot: "/home/freshuser/public_html", PHPVersion: "8.3"})
	next, err := Render(after)
	if err != nil {
		t.Fatal(err)
	}
	p, err := MakePlan(prev, next)
	if err != nil {
		t.Fatal(err)
	}
	want := Plan{
		Write:  []string{VhostConfigPath("blog"), VhostConfigPath("fresh"), ServerConfigPath},
		Remove: []string{VhostConfigPath("legacy")},
	}
	if !reflect.DeepEqual(p, want) {
		t.Fatalf("plan %+v, want %+v", p, want)
	}

	same, err := MakePlan(next, next)
	if err != nil {
		t.Fatal(err)
	}
	if len(same.Write) != 0 || len(same.Remove) != 0 {
		t.Fatalf("unchanged set produced work: %+v", same)
	}

	first, err := MakePlan(nil, next)
	if err != nil {
		t.Fatal(err)
	}
	if len(first.Write) != len(next) || first.Write[len(first.Write)-1] != ServerConfigPath || len(first.Remove) != 0 {
		t.Fatalf("first apply plan %+v", first)
	}
}

// TestMakePlanRefusesForeignPaths keeps a crafted previous or next set from
// directing writes or removals at files Sifruno does not own.
func TestMakePlanRefusesForeignPaths(t *testing.T) {
	next, err := Render(baseServer())
	if err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{
		"/etc/passwd", "../conf/httpd_config.conf", "conf/httpd_config.conf", "conf/vhosts/Example/vhconf.conf",
		"conf/vhosts/sifruno-../vhconf.conf", "conf/vhosts/sifruno-a/b/vhconf.conf", "conf/vhosts/sifruno-blog/htpasswd",
		"conf/vhosts/sifruno-blog/vhconf.conf/", "conf/vhosts/sifruno-Blog/vhconf.conf", "conf//sifruno.conf",
		"/usr/local/lsws/conf/sifruno.conf", "conf/vhosts/sifruno-/vhconf.conf", "",
	} {
		prev := map[string][]byte{ServerConfigPath: nil, path: []byte("x")}
		if _, err := MakePlan(prev, next); err == nil {
			t.Errorf("previous set with %q was accepted", path)
		}
		bad := map[string][]byte{ServerConfigPath: nil, path: []byte("x")}
		if _, err := MakePlan(nil, bad); err == nil {
			t.Errorf("new set with %q was accepted", path)
		}
	}
	if _, err := MakePlan(next, map[string][]byte{VhostConfigPath("blog"): nil}); err == nil {
		t.Error("a new set without the server fragment was accepted")
	}
	huge := map[string][]byte{ServerConfigPath: nil}
	for i := 0; i <= MaxSites; i++ {
		huge[VhostConfigPath("s"+strconv.Itoa(i))] = nil
	}
	if _, err := MakePlan(huge, next); err == nil {
		t.Error("an oversized previous set was accepted")
	}
}
