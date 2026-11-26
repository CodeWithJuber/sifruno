package olsweb

import (
	"errors"
	"fmt"
	"strings"
	"testing"
)

// The panel's own host names get one vhost on the plain listener that
// serves the HTTP-01 challenge folder and refuses everything else, so Let's
// Encrypt can validate the panel's certificate on port 80.
func TestChallengeHostsRenderChallengeOnlyVhost(t *testing.T) {
	s := baseServer()
	s.ChallengeHosts = []string{"panel.example.org", "admin.example.org"}
	files, err := Render(s)
	if err != nil {
		t.Fatal(err)
	}
	server := string(files[ServerConfigPath])
	const block = "\nvirtualhost sifruno-panel {\n" +
		"  vhRoot                  /var/lib/sifruno-suspended/\n" +
		"  configFile              /usr/local/lsws/conf/vhosts/sifruno-panel/vhconf.conf\n" +
		"  allowSymbolLink         0\n" +
		"  enableScript            0\n" +
		"  restrained              1\n" +
		"}\n"
	if strings.Count(server, "virtualhost sifruno-panel ") != 1 || !strings.Contains(server, block) {
		t.Fatalf("no challenge-only virtualhost:\n%s", server)
	}
	plain := listenerBlock(t, server, "sifruno-http")
	if !strings.Contains(plain, "  map                     sifruno-panel panel.example.org, admin.example.org\n") {
		t.Errorf("the plain listener does not map the panel's names:\n%s", plain)
	}
	if strings.Contains(listenerBlock(t, server, "sifruno-https"), "sifruno-panel") {
		t.Error("the secure listener maps the challenge-only vhost")
	}
	vhost := string(files[VhostConfigPath(PanelChallengeName)])
	for _, want := range []string{
		"docRoot                   /var/lib/sifruno-suspended/\n",
		"\ncontext /.well-known/acme-challenge/ {\n  location                /var/lib/sifruno-acme/\n",
		"  autoLoadHtaccess        0\n",
		"\nRewriteRule .* - [F,L]\n",
		"  ls_enabled              0\n",
		"  autoIndex               0\n",
	} {
		if !strings.Contains(vhost, want) {
			t.Errorf("vhconf lacks %q:\n%s", want, vhost)
		}
	}
	for _, refused := range []string{"extprocessor", "scripthandler", "vhssl", "/home/", "storagePath", "realm "} {
		if strings.Contains(vhost, refused) {
			t.Errorf("challenge-only vhconf has %q:\n%s", refused, vhost)
		}
	}
	if strings.Index(vhost, "context /.well-known/acme-challenge/") > strings.Index(vhost, "\nrewrite  {\n") {
		t.Error("the challenge context comes after the refusal")
	}
	if len(files) != len(s.Sites)+2 {
		t.Errorf("rendered %d files, want the sites, the server fragment and the challenge vhost", len(files))
	}
}

// Without the panel's names nothing changes: no extra vhost, no extra map.
func TestChallengeHostsNoneRendersAsBefore(t *testing.T) {
	before, err := Render(baseServer())
	if err != nil {
		t.Fatal(err)
	}
	s := baseServer()
	s.ChallengeHosts = []string{}
	after, err := Render(s)
	if err != nil {
		t.Fatal(err)
	}
	if len(before) != len(after) || string(before[ServerConfigPath]) != string(after[ServerConfigPath]) {
		t.Fatal("an empty list changed the render")
	}
	if strings.Contains(string(after[ServerConfigPath]), "sifruno-panel") {
		t.Fatal("a challenge vhost without names")
	}
}

// A name a website serves already, or its www. form (one name to
// OpenLiteSpeed), stays with the website, whose vhost serves the same
// challenge folder; only the rest go to the challenge-only vhost, and none
// left renders no such vhost.
func TestChallengeHostsLeaveWebsiteNamesToTheWebsite(t *testing.T) {
	s := baseServer()
	s.ChallengeHosts = []string{"www.shop.example.com", "panel.example.org"}
	files, err := Render(s)
	if err != nil {
		t.Fatal(err)
	}
	plain := listenerBlock(t, string(files[ServerConfigPath]), "sifruno-http")
	if !strings.Contains(plain, "  map                     sifruno-panel panel.example.org\n") || strings.Contains(plain, "sifruno-panel www.") || strings.Count(plain, "shop.example.com") != 1 {
		t.Errorf("wrong maps:\n%s", plain)
	}
	s.ChallengeHosts = []string{"example.com", "www.legacy.example.net"}
	files, err = Render(s)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(files[ServerConfigPath]), "sifruno-panel") || files[VhostConfigPath(PanelChallengeName)] != nil {
		t.Fatal("a challenge vhost for names only websites serve")
	}
	// With no website at all, port 80 still answers the panel's names.
	files, err = Render(Server{Listeners: baseServer().Listeners, ChallengeHosts: []string{"panel.example.org"}})
	if err != nil {
		t.Fatal(err)
	}
	server := string(files[ServerConfigPath])
	if !strings.Contains(listenerBlock(t, server, "sifruno-http"), "sifruno-panel panel.example.org") || strings.Contains(server, "listener sifruno-https") {
		t.Fatalf("no-site render:\n%s", server)
	}
}

func TestChallengeHostsHostile(t *testing.T) {
	for name, hosts := range map[string][]string{
		"an IP address":  {"192.0.2.1"},
		"upper case":     {"Panel.example.org"},
		"one label":      {"localhost"},
		"a wildcard":     {"*.example.org"},
		"a space":        {"panel.example.org other"},
		"a brace":        {"panel.example.org{"},
		"a newline":      {"panel.example.org\nlistener x {"},
		"empty":          {""},
		"listed twice":   {"panel.example.org", "panel.example.org"},
		"www. and plain": {"panel.example.org", "www.panel.example.org"},
	} {
		s := baseServer()
		s.ChallengeHosts = hosts
		err := Validate(s)
		var fe *FieldError
		if !errors.Is(err, ErrInvalid) || !errors.As(err, &fe) || !strings.HasPrefix(fe.Field, "challenge_hosts[") {
			t.Errorf("%s: %v", name, err)
		}
	}
	s := baseServer()
	for i := 0; i <= MaxDomainsPerSite; i++ {
		s.ChallengeHosts = append(s.ChallengeHosts, fmt.Sprintf("p%d.example.org", i))
	}
	if err := Validate(s); !errors.Is(err, ErrInvalid) {
		t.Errorf("too many names: %v", err)
	}
	// The vhost's name is the panel's: no website may take it.
	s = baseServer()
	s.Sites[0].Name = PanelChallengeName
	var fe *FieldError
	if err := Validate(s); !errors.As(err, &fe) || fe.Field != "sites[0].name" {
		t.Errorf("a site named %s: %v", PanelChallengeName, err)
	}
}

// listenerBlock is one listener's block of a rendered server fragment.
func listenerBlock(t *testing.T, server, name string) string {
	t.Helper()
	start := strings.Index(server, "\nlistener "+name+" {\n")
	if start < 0 {
		t.Fatalf("no listener %s:\n%s", name, server)
	}
	end := strings.Index(server[start+1:], "\n}\n")
	return server[start : start+1+end+3]
}
