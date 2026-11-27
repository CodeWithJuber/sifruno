package main

import (
	"slices"
	"strings"
	"testing"
)

// The panel asks Let's Encrypt for its own certificate only when it would
// otherwise serve a self-signed one, a --panel-host name is a public domain,
// there is an ACME account (--acme-email) and the account broker serves the
// challenge on port 80. Otherwise the startup line says why not.
func TestPanelLetsEncryptNamesOrWhyNot(t *testing.T) {
	hosts := []string{"panel.203-0-113-9.sslip.io", "203.0.113.9"}
	names, why := panelLetsEncrypt(hosts, true, "admin@hostname.dev", true)
	if !slices.Equal(names, []string{"panel.203-0-113-9.sslip.io"}) || why != "" {
		t.Fatalf("names %q, why %q", names, why)
	}
	// --tls-cert and --tls-key win: nothing is asked and nothing is said.
	if names, why = panelLetsEncrypt(hosts, false, "admin@hostname.dev", true); names != nil || why != "" {
		t.Fatalf("operator files: names %q, why %q", names, why)
	}
	for name, tc := range map[string]struct {
		hosts    []string
		email    string
		websites bool
		want     string
	}{
		"an IP only":       {[]string{"203.0.113.9"}, "admin@hostname.dev", true, "no --panel-host name is a public domain name, and Let's Encrypt issues this panel none for an IP address or a name like panel.test"},
		"no email":         {hosts, "", true, "Let's Encrypt needs a contact address: install again with --acme-email, or give --tls-cert"},
		"no broker":        {hosts, "admin@hostname.dev", false, "Let's Encrypt checks the name on port 80, which the account broker serves, and --accounts-socket is not set"},
		"no public, email": {[]string{"panel.test"}, "", false, "no --panel-host name is a public domain name"},
	} {
		names, why := panelLetsEncrypt(tc.hosts, true, tc.email, tc.websites)
		if names != nil || !strings.HasPrefix(why, tc.want) {
			t.Errorf("%s: names %q, why %q", name, names, why)
		}
	}
}
