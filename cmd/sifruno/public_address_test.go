package main

import "testing"

func TestPublicAddressForSetupLinks(t *testing.T) {
	for _, tc := range []struct{ host, listen, want string }{
		{"panel.example.com", "0.0.0.0:2083", "https://panel.example.com:2083"},
		{"panel.example.com", "0.0.0.0:443", "https://panel.example.com"},
		{"panel.example.com", ":443", "https://panel.example.com"},
		{"2001:db8::1", "[::]:2083", "https://[2001:db8::1]:2083"},
		{"panel.example.com", "not an address", "https://panel.example.com"},
	} {
		if got := publicAddress(tc.host, tc.listen); got != tc.want {
			t.Errorf("publicAddress(%q, %q) = %q, want %q", tc.host, tc.listen, got, tc.want)
		}
	}
}

// Passkeys work at the panel's names on the HTTPS port; with the panel's
// self-signed certificate, at the names Let's Encrypt is asked for only,
// and only while its certificate is in place.
func TestPasskeyOriginsAndTrust(t *testing.T) {
	hosts := []string{"panel.example.com", "panel.test", "203.0.113.10"}
	if got := passkeyOrigins(hosts, nil, false, "0.0.0.0:8443"); len(got) != 3 || got[0] != "https://panel.example.com:8443" || got[1] != "https://panel.test:8443" {
		t.Fatalf("operator certificate: %q", got)
	}
	if got := passkeyOrigins(hosts, []string{"panel.example.com"}, true, "0.0.0.0:443"); len(got) != 1 || got[0] != "https://panel.example.com" {
		t.Fatalf("Let's Encrypt names: %q", got)
	}
	if !passkeyCertificateTrusted(false, nil)() {
		t.Fatal("the operator's certificate must count as trusted")
	}
	if passkeyCertificateTrusted(true, nil)() {
		t.Fatal("a self-signed certificate without Let's Encrypt's must not count as trusted")
	}
}
