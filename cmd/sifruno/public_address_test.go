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
