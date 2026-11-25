package acme

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestPublicAddress(t *testing.T) {
	refused := []string{
		"127.0.0.1", "127.8.9.10", "::1", // loopback
		"10.0.0.1", "172.16.0.1", "172.31.255.255", "192.168.1.1", // RFC 1918
		"169.254.169.254", "fe80::1", "fe80::1%eth0", // link-local
		"fc00::1", "fd12:3456::1", // unique local
		"100.64.0.1", "100.127.255.255", // carrier-grade NAT
		"0.0.0.0", "::", "0.1.2.3", // unspecified, this network
		"224.0.0.1", "239.255.255.250", "ff02::1", "ff0e::1", // multicast
		"255.255.255.255", "240.0.0.1", // broadcast, reserved
		"192.0.2.1", "198.51.100.7", "203.0.113.9", "2001:db8::1", // documentation
		"198.18.0.1", "192.0.0.8", "100::1", "fec0::1", // benchmarking, IETF, discard, site-local
		"::ffff:127.0.0.1", "::ffff:10.0.0.1", "::ffff:169.254.169.254", "::ffff:100.64.0.1", // IPv4-mapped
		"64:ff9b::7f00:1", "64:ff9b::a00:1", "64:ff9b::c0a8:101", // NAT64 of loopback and private
		"::127.0.0.1", "::10.0.0.1", // IPv4-compatible
		"2002:7f00:1::1", "2002:a00:1::1", // 6to4 of loopback and private
		"2001:0:4136:e378:8000:63bf:3fff:fdd2", "2001:2::1", // Teredo, benchmarking
		"64:ff9b:1::a00:1", "3fff::1", // local-use NAT64, documentation
	}
	for _, s := range refused {
		if publicAddress(netip.MustParseAddr(s), false) {
			t.Errorf("%s admitted", s)
		}
	}
	admitted := []string{"8.8.8.8", "1.1.1.1", "100.63.255.255", "100.128.0.0", "172.32.0.1", "11.0.0.1", "2606:4700:4700::1111", "2a00:1450:4001::200e", "::ffff:8.8.8.8", "64:ff9b::808:808"}
	for _, s := range admitted {
		if !publicAddress(netip.MustParseAddr(s), false) {
			t.Errorf("%s refused", s)
		}
	}
	// The dev VM's switch admits loopback too, and nothing else.
	for _, s := range []string{"127.0.0.1", "127.8.9.10", "::1", "::ffff:127.0.0.1"} {
		if !publicAddress(netip.MustParseAddr(s), true) {
			t.Errorf("%s refused with loopback allowed", s)
		}
	}
	for _, s := range []string{"10.0.0.1", "192.168.0.1", "169.254.169.254", "fd00::1", "100.64.0.1", "0.0.0.0", "::"} {
		if publicAddress(netip.MustParseAddr(s), true) {
			t.Errorf("%s admitted with loopback allowed", s)
		}
	}
}

// TestProbeConnectsToPublicAddressesOnly: an alias whose DNS answers a
// loopback address does not reach, though this server's web server answers
// its challenge there; the check is made on the address connected to, once
// the name is resolved.
func TestProbeConnectsToPublicAddressesOnly(t *testing.T) {
	dir := t.TempDir()
	files := challengeFiles{dir: dir}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		token, _ := strings.CutPrefix(r.URL.Path, challengePath)
		data, err := os.ReadFile(filepath.Join(dir, filepath.Base(token)))
		if err != nil {
			http.NotFound(w, r)
			return
		}
		_, _ = w.Write(data)
	}))
	t.Cleanup(srv.Close)
	// DNS answering the test server's loopback address for every name, as
	// Pebble's does on the dev VM.
	client := func(loopback bool) *http.Client {
		c := newReachClient(loopback)
		dial := c.Transport.(*http.Transport).DialContext
		c.Transport.(*http.Transport).DialContext = func(ctx context.Context, network, _ string) (net.Conn, error) {
			return dial(ctx, network, srv.Listener.Addr().String())
		}
		return c
	}
	ctx := context.Background()
	if reaches(ctx, client(false), files, "www.example.com") {
		t.Fatal("an alias whose DNS answers a loopback address reaches")
	}
	if !reaches(ctx, client(true), files, "www.example.com") {
		t.Fatal("with the dev VM's switch, the alias does not reach its loopback server")
	}
	// A name the dialer resolves itself is judged by what it resolves to.
	_, port, _ := net.SplitHostPort(srv.Listener.Addr().String())
	if _, err := probeDialer(false).DialContext(ctx, "tcp", net.JoinHostPort("localhost", port)); !errors.Is(err, errNotPublic) {
		t.Fatalf("localhost: %v", err)
	}
	if _, err := probeDialer(false).DialContext(ctx, "tcp", net.JoinHostPort("::ffff:127.0.0.1", port)); !errors.Is(err, errNotPublic) {
		t.Fatalf("an IPv4-mapped loopback address: %v", err)
	}
	if defaultReachClient.Transport.(*http.Transport).DialContext == nil {
		t.Fatal("the probe's client connects without the check")
	}
}

// TestProbeLoopbackIsForATestServerOnly: the switch is refused unless the
// ACME directory is on this machine, and only it lets the probe reach
// loopback.
func TestProbeLoopbackIsForATestServerOnly(t *testing.T) {
	for _, directory := range []string{"", LetsEncrypt, "https://acme-staging-v02.api.letsencrypt.org/directory", "https://10.0.0.5:14000/dir", "https://pebble.test:14000/dir"} {
		cfg := testConfig(t)
		cfg.Directory, cfg.TestProbeLoopback = directory, true
		if _, err := newLegoIssuer(cfg); err == nil || !strings.Contains(err.Error(), "--acme-test-probe-loopback") {
			t.Errorf("%q: %v", directory, err)
		}
	}
	for _, directory := range []string{"https://127.0.0.1:14000/dir", "https://[::1]:14000/dir", "https://localhost:14000/dir"} {
		cfg := testConfig(t)
		cfg.Directory = directory
		plain, err := newLegoIssuer(cfg)
		if err != nil {
			t.Fatal(err)
		}
		cfg.TestProbeLoopback = true
		test, err := newLegoIssuer(cfg)
		if err != nil {
			t.Fatalf("%q: %v", directory, err)
		}
		if plain.reachClient() != defaultReachClient || test.reachClient() != loopbackReachClient {
			t.Fatalf("%q: the switch does not choose the probe's client", directory)
		}
	}
}
