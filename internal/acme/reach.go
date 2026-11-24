package acme

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"io"
	"net"
	"net/http"
	"net/netip"
	"regexp"
	"strings"
	"syscall"
	"time"
)

const (
	// challengePath is where every vhost the broker renders serves
	// ChallengeDir (RFC 8555 section 8.3).
	challengePath = "/.well-known/acme-challenge/"
	reachTimeout  = 10 * time.Second
	reachAnswer   = 512 // bytes of the answer read
)

// reachDomain admits only a lowercase DNS name with a dot into the probe's
// URL; the broker has checked the domain already.
var reachDomain = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9.-]{0,251}[a-z0-9])?$`)

// defaultReachClient asks without a proxy, without following a redirect and
// without keeping the connection: a domain answers on its own port 80 or
// not at all, as it must for the certificate authority's HTTP-01 check. It
// connects to public addresses only (probeDialer).
var defaultReachClient = newReachClient(false)

// loopbackReachClient is defaultReachClient that may also connect to a
// loopback address, for Config.TestProbeLoopback only.
var loopbackReachClient = newReachClient(true)

func newReachClient(loopback bool) *http.Client {
	return &http.Client{
		Timeout:       reachTimeout,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
		Transport:     &http.Transport{Proxy: nil, DisableKeepAlives: true, DialContext: probeDialer(loopback).DialContext},
	}
}

// errNotPublic is the probe's refusal to connect to an address outside the
// public internet.
var errNotPublic = errors.New("acme: the domain resolves to an address that is not on the public internet")

// probeDialer connects only to an address on the public internet, or with
// loopback also to a loopback address. It checks the address it connects
// to, after the name was resolved, for every address it tries: a name whose
// DNS answers a public address for one lookup and a private one for the
// next (DNS rebinding) cannot get past it. The certificate authority does
// not validate such an address either, and the probe must not reach this
// server's own loopback (its web server answers every challenge there) or
// a service on the private network.
func probeDialer(loopback bool) *net.Dialer {
	return &net.Dialer{Timeout: reachTimeout, Control: func(_, address string, _ syscall.RawConn) error {
		host, _, err := net.SplitHostPort(address)
		if err != nil {
			return errNotPublic
		}
		ip, err := netip.ParseAddr(host)
		if err != nil || !publicAddress(ip, loopback) {
			return errNotPublic
		}
		return nil
	}}
}

// notPublic are the special-purpose ranges (IANA's IPv4 and IPv6
// special-purpose address registries) that are not on the public internet
// and that netip's own tests in publicAddress leave in.
var notPublic = []netip.Prefix{
	netip.MustParsePrefix("0.0.0.0/8"),       // this network
	netip.MustParsePrefix("100.64.0.0/10"),   // shared address space (carrier-grade NAT)
	netip.MustParsePrefix("192.0.0.0/24"),    // IETF protocol assignments
	netip.MustParsePrefix("192.0.2.0/24"),    // documentation
	netip.MustParsePrefix("198.18.0.0/15"),   // benchmarking
	netip.MustParsePrefix("198.51.100.0/24"), // documentation
	netip.MustParsePrefix("203.0.113.0/24"),  // documentation
	netip.MustParsePrefix("240.0.0.0/4"),     // reserved, the broadcast address among them
	netip.MustParsePrefix("::/96"),           // IPv4-compatible, deprecated
	netip.MustParsePrefix("100::/64"),        // discard only
	netip.MustParsePrefix("64:ff9b:1::/48"),  // local-use NAT64 (RFC 8215), translated inside a network
	netip.MustParsePrefix("2001::/23"),       // IETF protocol assignments, Teredo (2001::/32) among them
	netip.MustParsePrefix("2001:db8::/32"),   // documentation
	netip.MustParsePrefix("2002::/16"),       // 6to4: an IPv4 address in bits 16-48, relayed
	netip.MustParsePrefix("3fff::/20"),       // documentation (RFC 9637)
	netip.MustParsePrefix("fec0::/10"),       // site-local, deprecated
}

// nat64 is the well-known NAT64 prefix (RFC 6052): an address in it stands
// for the IPv4 address in its last 32 bits.
var nat64 = netip.MustParsePrefix("64:ff9b::/96")

// publicAddress reports whether ip is a global unicast address on the
// public internet: not loopback, private (RFC 1918, IPv6 unique local),
// link-local, carrier-grade NAT, unspecified, multicast or another
// special-purpose range, judged by the IPv4 address an IPv4-mapped or
// NAT64 address stands for. With loopback a loopback address passes too.
func publicAddress(ip netip.Addr, loopback bool) bool {
	if ip.Zone() != "" {
		return false
	}
	ip = ip.Unmap()
	if nat64.Contains(ip) {
		b := ip.As16()
		ip = netip.AddrFrom4([4]byte(b[12:]))
	}
	if loopback && ip.IsLoopback() {
		return true
	}
	// IsGlobalUnicast leaves out loopback, link-local, multicast, the
	// unspecified and the IPv4 broadcast address, but not private ones.
	if !ip.IsGlobalUnicast() || ip.IsPrivate() {
		return false
	}
	for _, p := range notPublic {
		if p.Contains(ip) {
			return false
		}
	}
	return true
}

// loopbackHost reports whether host, a URL's host name, is this machine:
// localhost or a loopback address.
func loopbackHost(host string) bool {
	if host == "localhost" {
		return true
	}
	ip, err := netip.ParseAddr(host)
	return err == nil && ip.Unmap().IsLoopback()
}

// Reaches says whether domain reaches this server's challenge path now, the
// way the certificate authority will ask: it puts a random answer in the
// challenge directory under a random token, asks
// http://<domain>/.well-known/acme-challenge/<token>, compares the answer
// and removes the file. A domain whose DNS points elsewhere (or nowhere),
// or at an address outside the public internet, does not, so the
// certificate leaves it out instead of failing for every domain of the
// site. The request reveals nothing: the token and the answer are random
// and used once.
func (l *legoIssuer) Reaches(ctx context.Context, domain string) bool {
	return reaches(ctx, l.reachClient(), challengeFiles{dir: l.cfg.ChallengeDir}, domain)
}

// reachClient is the HTTP client the probe uses; tests point it at a server.
func (l *legoIssuer) reachClient() *http.Client {
	switch {
	case l.reach != nil:
		return l.reach
	case l.cfg.TestProbeLoopback:
		return loopbackReachClient
	}
	return defaultReachClient
}

func reaches(ctx context.Context, client *http.Client, files challengeFiles, domain string) bool {
	if !reachDomain.MatchString(domain) || !strings.Contains(domain, ".") {
		return false
	}
	token, answer := randomText(), randomText()
	if token == "" || answer == "" || files.Present(ctx, domain, token, answer) != nil {
		return false
	}
	defer func() { _ = files.CleanUp(ctx, domain, token, "") }()
	ctx, cancel := context.WithTimeout(ctx, reachTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://"+domain+challengePath+token, nil)
	if err != nil {
		return false
	}
	req.Header.Set("User-Agent", userAgent)
	resp, err := client.Do(req)
	if err != nil {
		return false
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, reachAnswer))
	return err == nil && resp.StatusCode == http.StatusOK && string(body) == answer
}

// randomText is 32 random base64url characters, empty if the system has no
// randomness to give.
func randomText() string {
	var b [24]byte
	if _, err := rand.Read(b[:]); err != nil {
		return ""
	}
	return base64.RawURLEncoding.EncodeToString(b[:])
}
