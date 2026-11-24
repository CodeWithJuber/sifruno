package acme

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"io"
	"net/http"
	"regexp"
	"strings"
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
// not at all, as it must for the certificate authority's HTTP-01 check.
var defaultReachClient = &http.Client{
	Timeout:       reachTimeout,
	CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	Transport:     &http.Transport{Proxy: nil, DisableKeepAlives: true},
}

// Reaches says whether domain reaches this server's challenge path now, the
// way the certificate authority will ask: it puts a random answer in the
// challenge directory under a random token, asks
// http://<domain>/.well-known/acme-challenge/<token>, compares the answer
// and removes the file. A domain whose DNS points elsewhere (or nowhere)
// does not, so the certificate leaves it out instead of failing for every
// domain of the site. The request reveals nothing: the token and the answer
// are random and used once.
func (l *legoIssuer) Reaches(ctx context.Context, domain string) bool {
	return reaches(ctx, l.reachClient(), challengeFiles{dir: l.cfg.ChallengeDir}, domain)
}

// reachClient is the HTTP client the probe uses; tests point it at a server.
func (l *legoIssuer) reachClient() *http.Client {
	if l.reach != nil {
		return l.reach
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
