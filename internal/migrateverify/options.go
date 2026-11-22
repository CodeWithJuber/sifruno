// Package migrateverify compares a migrated copy of a website with the live
// original before cutover. It reads both sites with credential-free GET
// requests only, compares pages discovered on the old site and the closed URLs
// the operator lists, and reduces the result to one cutover gate.
package migrateverify

import (
	"errors"
	"fmt"
	"net"
	"net/url"
	"strconv"
	"strings"
	"unicode"
)

const (
	DefaultPageLimit = 50
	MaxPageLimit     = 200
	// MaxProbes bounds a probe list fed from an automated .htaccess pre-flight.
	MaxProbes = 500

	DefaultSizeTolerancePercent = 10
	DefaultSizeToleranceBytes   = 2048
	// maxSizeTolerancePercent keeps the pass band inside the 25% warning band.
	maxSizeTolerancePercent = 25
	maxSizeToleranceBytes   = 1 << 20

	UserAgent = "Sifruno-MigrationVerify/1"

	maxTargetLength = 2048
)

// ProbeKind names the closed status an access-control probe expects on the old site.
type ProbeKind string

const (
	// ProbeAuth is a password-protected location: the old site must answer 401.
	ProbeAuth ProbeKind = "auth"
	// ProbeDeny is a deny rule: the old site must answer 403.
	ProbeDeny ProbeKind = "deny"
)

// Probe is one closed URL to check. A page crawl does not find these because
// nothing links to them, so they are listed explicitly.
type Probe struct {
	Path string    `json:"path"`
	Kind ProbeKind `json:"kind"`
}

// Options describes one verify run.
type Options struct {
	// Old is the bare origin of the live old site, for example https://example.com.
	Old string
	// New is the bare origin of the new copy. With NewConnect it is normally the
	// real site origin; without it, the temporary address of the new server.
	New string
	// NewConnect, when set, is the HOST:PORT every new-site request connects to
	// while keeping the Host header and TLS server name of New (curl --resolve).
	NewConnect string
	// PageLimit caps compared pages; 0 means DefaultPageLimit.
	PageLimit int
	// Paths are compared in addition to the discovered pages.
	Paths []string
	// Probes are closed URLs whose status must be the same on both sites.
	Probes []Probe
	// InsecureNewTLS skips certificate verification for the new site only. It is
	// meant for a copy whose certificate is not installed yet and is reported as
	// a warning.
	InsecureNewTLS bool
	// AcceptWarnings records that a person checked the warnings and lets them
	// pass the cutover gate. Failures always keep the gate closed.
	AcceptWarnings bool
	// SizeTolerancePercent and SizeToleranceBytes set the body size pass band;
	// 0 selects the defaults (10% or 2 KiB, whichever is larger).
	SizeTolerancePercent int
	SizeToleranceBytes   int64
}

type config struct {
	old, new       *url.URL
	newConnect     string
	pageLimit      int
	paths          []string
	probes         []Probe
	insecureNewTLS bool
	acceptWarnings bool
	tolerance      sizeTolerance
}

func (o Options) validate() (config, error) {
	var c config
	var err error
	if c.old, err = parseOrigin("old", o.Old); err != nil {
		return config{}, err
	}
	if c.new, err = parseOrigin("new", o.New); err != nil {
		return config{}, err
	}
	if o.NewConnect != "" {
		if c.newConnect, err = parseConnect(o.NewConnect); err != nil {
			return config{}, err
		}
	} else if originKey(c.old) == originKey(c.new) {
		// Without a connect-to override both requests reach the same server and
		// the old site would be compared with itself.
		return config{}, errors.New("new site URL is the same as the old site; set a different new URL or a new-connect HOST:PORT")
	}
	c.pageLimit = o.PageLimit
	if c.pageLimit == 0 {
		c.pageLimit = DefaultPageLimit
	}
	if c.pageLimit < 1 || c.pageLimit > MaxPageLimit {
		return config{}, fmt.Errorf("page limit must be between 1 and %d", MaxPageLimit)
	}
	seen := map[string]bool{"/": true}
	for _, raw := range o.Paths {
		target, e := cleanTarget(raw)
		if e != nil {
			return config{}, fmt.Errorf("extra path %q: %w", truncate(raw, 80), e)
		}
		if !seen[target] {
			seen[target] = true
			c.paths = append(c.paths, target)
		}
	}
	if 1+len(c.paths) > c.pageLimit {
		return config{}, fmt.Errorf("%d extra paths do not fit within the page limit of %d (the home page is always compared)", len(c.paths), c.pageLimit)
	}
	if len(o.Probes) > MaxProbes {
		return config{}, fmt.Errorf("at most %d access-control probes are allowed", MaxProbes)
	}
	kinds := map[string]ProbeKind{}
	for _, p := range o.Probes {
		if p.Kind != ProbeAuth && p.Kind != ProbeDeny {
			return config{}, fmt.Errorf("probe %q: kind must be %q or %q", truncate(p.Path, 80), ProbeAuth, ProbeDeny)
		}
		target, e := cleanTarget(p.Path)
		if e != nil {
			return config{}, fmt.Errorf("probe path %q: %w", truncate(p.Path, 80), e)
		}
		if previous, ok := kinds[target]; ok {
			if previous != p.Kind {
				return config{}, fmt.Errorf("probe path %s is listed as both %s and %s", target, previous, p.Kind)
			}
			continue
		}
		kinds[target] = p.Kind
		c.probes = append(c.probes, Probe{Path: target, Kind: p.Kind})
	}
	c.tolerance = sizeTolerance{percent: o.SizeTolerancePercent, floor: o.SizeToleranceBytes}
	if c.tolerance.percent == 0 {
		c.tolerance.percent = DefaultSizeTolerancePercent
	}
	if c.tolerance.floor == 0 {
		c.tolerance.floor = DefaultSizeToleranceBytes
	}
	if c.tolerance.percent < 1 || c.tolerance.percent > maxSizeTolerancePercent {
		return config{}, fmt.Errorf("size tolerance percent must be between 1 and %d", maxSizeTolerancePercent)
	}
	if c.tolerance.floor < 1 || c.tolerance.floor > maxSizeToleranceBytes {
		return config{}, fmt.Errorf("size tolerance bytes must be between 1 and %d", maxSizeToleranceBytes)
	}
	c.insecureNewTLS = o.InsecureNewTLS
	c.acceptWarnings = o.AcceptWarnings
	return c, nil
}

// parseOrigin accepts only a bare http(s) origin. Errors never echo the input
// because a rejected URL may carry a password.
func parseOrigin(label, raw string) (*url.URL, error) {
	if strings.TrimSpace(raw) == "" {
		return nil, fmt.Errorf("%s site URL is required", label)
	}
	u, err := url.Parse(raw)
	if err != nil {
		return nil, fmt.Errorf("%s site URL is not a valid URL", label)
	}
	if u.User != nil {
		return nil, fmt.Errorf("%s site URL must not contain credentials (user:pass@); verify never sends credentials", label)
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return nil, fmt.Errorf("%s site URL must use http or https", label)
	}
	if u.Hostname() == "" {
		return nil, fmt.Errorf("%s site URL must include a host", label)
	}
	if u.Opaque != "" || (u.Path != "" && u.Path != "/") || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" {
		return nil, fmt.Errorf("%s site URL must be a bare origin such as https://example.com", label)
	}
	if port := u.Port(); port != "" {
		if n, e := strconv.Atoi(port); e != nil || n < 1 || n > 65535 {
			return nil, fmt.Errorf("%s site URL has an invalid port", label)
		}
	}
	return &url.URL{Scheme: u.Scheme, Host: strings.ToLower(u.Host)}, nil
}

func parseConnect(raw string) (string, error) {
	host, port, err := net.SplitHostPort(raw)
	if err != nil || host == "" || strings.ContainsAny(host, "/@ ") {
		return "", errors.New("new-connect must be HOST:PORT")
	}
	if n, e := strconv.Atoi(port); e != nil || n < 1 || n > 65535 {
		return "", errors.New("new-connect has an invalid port")
	}
	return net.JoinHostPort(host, port), nil
}

// cleanTarget turns a site-relative path (optionally with a query) into the
// escaped request target used on both sites.
func cleanTarget(raw string) (string, error) {
	if raw == "" || raw[0] != '/' || strings.HasPrefix(raw, "//") {
		return "", errors.New("must start with a single /")
	}
	if len(raw) > maxTargetLength {
		return "", fmt.Errorf("is longer than %d bytes", maxTargetLength)
	}
	if strings.IndexFunc(raw, func(r rune) bool { return unicode.IsSpace(r) || unicode.IsControl(r) }) >= 0 {
		return "", errors.New("must not contain spaces or control characters")
	}
	if strings.Contains(raw, "#") {
		return "", errors.New("must not contain a fragment")
	}
	u, err := url.ParseRequestURI(raw)
	if err != nil || u.Scheme != "" || u.Host != "" || u.User != nil {
		return "", errors.New("is not a valid site-relative path")
	}
	return siteTarget(u, false), nil
}

func truncate(s string, n int) string {
	r := []rune(s)
	if len(r) <= n {
		return s
	}
	return string(r[:n]) + "…"
}
