package migrateverify

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"mime"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

// tuning holds the politeness and resource bounds. They are fixed for callers;
// tests in this package shorten them.
type tuning struct {
	concurrency    int
	delay          time.Duration
	requestTimeout time.Duration
	maxBody        int64
	roots          *x509.CertPool // nil means the system roots
}

var defaultTuning = tuning{concurrency: 2, delay: 100 * time.Millisecond, requestTimeout: 20 * time.Second, maxBody: 2 << 20}

const insecureNewTLSWarning = "new site TLS certificate was not verified (--insecure-new-tls); the identity of the new server is unproven"

// Run compares the new copy with the old site and returns the report. It sends
// only GET requests without credentials or cookies, never follows redirects and
// stays within the page limit. It returns an error and no report when the
// options are invalid or ctx ends before the comparison finishes.
func Run(ctx context.Context, opts Options) (Report, error) {
	return run(ctx, opts, defaultTuning)
}

func run(ctx context.Context, opts Options, tune tuning) (Report, error) {
	cfg, err := opts.validate()
	if err != nil {
		return Report{}, err
	}
	v := newVerifier(cfg, tune)
	defer v.close()
	r := Report{
		SchemaVersion:    SchemaVersion,
		Scope:            Scope,
		StartedAt:        time.Now().UTC(),
		OldOrigin:        cfg.old.String(),
		NewOrigin:        cfg.new.String(),
		NewConnect:       cfg.newConnect,
		OldClient:        clientText(cfg.oldClient),
		NewClient:        clientText(cfg.newClient),
		InsecureNewTLS:   cfg.insecureNewTLS,
		PageLimit:        cfg.pageLimit,
		AcceptedWarnings: cfg.acceptWarnings,
		Warnings:         []string{},
	}
	if cfg.insecureNewTLS {
		r.Warnings = append(r.Warnings, insecureNewTLSWarning)
	}
	sitemap, warnings := v.readSitemaps(ctx)
	r.Warnings = append(r.Warnings, warnings...)
	if err = ctx.Err(); err != nil {
		return Report{}, fmt.Errorf("migration verify stopped: %w", err)
	}
	var cutShort bool
	r.Pages, cutShort = v.comparePages(ctx, sitemap)
	if cutShort {
		// Pages past the limit were never compared, so a green result would
		// speak for part of the site only.
		r.Warnings = append(r.Warnings, fmt.Sprintf("the page limit (%d) was reached before the crawl ran out of pages; pages past it were not compared", cfg.pageLimit))
	}
	if err = ctx.Err(); err != nil {
		return Report{}, fmt.Errorf("migration verify stopped: %w", err)
	}
	r.Probes = v.runProbes(ctx)
	if err = ctx.Err(); err != nil {
		return Report{}, fmt.Errorf("migration verify stopped: %w", err)
	}
	r.FinishedAt = time.Now().UTC()
	r.finalize()
	return r, nil
}

type side struct {
	base   string
	client *http.Client
	pace   *pacer
}

type verifier struct {
	cfg      config
	tune     tuning
	old, new side
}

func newVerifier(cfg config, tune tuning) *verifier {
	return &verifier{
		cfg:  cfg,
		tune: tune,
		old:  side{base: cfg.old.String(), client: newClient(tune, false, ""), pace: &pacer{gap: tune.delay}},
		new:  side{base: cfg.new.String(), client: newClient(tune, cfg.insecureNewTLS, cfg.newConnect), pace: &pacer{gap: tune.delay}},
	}
}

func (v *verifier) close() {
	v.old.client.CloseIdleConnections()
	v.new.client.CloseIdleConnections()
}

// newClient connects directly (an inherited proxy would change what is being
// compared), speaks HTTP/1.1 on both sides, keeps no cookie jar and returns
// redirects instead of following them. With connect set every dial goes to that
// address; the TLS server name and certificate check still use the URL host,
// like curl --resolve. The client only ever requests its own origin.
func newClient(tune tuning, insecure bool, connect string) *http.Client {
	dialer := &net.Dialer{Timeout: 10 * time.Second}
	transport := &http.Transport{
		Proxy:       nil,
		DialContext: dialer.DialContext,
		TLSClientConfig: &tls.Config{
			MinVersion: tls.VersionTLS12,
			RootCAs:    tune.roots,
			// Only the new side may skip verification, when the operator asked
			// for it because the copied certificate is not installed yet.
			InsecureSkipVerify: insecure,
		},
		TLSHandshakeTimeout:   10 * time.Second,
		ResponseHeaderTimeout: tune.requestTimeout,
		MaxConnsPerHost:       tune.concurrency,
		MaxIdleConnsPerHost:   tune.concurrency,
		IdleConnTimeout:       30 * time.Second,
		Protocols:             new(http.Protocols),
	}
	transport.Protocols.SetHTTP1(true)
	if connect != "" {
		transport.DialContext = func(ctx context.Context, network, _ string) (net.Conn, error) {
			return dialer.DialContext(ctx, network, connect)
		}
	}
	return &http.Client{
		Transport:     transport,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
}

// pacer spaces request starts to one host by a fixed gap.
type pacer struct {
	mu   sync.Mutex
	next time.Time
	gap  time.Duration
}

func (p *pacer) wait(ctx context.Context) error {
	p.mu.Lock()
	now := time.Now()
	at := p.next
	if at.Before(now) {
		at = now
	}
	p.next = at.Add(p.gap)
	p.mu.Unlock()
	delay := time.Until(at)
	if delay <= 0 {
		return ctx.Err()
	}
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

type bodyMode int

const (
	bodyNone bodyMode = iota // status and headers only
	bodyHTML                 // keep HTML bodies, count the rest
	bodyAll                  // keep every body
)

type fetched struct {
	resp     Response
	url      *url.URL
	location *url.URL
	html     bool
	body     []byte
}

func (v *verifier) fetch(ctx context.Context, s *side, target string, mode bodyMode) fetched {
	var f fetched
	if err := s.pace.wait(ctx); err != nil {
		f.resp.Error = err.Error()
		return f
	}
	reqCtx, cancel := context.WithTimeout(ctx, v.tune.requestTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(reqCtx, http.MethodGet, s.base+target, nil)
	if err != nil {
		f.resp.Error = "request could not be built"
		return f
	}
	req.Header.Set("User-Agent", UserAgent)
	f.url = req.URL
	resp, err := s.client.Do(req)
	if err != nil {
		f.resp.Error = err.Error()
		return f
	}
	defer resp.Body.Close()
	f.resp.Status = resp.StatusCode
	f.resp.ContentType = mediaType(resp.Header.Get("Content-Type"))
	f.html = isHTML(f.resp.ContentType)
	if resp.StatusCode == http.StatusUnauthorized {
		f.resp.AuthScheme = authScheme(resp.Header.Values("WWW-Authenticate"))
	}
	if resp.StatusCode >= 300 && resp.StatusCode < 400 {
		if raw := resp.Header.Get("Location"); raw != "" {
			if loc, e := req.URL.Parse(raw); e == nil {
				f.location = loc
				f.resp.Location = normaliseLocation(loc, v.cfg.old, v.cfg.new)
			} else {
				f.resp.Location = "invalid Location header"
			}
		}
	}
	if mode == bodyNone {
		return f
	}
	limited := io.LimitReader(resp.Body, v.tune.maxBody+1)
	var n int64
	if mode == bodyAll || (f.html && resp.StatusCode >= 200 && resp.StatusCode < 300) {
		f.body, err = io.ReadAll(limited)
		n = int64(len(f.body))
	} else {
		n, err = io.Copy(io.Discard, limited)
	}
	if err != nil {
		f.resp.Error = "reading body: " + err.Error()
		return f
	}
	if n > v.tune.maxBody {
		n = v.tune.maxBody
		f.resp.Truncated = true
		if f.body != nil {
			f.body = f.body[:n]
		}
	}
	f.resp.Bytes = n
	return f
}

func mediaType(header string) string {
	if header == "" {
		return ""
	}
	if mt, _, err := mime.ParseMediaType(header); err == nil {
		return mt
	}
	mt, _, _ := strings.Cut(header, ";")
	return strings.ToLower(strings.TrimSpace(mt))
}

func isHTML(mediaType string) bool {
	return mediaType == "text/html" || mediaType == "application/xhtml+xml"
}

// authScheme lists the challenge scheme of each WWW-Authenticate header.
func authScheme(values []string) string {
	var schemes []string
	for _, v := range values {
		if fields := strings.Fields(v); len(fields) > 0 {
			schemes = append(schemes, strings.ToLower(strings.TrimRight(fields[0], ",")))
		}
	}
	return strings.Join(schemes, ",")
}

type pageOutcome struct {
	index    int
	result   PageResult
	links    []*url.URL
	redirect *url.URL
}

// comparePages walks the discovery queue with a fixed number of workers.
// Results are committed in queue order, so the discovered page set does not
// depend on which response arrived first.
// comparePages crawls and compares up to the page limit. The second result
// reports whether pages were found and left out because of the limit.
func (v *verifier) comparePages(ctx context.Context, sitemap []*url.URL) ([]PageResult, bool) {
	c := newCrawl(v.cfg.old, v.cfg.pageLimit)
	c.seed("/", "root")
	for _, p := range v.cfg.paths {
		c.seed(p, "path")
	}
	results := make([]PageResult, 0, v.cfg.pageLimit)
	done := make(chan pageOutcome, v.tune.concurrency)
	pending := map[int]pageOutcome{}
	next, inFlight := 0, 0
	for {
		for ctx.Err() == nil && inFlight < v.tune.concurrency && next < len(c.queue) {
			go func(i int, t target) { done <- v.verifyPage(ctx, i, t) }(next, c.queue[next])
			next++
			inFlight++
		}
		if inFlight == 0 {
			return results, c.full
		}
		o := <-done
		inFlight--
		pending[o.index] = o
		for {
			ready, ok := pending[len(results)]
			if !ok {
				break
			}
			delete(pending, ready.index)
			results = append(results, ready.result)
			c.addURL(ready.redirect, "redirect")
			if ready.index == 0 {
				c.addInterleaved(ready.links, sitemap)
				continue
			}
			for _, link := range ready.links {
				c.addURL(link, "link")
			}
		}
	}
}

func (v *verifier) verifyPage(ctx context.Context, index int, t target) pageOutcome {
	o := pageOutcome{index: index}
	was := v.fetch(ctx, &v.old, t.path, bodyHTML)
	if was.body != nil {
		was.resp.Title, o.links = parseHTML(was.body, was.url, true)
		if was.resp.Status != http.StatusOK {
			was.resp.Title = ""
		}
	}
	o.redirect = was.location
	now := v.fetch(ctx, &v.new, t.path, bodyHTML)
	if now.body != nil && now.resp.Status == http.StatusOK {
		now.resp.Title, _ = parseHTML(now.body, now.url, false)
	}
	o.result = PageResult{Path: t.path, Source: t.source, Old: was.resp, New: now.resp}
	o.result.Result, o.result.Critical, o.result.Reason = judgePage(was.resp, now.resp, v.cfg.tolerance)
	return o
}

func (v *verifier) runProbes(ctx context.Context) []ProbeResult {
	results := make([]ProbeResult, len(v.cfg.probes))
	slots := make(chan struct{}, v.tune.concurrency)
	var wg sync.WaitGroup
	for i, p := range v.cfg.probes {
		if ctx.Err() != nil {
			break
		}
		slots <- struct{}{}
		wg.Go(func() {
			defer func() { <-slots }()
			// Probe bodies are not read: only the status and challenge matter,
			// and a protected location may stream something large.
			was := v.fetch(ctx, &v.old, p.Path, bodyNone)
			now := v.fetch(ctx, &v.new, p.Path, bodyNone)
			if p.Kind == ProbeHosts {
				results[i] = judgeHosts(p, was.resp, now.resp, v.cfg.oldClient, v.cfg.newClient)
				return
			}
			results[i] = judgeProbe(p, was.resp, now.resp)
		})
	}
	wg.Wait()
	return results
}

// readSitemaps collects page URLs from the old site's sitemaps, following
// sitemap index files one level deep. A missing sitemap is normal; an
// unreadable one is a warning because discovery may then be incomplete.
func (v *verifier) readSitemaps(ctx context.Context) ([]*url.URL, []string) {
	var entries []*url.URL
	var warnings []string
	docs := map[string]bool{}
	seen := map[string]bool{}
	add := func(locs []*url.URL) {
		for _, u := range locs {
			if len(entries) >= v.cfg.pageLimit {
				return
			}
			if ok, _ := siteMatch(u, v.cfg.old); !ok || u.User != nil {
				continue
			}
			if t := siteTarget(u, false); !seen[t] {
				seen[t] = true
				entries = append(entries, u)
			}
		}
	}
	for _, start := range sitemapPaths {
		if ctx.Err() != nil || len(docs) >= maxSitemapDocuments {
			break
		}
		kind, locs, warning := v.fetchSitemap(ctx, start, docs)
		if warning != "" {
			warnings = append(warnings, warning)
		}
		switch kind {
		case sitemapURLs:
			add(locs)
		case sitemapIndex:
			for _, child := range locs {
				if ctx.Err() != nil || len(docs) >= maxSitemapDocuments || len(entries) >= v.cfg.pageLimit {
					break
				}
				if ok, _ := siteMatch(child, v.cfg.old); !ok || child.User != nil {
					continue
				}
				childKind, childLocs, childWarning := v.fetchSitemap(ctx, siteTarget(child, false), docs)
				if childWarning != "" {
					warnings = append(warnings, childWarning)
				}
				// A nested index is not followed: discovery stays one level deep.
				if childKind == sitemapURLs {
					add(childLocs)
				}
			}
		}
	}
	return entries, warnings
}

// fetchSitemap reads one sitemap document, following same-site redirects
// (WordPress and SEO plugins commonly redirect /sitemap.xml).
func (v *verifier) fetchSitemap(ctx context.Context, target string, docs map[string]bool) (string, []*url.URL, string) {
	for hop := 0; hop <= maxSitemapRedirects; hop++ {
		if docs[target] || len(docs) >= maxSitemapDocuments {
			return sitemapNone, nil, ""
		}
		docs[target] = true
		f := v.fetch(ctx, &v.old, target, bodyAll)
		switch {
		case ctx.Err() != nil:
			return sitemapNone, nil, ""
		case f.resp.Error != "":
			return sitemapNone, nil, fmt.Sprintf("sitemap %s could not be read: %s", target, f.resp.Error)
		case f.location != nil:
			if ok, _ := siteMatch(f.location, v.cfg.old); !ok {
				return sitemapNone, nil, ""
			}
			target = siteTarget(f.location, false)
			continue
		case f.resp.Status >= 500:
			return sitemapNone, nil, fmt.Sprintf("sitemap %s answered %d", target, f.resp.Status)
		case f.resp.Status != http.StatusOK || !looksLikeXML(f.resp.ContentType, f.body):
			return sitemapNone, nil, ""
		case f.resp.Truncated:
			return sitemapNone, nil, fmt.Sprintf("sitemap %s is larger than the read limit and was not read", target)
		}
		kind, raw, err := parseSitemap(f.body)
		if errors.Is(err, errNotSitemap) {
			return sitemapNone, nil, ""
		}
		if err != nil {
			return sitemapNone, nil, fmt.Sprintf("sitemap %s is not valid sitemap XML", target)
		}
		locs := make([]*url.URL, 0, len(raw))
		for _, loc := range raw {
			if u, e := f.url.Parse(loc); e == nil {
				locs = append(locs, u)
			}
		}
		return kind, locs, ""
	}
	return sitemapNone, nil, fmt.Sprintf("sitemap %s redirects more than %d times", target, maxSitemapRedirects)
}
