package migrateverify

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"errors"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"
)

const htmlType = "text/html; charset=utf-8"

var fastTuning = tuning{concurrency: 2, delay: time.Millisecond, requestTimeout: 10 * time.Second, maxBody: 2 << 20}

// page is one canned response. "{host}" in body or location is replaced with
// the request Host so fixtures can refer to their own origin.
type page struct {
	status   int
	ctype    string
	body     string
	location string
	header   map[string]string
}

type site map[string]page

func (s site) clone() site {
	c := site{}
	for k, v := range s {
		c[k] = v
	}
	return c
}

type hit struct {
	method, uri, host, ua, sni string
	auth, cookie               bool
}

type recorder struct {
	mu   sync.Mutex
	hits []hit
}

func (r *recorder) add(h hit) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.hits = append(r.hits, h)
}

func (r *recorder) list() []hit {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]hit(nil), r.hits...)
}

func handler(s site, rec *recorder) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if rec != nil {
			h := hit{method: r.Method, uri: r.URL.RequestURI(), host: r.Host, ua: r.UserAgent(), auth: r.Header.Get("Authorization") != "", cookie: r.Header.Get("Cookie") != ""}
			if r.TLS != nil {
				h.sni = r.TLS.ServerName
			}
			rec.add(h)
		}
		p, ok := s[r.URL.RequestURI()]
		if !ok {
			p = page{status: http.StatusNotFound, ctype: htmlType, body: "<title>Not found</title>missing"}
		}
		for k, v := range p.header {
			w.Header().Set(k, v)
		}
		if p.ctype != "" {
			w.Header().Set("Content-Type", p.ctype)
		}
		if p.location != "" {
			w.Header().Set("Location", strings.ReplaceAll(p.location, "{host}", r.Host))
		}
		if p.status == 0 {
			p.status = http.StatusOK
		}
		w.WriteHeader(p.status)
		_, _ = io.WriteString(w, strings.ReplaceAll(p.body, "{host}", r.Host))
	})
}

func serve(t *testing.T, s site, rec *recorder) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(handler(s, rec))
	t.Cleanup(srv.Close)
	return srv
}

func htmlPage(title string, links ...string) string {
	var b strings.Builder
	b.WriteString("<!doctype html><html><head><title>" + title + "</title></head><body>")
	for _, l := range links {
		b.WriteString(`<a href="` + l + `">link</a>`)
	}
	b.WriteString("</body></html>")
	return b.String()
}

func baseSite() site {
	return site{
		"/":         {ctype: htmlType, body: htmlPage("Home", "/about/", "/contact/")},
		"/about/":   {ctype: htmlType, body: htmlPage("About us", "/")},
		"/contact/": {ctype: htmlType, body: htmlPage("Contact", "/")},
	}
}

func verify(t *testing.T, opts Options) Report {
	t.Helper()
	r, err := run(context.Background(), opts, fastTuning)
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func pageByPath(t *testing.T, r Report, path string) PageResult {
	t.Helper()
	for _, p := range r.Pages {
		if p.Path == path {
			return p
		}
	}
	t.Fatalf("page %s not in report: %+v", path, paths(r))
	return PageResult{}
}

func paths(r Report) []string {
	out := []string{}
	for _, p := range r.Pages {
		out = append(out, p.Path)
	}
	return out
}

func TestIdenticalSitesOpenTheGate(t *testing.T) {
	oldRec, newRec := &recorder{}, &recorder{}
	oldSrv, newSrv := serve(t, baseSite(), oldRec), serve(t, baseSite(), newRec)
	// Run uses the production politeness settings on this small site.
	r, err := Run(context.Background(), Options{Old: oldSrv.URL, New: newSrv.URL})
	if err != nil {
		t.Fatal(err)
	}
	if !r.CutoverAllowed || r.Verdict != "CUTOVER ALLOWED: every compared page and closed URL matches the old site" {
		t.Fatalf("gate closed for identical sites: %s\n%s", r.Verdict, r.Text())
	}
	if got := paths(r); !reflect.DeepEqual(got, []string{"/", "/about/", "/contact/"}) {
		t.Fatalf("pages %v", got)
	}
	if r.Counts.PagesCompared != 3 || r.Counts.PagesPass != 3 || r.PageLimit != DefaultPageLimit || r.SchemaVersion != SchemaVersion {
		t.Fatalf("counts %+v limit %d", r.Counts, r.PageLimit)
	}
	if r.Pages[0].Source != "root" || r.Pages[1].Source != "link" || r.Pages[1].Old.Title != "About us" {
		t.Fatalf("page details %+v", r.Pages[:2])
	}
	for _, h := range append(oldRec.list(), newRec.list()...) {
		if h.method != http.MethodGet || h.ua != UserAgent || h.auth || h.cookie {
			t.Fatalf("unexpected request %+v", h)
		}
	}
	raw, err := json.Marshal(r)
	if err != nil {
		t.Fatal(err)
	}
	var fields map[string]any
	if err = json.Unmarshal(raw, &fields); err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{"schema_version", "scope", "started_at", "finished_at", "old_origin", "new_origin", "insecure_new_tls", "page_limit", "accepted_warnings", "cutover_allowed", "verdict", "counts", "warnings", "pages", "probes"} {
		if _, ok := fields[key]; !ok {
			t.Fatalf("report JSON lacks %q: %s", key, raw)
		}
	}
	if fields["old_origin"] != oldSrv.URL || fields["new_origin"] != newSrv.URL {
		t.Fatalf("origins %v %v", fields["old_origin"], fields["new_origin"])
	}
}

func TestNewServerErrorFailsThePage(t *testing.T) {
	broken := baseSite()
	broken["/about/"] = page{status: http.StatusInternalServerError, ctype: htmlType, body: "<title>Error</title>"}
	r := verify(t, Options{Old: serve(t, baseSite(), nil).URL, New: serve(t, broken, nil).URL})
	p := pageByPath(t, r, "/about/")
	if p.Result != Fail || p.Reason != "status 200 → 500" {
		t.Fatalf("page %+v", p)
	}
	if r.CutoverAllowed || r.Verdict != "CUTOVER LOCKED: 1 failed check(s)" {
		t.Fatalf("verdict %q", r.Verdict)
	}
}

func TestTitleDifferenceFailsAfterWhitespaceNormalisation(t *testing.T) {
	changed := baseSite()
	changed["/about/"] = page{ctype: htmlType, body: htmlPage("\n  About \t us  ", "/")}
	changed["/contact/"] = page{ctype: htmlType, body: htmlPage("Kontakt", "/")}
	r := verify(t, Options{Old: serve(t, baseSite(), nil).URL, New: serve(t, changed, nil).URL})
	if p := pageByPath(t, r, "/about/"); p.Result != Pass {
		t.Fatalf("whitespace-only title change failed: %+v", p)
	}
	p := pageByPath(t, r, "/contact/")
	if p.Result != Fail || !strings.Contains(p.Reason, "title differs") || r.CutoverAllowed {
		t.Fatalf("title change not caught: %+v", p)
	}
}

func padded(title string, size int) string {
	body := htmlPage(title)
	return body + "<!--" + strings.Repeat("x", size-len(body)-7) + "-->"
}

func TestWarningsLockTheGateUntilAccepted(t *testing.T) {
	old := baseSite()
	old["/"] = page{ctype: htmlType, body: htmlPage("Home", "/about/", "/contact/", "/big/")}
	old["/big/"] = page{ctype: htmlType, body: padded("Big", 20480)}
	drift := old.clone()
	drift["/big/"] = page{ctype: htmlType, body: padded("Big", 20480+3072)}
	oldURL, newURL := serve(t, old, nil).URL, serve(t, drift, nil).URL

	r := verify(t, Options{Old: oldURL, New: newURL})
	p := pageByPath(t, r, "/big/")
	if p.Result != Warn || p.Reason != "size 20480 → 23552 bytes (+15%)" {
		t.Fatalf("size drift %+v", p)
	}
	if r.CutoverAllowed || r.AcceptedWarnings || r.Verdict != "CUTOVER LOCKED: 1 warning(s) to review; rerun with --accept-warnings once a person has checked them" {
		t.Fatalf("warning did not lock the gate: %q", r.Verdict)
	}

	r = verify(t, Options{Old: oldURL, New: newURL, AcceptWarnings: true})
	if !r.CutoverAllowed || !r.AcceptedWarnings || !strings.HasPrefix(r.Verdict, "CUTOVER ALLOWED WITH 1 ACCEPTED WARNING(S): ") {
		t.Fatalf("accepted warning: %v %q", r.CutoverAllowed, r.Verdict)
	}
	raw, err := json.Marshal(r)
	if err != nil || !strings.Contains(string(raw), `"accepted_warnings":true`) {
		t.Fatalf("acceptance not recorded: %v %s", err, raw)
	}

	failing := drift.clone()
	failing["/contact/"] = page{status: http.StatusNotFound, ctype: htmlType, body: "gone"}
	r = verify(t, Options{Old: oldURL, New: serve(t, failing, nil).URL, AcceptWarnings: true})
	if r.CutoverAllowed || r.Verdict != "CUTOVER LOCKED: 1 failed check(s)" {
		t.Fatalf("failure passed with accepted warnings: %q", r.Verdict)
	}
}

func TestSizeTolerance(t *testing.T) {
	tol := sizeTolerance{percent: DefaultSizeTolerancePercent, floor: DefaultSizeToleranceBytes}
	cases := []struct {
		old, new int64
		want     Result
	}{
		{0, 0, Pass},
		{0, 1, Fail},
		{1229, 512, Fail}, // a 1.2 KiB page replaced by a 0.5 KiB one
		{1229, 1229 + 307, Pass},
		{1229, 1229 + 308, Fail}, // small pages have no warning band
		{4000, 4900, Pass},
		{4000, 5100, Fail},
		{8192, 8192 + 2048, Pass},
		{8192, 8192 + 2049, Fail},
		{20480, 20480 + 2048, Pass},
		{20480, 20480 - 2048, Pass},
		{20480, 20480 + 4096, Warn},
		{20480, 20480 - 5120, Warn},
		{20480, 20480 + 5121, Fail},
		{100000, 110000, Pass},
		{100000, 110001, Warn},
		{100000, 125000, Warn},
		{100000, 125001, Fail},
		{100000, 0, Fail},
	}
	for _, c := range cases {
		if got := compareSize(c.old, c.new, tol); got != c.want {
			t.Errorf("compareSize(%d, %d) = %s, want %s", c.old, c.new, got, c.want)
		}
	}
	huge := Response{Status: 200, ContentType: "text/html", Bytes: 2 << 20, Truncated: true}
	if result, _, reason := judgePage(huge, huge, tol); result != Warn || !strings.Contains(reason, "read limit") {
		t.Fatalf("truncated body: %s %s", result, reason)
	}
}

func TestTruncatedBodyIsAWarning(t *testing.T) {
	big := site{"/": {ctype: htmlType, body: padded("Home", 4096)}}
	tune := fastTuning
	tune.maxBody = 1024
	r, err := run(context.Background(), Options{Old: serve(t, big, nil).URL, New: serve(t, big, nil).URL}, tune)
	if err != nil {
		t.Fatal(err)
	}
	p := pageByPath(t, r, "/")
	if p.Result != Warn || !p.Old.Truncated || p.Old.Bytes != 1024 || p.Old.Title != "Home" || r.CutoverAllowed {
		t.Fatalf("truncated page %+v", p)
	}
}

func TestRedirectsCompareAcrossOrigins(t *testing.T) {
	old := site{
		"/":        {ctype: htmlType, body: htmlPage("Home", "/go", "/moved", "/away", "/secure")},
		"/go":      {status: http.StatusMovedPermanently, location: "http://{host}/target/"},
		"/moved":   {status: http.StatusFound, location: "/x"},
		"/away":    {status: http.StatusMovedPermanently, location: "https://elsewhere.example/"},
		"/secure":  {status: http.StatusMovedPermanently, location: "/secure/"},
		"/target/": {ctype: htmlType, body: htmlPage("Target")},
		"/secure/": {ctype: htmlType, body: htmlPage("Secure")},
	}
	copied := old.clone()
	copied["/go"] = page{status: http.StatusMovedPermanently, location: "/target/"}
	copied["/moved"] = page{status: http.StatusFound, location: "/y"}
	copied["/secure"] = page{status: http.StatusFound, location: "/secure/"}
	r := verify(t, Options{Old: serve(t, old, nil).URL, New: serve(t, copied, nil).URL})
	if p := pageByPath(t, r, "/go"); p.Result != Pass || p.Old.Location != "/target/" || p.New.Location != "/target/" {
		t.Fatalf("own-host redirect did not compare equal: %+v", p)
	}
	if p := pageByPath(t, r, "/moved"); p.Result != Fail || p.Reason != "redirect /x → /y" {
		t.Fatalf("redirect change not caught: %+v", p)
	}
	if p := pageByPath(t, r, "/away"); p.Result != Pass || p.Old.Location != "https://elsewhere.example/" {
		t.Fatalf("external redirect %+v", p)
	}
	if p := pageByPath(t, r, "/secure"); p.Result != Fail || p.Reason != "status 301 → 302" {
		t.Fatalf("redirect status change %+v", p)
	}
	if p := pageByPath(t, r, "/target/"); p.Source != "redirect" || p.Result != Pass {
		t.Fatalf("redirect target not compared: %+v", p)
	}
}

func TestLocationNormalisation(t *testing.T) {
	oldOrigin, _ := parseOrigin("old", "https://example.com")
	newOrigin, _ := parseOrigin("new", "http://203.0.113.7:8080")
	cases := map[string]string{
		"https://example.com/b?x=1":         "/b?x=1",
		"http://203.0.113.7:8080/b":         "/b",
		"http://example.com/b":              "http://(site)/b",
		"https://EXAMPLE.com:443/b#top":     "/b#top",
		"https://user:pw@other.example/b":   "https://other.example/b",
		"https://example.com:8443/b":        "https://example.com:8443/b",
		"https://www.example.com/":          "https://www.example.com/",
		"http://203.0.113.7:8080":           "/",
		"https://203.0.113.7:8080/insecure": "https://203.0.113.7:8080/insecure",
	}
	for raw, want := range cases {
		loc, err := oldOrigin.Parse(raw)
		if err != nil {
			t.Fatal(err)
		}
		if got := normaliseLocation(loc, oldOrigin, newOrigin); got != want {
			t.Errorf("normaliseLocation(%s) = %s, want %s", raw, got, want)
		}
	}
}

func TestSitemapDiscovery(t *testing.T) {
	old := site{
		"/":                  {ctype: htmlType, body: htmlPage("Home")},
		"/sitemap.xml":       {status: http.StatusMovedPermanently, location: "/sitemap_index.xml"},
		"/sitemap_index.xml": {ctype: "application/xml", body: `<?xml version="1.0" encoding="UTF-8"?><sitemapindex xmlns="http://www.sitemaps.org/schemas/sitemap/0.9"><sitemap><loc>http://{host}/sitemap-pages.xml</loc></sitemap><sitemap><loc>https://cdn.example/sitemap-x.xml</loc></sitemap></sitemapindex>`},
		"/sitemap-pages.xml": {ctype: "text/xml", body: "\xef\xbb\xbf" + `<?xml version="1.0"?><urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9"><url><loc> http://{host}/hidden/ </loc></url><url><loc>https://other.example/nope/</loc></url><url><loc>http://{host}/logo.png</loc></url></urlset>`},
		"/wp-sitemap.xml":    {ctype: "application/xml", body: `<?xml version="1.0"?><urlset><url><loc>http://{host}/wp-page/</loc></url><url><loc>http://{host}/hidden/</loc></url></urlset>`},
		"/hidden/":           {ctype: htmlType, body: htmlPage("Hidden")},
		"/wp-page/":          {ctype: htmlType, body: htmlPage("WP page")},
	}
	newRec := &recorder{}
	r := verify(t, Options{Old: serve(t, old, nil).URL, New: serve(t, old.clone(), newRec).URL})
	if got := paths(r); !reflect.DeepEqual(got, []string{"/", "/hidden/", "/wp-page/"}) {
		t.Fatalf("sitemap pages %v", got)
	}
	if r.Pages[1].Source != "sitemap" || r.Pages[2].Source != "sitemap" || len(r.Warnings) != 0 || !r.CutoverAllowed {
		t.Fatalf("sitemap report %+v %v %s", r.Pages, r.Warnings, r.Verdict)
	}
	for _, h := range newRec.list() {
		if strings.Contains(h.uri, "sitemap") {
			t.Fatalf("discovery touched the new site: %s", h.uri)
		}
	}
}

func TestBrokenSitemapIsAWarning(t *testing.T) {
	old := site{
		"/":               {ctype: htmlType, body: htmlPage("Home")},
		"/sitemap.xml":    {ctype: htmlType, body: "<!doctype html><title>Soft 404</title>"},
		"/wp-sitemap.xml": {ctype: "application/xml", body: `<?xml version="1.0"?><urlset><url><loc>`},
	}
	r := verify(t, Options{Old: serve(t, old, nil).URL, New: serve(t, old.clone(), nil).URL})
	if len(r.Warnings) != 1 || !strings.Contains(r.Warnings[0], "/wp-sitemap.xml is not valid sitemap XML") || r.CutoverAllowed {
		t.Fatalf("warnings %v verdict %q", r.Warnings, r.Verdict)
	}
}

func TestPageLimitIsRespected(t *testing.T) {
	old := site{}
	links := []string{}
	for i := 1; i <= 30; i++ {
		p := "/p" + string(rune('a'+i%26)) + strings.Repeat("x", i) + "/"
		links = append(links, p)
		old[p] = page{ctype: htmlType, body: htmlPage("Page", "/deep"+p)}
	}
	old["/"] = page{ctype: htmlType, body: htmlPage("Home", links...)}
	oldRec, newRec := &recorder{}, &recorder{}
	r := verify(t, Options{Old: serve(t, old, oldRec).URL, New: serve(t, old.clone(), newRec).URL, PageLimit: 5})
	if len(r.Pages) != 5 || r.PageLimit != 5 {
		t.Fatalf("pages %d", len(r.Pages))
	}
	pageHits := 0
	for _, h := range oldRec.list() {
		if !strings.Contains(h.uri, "sitemap") {
			pageHits++
		}
	}
	if pageHits != 5 || len(newRec.list()) != 5 {
		t.Fatalf("requests beyond the limit: old %d new %d", pageHits, len(newRec.list()))
	}
	// Identical copies, but most of the 61-page site went uncompared: a warning, so
	// the gate stays closed until a person accepts it.
	if r.CutoverAllowed || !hasWarning(r, "page limit (5) was reached") {
		t.Fatalf("a crawl cut short by the limit left the gate open: %v %q", r.CutoverAllowed, r.Warnings)
	}
	small := verify(t, Options{Old: serve(t, old, &recorder{}).URL, New: serve(t, old.clone(), &recorder{}).URL, PageLimit: MaxPageLimit})
	if hasWarning(small, "page limit") || !small.CutoverAllowed {
		t.Fatalf("a crawl that ran out of pages before the limit was warned about: %q", small.Warnings)
	}
}

func hasWarning(r Report, fragment string) bool {
	for _, w := range r.Warnings {
		if strings.Contains(w, fragment) {
			return true
		}
	}
	return false
}

func TestDiscoveryOrderAndFilters(t *testing.T) {
	home := `<!doctype html><html><head><title>Home</title></head><body>
<a href="/list?page=1">1</a><a href="/list?page=2">2</a><a href="/list?page=3">3</a>
<a href="/img/logo.PNG">logo</a><a href="/doc#part">doc</a><a href="/doc">doc again</a>
<a rel="external nofollow" href="/nofollow/">no</a><a href="mailto:a@example.com">mail</a>
<a href="https://other.example/x">other</a><a href="http://user:pw@{host}/creds/">creds</a>
</body></html>`
	old := site{
		"/":            {ctype: htmlType, body: home},
		"/sitemap.xml": {ctype: "application/xml", body: `<urlset><url><loc>http://{host}/s1/</loc></url><url><loc>http://{host}/s2/</loc></url></urlset>`},
	}
	r := verify(t, Options{Old: serve(t, old, nil).URL, New: serve(t, old.clone(), nil).URL, Paths: []string{"/extra/", "/"}})
	want := []string{"/", "/extra/", "/list?page=1", "/s1/", "/list?page=2", "/s2/", "/doc"}
	if got := paths(r); !reflect.DeepEqual(got, want) {
		t.Fatalf("order %v, want %v", got, want)
	}
	sources := []string{}
	for _, p := range r.Pages {
		sources = append(sources, p.Source)
	}
	if !reflect.DeepEqual(sources, []string{"root", "path", "link", "sitemap", "link", "sitemap", "link"}) {
		t.Fatalf("sources %v", sources)
	}
}

func TestParseHTML(t *testing.T) {
	page, err := parseOrigin("old", "https://example.com")
	if err != nil {
		t.Fatal(err)
	}
	page = page.JoinPath("/blog/post/")
	doc := `<html><head><base href="/root/"><title> Fish &amp;  Chips </title></head><body>
<svg><title>icon</title></svg><a href="next">n</a><a href=" /abs ">a</a><a rel="NoFollow" href="/skip">s</a></body></html>`
	title, links := parseHTML([]byte(doc), page, true)
	if title != "Fish & Chips" {
		t.Fatalf("title %q", title)
	}
	got := []string{}
	for _, l := range links {
		got = append(got, l.String())
	}
	if !reflect.DeepEqual(got, []string{"https://example.com/root/next", "https://example.com/abs"}) {
		t.Fatalf("links %v", got)
	}
	if title, _ = parseHTML([]byte(`<svg><title>icon</title></svg><p>no head`), page, false); title != "" {
		t.Fatalf("svg title used as page title: %q", title)
	}
}

func TestProbesNewOpenIsCriticalAndListedFirst(t *testing.T) {
	old := baseSite()
	old["/private/"] = page{status: http.StatusUnauthorized, ctype: htmlType, body: "auth", header: map[string]string{"WWW-Authenticate": `Basic realm="Private"`}}
	old["/wp-config.php"] = page{status: http.StatusForbidden, ctype: htmlType, body: "denied"}
	old["/open.php"] = page{ctype: htmlType, body: "open"}
	copied := old.clone()
	copied["/private/"] = page{ctype: htmlType, body: htmlPage("Private files")}
	copied["/about/"] = page{status: http.StatusInternalServerError, ctype: htmlType, body: "error"}
	r := verify(t, Options{
		Old: serve(t, old, nil).URL, New: serve(t, copied, nil).URL,
		Probes: []Probe{{Path: "/wp-config.php", Kind: ProbeDeny}, {Path: "/open.php", Kind: ProbeDeny}, {Path: "/private/", Kind: ProbeAuth}, {Path: "/wp-config.php", Kind: ProbeDeny}},
	})
	if len(r.Probes) != 3 {
		t.Fatalf("duplicate probe not merged: %+v", r.Probes)
	}
	byPath := map[string]ProbeResult{}
	for _, p := range r.Probes {
		byPath[p.Path] = p
	}
	if p := byPath["/private/"]; p.Code != CodeNewOpen || !p.Critical || p.Result != Fail || p.OldStatus != 401 || p.NewStatus != 200 || p.OldAuthScheme != "basic" {
		t.Fatalf("new_open probe %+v", p)
	}
	if p := byPath["/wp-config.php"]; p.Code != CodeOK || p.Result != Pass || p.OldStatus != 403 || p.NewStatus != 403 {
		t.Fatalf("deny probe %+v", p)
	}
	if p := byPath["/open.php"]; p.Code != CodeOldNotClosed || p.Result != Fail || p.Critical {
		t.Fatalf("old_not_closed probe %+v", p)
	}
	if r.CutoverAllowed || r.Counts.Critical != 1 || r.Counts.ProbesFail != 2 || r.Counts.ProbesPass != 1 {
		t.Fatalf("gate %v counts %+v", r.CutoverAllowed, r.Counts)
	}
	lines := strings.Split(r.Text(), "\n")
	if !strings.HasPrefix(lines[0], "CRITICAL closed URL /private/ (auth) new_open: ") {
		t.Fatalf("new_open not listed first:\n%s", r.Text())
	}
	if lines[1] != "CUTOVER LOCKED: 3 failed check(s)" || !strings.HasPrefix(lines[2], "FAIL ") {
		t.Fatalf("text order:\n%s", r.Text())
	}
}

func TestProbeClassification(t *testing.T) {
	resp := func(status int, scheme string) Response { return Response{Status: status, AuthScheme: scheme} }
	cases := []struct {
		kind     ProbeKind
		old, new Response
		code     ProbeCode
		critical bool
	}{
		{ProbeAuth, resp(401, "basic"), resp(401, "basic"), CodeOK, false},
		{ProbeAuth, resp(401, "basic"), resp(302, ""), CodeNewOpen, true},
		{ProbeAuth, resp(403, ""), resp(200, ""), CodeNewOpen, true},
		{ProbeAuth, resp(403, ""), resp(403, ""), CodeOldUnexpectedStatus, false},
		{ProbeDeny, resp(404, ""), resp(404, ""), CodeOldUnexpectedStatus, false},
		{ProbeDeny, resp(301, ""), resp(301, ""), CodeOldNotClosed, false},
		{ProbeDeny, resp(403, ""), resp(404, ""), CodeNewDiffers, false},
		{ProbeAuth, resp(401, "basic"), resp(403, ""), CodeNewDiffers, false},
		{ProbeAuth, resp(401, "basic"), resp(401, "digest"), CodeAuthSchemeDiffers, false},
		{ProbeDeny, resp(403, ""), Response{Error: "connection refused"}, CodeRequestFailed, false},
		{ProbeAllow, resp(200, ""), resp(200, ""), CodeOK, false},
		{ProbeAllow, resp(200, ""), resp(403, ""), CodeNewDiffers, false},
		{ProbeAllow, resp(403, ""), resp(403, ""), CodeOldUnexpectedStatus, false},
		{ProbeAllow, resp(404, ""), resp(200, ""), CodeOldUnexpectedStatus, false},
	}
	for _, c := range cases {
		got := judgeProbe(Probe{Path: "/x", Kind: c.kind}, c.old, c.new)
		wantResult := Fail
		if c.code == CodeOK {
			wantResult = Pass
		}
		if got.Code != c.code || got.Critical != c.critical || got.Result != wantResult {
			t.Errorf("%s old %d new %d: got %s critical=%v %s", c.kind, c.old.Status, c.new.Status, got.Code, got.Critical, got.Result)
		}
	}
}

func TestClosedCrawledPageOpenOnNewIsCritical(t *testing.T) {
	old := baseSite()
	old["/"] = page{ctype: htmlType, body: htmlPage("Home", "/members/")}
	old["/members/"] = page{status: http.StatusForbidden, ctype: htmlType, body: "forbidden"}
	copied := old.clone()
	copied["/members/"] = page{ctype: htmlType, body: htmlPage("Members")}
	r := verify(t, Options{Old: serve(t, old, nil).URL, New: serve(t, copied, nil).URL})
	p := pageByPath(t, r, "/members/")
	if p.Result != Fail || !p.Critical || r.CutoverAllowed {
		t.Fatalf("closed page %+v", p)
	}
	if !strings.HasPrefix(r.Text(), "CRITICAL page /members/: closed on the old site (403) but open on the new site (200)\n") {
		t.Fatalf("critical page not first:\n%s", r.Text())
	}
}

func TestConnectToOverrideSendsSiteHost(t *testing.T) {
	newRec := &recorder{}
	newSrv := serve(t, baseSite(), newRec)
	addr := newSrv.Listener.Addr().String()
	r := verify(t, Options{Old: serve(t, baseSite(), nil).URL, New: "http://shop.example.test", NewConnect: addr})
	if !r.CutoverAllowed || r.NewConnect != addr || r.NewOrigin != "http://shop.example.test" {
		t.Fatalf("connect-to run: %s %+v", r.Verdict, r.Pages)
	}
	hits := newRec.list()
	if len(hits) != 3 {
		t.Fatalf("new hits %+v", hits)
	}
	for _, h := range hits {
		if h.host != "shop.example.test" {
			t.Fatalf("Host header %q", h.host)
		}
	}
	if !strings.Contains(r.Text(), "New site: http://shop.example.test connecting to "+addr) {
		t.Fatalf("text:\n%s", r.Text())
	}
}

func TestConnectToTLSVerifiesTheSiteHostname(t *testing.T) {
	newRec := &recorder{}
	newSrv := httptest.NewUnstartedServer(handler(baseSite(), newRec))
	newSrv.Config.ErrorLog = log.New(io.Discard, "", 0)
	newSrv.StartTLS()
	t.Cleanup(newSrv.Close)
	addr := newSrv.Listener.Addr().String()
	oldURL := serve(t, baseSite(), nil).URL
	roots := x509.NewCertPool()
	roots.AddCert(newSrv.Certificate())
	trusted := fastTuning
	trusted.roots = roots

	// The test certificate is issued for example.com.
	r, err := run(context.Background(), Options{Old: oldURL, New: "https://example.com", NewConnect: addr}, trusted)
	if err != nil {
		t.Fatal(err)
	}
	if !r.CutoverAllowed || len(r.Warnings) != 0 {
		t.Fatalf("verified TLS run: %s\n%s", r.Verdict, r.Text())
	}
	for _, h := range newRec.list() {
		if h.sni != "example.com" || h.host != "example.com" {
			t.Fatalf("SNI %q Host %q", h.sni, h.host)
		}
	}

	r, err = run(context.Background(), Options{Old: oldURL, New: "https://wrong.example", NewConnect: addr}, trusted)
	if err != nil {
		t.Fatal(err)
	}
	if r.CutoverAllowed || !strings.Contains(r.Pages[0].Reason, "new site request failed") || !strings.Contains(r.Pages[0].Reason, "certificate") {
		t.Fatalf("hostname mismatch accepted: %+v", r.Pages[0])
	}

	r = verify(t, Options{Old: oldURL, New: "https://example.com", NewConnect: addr})
	if r.CutoverAllowed || !strings.Contains(r.Pages[0].Reason, "certificate") {
		t.Fatalf("untrusted certificate accepted by default: %+v", r.Pages[0])
	}

	r = verify(t, Options{Old: oldURL, New: "https://example.com", NewConnect: addr, InsecureNewTLS: true})
	if !r.InsecureNewTLS || len(r.Warnings) != 1 || r.Warnings[0] != insecureNewTLSWarning || r.Counts.PagesPass != 3 || r.CutoverAllowed {
		t.Fatalf("insecure TLS run: %v %s %+v", r.Warnings, r.Verdict, r.Counts)
	}
	if !strings.Contains(r.Text(), "WARN "+insecureNewTLSWarning) {
		t.Fatalf("insecure TLS warning line missing:\n%s", r.Text())
	}
	r = verify(t, Options{Old: oldURL, New: "https://example.com", NewConnect: addr, InsecureNewTLS: true, AcceptWarnings: true})
	if !r.CutoverAllowed {
		t.Fatalf("accepted insecure TLS warning: %s", r.Verdict)
	}
}

func TestCancellationStopsTheRun(t *testing.T) {
	started := make(chan struct{}, 1)
	release := make(chan struct{})
	hang := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case started <- struct{}{}:
		default:
		}
		select {
		case <-r.Context().Done():
		case <-release:
		}
	})
	oldSrv := httptest.NewServer(hang)
	defer oldSrv.Close()
	defer close(release)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() {
		<-started
		cancel()
	}()
	began := time.Now()
	r, err := run(ctx, Options{Old: oldSrv.URL, New: serve(t, baseSite(), nil).URL}, fastTuning)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled run returned %v", err)
	}
	if elapsed := time.Since(began); elapsed > 5*time.Second {
		t.Fatalf("cancellation took %s", elapsed)
	}
	if r.Verdict != "" || r.Pages != nil {
		t.Fatalf("cancelled run returned a report: %+v", r)
	}
}

func TestCredentialURLsAreRejected(t *testing.T) {
	secret := "hidden-value-7"
	for _, opts := range []Options{
		{Old: "http://user:" + secret + "@127.0.0.1:1", New: "http://127.0.0.1:2"},
		{Old: "http://127.0.0.1:1", New: "https://admin:" + secret + "@example.com"},
		{Old: "http://user:" + secret + "@[bad", New: "http://127.0.0.1:2"},
	} {
		_, err := Run(context.Background(), opts)
		if err == nil || strings.Contains(err.Error(), secret) {
			t.Fatalf("credential URL: %v", err)
		}
	}
	_, err := Run(context.Background(), Options{Old: "http://user:" + secret + "@127.0.0.1:1", New: "http://127.0.0.1:2"})
	if !strings.Contains(err.Error(), "must not contain credentials") {
		t.Fatalf("unclear credential error: %v", err)
	}
}

func TestOptionValidation(t *testing.T) {
	cases := map[string]Options{
		"same origin without connect": {Old: "https://example.com", New: "https://EXAMPLE.com:443/"},
		"origin with path":            {Old: "https://example.com/blog", New: "https://new.example"},
		"origin with query":           {Old: "https://example.com", New: "https://new.example?x=1"},
		"ftp origin":                  {Old: "ftp://example.com", New: "https://new.example"},
		"page limit too high":         {Old: "https://example.com", New: "https://new.example", PageLimit: MaxPageLimit + 1},
		"negative page limit":         {Old: "https://example.com", New: "https://new.example", PageLimit: -1},
		"paths do not fit":            {Old: "https://example.com", New: "https://new.example", PageLimit: 2, Paths: []string{"/a", "/b"}},
		"relative path":               {Old: "https://example.com", New: "https://new.example", Paths: []string{"a"}},
		"protocol-relative path":      {Old: "https://example.com", New: "https://new.example", Paths: []string{"//evil.example/"}},
		"bad probe kind":              {Old: "https://example.com", New: "https://new.example", Probes: []Probe{{Path: "/x", Kind: "open"}}},
		"conflicting probe kinds":     {Old: "https://example.com", New: "https://new.example", Probes: []Probe{{Path: "/x", Kind: ProbeAuth}, {Path: "/x", Kind: ProbeDeny}}},
		"probe with fragment":         {Old: "https://example.com", New: "https://new.example", Probes: []Probe{{Path: "/x#y", Kind: ProbeAuth}}},
		"bad connect":                 {Old: "https://example.com", New: "https://example.com", NewConnect: "203.0.113.5"},
		"tolerance too wide":          {Old: "https://example.com", New: "https://new.example", SizeTolerancePercent: 30},
	}
	for name, opts := range cases {
		if _, err := opts.validate(); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	cfg, err := Options{Old: "https://example.com", New: "https://example.com", NewConnect: "[2001:db8::1]:443", PageLimit: 2, Paths: []string{"/a", "/a", "/"}}.validate()
	if err != nil || cfg.newConnect != "[2001:db8::1]:443" || !reflect.DeepEqual(cfg.paths, []string{"/a"}) || cfg.tolerance != (sizeTolerance{10, 2048}) {
		t.Fatalf("valid options rejected: %v %+v", err, cfg)
	}
}
