package migrateverify

import (
	"bytes"
	"encoding/xml"
	"errors"
	"io"
	"net/url"
	"path"
	"strings"

	"golang.org/x/net/html"
	"golang.org/x/net/html/atom"
)

const (
	// maxQueryVariants stops calendars, filters and session-style query strings
	// from filling the page budget with one path.
	maxQueryVariants    = 2
	maxLinksPerPage     = 2000
	maxSitemapDocuments = 20
	maxSitemapRedirects = 3
)

var sitemapPaths = []string{"/sitemap.xml", "/wp-sitemap.xml"}

// assetExtensions are skipped during discovery: they are not pages and would
// spend the page budget on files the page checks cannot judge.
var assetExtensions = map[string]bool{
	".css": true, ".js": true, ".mjs": true, ".map": true, ".json": true, ".xml": true, ".txt": true, ".rss": true, ".atom": true,
	".png": true, ".jpg": true, ".jpeg": true, ".gif": true, ".webp": true, ".avif": true, ".svg": true, ".ico": true, ".bmp": true, ".tif": true, ".tiff": true,
	".woff": true, ".woff2": true, ".ttf": true, ".otf": true, ".eot": true,
	".mp3": true, ".mp4": true, ".m4a": true, ".m4v": true, ".mov": true, ".avi": true, ".webm": true, ".ogg": true, ".wav": true, ".flac": true,
	".pdf": true, ".zip": true, ".gz": true, ".tgz": true, ".tar": true, ".rar": true, ".7z": true, ".bz2": true, ".xz": true,
	".exe": true, ".dmg": true, ".iso": true, ".apk": true, ".msi": true,
	".doc": true, ".docx": true, ".xls": true, ".xlsx": true, ".ppt": true, ".pptx": true, ".odt": true, ".ods": true, ".csv": true,
}

type target struct {
	path   string
	source string
}

// crawl holds the ordered discovery queue. Only the first limit entries are
// ever requested, so nothing is queued beyond it.
type crawl struct {
	origin   *url.URL
	limit    int
	queue    []target
	seen     map[string]bool
	variants map[string]int
}

func newCrawl(origin *url.URL, limit int) *crawl {
	return &crawl{origin: origin, limit: limit, seen: map[string]bool{}, variants: map[string]int{}}
}

// seed queues an explicitly requested target. Seeds bypass the query-variant
// cap because the operator asked for each of them.
func (c *crawl) seed(t, source string) {
	if c.seen[t] || len(c.queue) >= c.limit {
		return
	}
	if p, _, ok := strings.Cut(t, "?"); ok {
		c.variants[p]++
	}
	c.seen[t] = true
	c.queue = append(c.queue, target{path: t, source: source})
}

func (c *crawl) addURL(u *url.URL, source string) {
	if len(c.queue) >= c.limit || u == nil || u.User != nil {
		return
	}
	if ok, _ := siteMatch(u, c.origin); !ok || assetExtensions[strings.ToLower(path.Ext(u.Path))] {
		return
	}
	t := siteTarget(u, false)
	if c.seen[t] {
		return
	}
	if p, _, ok := strings.Cut(t, "?"); ok {
		if c.variants[p] >= maxQueryVariants {
			return
		}
		c.variants[p]++
	}
	c.seen[t] = true
	c.queue = append(c.queue, target{path: t, source: source})
}

// addInterleaved alternates home page links with sitemap entries so neither
// source can use up the page budget alone.
func (c *crawl) addInterleaved(links, sitemap []*url.URL) {
	for i := 0; i < len(links) || i < len(sitemap); i++ {
		if len(c.queue) >= c.limit {
			return
		}
		if i < len(links) {
			c.addURL(links[i], "link")
		}
		if i < len(sitemap) {
			c.addURL(sitemap[i], "sitemap")
		}
	}
}

// siteTarget is the escaped path and query of u, used identically on both
// sites. Fragments never reach a server, so they are kept only for redirect
// display.
func siteTarget(u *url.URL, withFragment bool) string {
	t := u.EscapedPath()
	if t == "" {
		t = "/"
	}
	if u.RawQuery != "" {
		t += "?" + u.RawQuery
	}
	if withFragment && u.Fragment != "" {
		t += "#" + u.EscapedFragment()
	}
	return t
}

func effectivePort(u *url.URL) string {
	if p := u.Port(); p != "" {
		return p
	}
	if u.Scheme == "https" {
		return "443"
	}
	return "80"
}

func originKey(u *url.URL) string {
	return u.Scheme + "://" + strings.ToLower(u.Hostname()) + ":" + effectivePort(u)
}

// siteMatch reports whether u belongs to the site at origin. An http/https
// switch on default ports is still the same site (for example an HTTPS
// upgrade redirect); sameScheme tells the caller which case it is.
func siteMatch(u, origin *url.URL) (match, sameScheme bool) {
	if (u.Scheme != "http" && u.Scheme != "https") || !strings.EqualFold(u.Hostname(), origin.Hostname()) {
		return false, false
	}
	if u.Scheme == origin.Scheme {
		return effectivePort(u) == effectivePort(origin), true
	}
	return u.Port() == "" && origin.Port() == "", false
}

// normaliseLocation renders a redirect target so that the old site and the
// new copy compare equal when both point at their own site: a target on
// either origin becomes site-relative.
func normaliseLocation(loc *url.URL, origins ...*url.URL) string {
	for _, o := range origins {
		if ok, sameScheme := siteMatch(loc, o); ok {
			if sameScheme {
				return siteTarget(loc, true)
			}
			return loc.Scheme + "://(site)" + siteTarget(loc, true)
		}
	}
	external := *loc
	external.User = nil
	return external.String()
}

// parseHTML returns the document title and the followable <a href> links,
// resolved against the page URL or its <base href>. rel=nofollow links are
// skipped because site owners use them for pages not meant to be crawled.
func parseHTML(body []byte, page *url.URL, wantLinks bool) (string, []*url.URL) {
	z := html.NewTokenizer(bytes.NewReader(body))
	base := page
	baseSet := false
	svgDepth := 0
	inTitle, titleDone := false, false
	var title strings.Builder
	var links []*url.URL
	for {
		tt := z.Next()
		switch tt {
		case html.ErrorToken:
			return strings.Join(strings.Fields(title.String()), " "), links
		case html.StartTagToken, html.SelfClosingTagToken:
			name, hasAttr := z.TagName()
			switch atom.Lookup(name) {
			case atom.Svg:
				if tt == html.StartTagToken {
					svgDepth++
				}
			case atom.Title:
				// SVG icons carry their own <title>; only the document title counts.
				if tt == html.StartTagToken && !titleDone && svgDepth == 0 {
					inTitle = true
				}
			case atom.Base:
				if href, _ := tagAttrs(z, hasAttr); !baseSet && href != "" {
					if resolved, err := page.Parse(href); err == nil {
						base = resolved
						baseSet = true
					}
				}
			case atom.A:
				href, rel := tagAttrs(z, hasAttr)
				if !wantLinks || href == "" || len(links) >= maxLinksPerPage || hasToken(rel, "nofollow") {
					continue
				}
				if resolved, err := base.Parse(href); err == nil {
					links = append(links, resolved)
				}
			}
		case html.EndTagToken:
			name, _ := z.TagName()
			switch atom.Lookup(name) {
			case atom.Svg:
				if svgDepth > 0 {
					svgDepth--
				}
			case atom.Title:
				if inTitle {
					inTitle = false
					titleDone = true
				}
			}
		case html.TextToken:
			if inTitle {
				title.Write(z.Text())
			}
		}
	}
}

func tagAttrs(z *html.Tokenizer, more bool) (href, rel string) {
	for more {
		var key, val []byte
		key, val, more = z.TagAttr()
		switch string(key) {
		case "href":
			href = strings.TrimSpace(string(val))
		case "rel":
			rel = string(val)
		}
	}
	return href, rel
}

func hasToken(list, token string) bool {
	for _, f := range strings.Fields(list) {
		if strings.EqualFold(f, token) {
			return true
		}
	}
	return false
}

const (
	sitemapNone  = ""
	sitemapURLs  = "urlset"
	sitemapIndex = "sitemapindex"
)

var errNotSitemap = errors.New("not a sitemap document")

// parseSitemap reads a urlset or sitemapindex. A document whose root is
// something else (for example an XHTML soft-404 page) returns errNotSitemap.
func parseSitemap(body []byte) (string, []string, error) {
	body = bytes.TrimPrefix(body, []byte("\xef\xbb\xbf"))
	d := xml.NewDecoder(bytes.NewReader(body))
	for {
		tok, err := d.Token()
		if err != nil {
			if errors.Is(err, io.EOF) {
				return sitemapNone, nil, errNotSitemap
			}
			return sitemapNone, nil, err
		}
		start, ok := tok.(xml.StartElement)
		if !ok {
			continue
		}
		var locs []string
		switch start.Name.Local {
		case sitemapURLs:
			var doc struct {
				Entries []struct {
					Loc string `xml:"loc"`
				} `xml:"url"`
			}
			if err = d.DecodeElement(&doc, &start); err != nil {
				return sitemapNone, nil, err
			}
			for _, e := range doc.Entries {
				locs = append(locs, strings.TrimSpace(e.Loc))
			}
		case sitemapIndex:
			var doc struct {
				Entries []struct {
					Loc string `xml:"loc"`
				} `xml:"sitemap"`
			}
			if err = d.DecodeElement(&doc, &start); err != nil {
				return sitemapNone, nil, err
			}
			for _, e := range doc.Entries {
				locs = append(locs, strings.TrimSpace(e.Loc))
			}
		default:
			return sitemapNone, nil, errNotSitemap
		}
		return start.Name.Local, locs, nil
	}
}

func looksLikeXML(mediaType string, body []byte) bool {
	if strings.HasSuffix(mediaType, "/xml") || strings.HasSuffix(mediaType, "+xml") {
		return true
	}
	trimmed := bytes.TrimLeft(bytes.TrimPrefix(body, []byte("\xef\xbb\xbf")), " \t\r\n")
	for _, prefix := range []string{"<?xml", "<urlset", "<sitemapindex"} {
		if bytes.HasPrefix(trimmed, []byte(prefix)) {
			return true
		}
	}
	return false
}
