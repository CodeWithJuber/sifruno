package hostaccounts

import (
	"context"
	"fmt"
	"regexp"
	"sort"

	"sifruno/internal/olsweb"
)

// The web operation puts an account's website live on OpenLiteSpeed: the web
// server may read the home, the home gets a disk quota, and the account's
// vhost joins the rendered OpenLiteSpeed config, which is tested before a
// graceful reload. It runs only when the broker was started with WebOptions;
// without them it needs none of the web tools and refuses the operation.

// WebOptions turns on the web operation.
type WebOptions struct {
	// ServerUser is the OpenLiteSpeed process user (the `user` setting in
	// httpd_config.conf) that reads static files from public_html.
	ServerUser string
}

// WebInput asks for an account's site to be live with these settings.
// Applying the same settings again repairs drift (ACL, quota or config).
type WebInput struct {
	PHPVersion       string `json:"php_version"`
	QuotaMiB         int    `json:"quota_mib"`
	ExpectedRevision uint64 `json:"expected_revision"`
	Reason           string `json:"reason"`
}

// WebState is what is applied now; empty PHPVersion means no live site.
type WebState struct {
	PHPVersion string `json:"php_version,omitempty"`
	QuotaMiB   int    `json:"quota_mib,omitempty"`
}

type WebResult struct {
	Account Account  `json:"account"`
	Web     WebState `json:"web"`
}

// WebService is implemented by the store and the client.
type WebService interface {
	SetWeb(context.Context, string, WebInput, string) (WebResult, error)
}

const (
	minQuotaMiB = 64
	maxQuotaMiB = 1 << 20 // 1 TiB
)

var webPHPVersions = map[string]bool{"8.1": true, "8.2": true, "8.3": true, "8.4": true}
var webDigestPattern = regexp.MustCompile(`^php=8\.[1-4];quota=[1-9][0-9]{1,6}$`)

func (w WebState) enabled() bool { return w.PHPVersion != "" }

func validWebState(w WebState) bool {
	return webPHPVersions[w.PHPVersion] && w.QuotaMiB >= minQuotaMiB && w.QuotaMiB <= maxQuotaMiB
}

// webDigest is the journal target for a web operation.
func webDigest(w WebState) string { return fmt.Sprintf("php=%s;quota=%d", w.PHPVersion, w.QuotaMiB) }

// siteName is the vhost name: the account ID, which is unique and fits
// OpenLiteSpeed's name rules (usernames may hold underscores; names may not).
func siteName(id string) string { return "u" + id[:31] }

// softQuotaMiB leaves a warning margin under the hard limit.
func softQuotaMiB(hard int) int { return hard - hard/10 }

// webSites lists every live site as OpenLiteSpeed should serve it, sorted by
// name, without the account named by except (used while removing a site).
// Settings in flight are used for the account they belong to, so a recovery
// renders the same config as the interrupted write. A site with a
// certificate gets its files in olsweb.TLSRoot/<site name>/. A suspended
// account's site stays in the list marked suspended, so OpenLiteSpeed
// refuses every request for it; a state change in flight counts as done.
func webSites(items []record, except string) []olsweb.Site {
	sites := []olsweb.Site{}
	for _, r := range items {
		if r.Account.ID == except {
			continue
		}
		w := r.Web
		if r.Pending != nil && r.Pending.Action == "web" {
			w = r.WebNext
		}
		if !w.enabled() || (r.Pending != nil && r.Pending.Action == "delete") {
			continue
		}
		certificate := r.TLS
		if r.Pending != nil && r.Pending.Action == "certificate" {
			certificate = r.TLSNext
		}
		state := r.Account.State
		if r.Pending != nil && r.Pending.Action == "state" {
			state = r.Pending.Target
		}
		site := olsweb.Site{
			Name:       siteName(r.Account.ID),
			Username:   r.Account.Username,
			Group:      r.Account.Username,
			Domains:    []string{r.Account.Domain},
			DocRoot:    r.Account.PublicHTML,
			PHPVersion: w.PHPVersion,
			Suspended:  state == "suspended",
			Limits:     olsweb.Limits{PHPChildren: 4},
			Isolation:  olsweb.Isolation{Namespace: true},
		}
		if certificate.installed() {
			site.TLS = siteTLS(site.Name)
		}
		sites = append(sites, site)
	}
	sort.Slice(sites, func(i, j int) bool { return sites[i].Name < sites[j].Name })
	return sites
}

// webServer is the whole OpenLiteSpeed fragment the broker owns: plain HTTP
// on port 80 for every site, and HTTPS on 443 for the sites with their own
// certificate. olsweb leaves the HTTPS listener out while no site has one.
func webServer(sites []olsweb.Site) olsweb.Server {
	return olsweb.Server{Listeners: []olsweb.Listener{
		{Name: "http", Address: "*", Port: 80},
		{Name: "https", Address: "*", Port: 443, Secure: true, CertFile: olsweb.TLSRoot + "/" + listenerCertFile, KeyFile: olsweb.TLSRoot + "/" + listenerKeyFile},
	}, Sites: sites}
}

// anyCertificate reports whether a site list renders the HTTPS listener,
// which needs the listener's own certificate on disk.
func anyCertificate(sites []olsweb.Site) bool {
	for _, s := range sites {
		if s.TLS.CertFile != "" {
			return true
		}
	}
	return false
}
