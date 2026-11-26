package hostaccounts

import (
	"context"
	"fmt"
	"regexp"
	"sort"
	"time"

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
	// PanelHosts are the panel's own host names (DNS names only, lower
	// case, each once counting its www. form). Port 80 serves them for the
	// panel's certificate challenges only (olsweb.Server.ChallengeHosts).
	PanelHosts []string
}

// ValidPanelHosts reports whether hosts may be WebOptions.PanelHosts: at
// most olsweb.MaxDomainsPerSite lowercase DNS names, none twice counting
// its www. form.
func ValidPanelHosts(hosts []string) bool {
	return olsweb.ValidateChallengeHosts(hosts) == nil
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

// sitePHPChildren is the LSAPI children of every site's lsphp app.
const sitePHPChildren = 4

// siteName is the vhost name: the account ID, which is unique and fits
// OpenLiteSpeed's name rules (usernames may hold underscores; names may not).
func siteName(id string) string { return "u" + id[:31] }

// softQuotaMiB leaves a warning margin under the hard limit.
func softQuotaMiB(hard int) int { return hard - hard/10 }

// servedWeb is the web state webSites renders for a record, and whether it
// lists the site at all: live, and not being deleted. A web change in
// flight counts as done.
func servedWeb(r record) (WebState, bool) {
	w := r.Web
	if r.Pending != nil && r.Pending.Action == "web" {
		w = r.WebNext
	}
	return w, w.enabled() && (r.Pending == nil || r.Pending.Action != "delete")
}

// httpsUntil is the Unix second at which the record's "Always use HTTPS"
// stops: its certificate's NotAfter. Zero when it has none in the config:
// no certificate is installed, or the owner turned it off. A certificate or
// switch change in flight counts as done.
func httpsUntil(r record) int64 {
	certificate := r.TLS
	if r.Pending != nil && r.Pending.Action == "certificate" {
		certificate = r.TLSNext
	}
	plainHTTP := r.Account.PlainHTTP
	if r.Pending != nil && r.Pending.Action == "https" {
		plainHTTP = r.Pending.Target == "off"
	}
	if !certificate.installed() || plainHTTP {
		return 0
	}
	return certificate.NotAfter
}

// webSites lists every live site as OpenLiteSpeed should serve it, sorted by
// name, without the account named by except (used while removing a site).
// Settings in flight are used for the account they belong to, so a recovery
// renders the same config as the interrupted write. A site with a
// certificate gets its files in olsweb.TLSRoot/<site name>/, and plain
// http for the domains it covers is redirected to https while it is valid,
// unless the account's PlainHTTP says otherwise. A suspended
// account's site stays in the list marked suspended, so OpenLiteSpeed
// refuses every request for it; a state change in flight counts as done.
func webSites(items []record, except string) []olsweb.Site {
	sites := []olsweb.Site{}
	for _, r := range items {
		if r.Account.ID == except {
			continue
		}
		w, served := servedWeb(r)
		if !served {
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
		limits := recordLimits(r)
		// The account's own domain first, then its aliases; a domains
		// change in flight counts as done. olsweb renders the redirects for
		// an active site only.
		extra := recordSiteDomains(r)
		site := olsweb.Site{
			Name:       siteName(r.Account.ID),
			Username:   r.Account.Username,
			Group:      r.Account.Username,
			Domains:    append([]string{r.Account.Domain}, extra.Aliases...),
			Redirects:  olswebRedirects(extra.Redirects),
			Folders:    recordFolders(r),
			DocRoot:    r.Account.PublicHTML,
			PHPVersion: w.PHPVersion,
			Suspended:  state == "suspended",
			// The account's limits for its lsphp app: memory as each
			// process's RLIMIT_AS, processes as RLIMIT_NPROC, raised to the
			// floor OpenLiteSpeed keeps for these children (it would raise a
			// lower number itself). OpenLiteSpeed 1.9.4 sets these rlimits on
			// the path without its namespace container; in the container's
			// path (ns.c) it sets none. The account-wide bound comes from
			// cgroups: with them on, lscgid puts lsphp in
			// user-<uid>.slice/litespeed-exec.scope (cgroup_v2 in lscgid.cpp),
			// under the slice's TasksMax, MemoryMax and CPUQuota.
			Limits:    olsweb.Limits{PHPChildren: sitePHPChildren, MemoryMiB: limits.MemoryMiB, Processes: max(limits.Processes, olsweb.ProcessFloor(sitePHPChildren, 0))},
			Isolation: olsweb.Isolation{Namespace: true, CGroups: true},
		}
		if certificate.installed() {
			// The HTTPS listener maps only the domains the certificate
			// names, so an alias it does not cover (its DNS may not point
			// here yet, or it was added since) is served over http only.
			site.TLS = siteTLS(site.Name)
			site.TLS.Domains = coveredDomains(certificate, site.Domains, r.Account.Domain)
			// "Always use HTTPS": plain http for those domains goes to
			// https while the certificate is valid, unless the owner
			// turned it off. One past its NotAfter is not in force, so the
			// next render after it expires serves plain http again; the
			// broker renders at that second (https_expiry.go).
			site.AlwaysHTTPS = time.Now().Unix() < httpsUntil(r)
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
