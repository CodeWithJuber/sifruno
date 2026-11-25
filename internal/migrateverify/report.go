package migrateverify

import (
	"fmt"
	"strings"
	"time"
)

// SchemaVersion changes when a report field changes meaning or is removed.
const SchemaVersion = 1

// Scope states what this report proves so a green gate is not read as more.
const Scope = "Pages discovered on the old site (status, redirect target, content type, HTML title, body size), listed closed URLs (401/403) and folders open to some addresses only (the status each folder's rule gives the address each site sees verify come from). Screenshots, WordPress admin, database rows, mail, DNS and SSL are not compared."

// Result is the outcome of one page or probe check.
type Result string

const (
	Pass Result = "pass"
	Warn Result = "warn"
	Fail Result = "fail"
)

// ProbeCode explains a probe result.
type ProbeCode string

const (
	CodeOK                  ProbeCode = "ok"
	CodeNewOpen             ProbeCode = "new_open"
	CodeOldNotClosed        ProbeCode = "old_not_closed"
	CodeRequestFailed       ProbeCode = "request_failed"
	CodeOldUnexpectedStatus ProbeCode = "old_unexpected_status"
	CodeNewDiffers          ProbeCode = "new_differs"
	CodeAuthSchemeDiffers   ProbeCode = "auth_scheme_differs"
	// CodeClientUnknown is a ProbeHosts folder checked without a known
	// client address for a site: what its rule gives that site is unknown.
	CodeClientUnknown ProbeCode = "client_unknown"
)

// Response is what one site answered for one request target.
type Response struct {
	Status      int    `json:"status,omitempty"`
	ContentType string `json:"content_type,omitempty"`
	Location    string `json:"location,omitempty"`
	AuthScheme  string `json:"auth_scheme,omitempty"`
	Title       string `json:"title,omitempty"`
	Bytes       int64  `json:"bytes"`
	Truncated   bool   `json:"truncated,omitempty"`
	Error       string `json:"error,omitempty"`
}

// PageResult compares one page on both sites. Source says how the page was
// found: root, path (requested by the operator), link, sitemap or redirect.
type PageResult struct {
	Path     string   `json:"path"`
	Source   string   `json:"source"`
	Result   Result   `json:"result"`
	Critical bool     `json:"critical"`
	Reason   string   `json:"reason"`
	Old      Response `json:"old"`
	New      Response `json:"new"`
}

// ProbeResult compares one closed URL on both sites. For a ProbeHosts
// folder ExpectedStatus is the old site's and ExpectedNewStatus the
// copy's, each from the folder's rule and that site's client address, and
// a failure carries Message: in plain words, the folder, why and what to
// do next. Reason is the technical detail.
type ProbeResult struct {
	Path              string    `json:"path"`
	Kind              ProbeKind `json:"kind"`
	Result            Result    `json:"result"`
	Code              ProbeCode `json:"code"`
	Critical          bool      `json:"critical"`
	Reason            string    `json:"reason"`
	Message           string    `json:"message,omitempty"`
	ExpectedStatus    int       `json:"expected_status"`
	ExpectedNewStatus int       `json:"expected_new_status,omitempty"`
	OldStatus         int       `json:"old_status,omitempty"`
	NewStatus         int       `json:"new_status,omitempty"`
	OldAuthScheme     string    `json:"old_auth_scheme,omitempty"`
	NewAuthScheme     string    `json:"new_auth_scheme,omitempty"`
}

// Counts summarises the results. Warnings includes report-level warnings,
// because every warning keeps the gate closed until a person accepts it.
type Counts struct {
	PagesCompared int `json:"pages_compared"`
	PagesPass     int `json:"pages_pass"`
	PagesWarn     int `json:"pages_warn"`
	PagesFail     int `json:"pages_fail"`
	ProbesPass    int `json:"probes_pass"`
	ProbesFail    int `json:"probes_fail"`
	Critical      int `json:"critical"`
	Warnings      int `json:"warnings"`
}

// Report is the verify result. Origins are stored without credentials because
// URLs carrying credentials are rejected before any request.
type Report struct {
	SchemaVersion    int           `json:"schema_version"`
	Scope            string        `json:"scope"`
	StartedAt        time.Time     `json:"started_at"`
	FinishedAt       time.Time     `json:"finished_at"`
	OldOrigin        string        `json:"old_origin"`
	NewOrigin        string        `json:"new_origin"`
	NewConnect       string        `json:"new_connect,omitempty"`
	OldClient        string        `json:"old_client,omitempty"`
	NewClient        string        `json:"new_client,omitempty"`
	InsecureNewTLS   bool          `json:"insecure_new_tls"`
	PageLimit        int           `json:"page_limit"`
	AcceptedWarnings bool          `json:"accepted_warnings"`
	CutoverAllowed   bool          `json:"cutover_allowed"`
	Verdict          string        `json:"verdict"`
	Counts           Counts        `json:"counts"`
	Warnings         []string      `json:"warnings"`
	Pages            []PageResult  `json:"pages"`
	Probes           []ProbeResult `json:"probes"`
}

// finalize computes the counts and the gate. Failures always close it, and
// warnings close it unless the operator accepted them.
func (r *Report) finalize() {
	var c Counts
	for _, p := range r.Pages {
		if p.Old.Error == "" && p.New.Error == "" {
			c.PagesCompared++
		}
		switch p.Result {
		case Pass:
			c.PagesPass++
		case Warn:
			c.PagesWarn++
		default:
			c.PagesFail++
		}
		if p.Critical {
			c.Critical++
		}
	}
	for _, p := range r.Probes {
		if p.Result == Pass {
			c.ProbesPass++
		} else {
			c.ProbesFail++
		}
		if p.Critical {
			c.Critical++
		}
	}
	c.Warnings = c.PagesWarn + len(r.Warnings)
	r.Counts = c
	failures := c.PagesFail + c.ProbesFail
	r.CutoverAllowed = false
	switch {
	case failures > 0:
		r.Verdict = fmt.Sprintf("CUTOVER LOCKED: %d failed check(s)", failures)
	case c.PagesCompared == 0:
		r.Verdict = "CUTOVER LOCKED: no page was compared"
	case c.Warnings > 0 && !r.AcceptedWarnings:
		r.Verdict = fmt.Sprintf("CUTOVER LOCKED: %d warning(s) to review; rerun with --accept-warnings once a person has checked them", c.Warnings)
	case c.Warnings > 0:
		r.CutoverAllowed = true
		r.Verdict = fmt.Sprintf("CUTOVER ALLOWED WITH %d ACCEPTED WARNING(S): no check failed and the operator accepted the warnings with --accept-warnings", c.Warnings)
	default:
		r.CutoverAllowed = true
		r.Verdict = "CUTOVER ALLOWED: every compared page and closed URL matches the old site"
	}
}

// Text renders the report for a person. Critical lines come first so an
// exposed closed URL cannot scroll out of view, followed by the verdict,
// failures, warnings and passes.
func (r Report) Text() string {
	var b strings.Builder
	line := func(format string, args ...any) {
		fmt.Fprintf(&b, format+"\n", args...)
	}
	for _, p := range r.Probes {
		if p.Critical {
			line("CRITICAL closed URL %s (%s) %s: %s", p.Path, p.Kind, p.Code, p.Reason)
		}
	}
	for _, p := range r.Pages {
		if p.Critical {
			line("CRITICAL page %s: %s", p.Path, p.Reason)
		}
	}
	line("%s", r.Verdict)
	for _, p := range r.Probes {
		if p.Result == Fail && !p.Critical {
			line("FAIL closed URL %s (%s) %s: %s", p.Path, p.Kind, p.Code, p.Reason)
		}
	}
	for _, p := range r.Pages {
		if p.Result == Fail && !p.Critical {
			line("FAIL page %s: %s", p.Path, p.Reason)
		}
	}
	for _, w := range r.Warnings {
		line("WARN %s", w)
	}
	for _, p := range r.Pages {
		if p.Result == Warn {
			line("WARN page %s: %s", p.Path, p.Reason)
		}
	}
	for _, p := range r.Probes {
		if p.Result == Pass {
			line("PASS closed URL %s (%s): %s", p.Path, p.Kind, p.Reason)
		}
	}
	for _, p := range r.Pages {
		if p.Result == Pass {
			line("PASS page %s", p.Path)
		}
	}
	newSite := r.NewOrigin
	if r.NewConnect != "" {
		newSite += " connecting to " + r.NewConnect
	}
	line("Old site: %s", r.OldOrigin)
	line("New site: %s", newSite)
	if r.OldClient != "" || r.NewClient != "" {
		line("Verify's address as each site sees it: old %s, new %s", orNone(r.OldClient), orNone(r.NewClient))
	}
	line("Pages: %d compared (limit %d): %d pass, %d warn, %d fail", r.Counts.PagesCompared, r.PageLimit, r.Counts.PagesPass, r.Counts.PagesWarn, r.Counts.PagesFail)
	line("Closed URLs: %d checked: %d pass, %d fail", len(r.Probes), r.Counts.ProbesPass, r.Counts.ProbesFail)
	if r.AcceptedWarnings {
		line("Warnings accepted by the operator: yes (--accept-warnings)")
	}
	line("Scope: %s", r.Scope)
	line("Started %s, finished %s", r.StartedAt.Format(time.RFC3339), r.FinishedAt.Format(time.RFC3339))
	return b.String()
}
