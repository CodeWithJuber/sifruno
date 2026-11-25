package api

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"net/http"
	"regexp"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/danielgtaylor/huma/v2"
	"sifruno/internal/hostaccounts"
	"sifruno/internal/operator"
)

// A site's scheduled jobs, logs and usage, on its page. The hosting account
// service (the root broker) does the work; the panel checks, joins and
// explains. They sit under /api/v1/websites/, so the wizard's admission
// applies: an admin session, and for the jobs' POST also Origin, CSRF and
// the strict body check below.

// WebsiteCron is a site's Scheduled jobs section.
type WebsiteCron struct {
	Jobs       []WebsiteCronJob `json:"jobs"`
	MaxJobs    int              `json:"max_jobs" doc:"How many jobs a site may have."`
	ServerTime string           `json:"server_time" doc:"The server's clock, RFC 3339 with its UTC offset. Schedules run on this clock."`
	Revision   uint64           `json:"revision" doc:"The hosting account's revision. A change sends it back as expected_revision."`
	State      string           `json:"state" doc:"The hosting account's state. A suspended account runs no jobs."`
}

// WebsiteCronJob is one installed job.
type WebsiteCronJob struct {
	Schedule string `json:"schedule" doc:"Five cron fields: minute, hour, day of month, month, day of week."`
	Command  string `json:"command" doc:"Run with /bin/sh as the hosting account's user, in its home."`
	NextRun  string `json:"next_run" doc:"When it runs next, RFC 3339 on the server's clock; empty when the schedule names no date that comes."`
}

// WebsiteCronBody replaces the site's whole job list. The middleware has
// already checked its shape.
type WebsiteCronBody struct {
	Jobs             []WebsiteCronJobInput `json:"jobs" maxItems:"50" doc:"The whole list; an empty list removes every job."`
	ExpectedRevision uint64                `json:"expected_revision" minimum:"1" doc:"The revision the site entry had."`
}

// WebsiteCronJobInput is one job to install.
type WebsiteCronJobInput struct {
	Schedule string `json:"schedule" maxLength:"100" doc:"Five fields one space apart, each *, */step, a number, a range n-m or n-m/step, or a comma list of these. No names and no @ shortcuts."`
	Command  string `json:"command" maxLength:"1024" doc:"One line, without %, which cron turns into a new line, and not starting with - or *."`
}

// WebsiteLog is the end of one of a site's logs.
type WebsiteLog struct {
	Kind      string   `json:"kind" enum:"access,error"`
	Lines     []string `json:"lines" doc:"The last lines, oldest first, at most 200. They hold what visitors sent: show them as text."`
	Truncated bool     `json:"truncated" doc:"The log has earlier lines."`
	SizeBytes int64    `json:"size_bytes"`
	Missing   bool     `json:"missing" doc:"The site has no such log yet."`
}

// WebsiteUsage is a site's disk use and this month's traffic.
type WebsiteUsage struct {
	DiskUsedBytes   int64  `json:"disk_used_bytes"`
	DiskLimitBytes  int64  `json:"disk_limit_bytes" doc:"The account's disk quota; 0 when none is set."`
	TrafficMonth    string `json:"traffic_month" doc:"The month counted, YYYY-MM on the server's clock."`
	TrafficBytes    int64  `json:"traffic_bytes" doc:"Response bytes the site served this month, from its access log. Headers are not counted."`
	TrafficComplete bool   `json:"traffic_complete" doc:"false while earlier log lines are still being counted; the number can still grow."`
}

type websiteCronOutput struct{ Body WebsiteCron }
type websiteCronInput struct {
	AccountID string `path:"account_id"`
	Body      WebsiteCronBody
}
type websiteLogInput struct {
	AccountID string `path:"account_id"`
	Kind      string `path:"kind"`
}
type websiteLogOutput struct{ Body WebsiteLog }
type websiteUsageOutput struct{ Body WebsiteUsage }

const (
	siteToolsMissing   = "This server's account service does not offer scheduled jobs, logs and usage. Update and restart the account service, then try again."
	siteToolsNoWeb     = "The account service cannot read logs or usage, because its web operation is off (hostbroker runs without --web-user). Ask whoever runs this server to turn it on."
	siteToolsNoAnswer  = "The account service did not answer, so the panel cannot show this. Reload the page to try again."
	cronDamaged        = "The account service's record of this site's scheduled jobs does not check out, so it shows none. Ask whoever runs this server to check the hosting account."
	cronNotWritten     = "The account service could not write the scheduled jobs, or did not answer, so the panel cannot tell whether they changed. Reload the page to see the jobs as they are now."
	websiteCronChanged = "Scheduled jobs changed on the website's page"
	cronBodyLimit      = 64 << 10
	usageListWait      = 4 * time.Second
)

var cronPath = regexp.MustCompile(`^/api/v1/websites/sites/[a-f0-9]{32}/cron$`)

// allowedCronMutation is the jobs' POST, whose body is checked by
// prepareCronJSON instead of the wizard's text-only rule.
func allowedCronMutation(r *http.Request) bool {
	return r.Method == http.MethodPost && cronPath.MatchString(r.URL.Path)
}

// prepareCronJSON bounds and checks the jobs' body before Huma decodes it:
// JSON, at most 64 KiB, one object with exactly jobs and expected_revision,
// the revision a whole number, and jobs an array of at most 50 objects with
// exactly schedule and command, both text. Keys are compared exactly, since
// Go's decoder would take another case. Nothing from the body is echoed.
func prepareCronJSON(w http.ResponseWriter, r *http.Request) bool {
	fail := func(status int, message string) bool {
		operator.WriteError(w, status, "invalid_request", message)
		return false
	}
	ct, params, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil || ct != "application/json" || (params["charset"] != "" && !strings.EqualFold(params["charset"], "utf-8")) {
		return fail(415, "Send the request as JSON.")
	}
	_ = http.NewResponseController(w).SetReadDeadline(time.Now().Add(5 * time.Second))
	defer http.NewResponseController(w).SetReadDeadline(time.Time{})
	raw, err := io.ReadAll(io.LimitReader(r.Body, cronBodyLimit+1))
	if err != nil {
		return fail(400, "The request could not be read.")
	}
	if len(raw) > cronBodyLimit {
		return fail(413, "The request is larger than 64 KiB.")
	}
	if !utf8.Valid(raw) || !json.Valid(raw) {
		return fail(400, "The request must be one JSON object.")
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	if t, err := d.Token(); err != nil || t != json.Delim('{') {
		return fail(400, "The request must be one JSON object.")
	}
	seen := map[string]bool{}
	for d.More() {
		t, _ := d.Token()
		key, _ := t.(string)
		if key != "jobs" && key != "expected_revision" {
			return fail(422, "The request has a field this form does not use. Send only jobs and expected_revision.")
		}
		if seen[key] {
			return fail(422, "The request has the field "+key+" more than once.")
		}
		seen[key] = true
		var value json.RawMessage
		if d.Decode(&value) != nil {
			return fail(400, "The request must be one JSON object.")
		}
		if key == "expected_revision" {
			if !wholeNumber.Match(bytes.TrimSpace(value)) {
				return fail(422, "expected_revision must be a whole number.")
			}
			continue
		}
		if message := cronJobsShape(value); message != "" {
			return fail(422, message)
		}
	}
	if len(seen) != 2 {
		return fail(422, "The request needs jobs and expected_revision.")
	}
	r.Body = io.NopCloser(bytes.NewReader(raw))
	r.ContentLength = int64(len(raw))
	return true
}

// cronJobsShape checks the jobs array's shape; "" when it is right.
func cronJobsShape(raw json.RawMessage) string {
	const shape = "jobs must be a list of at most 50 jobs, each with exactly a schedule and a command, both text."
	d := json.NewDecoder(bytes.NewReader(raw))
	if t, err := d.Token(); err != nil || t != json.Delim('[') {
		return shape
	}
	for n := 0; d.More(); n++ {
		if n >= hostaccounts.MaxCronJobs {
			return shape
		}
		if t, err := d.Token(); err != nil || t != json.Delim('{') {
			return shape
		}
		seen := map[string]bool{}
		for d.More() {
			t, _ := d.Token()
			key, _ := t.(string)
			if (key != "schedule" && key != "command") || seen[key] {
				return shape
			}
			seen[key] = true
			if v, err := d.Token(); err != nil {
				return shape
			} else if _, ok := v.(string); !ok {
				return shape
			}
		}
		if t, err := d.Token(); err != nil || t != json.Delim('}') || len(seen) != 2 {
			return shape
		}
	}
	return ""
}

func registerSiteTools(a huma.API, o Options) {
	get := func(id, path string) huma.Operation {
		return huma.Operation{OperationID: id, Method: http.MethodGet, Path: path, SkipValidateParams: true}
	}
	tools := func(ctx context.Context, id string) (hostaccounts.SiteToolsService, Website, hostaccounts.Account, error) {
		site, account, err := findWebsite(ctx, o, id)
		if err != nil {
			return nil, Website{}, hostaccounts.Account{}, err
		}
		if site.State == partlyDeleted {
			return nil, Website{}, hostaccounts.Account{}, huma.Error409Conflict(websitePartly)
		}
		t, ok := o.Accounts.(hostaccounts.SiteToolsService)
		if !ok {
			return nil, Website{}, hostaccounts.Account{}, huma.Error503ServiceUnavailable(siteToolsMissing)
		}
		return t, site, account, nil
	}
	huma.Register(a, get("get-website-cron", "/api/v1/websites/sites/{account_id}/cron"), func(ctx context.Context, in *websiteInput) (*websiteCronOutput, error) {
		t, _, account, err := tools(ctx, in.AccountID)
		if err != nil {
			return nil, err
		}
		res, err := t.Cron(ctx, account.ID)
		if err != nil {
			return nil, siteToolsReadError(err, cronDamaged)
		}
		return &websiteCronOutput{Body: websiteCron(res)}, nil
	})
	huma.Register(a, huma.Operation{OperationID: "set-website-cron", Method: http.MethodPost, Path: "/api/v1/websites/sites/{account_id}/cron", MaxBodyBytes: cronBodyLimit, BodyReadTimeout: 5 * time.Second, SkipValidateBody: true, SkipValidateParams: true}, func(ctx context.Context, in *websiteCronInput) (*websiteCronOutput, error) {
		t, _, account, err := tools(ctx, in.AccountID)
		if err != nil {
			return nil, err
		}
		switch {
		case in.Body.ExpectedRevision == 0:
			return nil, huma.Error422UnprocessableEntity(websiteNoRevision)
		case in.Body.ExpectedRevision != account.Revision:
			return nil, huma.Error409Conflict(websiteStale)
		case account.State == "recovery_required":
			return nil, huma.Error503ServiceUnavailable(websiteRecovery)
		case len(in.Body.Jobs) > hostaccounts.MaxCronJobs:
			return nil, huma.Error422UnprocessableEntity(fmt.Sprintf("A website can have at most %d scheduled jobs.", hostaccounts.MaxCronJobs))
		}
		jobs := make([]hostaccounts.CronJob, len(in.Body.Jobs))
		for i, j := range in.Body.Jobs {
			jobs[i] = hostaccounts.CronJob{Schedule: j.Schedule, Command: j.Command}
			if problem := hostaccounts.CronJobProblem(jobs[i]); problem != "" {
				return nil, huma.Error422UnprocessableEntity(fmt.Sprintf("Job %d: %s", i+1, problem))
			}
		}
		res, err := t.SetCron(ctx, account.ID, hostaccounts.CronInput{Jobs: jobs, ExpectedRevision: in.Body.ExpectedRevision, Reason: websiteCronChanged}, siteActor(ctx))
		if err != nil {
			if errors.Is(err, hostaccounts.ErrUnavailable) {
				return nil, huma.Error503ServiceUnavailable(cronNotWritten, errors.New("account service: "+err.Error()))
			}
			return nil, websiteChangeError(err, "")
		}
		return &websiteCronOutput{Body: websiteCron(res)}, nil
	})
	huma.Register(a, get("get-website-log", "/api/v1/websites/sites/{account_id}/logs/{kind}"), func(ctx context.Context, in *websiteLogInput) (*websiteLogOutput, error) {
		if in.Kind != "access" && in.Kind != "error" {
			return nil, huma.Error404NotFound("A site has an access log and an error log; there is no other.")
		}
		t, _, account, err := tools(ctx, in.AccountID)
		if err != nil {
			return nil, err
		}
		tail, err := t.SiteLog(ctx, account.ID, in.Kind)
		if err != nil {
			return nil, siteToolsReadError(err, siteToolsNoAnswer)
		}
		return &websiteLogOutput{Body: WebsiteLog{Kind: tail.Kind, Lines: tail.Lines, Truncated: tail.Truncated, SizeBytes: tail.Size, Missing: tail.Missing}}, nil
	})
	huma.Register(a, get("get-website-usage", "/api/v1/websites/sites/{account_id}/usage"), func(ctx context.Context, in *websiteInput) (*websiteUsageOutput, error) {
		t, _, account, err := tools(ctx, in.AccountID)
		if err != nil {
			return nil, err
		}
		u, err := t.SiteUsage(ctx, account.ID)
		if err != nil {
			return nil, siteToolsReadError(err, siteToolsNoAnswer)
		}
		return &websiteUsageOutput{Body: *websiteUsage(u)}, nil
	})
}

// siteToolsReadError explains a failed read; recovery is what the read
// itself says when its record does not check out.
func siteToolsReadError(err error, recovery string) error {
	technical := errors.New("account service: " + err.Error())
	switch {
	case errors.Is(err, hostaccounts.ErrNotFound):
		return huma.Error404NotFound(websiteNotFound, technical)
	case errors.Is(err, hostaccounts.ErrRecovery):
		return huma.Error503ServiceUnavailable(recovery, technical)
	case errors.Is(err, hostaccounts.ErrUnavailable):
		return huma.Error503ServiceUnavailable(siteToolsNoWeb+" Or it did not answer: reload the page to try again.", technical)
	default:
		return huma.Error503ServiceUnavailable(siteToolsNoAnswer, technical)
	}
}

func websiteCron(res hostaccounts.CronResult) WebsiteCron {
	out := WebsiteCron{Jobs: make([]WebsiteCronJob, 0, len(res.Jobs)), MaxJobs: hostaccounts.MaxCronJobs, ServerTime: res.ServerTime, Revision: res.Account.Revision, State: res.Account.State}
	for _, j := range res.Jobs {
		out.Jobs = append(out.Jobs, WebsiteCronJob{Schedule: j.Schedule, Command: j.Command, NextRun: j.NextRun})
	}
	return out
}

func websiteUsage(u hostaccounts.SiteUsage) *WebsiteUsage {
	return &WebsiteUsage{DiskUsedBytes: u.DiskUsedKiB << 10, DiskLimitBytes: u.DiskLimitKiB << 10, TrafficMonth: u.TrafficMonth, TrafficBytes: u.TrafficBytes, TrafficComplete: u.TrafficComplete}
}

// listUsage is every account's usage for the Websites list, by account ID,
// or nil when the account service cannot say within a few seconds: the list
// then shows the sites without it.
func listUsage(ctx context.Context, o Options) map[string]*WebsiteUsage {
	t, ok := o.Accounts.(hostaccounts.SiteToolsService)
	if !ok {
		return nil
	}
	ctx, cancel := context.WithTimeout(ctx, usageListWait)
	defer cancel()
	items, err := t.UsageAll(ctx)
	if err != nil {
		return nil
	}
	out := make(map[string]*WebsiteUsage, len(items))
	for _, u := range items {
		out[u.AccountID] = websiteUsage(u)
	}
	return out
}
