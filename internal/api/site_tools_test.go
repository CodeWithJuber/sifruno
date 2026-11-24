package api

import (
	"context"
	"encoding/json"
	"fmt"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"sifruno/internal/hostaccounts"
	"sifruno/internal/wizard"
)

// toolsBroker adds the scheduled jobs, logs and usage surface to the sites
// fake. It keeps one job list per account and answers the revision rule as
// the broker does.
type toolsBroker struct {
	*sitesBroker
	jobs     map[string][]hostaccounts.CronJob
	setCalls []hostaccounts.CronInput
	actors   []string
	setErr   error
	logs     map[string]hostaccounts.LogTail
	usage    []hostaccounts.SiteUsage
	usageErr error
}

func (b *toolsBroker) Cron(_ context.Context, id string) (hostaccounts.CronResult, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	for _, a := range b.accounts {
		if a.ID == id {
			return cronAnswer(a, b.jobs[id]), nil
		}
	}
	return hostaccounts.CronResult{}, hostaccounts.ErrNotFound
}

func cronAnswer(a hostaccounts.Account, jobs []hostaccounts.CronJob) hostaccounts.CronResult {
	res := hostaccounts.CronResult{Account: a, Jobs: []hostaccounts.CronEntry{}, ServerTime: "2026-11-24T10:00:00+04:00"}
	for _, j := range jobs {
		res.Jobs = append(res.Jobs, hostaccounts.CronEntry{CronJob: j, NextRun: "2026-11-24T10:05:00+04:00"})
	}
	return res
}

func (b *toolsBroker) SetCron(_ context.Context, id string, in hostaccounts.CronInput, actor string) (hostaccounts.CronResult, error) {
	b.mu.Lock()
	b.setCalls = append(b.setCalls, in)
	b.actors = append(b.actors, actor)
	err := b.setErr
	b.mu.Unlock()
	if err != nil {
		return hostaccounts.CronResult{}, err
	}
	a, err := b.changed("cron "+id, id, in.ExpectedRevision, func(*hostaccounts.Account) {})
	if err != nil {
		return hostaccounts.CronResult{}, err
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	b.jobs[id] = in.Jobs
	return cronAnswer(a, in.Jobs), nil
}

func (b *toolsBroker) SiteLog(_ context.Context, id, kind string) (hostaccounts.LogTail, error) {
	if l, ok := b.logs[id+"/"+kind]; ok {
		return l, nil
	}
	return hostaccounts.LogTail{Kind: kind, Lines: []string{}, Missing: true}, nil
}

func (b *toolsBroker) SiteUsage(_ context.Context, id string) (hostaccounts.SiteUsage, error) {
	for _, u := range b.usage {
		if u.AccountID == id {
			return u, nil
		}
	}
	return hostaccounts.SiteUsage{}, hostaccounts.ErrUnavailable
}

func (b *toolsBroker) UsageAll(context.Context) ([]hostaccounts.SiteUsage, error) {
	return b.usage, b.usageErr
}

func toolsFixture(t *testing.T) (siteFixture, *wizard.Runner, *toolsBroker) {
	t.Helper()
	f := websiteFixture(t)
	store, err := wizard.OpenStore(filepath.Join(realTempDir(t), "wizard"))
	if err != nil {
		t.Fatal(err)
	}
	inner := &sitesBroker{}
	broker := &toolsBroker{sitesBroker: inner, jobs: map[string][]hostaccounts.CronJob{}, logs: map[string]hostaccounts.LogTail{}}
	runner := wizard.New(inner, wizardDatabaseSpy{}, store, nil)
	t.Cleanup(runner.Wait)
	f.handler = New(Options{Operator: f.manager, Accounts: broker, Wizard: runner, AllowedOrigins: []string{"http://127.0.0.1:8080"}})
	return f, runner, broker
}

func TestWebsiteCronThroughTheHandler(t *testing.T) {
	f, runner, broker := toolsFixture(t)
	site := makeSite(t, runner, "example.com", "8.3")
	id := site.Result.AccountID
	cookie, csrf := websiteSignIn(t, f)
	path := "/api/v1/websites/sites/" + id + "/cron"

	w := websiteRequest(f.handler, "GET", path, nil, cookie, "")
	var before WebsiteCron
	if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &before) != nil || !strings.Contains(w.Body.String(), `"jobs":[]`) || before.MaxJobs != 50 || before.Revision == 0 {
		t.Fatalf("empty list %d %s", w.Code, w.Body.String())
	}
	rev := before.Revision
	body := fmt.Sprintf(`{"jobs":[{"schedule":"*/5 * * * *","command":"php ~/public_html/wp-cron.php > /dev/null 2>&1"}],"expected_revision":%d}`, rev)
	w = websiteRequest(f.handler, "POST", path, body, cookie, csrf)
	var got WebsiteCron
	if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &got) != nil || len(got.Jobs) != 1 || got.Revision != rev+1 || got.Jobs[0].NextRun == "" || got.ServerTime == "" {
		t.Fatalf("set %d %s", w.Code, w.Body.String())
	}
	rev = got.Revision
	if call := broker.setCalls[0]; call.Reason != websiteCronChanged || call.ExpectedRevision != rev-1 || call.Jobs[0].Command != "php ~/public_html/wp-cron.php > /dev/null 2>&1" || broker.actors[0] == "" {
		t.Fatalf("broker call %+v %q", call, broker.actors[0])
	}

	// Refused before the account service: each says what is wrong.
	calls := len(broker.setCalls)
	r := func(text string) string { return strings.ReplaceAll(text, "REV", fmt.Sprint(rev)) }
	for name, c := range map[string]struct {
		body   string
		status int
		detail string
	}{
		"percent":       {`{"jobs":[{"schedule":"* * * * *","command":"date +%s"}],"expected_revision":REV}`, 422, "Job 1: The command contains %"},
		"schedule":      {`{"jobs":[{"schedule":"* * * * *","command":"true"},{"schedule":"@hourly","command":"true"}],"expected_revision":REV}`, 422, "Job 2: The schedule needs five fields"},
		"newline":       {`{"jobs":[{"schedule":"* * * * *","command":"true\n* * * * * id"}],"expected_revision":REV}`, 422, "Job 1: The command must be one line"},
		"stale":         {`{"jobs":[],"expected_revision":1}`, 409, websiteStale},
		"no revision":   {`{"jobs":[],"expected_revision":0}`, 422, websiteNoRevision},
		"extra field":   {`{"jobs":[],"expected_revision":REV,"user":"root"}`, 422, ""},
		"job extra key": {`{"jobs":[{"schedule":"* * * * *","command":"true","user":"root"}],"expected_revision":REV}`, 422, ""},
		"case alias":    {`{"jobs":[{"Schedule":"* * * * *","command":"true"}],"expected_revision":REV}`, 422, ""},
		"duplicate":     {`{"jobs":[{"schedule":"* * * * *","command":"true","command":"id"}],"expected_revision":REV}`, 422, ""},
		"not text":      {`{"jobs":[{"schedule":"* * * * *","command":7}],"expected_revision":REV}`, 422, ""},
		"null jobs":     {`{"jobs":null,"expected_revision":REV}`, 422, ""},
		"too many":      {`{"jobs":[` + strings.TrimSuffix(strings.Repeat(`{"schedule":"* * * * *","command":"true"},`, 51), ",") + `],"expected_revision":REV}`, 422, ""},
		"revision text": {`{"jobs":[],"expected_revision":"2"}`, 422, ""},
	} {
		w := websiteRequest(f.handler, "POST", path, r(c.body), cookie, csrf)
		if w.Code != c.status {
			t.Errorf("%s: %d %s", name, w.Code, w.Body.String())
			continue
		}
		if c.detail != "" && !strings.HasPrefix(problemDetail(t, w), c.detail) {
			t.Errorf("%s: %s", name, w.Body.String())
		}
	}
	if len(broker.setCalls) != calls {
		t.Fatal("a refused body reached the account service")
	}
	// Admission: no CSRF token, no session.
	if w := websiteRequest(f.handler, "POST", path, r(`{"jobs":[],"expected_revision":REV}`), cookie, ""); w.Code != 403 {
		t.Fatalf("without CSRF %d", w.Code)
	}
	if w := websiteRequest(f.handler, "GET", path, nil, nil, ""); w.Code != 401 {
		t.Fatalf("without a session %d", w.Code)
	}
	// A write the account service could not confirm.
	broker.setErr = hostaccounts.ErrUnavailable
	w = websiteRequest(f.handler, "POST", path, r(`{"jobs":[],"expected_revision":REV}`), cookie, csrf)
	if w.Code != 503 || !strings.HasPrefix(problemDetail(t, w), "The account service could not write the scheduled jobs") {
		t.Fatalf("unavailable %d %s", w.Code, w.Body.String())
	}
	broker.setErr = nil
	// Removing every job.
	w = websiteRequest(f.handler, "POST", path, r(`{"jobs":[],"expected_revision":REV}`), cookie, csrf)
	if w.Code != 200 || !strings.Contains(w.Body.String(), `"jobs":[]`) || len(broker.jobs[id]) != 0 {
		t.Fatalf("remove all %d %s", w.Code, w.Body.String())
	}
	// Not a website: 404.
	if w := websiteRequest(f.handler, "GET", "/api/v1/websites/sites/"+strings.Repeat("0", 32)+"/cron", nil, cookie, ""); w.Code != 404 {
		t.Fatalf("unknown site %d", w.Code)
	}
}

func TestWebsiteLogsAndUsageThroughTheHandler(t *testing.T) {
	f, runner, broker := toolsFixture(t)
	site := makeSite(t, runner, "example.com", "8.3")
	other := makeSite(t, runner, "other.example", "8.3")
	id := site.Result.AccountID
	cookie, _ := websiteSignIn(t, f)
	broker.logs[id+"/access"] = hostaccounts.LogTail{Kind: "access", Lines: []string{`203.0.113.9 - - [24/Nov/2026:10:00:00 +0400] "GET /<script> HTTP/1.1" 200 5 "-" "-"`}, Truncated: true, Size: 4096}
	w := websiteRequest(f.handler, "GET", "/api/v1/websites/sites/"+id+"/logs/access", nil, cookie, "")
	var tail WebsiteLog
	if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &tail) != nil || len(tail.Lines) != 1 || !tail.Truncated || tail.SizeBytes != 4096 || !strings.Contains(tail.Lines[0], "<script>") {
		t.Fatalf("access log %d %s", w.Code, w.Body.String())
	}
	// A visitor's text is only ever JSON data: never sniffed as a page.
	if ct := w.Header().Get("Content-Type"); !strings.HasPrefix(ct, "application/json") || w.Header().Get("X-Content-Type-Options") != "nosniff" {
		t.Fatalf("log answer served as %q, nosniff %q", ct, w.Header().Get("X-Content-Type-Options"))
	}
	w = websiteRequest(f.handler, "GET", "/api/v1/websites/sites/"+id+"/logs/error", nil, cookie, "")
	if w.Code != 200 || !strings.Contains(w.Body.String(), `"missing":true`) || !strings.Contains(w.Body.String(), `"lines":[]`) {
		t.Fatalf("missing error log %d %s", w.Code, w.Body.String())
	}
	for _, kind := range []string{"other", "access.log", "Access"} {
		if w := websiteRequest(f.handler, "GET", "/api/v1/websites/sites/"+id+"/logs/"+kind, nil, cookie, ""); w.Code != 404 {
			t.Errorf("log kind %q: %d", kind, w.Code)
		}
	}

	broker.usage = []hostaccounts.SiteUsage{
		{AccountID: id, DiskUsedKiB: 2048, DiskLimitKiB: 204800, TrafficMonth: "2026-11", TrafficBytes: 123456, TrafficComplete: true},
		{AccountID: other.Result.AccountID, TrafficMonth: "2026-11", TrafficComplete: false},
	}
	w = websiteRequest(f.handler, "GET", "/api/v1/websites/sites/"+id+"/usage", nil, cookie, "")
	var u WebsiteUsage
	if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &u) != nil || u.DiskUsedBytes != 2048*1024 || u.DiskLimitBytes != 204800*1024 || u.TrafficBytes != 123456 || !u.TrafficComplete {
		t.Fatalf("usage %d %s", w.Code, w.Body.String())
	}
	// The list carries each site's usage.
	w = websiteRequest(f.handler, "GET", "/api/v1/websites/sites", nil, cookie, "")
	sites := decodeSites(t, w.Body.Bytes())
	i := slices.IndexFunc(sites, func(s Website) bool { return s.AccountID == id })
	if w.Code != 200 || i < 0 || sites[i].Usage == nil || sites[i].Usage.TrafficBytes != 123456 {
		t.Fatalf("list usage %s", w.Body.String())
	}
	// Without an answer the list still comes, without usage.
	broker.usageErr = hostaccounts.ErrUnavailable
	w = websiteRequest(f.handler, "GET", "/api/v1/websites/sites", nil, cookie, "")
	if w.Code != 200 || strings.Contains(w.Body.String(), `"usage"`) || len(decodeSites(t, w.Body.Bytes())) != 2 {
		t.Fatalf("list without usage %d %s", w.Code, w.Body.String())
	}
}

// The sites fake alone has no such surface: the routes say the account
// service must be updated, and the list has no usage.
func TestSiteToolsNeedTheAccountService(t *testing.T) {
	f, runner, _ := sitesFixture(t)
	site := makeSite(t, runner, "example.com", "8.3")
	cookie, _ := websiteSignIn(t, f)
	for _, suffix := range []string{"/cron", "/logs/access", "/usage"} {
		w := websiteRequest(f.handler, "GET", "/api/v1/websites/sites/"+site.Result.AccountID+suffix, nil, cookie, "")
		if w.Code != 503 || problemDetail(t, w) != siteToolsMissing {
			t.Errorf("%s: %d %s", suffix, w.Code, w.Body.String())
		}
	}
}
