package hostaccounts

import "context"

// Response bounds for the scheduled jobs, logs and usage routes. A log's
// end is at most 256 KiB of text, which JSON may write six bytes to the
// byte; a usage line is well under 512 bytes per account.
const (
	maxLogResponseBytes   = 6*maxLogTailBytes + 64<<10
	maxUsageResponseBytes = MaxAccounts * 512
)

// Cron reads the account's scheduled jobs with their next runs.
func (c *client) Cron(ctx context.Context, id string) (CronResult, error) {
	if !idPattern.MatchString(id) {
		return CronResult{}, ErrInvalid
	}
	var out CronResult
	if err := c.request(ctx, "GET", "/v1/accounts/"+id+"/cron", nil, &out); err != nil {
		return CronResult{}, err
	}
	if out.Account.ID != id || len(out.Jobs) > MaxCronJobs {
		return CronResult{}, ErrUnavailable
	}
	return out, nil
}

// SetCron replaces the account's scheduled jobs. 503 unavailable can mean
// the crontab could not be written and the old one stayed: nothing changed.
func (c *client) SetCron(ctx context.Context, id string, in CronInput, actor string) (CronResult, error) {
	if !idPattern.MatchString(id) || !validCronInput(in, actor) {
		return CronResult{}, ErrInvalid
	}
	if in.Jobs == nil {
		in.Jobs = []CronJob{}
	}
	var out CronResult
	err := c.exchange(ctx, c.http, "POST", "/v1/accounts/"+id+"/cron", struct {
		Input CronInput `json:"input"`
		Actor string    `json:"actor"`
	}{in, actor}, cronRequestBytes, &out, maxResponseBytes)
	if err != nil {
		return CronResult{}, err
	}
	if out.Account.ID != id || len(out.Jobs) > MaxCronJobs {
		return CronResult{}, ErrUnavailable
	}
	return out, nil
}

// SiteLog reads the end of the site's access or error log.
func (c *client) SiteLog(ctx context.Context, id, kind string) (LogTail, error) {
	if !idPattern.MatchString(id) || logFileNames[kind] == "" {
		return LogTail{}, ErrInvalid
	}
	var out LogTail
	if err := c.requestBounded(ctx, "GET", "/v1/accounts/"+id+"/logs/"+kind, nil, &out, maxLogResponseBytes); err != nil {
		return LogTail{}, err
	}
	if out.Kind != kind || len(out.Lines) > MaxLogTailLines {
		return LogTail{}, ErrUnavailable
	}
	if out.Lines == nil {
		out.Lines = []string{}
	}
	return out, nil
}

// SiteUsage reads one account's disk use and its site's traffic this month.
func (c *client) SiteUsage(ctx context.Context, id string) (SiteUsage, error) {
	if !idPattern.MatchString(id) {
		return SiteUsage{}, ErrInvalid
	}
	var out SiteUsage
	if err := c.request(ctx, "GET", "/v1/accounts/"+id+"/usage", nil, &out); err != nil {
		return SiteUsage{}, err
	}
	if out.AccountID != id {
		return SiteUsage{}, ErrUnavailable
	}
	return out, nil
}

// UsageAll reads every account's usage in one request.
func (c *client) UsageAll(ctx context.Context) ([]SiteUsage, error) {
	var out struct {
		Items []SiteUsage `json:"items"`
	}
	if err := c.requestBounded(ctx, "GET", "/v1/usage", nil, &out, maxUsageResponseBytes); err != nil {
		return nil, err
	}
	if len(out.Items) > MaxAccounts {
		return nil, ErrUnavailable
	}
	if out.Items == nil {
		out.Items = []SiteUsage{}
	}
	return out.Items, nil
}

// The panel and brokerdrive reach these through a type assertion.
var _ SiteToolsService = (*client)(nil)
