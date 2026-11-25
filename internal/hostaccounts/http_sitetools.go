package hostaccounts

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"regexp"
	"strings"
)

// The broker's routes for scheduled jobs, logs and usage:
//
//	GET  /v1/accounts/{id}/cron         the installed jobs with their next runs
//	POST /v1/accounts/{id}/cron         jobs, expected_revision, reason
//	GET  /v1/accounts/{id}/logs/access  the end of the site's access log
//	GET  /v1/accounts/{id}/logs/error   the end of the site's error log
//	GET  /v1/accounts/{id}/usage        disk and this month's traffic
//	GET  /v1/usage                      the same for every account
var siteToolsPath = regexp.MustCompile(`^/v1/accounts/([a-f0-9]{32})/(cron|usage|logs/access|logs/error)$`)

func siteToolsRoute(path string) bool {
	return path == "/v1/usage" || siteToolsPath.MatchString(path)
}

// noBody admits a GET only without a body.
func noBody(r *http.Request) bool {
	if r.ContentLength != 0 || len(r.TransferEncoding) != 0 {
		return false
	}
	if r.Body != nil {
		var one [1]byte
		if n, err := r.Body.Read(one[:]); n != 0 || err != io.EOF {
			return false
		}
	}
	return true
}

func serveSiteTools(ctx context.Context, w http.ResponseWriter, r *http.Request, s *store) {
	if r.URL.Path == "/v1/usage" {
		if r.Method != "GET" {
			writeError(w, ErrNotFound)
			return
		}
		if !noBody(r) {
			writeError(w, ErrInvalid)
			return
		}
		items, err := s.usageAll(ctx)
		if err != nil {
			writeError(w, err)
			return
		}
		json.NewEncoder(w).Encode(struct {
			Items []SiteUsage `json:"items"`
		}{items})
		return
	}
	m := siteToolsPath.FindStringSubmatch(r.URL.Path)
	id, what := m[1], m[2]
	switch {
	case r.Method == "POST" && what == "cron":
		var in struct {
			Input struct {
				Jobs             json.RawMessage `json:"jobs"`
				ExpectedRevision uint64          `json:"expected_revision"`
				Reason           string          `json:"reason"`
			} `json:"input"`
			Actor string `json:"actor"`
		}
		if decodeBodyWithin(w, r, &in, []string{"jobs", "expected_revision", "reason"}, cronRequestBytes) != nil {
			writeError(w, ErrInvalid)
			return
		}
		jobs, err := decodeCronJobs(in.Input.Jobs)
		if err != nil {
			writeError(w, ErrInvalid)
			return
		}
		result, err := s.setCron(ctx, id, CronInput{Jobs: jobs, ExpectedRevision: in.Input.ExpectedRevision, Reason: in.Input.Reason}, in.Actor)
		if err != nil {
			writeError(w, err)
			return
		}
		json.NewEncoder(w).Encode(result)
	case r.Method != "GET":
		writeError(w, ErrNotFound)
	case !noBody(r):
		writeError(w, ErrInvalid)
	case what == "cron":
		result, err := s.cron(ctx, id)
		if err != nil {
			writeError(w, err)
			return
		}
		json.NewEncoder(w).Encode(result)
	case what == "usage":
		result, err := s.siteUsage(ctx, id)
		if err != nil {
			writeError(w, err)
			return
		}
		json.NewEncoder(w).Encode(result)
	default:
		result, err := s.siteLog(ctx, id, strings.TrimPrefix(what, "logs/"))
		if err != nil {
			writeError(w, err)
			return
		}
		json.NewEncoder(w).Encode(result)
	}
}

// decodeCronJobs reads the jobs array as strictly as decodeBody reads the
// input: an array of at most MaxCronJobs objects, each with exactly
// "schedule" and "command", once each, spelled exactly, both strings.
func decodeCronJobs(raw json.RawMessage) ([]CronJob, error) {
	d := json.NewDecoder(bytes.NewReader(raw))
	if t, err := d.Token(); err != nil || t != json.Delim('[') {
		return nil, ErrInvalid
	}
	jobs := []CronJob{}
	for d.More() {
		if len(jobs) >= MaxCronJobs {
			return nil, ErrInvalid
		}
		if t, err := d.Token(); err != nil || t != json.Delim('{') {
			return nil, ErrInvalid
		}
		var job CronJob
		seen := map[string]bool{}
		for d.More() {
			t, err := d.Token()
			key, ok := t.(string)
			if err != nil || !ok || (key != "schedule" && key != "command") || seen[key] {
				return nil, ErrInvalid
			}
			seen[key] = true
			v, err := d.Token()
			value, ok := v.(string)
			if err != nil || !ok {
				return nil, ErrInvalid
			}
			if key == "schedule" {
				job.Schedule = value
			} else {
				job.Command = value
			}
		}
		if t, err := d.Token(); err != nil || t != json.Delim('}') || len(seen) != 2 {
			return nil, ErrInvalid
		}
		jobs = append(jobs, job)
	}
	if t, err := d.Token(); err != nil || t != json.Delim(']') {
		return nil, ErrInvalid
	}
	if _, err := d.Token(); err != io.EOF {
		return nil, ErrInvalid
	}
	return jobs, nil
}
