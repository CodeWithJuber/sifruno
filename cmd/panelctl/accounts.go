package main

import (
	"encoding/json"
	"errors"
	"flag"
	"io"
	"net/http"
	"strings"
	"time"

	"sifruno/internal/hostaccounts"
)

// Account commands reuse the same loopback-only operator session transport.
// They never run an OS utility or open privileged broker state directly.
func runAccounts(args []string, state, base string, out, errs io.Writer) error {
	if len(args) == 0 {
		return errors.New("accounts requires capability, list, web-preview, create or state")
	}
	f := flag.NewFlagSet("accounts "+args[0], flag.ContinueOnError)
	f.SetOutput(io.Discard)
	username := f.String("username", "", "Native Linux username")
	domain := f.String("domain", "", "Reserved domain metadata")
	plan := f.String("plan", "", "Reserved package/plan metadata")
	reason := f.String("reason", "", "Operator reason")
	id := f.String("id", "", "Managed account ID")
	wanted := f.String("state", "", "active or suspended")
	revision := f.Uint64("revision", 0, "Expected account revision")
	if f.Parse(args[1:]) != nil || f.NArg() != 0 {
		return errors.New("invalid accounts flags; run panelctl help")
	}
	allowed := map[string]bool{}
	method, endpoint := http.MethodGet, "/api/v1/accounts"
	var body any
	switch args[0] {
	case "capability":
		endpoint += "/capability"
	case "list":
	case "web-preview":
		endpoint += "/web-preview"
	case "create":
		allowed = map[string]bool{"username": true, "domain": true, "plan": true, "reason": true}
		if *username == "" || *domain == "" || strings.TrimSpace(*reason) == "" || len(*username) > 32 || len(*domain) > 253 || len(*reason) > 500 {
			return errors.New("create requires bounded --username, --domain and --reason")
		}
		method = http.MethodPost
		body = hostaccounts.CreateInput{Username: *username, Domain: *domain, Plan: *plan, Reason: *reason}
	case "state":
		allowed = map[string]bool{"id": true, "state": true, "revision": true, "reason": true}
		if len(*id) < 1 || len(*id) > 64 || strings.ContainsAny(*id, "/\\?#%") || (*wanted != "active" && *wanted != "suspended") || *revision == 0 || strings.TrimSpace(*reason) == "" || len(*reason) > 500 {
			return errors.New("state requires --id, --state active|suspended, --revision and bounded --reason")
		}
		endpoint += "/" + *id + "/state"
		method = http.MethodPost
		body = hostaccounts.StateInput{State: *wanted, ExpectedRevision: *revision, Reason: *reason}
	default:
		return errors.New("unknown accounts subcommand; run panelctl help")
	}
	invalidFlag := false
	f.Visit(func(v *flag.Flag) {
		if !allowed[v.Name] {
			invalidFlag = true
		}
	})
	if invalidFlag {
		return errors.New("flag is not valid for this accounts subcommand")
	}
	c, err := newSiteClient(base)
	if err != nil {
		return err
	}
	c.client.Timeout = 50 * time.Second
	if transport, ok := c.client.Transport.(*http.Transport); ok {
		transport.ResponseHeaderTimeout = 50 * time.Second
	}
	key, err := readOperatorKey(state)
	if err != nil {
		return err
	}
	if err = c.login(key); err != nil {
		return err
	}
	key = ""
	defer func() { _, _ = c.request(http.MethodPost, "/api/v1/session/logout", map[string]any{}) }()
	raw, err := c.request(method, endpoint, body)
	if err != nil {
		return err
	}
	e := json.NewEncoder(out)
	e.SetIndent("", "  ")
	return e.Encode(raw)
}
