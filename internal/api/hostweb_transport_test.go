package api

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"sifruno/internal/hostaccounts"
)

// Characterizes the real authenticated HTTP envelope, not native provisioning.
type hostwebTransportAccounts struct {
	accountSpy
	rows []hostaccounts.Account
}

func (s *hostwebTransportAccounts) List(context.Context) ([]hostaccounts.Account, error) {
	s.calls++
	return s.rows, nil
}

func TestHostwebAccountHTTPEnvelope(t *testing.T) {
	f := websiteFixture(t)
	stamp := time.Date(2026, 10, 5, 0, 0, 0, 0, time.UTC)
	s := &hostwebTransportAccounts{rows: []hostaccounts.Account{
		{ID: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", Username: "webalpha", Domain: "webalpha.example.test", Home: "/home/sifruno-managed/webalpha", PublicHTML: "/home/sifruno-managed/webalpha/public_html", State: "active", UID: 20000, GID: 20000, Revision: 1, CreatedAt: stamp, UpdatedAt: stamp},
		{ID: "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", Username: "webbravo", Domain: "webbravo.example.test", Home: "/home/sifruno-managed/webbravo", PublicHTML: "/home/sifruno-managed/webbravo/public_html", State: "suspended", UID: 20001, GID: 20001, Revision: 2, CreatedAt: stamp, UpdatedAt: stamp},
	}}
	f.handler = New(Options{Operator: f.manager, Accounts: s, AllowedOrigins: []string{"http://127.0.0.1:8080"}})
	cookie, _ := websiteSignIn(t, f)
	w := websiteRequest(f.handler, "GET", "/api/v1/accounts", nil, cookie, "")
	if w.Code != 200 || s.calls != 1 {
		t.Fatalf("account HTTP status %d; list calls %d", w.Code, s.calls)
	}
	var envelope map[string]json.RawMessage
	if json.Unmarshal(w.Body.Bytes(), &envelope) != nil || len(envelope) != 2 {
		t.Fatal("expected items plus Huma schema metadata")
	}
	var schema string
	if json.Unmarshal(envelope["$schema"], &schema) != nil || schema != "http://127.0.0.1:8080/AccountListBody.json" {
		t.Fatalf("unexpected Huma schema metadata %q", schema)
	}
	var items []hostaccounts.Account
	if json.Unmarshal(envelope["items"], &items) != nil || len(items) != 2 || items[0] != s.rows[0] || items[1] != s.rows[1] {
		t.Fatal("account DTO identities/states changed in HTTP transport")
	}
}
