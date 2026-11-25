package main

import (
	"bytes"
	"encoding/json"
	"net"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"sifruno/internal/api"
	"sifruno/internal/hostaccounts"
	"sifruno/internal/operator"
)

func TestAccountsCLIUnavailableAndAdmission(t *testing.T) {
	state := filepath.Join(t.TempDir(), "state")
	op, err := operator.Open(filepath.Join(state, "operator"))
	if err != nil {
		t.Fatal(err)
	}
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	base := "http://" + l.Addr().String()
	s := httptest.NewUnstartedServer(api.New(api.Options{Operator: op, AllowedOrigins: []string{base}}))
	s.Listener = l
	s.Start()
	defer s.Close()
	var out, errs bytes.Buffer
	args := []string{"--state", state, "--panel-url", base, "accounts", "capability"}
	if err = run(args, &out, &errs); err != nil {
		t.Fatal(err)
	}
	var cap hostaccounts.Capability
	if json.Unmarshal(out.Bytes(), &cap) != nil || cap.Available || cap.Reason == "" {
		t.Fatal("missing broker reported available")
	}
	key, err := readOperatorKey(state)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(out.String()+errs.String(), key) || strings.Contains(out.String(), "csrf_token") {
		t.Fatal("CLI leaked operator credentials")
	}
	for _, tail := range [][]string{{"list", "--id", "unexpected"}, {"state", "--id", "../../etc/passwd", "--state", "active", "--revision", "1", "--reason", "fixture"}, {"create", "--username", "nativeuser", "--domain", "fixture.example"}, {"unknown"}} {
		out.Reset()
		errs.Reset()
		args = append([]string{"--state", state, "--panel-url", base, "accounts"}, tail...)
		if run(args, &out, &errs) == nil || out.Len() != 0 {
			t.Fatal("invalid CLI operation admitted")
		}
	}
	// A create reaches the account service: with no broker the panel answers
	// that the broker is unavailable (503), not that the request was
	// malformed (400). The panel admits only username, domain and reason.
	out.Reset()
	errs.Reset()
	err = run([]string{"--state", state, "--panel-url", base, "accounts", "create", "--username", "nativeuser", "--domain", "fixture.example", "--reason", "fixture"}, &out, &errs)
	if err == nil || strings.Contains(err.Error(), "panel operation rejected") {
		t.Fatalf("create did not reach the account service: %v", err)
	}
	// A remote destination is refused before reading or sending an access key.
	if runAccounts([]string{"capability"}, "missing", "https://remote.example:443", &out, &errs) == nil {
		t.Fatal("remote account destination admitted")
	}
}
