package main

import (
	"bytes"
	"context"
	"encoding/json"
	"net"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"sifruno/internal/api"
	"sifruno/internal/hostaccounts"
	"sifruno/internal/operator"
)

type cliWebPreview struct{ calls atomic.Int32 }

func (p *cliWebPreview) Preview(context.Context) (hostaccounts.WebPreview, error) {
	p.calls.Add(1)
	return hostaccounts.WebPreview{Profile: "restricted-chroot-v1", ProfileSHA256: strings.Repeat("b", 64), SnapshotSHA256: strings.Repeat("c", 64), BundleSHA256: strings.Repeat("a", 64), Files: []hostaccounts.WebPreviewFile{{Path: "apache/front.conf", Mode: 0600, Bytes: 99, SHA256: strings.Repeat("d", 64)}}}, nil
}

func TestAccountsWebPreviewCLI(t *testing.T) {
	for _, enabled := range []bool{true, false} {
		t.Run(map[bool]string{true: "enabled", false: "disabled"}[enabled], func(t *testing.T) {
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
			spy := &cliWebPreview{}
			var service hostaccounts.WebPreviewService
			if enabled {
				service = spy
			}
			s := httptest.NewUnstartedServer(api.New(api.Options{Operator: op, WebPreview: service, AllowedOrigins: []string{base}}))
			s.Listener = l
			s.Start()
			defer s.Close()
			var out, errs bytes.Buffer
			err = run([]string{"--state", state, "--panel-url", base, "accounts", "web-preview"}, &out, &errs)
			if enabled {
				var result hostaccounts.WebPreview
				if err != nil || json.Unmarshal(out.Bytes(), &result) != nil || result.BundleSHA256 != strings.Repeat("a", 64) || spy.calls.Load() != 1 {
					t.Fatal("CLI did not return authenticated preview")
				}
			} else if err == nil || out.Len() != 0 || spy.calls.Load() != 0 {
				t.Fatal("disabled preview accepted")
			}
			key, err := readOperatorKey(state)
			if err != nil {
				t.Fatal(err)
			}
			if strings.Contains(out.String()+errs.String(), key) || strings.Contains(out.String(), "csrf_token") {
				t.Fatal("CLI leaked session credentials")
			}
		})
	}
	for _, tail := range [][]string{{"web-preview", "--reason", "caller-input"}, {"web-preview", "--id", "a"}, {"web-preview", "extra"}} {
		var out, errs bytes.Buffer
		if runAccounts(tail, "missing", "http://127.0.0.1:9999", &out, &errs) == nil || out.Len() != 0 {
			t.Fatal("preview arguments accepted")
		}
	}
}
