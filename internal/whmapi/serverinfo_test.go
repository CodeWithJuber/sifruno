package whmapi

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func doWHM(t *testing.T, srv *Server, token, fn string) map[string]any {
	t.Helper()
	req := httptest.NewRequest("GET", "/json-api/"+fn+"?api.version=1", nil)
	req.Header.Set("Authorization", "whm root:"+token)
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("%s: status %d body %s", fn, rec.Code, rec.Body.String())
	}
	var env struct {
		Data     map[string]any `json:"data"`
		Metadata struct {
			Result int    `json:"result"`
			Reason string `json:"reason"`
		} `json:"metadata"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &env); err != nil {
		t.Fatalf("%s: decode: %v", fn, err)
	}
	if env.Metadata.Result != 1 {
		t.Fatalf("%s: result=0 reason=%q", fn, env.Metadata.Reason)
	}
	return env.Data
}

func TestGetHostname(t *testing.T) {
	srv, token := newServer(t)
	data := doWHM(t, srv, token, "gethostname")
	host, _ := data["hostname"].(string)
	if host == "" {
		t.Fatal("hostname empty")
	}
}

func TestLoadAvg(t *testing.T) {
	srv, token := newServer(t)
	data := doWHM(t, srv, token, "loadavg")
	for _, k := range []string{"one", "five", "fifteen"} {
		if v, _ := data[k].(string); v == "" {
			t.Fatalf("loadavg %s missing/empty", k)
		}
	}
}

func TestListIPs(t *testing.T) {
	srv, token := newServer(t)
	data := doWHM(t, srv, token, "listips")
	// sandbox CI may have no non-loopback IPv4; shape must still decode.
	if _, ok := data["ip"].([]any); !ok {
		t.Fatalf("listips ip field wrong type: %T", data["ip"])
	}
}

func TestServiceStatusShape(t *testing.T) {
	srv, token := newServer(t)
	data := doWHM(t, srv, token, "servicestatus")
	svcs, ok := data["service"].([]any)
	if !ok || len(svcs) == 0 {
		t.Fatalf("service list missing: %v", data)
	}
	for _, raw := range svcs {
		m, _ := raw.(map[string]any)
		if m["name"] == "" || m["running"] == nil {
			t.Fatalf("service entry malformed: %v", m)
		}
	}
}

func TestShowBWHonestZeros(t *testing.T) {
	srv, token := newServer(t)
	data := doWHM(t, srv, token, "showbw")
	accts, ok := data["acct"].([]any)
	if !ok || len(accts) == 0 {
		t.Fatalf("acct list missing: %v", data)
	}
	first, _ := accts[0].(map[string]any)
	if first["acct"] != "example" || first["totalbytes"] != "0" {
		t.Fatalf("unexpected showbw row: %v", first)
	}
}

func TestP1UnknownAppUnchanged(t *testing.T) {
	srv, token := newServer(t)
	req := httptest.NewRequest("GET", "/json-api/getssldomains?api.version=1", nil)
	req.Header.Set("Authorization", "whm root:"+token)
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, req)
	if rec.Code == http.StatusOK {
		var env struct {
			Metadata struct {
				Result int `json:"result"`
			} `json:"metadata"`
		}
		if json.Unmarshal(rec.Body.Bytes(), &env) == nil && env.Metadata.Result == 1 {
			t.Fatal("unknown function reported success")
		}
	}
}
