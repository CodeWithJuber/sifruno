package api

import (
	"encoding/json"
	"strings"
	"testing"

	"sifruno/internal/serverinfo"
)

func TestTypedTelemetryAPIAndGuards(t *testing.T) {
	c := serverinfo.NewCollector()
	t.Cleanup(c.Close)
	h := New(Options{Server: c})
	for _, path := range []string{"/api/v1/server", "/api/v1/server?range_seconds=5", "/api/v1/server?range_seconds=600", "/api/v1/services"} {
		w := request(h, "GET", path, "localhost:8080", "")
		if w.Code != 200 || !strings.Contains(w.Header().Get("Content-Type"), "application/json") || w.Header().Get("Cache-Control") != "no-store" {
			t.Fatal("typed telemetry route unavailable", path, w.Code)
		}
		var body map[string]json.RawMessage
		if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
			t.Fatal(err)
		}
		if len(body["sampled_at"]) == 0 {
			t.Fatal("missing sampling provenance")
		}
		if strings.Contains(path, "/server") && (len(body["history"]) == 0 || len(body["cpu"]) == 0) {
			t.Fatal("server measurements/history absent")
		}
		if strings.Contains(path, "/services") && (len(body["available"]) == 0 || len(body["items"]) == 0) {
			t.Fatal("service availability contract absent")
		}
		if request(h, "GET", path, "evil.example", "").Code != 403 || request(h, "GET", path, "localhost", "https://evil.example").Code != 403 || request(h, "POST", path, "localhost", "").Code != 405 {
			t.Fatal("telemetry bypassed original host/origin/mutation guards")
		}
	}
	for _, value := range []string{"0", "4", "601", "999999999999999999999", "invalid", "5.5"} {
		if w := request(h, "GET", "/api/v1/server?range_seconds="+value, "localhost", ""); w.Code != 422 {
			t.Fatal("unbounded or invalid range accepted", value, w.Code)
		}
	}
	w := request(h, "GET", "/openapi.json", "localhost", "")
	if w.Code != 200 {
		t.Fatal("OpenAPI unavailable")
	}
	var spec struct {
		Paths      map[string]json.RawMessage `json:"paths"`
		Components struct {
			Schemas map[string]json.RawMessage `json:"schemas"`
		} `json:"components"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &spec); err != nil {
		t.Fatal(err)
	}
	if len(spec.Paths["/api/v1/server"]) == 0 || len(spec.Paths["/api/v1/services"]) == 0 || len(spec.Components.Schemas["ServerReport"]) == 0 {
		t.Fatal("telemetry routes lack typed schema")
	}
}
