package main

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync/atomic"
	"testing"
)

func TestSessionControlsNeverReachPublicPreviewUpstream(t *testing.T) {
	var calls atomic.Int32
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { calls.Add(1); w.WriteHeader(200) }))
	defer up.Close()
	u, _ := url.Parse(up.URL)
	h := preview(u, "", "192.0.2.1:8081")
	for _, tc := range []struct {
		method, path string
		status       int
	}{
		{"GET", "/api/v1/session/sessions", 404},
		{"HEAD", "/api/v1/session/sessions", 404},
		{"GET", "/api/v1/session/revoke-others", 404},
		{"POST", "/api/v1/session/revoke-others", 405},
		{"GET", "/api/v1/session/sessions/11111111111111111111111111111111/revoke", 404},
		{"POST", "/api/v1/session/sessions/11111111111111111111111111111111/revoke", 405},
	} {
		t.Run(tc.method+tc.path, func(t *testing.T) {
			r := httptest.NewRequest(tc.method, tc.path, nil)
			r.Host = "192.0.2.1:8081"
			r.Header.Set("Cookie", "non-secret-canary=test")
			w := httptest.NewRecorder()
			h.ServeHTTP(w, r)
			if w.Code != tc.status {
				t.Fatalf("private preview route status %d", w.Code)
			}
			if calls.Load() != 0 {
				t.Fatal("private session route reached upstream")
			}
		})
	}
}
