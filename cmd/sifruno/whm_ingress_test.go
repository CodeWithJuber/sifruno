package main

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

// The WHM ingress exposes only the two API prefixes; every other path is
// 404, and the panel UI/operator endpoints are unreachable through it.
func TestWHMIngressMuxIsolation(t *testing.T) {
	whm := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusTeapot)
	})
	mux := whmIngressMux(whm)
	for _, path := range []string{"/json-api/version", "/execute/DomainInfo/list_domains"} {
		r := httptest.NewRequest(http.MethodGet, path, nil)
		w := httptest.NewRecorder()
		mux.ServeHTTP(w, r)
		if w.Code != http.StatusTeapot {
			t.Fatalf("%s: code = %d", path, w.Code)
		}
	}
	for _, path := range []string{"/", "/api/v1/accounts", "/cpsess123/login"} {
		r := httptest.NewRequest(http.MethodGet, path, nil)
		w := httptest.NewRecorder()
		mux.ServeHTTP(w, r)
		if w.Code != http.StatusNotFound {
			t.Fatalf("%s: code = %d (must be 404 through ingress)", path, w.Code)
		}
	}
	// /json-api (no slash) canonically redirects to the API prefix — the
	// handler itself, not panel content, answers there.
	r := httptest.NewRequest(http.MethodGet, "/json-api", nil)
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, r)
	if w.Code != http.StatusMovedPermanently && w.Code != http.StatusTemporaryRedirect {
		t.Fatalf("/json-api: code = %d", w.Code)
	}
}

func TestWHMIngressFailClosed(t *testing.T) {
	// Nil handler: refuse.
	if _, _, err := listenWHMIngress("127.0.0.1:0", "cert.pem", "key.pem", nil); err == nil {
		t.Fatal("nil WHM handler must refuse ingress")
	}
	// Missing cert/key: refuse, never self-sign silently.
	whm := http.HandlerFunc(func(http.ResponseWriter, *http.Request) {})
	if _, _, err := listenWHMIngress("127.0.0.1:0", "", "", whm); err == nil {
		t.Fatal("missing cert/key must refuse ingress")
	}
	if _, _, err := listenWHMIngress("127.0.0.1:0", "/nonexistent/cert.pem", "/nonexistent/key.pem", whm); err == nil {
		t.Fatal("unreadable cert must refuse ingress")
	}
}
