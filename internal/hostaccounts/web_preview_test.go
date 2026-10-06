package hostaccounts

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
)

type previewFunc func(context.Context) (WebPreview, error)

func (f previewFunc) Preview(ctx context.Context) (WebPreview, error) { return f(ctx) }
func fixturePreview() WebPreview {
	h := strings.Repeat("a", 64)
	return WebPreview{Profile: "restricted-chroot-v1", ProfileSHA256: h, SnapshotSHA256: h, BundleSHA256: h, Files: []WebPreviewFile{{Path: "apache/front.conf", Mode: 0600, Bytes: 100, SHA256: h}}}
}

type previewRoundTrip func(*http.Request) (*http.Response, error)

func (f previewRoundTrip) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }
func TestWebPreviewBrokerClientContract(t *testing.T) {
	s, _, _ := setupStore(t)
	calls := 0
	svc := previewFunc(func(context.Context) (WebPreview, error) { calls++; return fixturePreview(), nil })
	h := handlerWithWebPreview(s, svc)
	c := &client{configured: true, http: &http.Client{Transport: previewRoundTrip(func(r *http.Request) (*http.Response, error) {
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		return w.Result(), nil
	})}}
	got, err := c.Preview(context.Background())
	if err != nil || !reflect.DeepEqual(got, fixturePreview()) || calls != 1 {
		t.Fatal("typed client broker roundtrip failed", err)
	}
	for _, tc := range []struct {
		method, url, origin, body string
		length                    int64
		chunked                   bool
	}{{"GET", "http://else/v1/web-preview", "", "", 0, false}, {"GET", "http://unix/v1/web-preview?accounts=x", "", "", 0, false}, {"GET", "http://unix/v1/web-preview", "http://localhost", "", 0, false}, {"POST", "http://unix/v1/web-preview", "", "", 0, false}, {"GET", "http://unix/v1/web-preview", "", "{}", 2, false}, {"GET", "http://unix/v1/web-preview", "", "{}", 0, false}, {"GET", "http://unix/v1/web-preview", "", "", 0, true}} {
		r := httptest.NewRequest(tc.method, tc.url, strings.NewReader(tc.body))
		r.ContentLength = tc.length
		r.Header.Set("Origin", tc.origin)
		if tc.chunked {
			r.TransferEncoding = []string{"chunked"}
		}
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		if w.Code == 200 || calls != 1 {
			t.Fatal("malformed preview admitted")
		}
	}
	w := httptest.NewRecorder()
	handler(s).ServeHTTP(w, httptest.NewRequest("GET", "http://unix/v1/web-preview", nil))
	if w.Code != 503 {
		t.Fatal("unconfigured preview not unavailable")
	}
}
func TestWebPreviewSnapshotRecoveryRetained(t *testing.T) {
	s, n, _ := setupStore(t)
	createFixture(t, s)
	n.changed = true
	callbacks := 0
	err := s.SnapshotProvider().WithSnapshot(context.Background(), func(SnapshotLease) error { callbacks++; return nil })
	if err == nil || callbacks != 0 {
		t.Fatal("drift admitted")
	}
	rows, err := s.records()
	if err != nil || len(rows) != 1 || rows[0].Pending == nil || rows[0].Pending.Action != "conflict" {
		t.Fatal("existing durable recovery not retained")
	}
}
func TestWebPreviewClientRejectsMalformedMetadata(t *testing.T) {
	good, _ := json.Marshal(fixturePreview())
	for _, raw := range []string{`{}`, strings.Replace(string(good), `"accounts":0`, `"accounts":null`, 1), strings.Replace(string(good), `"profile":`, `"PROFILE":`, 1), strings.Replace(string(good), `"accounts":0,`, ``, 1), strings.Replace(string(good), `"path":"apache/front.conf"`, `"path":"arbitrary.conf"`, 1), string(good) + `{}`, strings.Replace(string(good), `"accounts":0`, `"accounts":0,"accounts":0`, 1), strings.Replace(string(good), `"bytes":100`, `"bytes":-1`, 1), strings.Replace(string(good), `"path":"apache/front.conf"`, `"path":"../secret"`, 1), strings.Replace(string(good), `"profile":`, `"unknown":0,"profile":`, 1)} {
		c := &client{configured: true, http: &http.Client{Transport: previewRoundTrip(func(*http.Request) (*http.Response, error) {
			return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(raw)), Header: make(http.Header)}, nil
		})}}
		v, err := c.Preview(context.Background())
		if err == nil || v.Files != nil {
			t.Fatal("malformed response accepted")
		}
	}
	if _, err := NewWebPreviewClient("").Preview(context.Background()); err == nil {
		t.Fatal("unconfigured client admitted")
	}
}
