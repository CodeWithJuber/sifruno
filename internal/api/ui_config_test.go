package api

import (
	"net/http"
	"strconv"
	"strings"
	"testing"
	"testing/fstest"
)

func TestSitePreviewPortUsesConfiguredListener(t *testing.T) {
	const original = "<html><head><title>Sifruno</title></head><body>Panel</body></html>"
	for _, port := range []uint16{0, 8082, 8086, 65535} {
		h := New(Options{UI: fstest.MapFS{"index.html": {Data: []byte(original)}}, SitePreviewPort: &port})
		for _, path := range []string{"/", "/websites", "/index.html"} {
			w := request(h, http.MethodGet, path, "127.0.0.1:8080", "")
			meta := `<meta name="sifruno-sites-port" content="` + strconv.Itoa(int(port)) + `">`
			if w.Code != http.StatusOK || strings.Count(w.Body.String(), meta) != 1 || w.Header().Get("Content-Length") != strconv.Itoa(w.Body.Len()) {
				t.Fatal("preview configuration or response length mismatch")
			}
			head := request(h, http.MethodHead, path, "127.0.0.1:8080", "")
			if head.Code != http.StatusOK || head.Body.Len() != 0 || head.Header().Get("Content-Length") != w.Header().Get("Content-Length") {
				t.Fatal("HEAD response did not describe the configured document")
			}
		}
	}
	h := New(Options{UI: fstest.MapFS{"index.html": {Data: []byte(original)}}})
	if w := request(h, "GET", "/", "localhost:8080", ""); w.Body.String() != original {
		t.Fatal("unconfigured legacy caller changed")
	}
	port := uint16(8086)
	invalid := New(Options{UI: fstest.MapFS{"index.html": {Data: []byte("<html>incomplete</html>")}}, SitePreviewPort: &port})
	if request(invalid, "GET", "/", "localhost:8080", "").Code != http.StatusServiceUnavailable {
		t.Fatal("incomplete document silently lost listener configuration")
	}
}
