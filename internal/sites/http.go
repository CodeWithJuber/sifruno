package sites

import (
	"bytes"
	"mime"
	"net"
	"net/http"
	"path"
	"strconv"
	"strings"
	"time"
)

func (s *Store) Handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("Cache-Control", "no-store")
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			w.Header().Set("Allow", "GET, HEAD")
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		if r.URL.IsAbs() || r.URL.RawPath != "" || r.URL.Path == "" || path.Clean(r.URL.Path) != r.URL.Path || (r.URL.Path != "/" && strings.HasSuffix(r.URL.Path, "/")) {
			http.NotFound(w, r)
			return
		}
		host := r.Host
		if h, port, err := net.SplitHostPort(host); err == nil {
			if p, err := strconv.Atoi(port); err != nil || p < 1 || p > 65535 {
				http.NotFound(w, r)
				return
			}
			host = h
		}
		if host == "" || strings.ContainsAny(host, "/\\:@?#% ") {
			http.NotFound(w, r)
			return
		}
		host = strings.ToLower(host)
		file := strings.TrimPrefix(r.URL.Path, "/")
		if file == "" {
			file = "index.html"
		}
		if safeFile(file) != nil {
			http.NotFound(w, r)
			return
		}
		s.mu.Lock()
		if s.healthy() != nil {
			s.mu.Unlock()
			http.Error(w, "Website unavailable", http.StatusServiceUnavailable)
			return
		}
		records, err := s.records()
		if err != nil {
			s.mu.Unlock()
			http.Error(w, "Website unavailable", http.StatusServiceUnavailable)
			return
		}
		var found *record
		for i := range records {
			if records[i].Site.Domain == host || records[i].Site.PreviewHost == host {
				found = &records[i]
				break
			}
		}
		if found == nil {
			s.mu.Unlock()
			http.NotFound(w, r)
			return
		}
		if found.Pending != nil || s.verify(*found) != nil {
			s.mu.Unlock()
			http.Error(w, "Website recovery required", http.StatusServiceUnavailable)
			return
		}
		if found.Site.State != "active" {
			s.mu.Unlock()
			http.Error(w, "Website suspended", http.StatusServiceUnavailable)
			return
		}
		var expected *FileInfo
		for i := range found.Files {
			if found.Files[i].Path == file {
				expected = &found.Files[i]
			}
		}
		if expected == nil {
			s.mu.Unlock()
			http.NotFound(w, r)
			return
		}
		rt, err := s.siteRoot(found.Site.ID)
		if err != nil {
			s.mu.Unlock()
			http.Error(w, "Website unavailable", http.StatusServiceUnavailable)
			return
		}
		data, err := readRoot(rt, "content/"+file, MaxFileBytes)
		rt.Close()
		if err != nil || int64(len(data)) != expected.Bytes || sum(data) != expected.SHA256 {
			s.mu.Unlock()
			http.Error(w, "Website unavailable", http.StatusServiceUnavailable)
			return
		}
		updated := found.Site.UpdatedAt
		s.mu.Unlock()
		if contentType := mime.TypeByExtension(path.Ext(file)); contentType != "" {
			w.Header().Set("Content-Type", contentType)
		} else {
			w.Header().Set("Content-Type", "application/octet-stream")
		}
		// Site code runs on a separate local hostname/port, never the operator UI.
		w.Header().Set("Content-Security-Policy", "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; font-src 'self'; connect-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'none'")
		http.ServeContent(w, r, path.Base(file), updated.UTC().Truncate(time.Second), bytes.NewReader(data))
	})
}
