package operator

import (
	"context"
	"net"
	"net/http"
	"strings"
)

// The panel can also be served over HTTPS beyond loopback. Requests from that
// listener are marked here, and only here, so nothing a client sends can make
// a request count as remote or as local. Over the network only admin
// sessions (password and code) work; the access key and first-run setup stay
// on the server itself.

type remoteKey struct{}

// Remote wraps the network-facing HTTPS listener. It marks a request remote
// only when it arrived over TLS for one of the panel's own host names, and
// refuses every other host name before the API sees it.
func Remote(next http.Handler, hosts []string) http.Handler {
	allowed := make(map[string]bool, len(hosts))
	for _, h := range hosts {
		allowed[strings.ToLower(h)] = true
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		host := r.Host
		if h, _, err := net.SplitHostPort(host); err == nil {
			host = h
		}
		host = strings.ToLower(strings.Trim(host, "[]"))
		if r.TLS == nil || !allowed[host] {
			w.Header().Set("Cache-Control", "no-store")
			http.Error(w, "This panel does not answer for that host name.", http.StatusMisdirectedRequest)
			return
		}
		next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), remoteKey{}, true)))
	})
}

// IsRemote reports whether the request came through Remote.
func IsRemote(r *http.Request) bool {
	v, _ := r.Context().Value(remoteKey{}).(bool)
	return v
}

// admitted is localRequest widened to the HTTPS listener.
func admitted(r *http.Request) bool { return localRequest(r) || IsRemote(r) }
