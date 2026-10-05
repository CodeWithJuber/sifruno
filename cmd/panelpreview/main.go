// panelpreview publishes the explicitly requested read-only mobile preview.
// Private recovery and spending stores remain behind the loopback workbench.
package main

import (
	"bytes"
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"os/signal"
	"path"
	"strconv"
	"strings"
	"syscall"
	"time"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run() error {
	listen := flag.String("listen", "0.0.0.0:8081", "Public preview listener")
	public := flag.String("public-host", "", "Explicit public IP for mobile access")
	external := flag.String("external-origin", "", "One exact HTTPS origin for the temporary mobile tunnel")
	flag.Parse()
	if err := validateExternalOrigin(*external); err != nil {
		return err
	}
	ip := net.ParseIP(*public)
	if ip == nil || ip.IsLoopback() || ip.IsUnspecified() {
		return errors.New("an explicit public IP is required")
	}
	bind, port, err := net.SplitHostPort(*listen)
	if err != nil {
		return err
	}
	if net.ParseIP(bind) == nil {
		return errors.New("listener must use an explicit IP")
	}
	if p, err := strconv.Atoi(port); err != nil || p < 1 || p > 65535 {
		return errors.New("invalid preview port")
	}
	upstream, _ := url.Parse("http://127.0.0.1:8080")
	handler := preview(upstream, *external, net.JoinHostPort(ip.String(), port), "127.0.0.1:"+port, "localhost:"+port)
	server := &http.Server{Addr: *listen, Handler: handler, ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 10 * time.Second, WriteTimeout: 15 * time.Second, IdleTimeout: 30 * time.Second, MaxHeaderBytes: 16 << 10}
	listener, err := net.Listen("tcp", *listen)
	if err != nil {
		return err
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	done := make(chan error, 1)
	go func() { done <- server.Serve(listener) }()
	fmt.Printf("Sifruno read-only public preview http://%s\n", net.JoinHostPort(ip.String(), port))
	select {
	case err := <-done:
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return err
	case <-ctx.Done():
		shutdown, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		return server.Shutdown(shutdown)
	}
}

func validateExternalOrigin(origin string) error {
	if origin == "" {
		return nil
	}
	u, err := url.Parse(origin)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.Hostname() == "" || u.User != nil || u.Opaque != "" || u.Path != "" || u.RawPath != "" || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || u.RawFragment != "" || strings.ContainsAny(origin, "?#") || u.String() != origin || strings.HasSuffix(u.Host, ":") {
		return errors.New("external origin must be an exact HTTPS origin without credentials, path, query or fragment")
	}
	if port := u.Port(); port != "" {
		if p, err := strconv.Atoi(port); err != nil || p < 1 || p > 65535 {
			return errors.New("invalid external HTTPS port")
		}
	}
	return nil
}

func preview(upstream *url.URL, externalOrigin string, hosts ...string) http.Handler {
	allowed := make(map[string]bool, len(hosts))
	for _, host := range hosts {
		allowed[host] = true
	}
	proxy := &httputil.ReverseProxy{
		Rewrite: func(r *httputil.ProxyRequest) {
			r.SetURL(upstream)
			r.Out.Host = upstream.Host
			for _, name := range []string{"Authorization", "Cookie", "X-Forwarded-For", "X-Forwarded-Host", "X-Forwarded-Proto", "Forwarded"} {
				r.Out.Header.Del(name)
			}
			if r.Out.Header.Get("Origin") != "" {
				r.Out.Header.Set("Origin", upstream.String())
			}
			// Only a validated top-level document can pass the incoming
			// cross-site gate. Its proxy-to-loopback hop is same-origin.
			if r.Out.Header.Get("Sec-Fetch-Site") == "cross-site" {
				r.Out.Header.Set("Sec-Fetch-Site", "same-origin")
			}
		},
		Transport: &http.Transport{Proxy: nil, DialContext: (&net.Dialer{Timeout: 3 * time.Second}).DialContext, ResponseHeaderTimeout: 10 * time.Second, IdleConnTimeout: 30 * time.Second, MaxConnsPerHost: 32},
		ModifyResponse: func(r *http.Response) error {
			r.Header.Set("X-Sifruno-View", "public-read-only")
			r.Header.Del("Set-Cookie")
			if r.StatusCode == http.StatusOK && strings.HasPrefix(r.Header.Get("Content-Type"), "text/html") {
				defer r.Body.Close()
				body, err := io.ReadAll(io.LimitReader(r.Body, (1<<20)+1))
				if err != nil {
					return err
				}
				if len(body) > 1<<20 {
					return errors.New("preview document exceeds bounds")
				}
				if !bytes.Contains(body, []byte("<head>")) {
					return errors.New("preview document has no metadata insertion point")
				}
				body = bytes.Replace(body, []byte("<head>"), []byte(`<head><meta name="sifruno-public-preview" content="true">`), 1)
				r.Body = io.NopCloser(bytes.NewReader(body))
				r.ContentLength = int64(len(body))
				r.Header.Set("Content-Length", strconv.Itoa(len(body)))
				r.Header.Del("ETag")
			}
			return nil
		},
		ErrorHandler: func(w http.ResponseWriter, _ *http.Request, _ error) {
			http.Error(w, "Preview service temporarily unavailable", http.StatusBadGateway)
		},
	}
	requests := make(chan struct{}, 32)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Referrer-Policy", "no-referrer")
		if !allowed[r.Host] {
			http.Error(w, "Preview host not allowed", http.StatusForbidden)
			return
		}
		if origin := r.Header.Get("Origin"); origin != "" {
			u, err := url.Parse(origin)
			local := err == nil && u.Scheme == "http" && allowed[u.Host] && u.User == nil && u.Path == "" && u.RawQuery == "" && !u.ForceQuery && u.Fragment == "" && !strings.ContainsAny(origin, "?#") && u.String() == origin
			if !local && (externalOrigin == "" || origin != externalOrigin || validateExternalOrigin(externalOrigin) != nil) {
				http.Error(w, "Preview origin not allowed", http.StatusForbidden)
				return
			}
		}
		uiRoute := r.URL.Path == "/" || r.URL.Path == "/overview" || r.URL.Path == "/services" || r.URL.Path == "/compatibility" || r.URL.Path == "/platforms"
		// Clicking a dashboard link is a document navigation. Cross-site
		// fetches, frames and API navigations remain denied.
		topLevelNavigation := uiRoute && r.Method == http.MethodGet && r.Header.Get("Sec-Fetch-Mode") == "navigate" && r.Header.Get("Sec-Fetch-Dest") == "document"
		if r.Header.Get("Sec-Fetch-Site") == "cross-site" && !topLevelNavigation {
			http.Error(w, "Cross-site preview access denied", http.StatusForbidden)
			return
		}
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			w.Header().Set("Allow", "GET, HEAD")
			http.Error(w, "Preview is read-only", http.StatusMethodNotAllowed)
			return
		}
		if r.URL.IsAbs() || path.Clean(r.URL.Path) != r.URL.Path {
			http.NotFound(w, r)
			return
		}
		for _, part := range strings.Split(r.URL.Path, "/") {
			if strings.HasPrefix(part, ".") {
				http.NotFound(w, r)
				return
			}
		}
		if r.URL.Path == "/api/v1/trail" || r.URL.Path == "/api/v1/budget" {
			http.Error(w, "Private tools are available only in the local panel", http.StatusForbidden)
			return
		}
		ok := uiRoute || r.URL.Path == "/api/v1/status" || r.URL.Path == "/api/v1/platform" || r.URL.Path == "/api/v1/server" || r.URL.Path == "/api/v1/services" || r.URL.Path == "/favicon.ico" || r.URL.Path == "/favicon.svg"
		for _, prefix := range []string{"/assets/", "/brand/"} {
			if strings.HasPrefix(r.URL.Path, prefix) {
				ok = true
			}
		}
		if !ok {
			http.NotFound(w, r)
			return
		}
		select {
		case requests <- struct{}{}:
			defer func() { <-requests }()
		default:
			http.Error(w, "Preview busy", http.StatusServiceUnavailable)
			return
		}
		proxy.ServeHTTP(w, r)
	})
}
