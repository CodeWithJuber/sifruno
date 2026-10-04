// Package api exposes the local feasibility workbench. Hosting compatibility
// endpoints fail closed until authentic implementations and evidence exist.
package api

import (
	"context"
	"encoding/json"
	"io/fs"
	"net"
	"net/http"
	"strings"

	"github.com/danielgtaylor/huma/v2"
	"github.com/danielgtaylor/huma/v2/adapters/humago"
	"sifruno/internal/budget"
	"sifruno/internal/compat"
	"sifruno/internal/operator"
	"sifruno/internal/platform"
	"sifruno/internal/serverinfo"
	"sifruno/internal/sites"
	"sifruno/internal/trail"
)

type Options struct {
	Report         compat.Report
	Trail          *trail.Store
	Budget         *budget.Store
	UI             fs.FS
	AllowedOrigins []string
	Server         *serverinfo.Collector
	Sites          *sites.Store
	Operator       *operator.Manager
}
type statusOutput struct{ Body compat.Report }
type trailBody struct {
	Items []trail.Summary `json:"items"`
}
type trailOutput struct{ Body trailBody }
type budgetOutput struct{ Body budget.Status }
type PlatformReport platform.Report
type platformOutput struct{ Body PlatformReport }
type serverInput struct {
	RangeSeconds int `query:"range_seconds" default:"600" minimum:"5" maximum:"600"`
}
type ServerReport serverinfo.Report
type serverOutput struct{ Body ServerReport }
type servicesOutput struct{ Body serverinfo.Services }

func New(o Options) http.Handler {
	mux := http.NewServeMux()
	cfg := huma.DefaultConfig("Sifruno feasibility workbench", "0.1.0")
	cfg.DocsPath = ""
	cfg.SchemasPath = "" // Local spec, no third-party documentation CDN.
	api := humago.New(mux, cfg)
	registerSites(api, o)
	registerSiteTransfers(mux, api, o)
	documentOperator(api)
	if o.Operator != nil {
		o.Operator.Register(mux)
	}
	collector := func() *serverinfo.Collector {
		if o.Server != nil {
			return o.Server
		}
		return serverinfo.Default()
	}
	huma.Register(api, huma.Operation{OperationID: "get-server", Method: http.MethodGet, Path: "/api/v1/server", Summary: "Real sanitized host measurements and bounded observed history"}, func(ctx context.Context, input *serverInput) (*serverOutput, error) {
		return &serverOutput{Body: ServerReport(collector().Snapshot(input.RangeSeconds))}, nil
	})
	huma.Register(api, huma.Operation{OperationID: "get-services", Method: http.MethodGet, Path: "/api/v1/services", Summary: "Cached read-only native service inventory"}, func(context.Context, *struct{}) (*servicesOutput, error) {
		return &servicesOutput{Body: collector().Services()}, nil
	})
	huma.Register(api, huma.Operation{OperationID: "get-status", Method: http.MethodGet, Path: "/api/v1/status", Summary: "Unverified compatibility obligations"}, func(context.Context, *struct{}) (*statusOutput, error) { return &statusOutput{Body: o.Report}, nil })
	huma.Register(api, huma.Operation{OperationID: "get-platform", Method: http.MethodGet, Path: "/api/v1/platform", Summary: "Native and legacy candidate scope"}, func(context.Context, *struct{}) (*platformOutput, error) {
		return &platformOutput{Body: PlatformReport(platform.Current())}, nil
	})
	huma.Register(api, huma.Operation{OperationID: "get-trail", Method: http.MethodGet, Path: "/api/v1/trail", Summary: "Verified scoped checkpoint journal"}, func(context.Context, *struct{}) (*trailOutput, error) {
		if o.Trail == nil {
			return nil, huma.Error503ServiceUnavailable("Trail store unavailable")
		}
		items, err := o.Trail.List()
		if err != nil {
			return nil, huma.Error503ServiceUnavailable("Trail integrity check failed")
		}
		if items == nil {
			items = []trail.Summary{}
		}
		return &trailOutput{Body: trailBody{Items: items}}, nil
	})
	huma.Register(api, huma.Operation{OperationID: "get-budget", Method: http.MethodGet, Path: "/api/v1/budget", Summary: "Local operator-approved AI budget ledger"}, func(context.Context, *struct{}) (*budgetOutput, error) {
		if o.Budget == nil {
			return nil, huma.Error503ServiceUnavailable("Budget store unavailable")
		}
		st, err := o.Budget.Status()
		if err != nil {
			return nil, huma.Error503ServiceUnavailable("Budget integrity check failed")
		}
		return &budgetOutput{Body: st}, nil
	})
	unavailable := func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusNotImplemented)
		json.NewEncoder(w).Encode(map[string]any{"error": "compatibility_not_implemented", "ready": false, "message": "Original WHM/cPanel behavior has not been implemented or verified."})
	}
	for _, path := range []string{"/json-api/", "/execute/", "/cpsess", "/scripts/", "/usr/local/cpanel/"} {
		mux.HandleFunc(path, unavailable)
	}
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/api/") || strings.HasPrefix(r.URL.Path, "/openapi") {
			http.NotFound(w, r)
			return
		}
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		name := strings.TrimPrefix(r.URL.Path, "/")
		for _, part := range strings.Split(name, "/") {
			if strings.HasPrefix(part, ".") {
				http.NotFound(w, r)
				return
			}
		}
		if o.UI == nil {
			http.Error(w, "Panel UI is not built. Run npm --prefix web run build.", http.StatusServiceUnavailable)
			return
		}
		if name == "" {
			name = "index.html"
		}
		if !fs.ValidPath(name) {
			http.NotFound(w, r)
			return
		}
		if _, err := fs.Stat(o.UI, name); err != nil {
			if strings.HasPrefix(name, "assets/") || strings.Contains(name, ".") {
				http.NotFound(w, r)
				return
			}
			name = "index.html"
		}
		if name == "index.html" {
			raw, err := fs.ReadFile(o.UI, name)
			if err != nil {
				http.Error(w, "Panel entry unavailable", http.StatusServiceUnavailable)
				return
			}
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			if r.Method != http.MethodHead {
				w.Write(raw)
			}
			return
		}
		r2 := r.Clone(r.Context())
		r2.URL.Path = "/" + name
		http.FileServer(http.FS(o.UI)).ServeHTTP(w, r2)
	})
	origins := map[string]bool{}
	for _, origin := range o.AllowedOrigins {
		origins[origin] = true
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		host := r.Host
		if h, _, err := net.SplitHostPort(host); err == nil {
			host = h
		}
		host = strings.Trim(host, "[]")
		if host != "localhost" && host != "127.0.0.1" && host != "::1" {
			http.Error(w, "Loopback Host required", http.StatusForbidden)
			return
		}
		if origin := r.Header.Get("Origin"); origin != "" && !origins[origin] {
			if isSitePath(r.URL.Path) || isSessionPath(r.URL.Path) {
				operator.WriteError(w, 403, "origin_not_allowed", "Origin not allowed")
				return
			}
			http.Error(w, "Origin not allowed", http.StatusForbidden)
			return
		}
		if r.Header.Get("Sec-Fetch-Site") == "cross-site" {
			http.Error(w, "Cross-site access denied", http.StatusForbidden)
			return
		}
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("Content-Security-Policy", "default-src 'self'; script-src 'self'; style-src 'self'; font-src 'self'; img-src 'self' data:; connect-src 'self'; base-uri 'none'; frame-ancestors 'none'; form-action 'none'")
		for _, prefix := range []string{"/json-api", "/execute", "/cpsess", "/scripts/", "/usr/local/cpanel/"} {
			if strings.HasPrefix(r.URL.Path, prefix) {
				unavailable(w, r)
				return
			}
		}
		mutation := r.Method != http.MethodGet && r.Method != http.MethodHead
		allowedMutation := allowedSiteMutation(r) || (r.Method == http.MethodPost && (r.URL.Path == "/api/v1/session/login" || r.URL.Path == "/api/v1/session/logout"))
		if mutation && strings.HasPrefix(r.URL.Path, "/api/") && !allowedMutation {
			w.Header().Set("Allow", "GET, HEAD")
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		if isSitePath(r.URL.Path) || isSessionPath(r.URL.Path) {
			if o.Operator == nil {
				operator.WriteError(w, 503, "operator_unavailable", "Operator authentication unavailable")
				return
			}
		}
		if isSitePath(r.URL.Path) {
			actor, ok := o.Operator.Authorize(w, r, mutation)
			if !ok {
				return
			}
			if o.Sites == nil {
				operator.WriteError(w, 503, "unavailable", "Website storage unavailable")
				return
			}
			r = r.WithContext(context.WithValue(r.Context(), actorKey{}, actor))
			if mutation && r.URL.Path != "/api/v1/sites/import" && !prepareSiteJSON(w, r) {
				return
			}
		}
		mux.ServeHTTP(w, r)
	})
}
