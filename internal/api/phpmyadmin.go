package api

import (
	"context"
	"errors"
	"net/http"
	pathpkg "path"
	"strings"
	"time"

	"github.com/danielgtaylor/huma/v2"
	"sifruno/internal/dbhost"
	"sifruno/internal/phpmyadmin"
)

// PhpMyAdmin opens phpMyAdmin for one website; internal/phpmyadmin's
// Service is the real one.
type PhpMyAdmin interface {
	Open(ctx context.Context, owner string, databases []string) (phpmyadmin.Handoff, error)
}

// phpMyAdminCSP is the policy for phpMyAdmin's pages only: the one
// phpMyAdmin 5.2 sends itself (its scripts need inline code and eval), with
// framing, plugins, form targets and the base address held to the panel.
// Every other route keeps the panel's own policy.
const phpMyAdminCSP = "default-src 'self'; script-src 'self' 'unsafe-inline' 'unsafe-eval'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; font-src 'self'; connect-src 'self'; object-src 'none'; base-uri 'self'; form-action 'self'; frame-ancestors 'none'"

// phpMyAdminWait bounds one phpMyAdmin request: a large export or import.
const phpMyAdminWait = 10 * time.Minute

type siteDatabaseOpenBody struct{}
type siteDatabaseOpenInput struct {
	AccountID string `path:"account_id"`
	Body      siteDatabaseOpenBody
}
type siteDatabaseOpenBodyOut struct {
	URL            string    `json:"url" doc:"The address to open in a new browser tab. It signs in to phpMyAdmin once and works for 60 seconds."`
	LinkExpiresAt  time.Time `json:"link_expires_at"`
	LoginExpiresAt time.Time `json:"login_expires_at" doc:"When the temporary database user phpMyAdmin signs in as is removed."`
}
type siteDatabaseOpenOutput struct{ Body siteDatabaseOpenBodyOut }

const (
	phpMyAdminNotSetUp = "phpMyAdmin is not set up on this server. Run Sifruno's installer (install.sh) again to add it."
	phpMyAdminNoData   = "This website has no database yet, so phpMyAdmin would have nothing to show. Create a database first."
	phpMyAdminTooMany  = "Too many phpMyAdmin sign-ins are open on this server. Each ends one hour after it was opened; try again later."
	phpMyAdminRecord   = "The panel could not record the phpMyAdmin sign-in, so it made none. Check that the panel's state folder can be written, then try again."
)

// registerSiteDatabasePhpMyAdmin adds the one click: a temporary database
// user for this website's databases and a one-time link that signs in to
// phpMyAdmin as it. It has the database routes' admission, and API tokens
// may not use it (tokenRefusedSiteDatabase).
func registerSiteDatabasePhpMyAdmin(a huma.API, o Options) {
	huma.Register(a, huma.Operation{OperationID: "open-site-phpmyadmin", Method: http.MethodPost, Path: "/api/v1/websites/sites/{account_id}/databases/phpmyadmin", DefaultStatus: http.StatusCreated,
		Summary: "Open phpMyAdmin for this website's databases", MaxBodyBytes: 4096, BodyReadTimeout: 5 * time.Second, SkipValidateBody: true, SkipValidateParams: true,
	}, func(ctx context.Context, in *siteDatabaseOpenInput) (*siteDatabaseOpenOutput, error) {
		ctx, cancel := context.WithTimeout(ctx, databaseWait)
		defer cancel()
		owner, err := siteDatabaseOwner(ctx, o, in.AccountID)
		if err != nil {
			return nil, err
		}
		if o.PhpMyAdmin == nil {
			return nil, huma.Error503ServiceUnavailable(phpMyAdminNotSetUp)
		}
		databases, _, err := ownDatabases(ctx, o.Databases, owner)
		if err != nil {
			return nil, databaseFailure(err)
		}
		names := make([]string, 0, len(databases))
		for _, d := range databases {
			// ownDatabases keeps only the owner's; the prefix is checked again.
			if strings.HasPrefix(d.Name, owner+"_") {
				names = append(names, d.Name)
			}
		}
		if len(names) == 0 {
			return nil, huma.Error409Conflict(phpMyAdminNoData)
		}
		h, err := o.PhpMyAdmin.Open(ctx, owner, names)
		switch {
		case errors.Is(err, phpmyadmin.ErrTooMany):
			return nil, huma.Error429TooManyRequests(phpMyAdminTooMany)
		case errors.Is(err, phpmyadmin.ErrNotRecorded):
			return nil, huma.Error500InternalServerError(phpMyAdminRecord, databaseTechnical(err))
		case errors.Is(err, dbhost.ErrUnavailable):
			return nil, huma.Error503ServiceUnavailable(databaseServerDown, databaseTechnical(err))
		case err != nil:
			return nil, databaseFailureWith("The database server refused to make phpMyAdmin's temporary user. Open Technical details to see why.", err)
		}
		return &siteDatabaseOpenOutput{Body: siteDatabaseOpenBodyOut{URL: h.URL, LinkExpiresAt: h.CodeExpires.UTC(), LoginExpiresAt: h.LoginExpires.UTC()}}, nil
	})
}

// tokenRefusedSiteDatabase is the one click: it hands out a database login,
// which is for a person signed in to the panel, never for an API token.
func tokenRefusedSiteDatabase(p string) bool {
	rest, ok := strings.CutPrefix(p, "/api/v1/websites/sites/")
	if !ok {
		return false
	}
	parts := strings.Split(rest, "/")
	return len(parts) >= 3 && parts[1] == "databases" && parts[2] == "phpmyadmin"
}

// isPhpMyAdminPath reports whether a request is for phpMyAdmin itself.
func isPhpMyAdminPath(p string) bool {
	return p+"/" == phpmyadmin.BasePath || strings.HasPrefix(p, phpmyadmin.BasePath)
}

// statusOnly keeps what an admission check would have answered, so the
// panel can answer a browser tab with a page instead of JSON.
type statusOnly struct {
	header http.Header
	status int
}

func (s *statusOnly) Header() http.Header         { return s.header }
func (s *statusOnly) Write(b []byte) (int, error) { return len(b), nil }
func (s *statusOnly) WriteHeader(status int)      { s.status = status }

// servePhpMyAdmin admits a request for phpMyAdmin and passes it on: a panel
// session (an admin's over the network, as Authorize decides), never an API
// token, and for a POST an Origin header, which the panel has already
// matched to its own. phpMyAdmin's forms cannot send the panel's CSRF header;
// phpMyAdmin checks its own token on every change.
func servePhpMyAdmin(w http.ResponseWriter, r *http.Request, o Options) {
	h := w.Header()
	h.Set("Content-Security-Policy", phpMyAdminCSP)
	// phpMyAdmin sets its own caching; its scripts and styles may be cached.
	h.Del("Cache-Control")
	if o.PhpMyAdmin == nil || o.PhpMyAdminProxy == nil || o.Operator == nil {
		phpmyadmin.WritePage(w, http.StatusServiceUnavailable, "phpMyAdmin is not available.", phpMyAdminNotSetUp, "After the installer has run, open phpMyAdmin from a website's Databases page.")
		return
	}
	if len(r.Header.Values("Authorization")) > 0 {
		phpmyadmin.WritePage(w, http.StatusForbidden, "API tokens cannot open phpMyAdmin.", "phpMyAdmin signs in to a website's databases, which only a person signed in to the panel may do.", "Sign in to the panel in a browser, then open phpMyAdmin from the website's Databases page.")
		return
	}
	p := r.URL.Path
	if p+"/" == phpmyadmin.BasePath {
		http.Redirect(w, r, phpmyadmin.BasePath, http.StatusMovedPermanently)
		return
	}
	clean := pathpkg.Clean(p)
	if strings.HasSuffix(p, "/") {
		clean += "/"
	}
	if clean != p || strings.Contains(p, "\\") || strings.Contains(strings.ToLower(r.URL.RawPath), "%2f") {
		phpmyadmin.WritePage(w, http.StatusBadRequest, "That phpMyAdmin address is not valid.", "The address has parts such as .. or // that the panel does not pass on.", "Open phpMyAdmin again from the website's Databases page.")
		return
	}
	if r.Method != http.MethodGet && r.Method != http.MethodHead && r.Method != http.MethodPost {
		h.Set("Allow", "GET, HEAD, POST")
		phpmyadmin.WritePage(w, http.StatusMethodNotAllowed, "phpMyAdmin does not take that kind of request.", "phpMyAdmin pages use GET and POST only.", "Use phpMyAdmin's own links and buttons.")
		return
	}
	check := &statusOnly{header: http.Header{}}
	if _, ok := o.Operator.Authorize(check, r, false); !ok {
		switch check.status {
		case http.StatusUnauthorized:
			phpmyadmin.WritePage(w, http.StatusUnauthorized, "You are not signed in to the panel.", "phpMyAdmin opens only while you are signed in to the panel. A panel sign-in lasts 15 minutes.", "Sign in to the panel again, then choose Open phpMyAdmin on the website's Databases page.")
		default:
			phpmyadmin.WritePage(w, http.StatusForbidden, "The panel refused to open phpMyAdmin.", "Over the network, phpMyAdmin opens only for an admin signed in with a password and a code.", "Sign in to the panel as an admin, then choose Open phpMyAdmin on the website's Databases page.")
		}
		return
	}
	if r.Method == http.MethodPost && r.Header.Get("Origin") == "" {
		phpmyadmin.WritePage(w, http.StatusForbidden, "The panel refused this phpMyAdmin change.", "The browser did not say which page sent it, so the panel cannot tell it came from phpMyAdmin.", "Reload phpMyAdmin and try again.")
		return
	}
	_ = http.NewResponseController(w).SetReadDeadline(time.Now().Add(phpMyAdminWait))
	_ = http.NewResponseController(w).SetWriteDeadline(time.Now().Add(phpMyAdminWait))
	o.PhpMyAdminProxy.ServeHTTP(w, r)
}
