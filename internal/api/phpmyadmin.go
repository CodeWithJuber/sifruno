package api

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/danielgtaylor/huma/v2"
	"sifruno/internal/dbhost"
	"sifruno/internal/phpmyadmin"
)

// PhpMyAdmin opens phpMyAdmin for one website; internal/phpmyadmin's
// Service is the real one. phpMyAdmin is served on its own origin (the
// panel's host names on another HTTPS port), never by this API.
type PhpMyAdmin interface {
	Open(ctx context.Context, owner string, databases []string) (phpmyadmin.Handoff, error)
	SignonURL(host string, h phpmyadmin.Handoff) string
}

// requestHost is the host name a request came to, as the outer handler
// checked it, and whether it came over the network.
type requestHost struct {
	name   string
	remote bool
}
type requestHostKey struct{}

type siteDatabaseOpenBody struct{}
type siteDatabaseOpenInput struct {
	AccountID string `path:"account_id"`
	Body      siteDatabaseOpenBody
}
type siteDatabaseOpenBodyOut struct {
	URL            string    `json:"url" doc:"The address to open in a new browser tab, on phpMyAdmin's own HTTPS origin. It signs in to phpMyAdmin once and works for 60 seconds."`
	LinkExpiresAt  time.Time `json:"link_expires_at"`
	LoginExpiresAt time.Time `json:"login_expires_at" doc:"When the temporary database user phpMyAdmin signs in as is removed, and phpMyAdmin's admission with it."`
}
type siteDatabaseOpenOutput struct{ Body siteDatabaseOpenBodyOut }

const (
	phpMyAdminNotSetUp = "phpMyAdmin is not set up on this server. It opens on the panel's own HTTPS address, on its own port: run Sifruno's installer (install.sh) with --panel-host to add it."
	phpMyAdminNoData   = "This website has no database yet, so phpMyAdmin would have nothing to show. Create a database first."
	phpMyAdminTooMany  = "Too many phpMyAdmin sign-ins are open on this server. Each ends one hour after it was opened; try again later."
	phpMyAdminRecord   = "The panel could not record the phpMyAdmin sign-in, so it made none. Check that the panel's state folder can be written, then try again."
)

// registerSiteDatabasePhpMyAdmin adds the one click: a temporary database
// user for this website's databases and a one-time link to phpMyAdmin's
// origin that signs in as it. It has the database routes' admission (an
// admin session, Origin and CSRF), and API tokens may not use it
// (tokenRefusedSiteDatabase).
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
		host := phpMyAdminHost(ctx, o)
		if o.PhpMyAdmin == nil || host == "" {
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
		return &siteDatabaseOpenOutput{Body: siteDatabaseOpenBodyOut{URL: o.PhpMyAdmin.SignonURL(host, h), LinkExpiresAt: h.CodeExpires.UTC(), LoginExpiresAt: h.LoginExpires.UTC()}}, nil
	})
}

// phpMyAdminHost is the host name phpMyAdmin's origin is reached at: the
// one this request came to over the network (operator.Remote checked it is a
// panel host name), or the first panel host name for a request on loopback.
// "" means the panel has no host names, so phpMyAdmin has no origin.
func phpMyAdminHost(ctx context.Context, o Options) string {
	h, _ := ctx.Value(requestHostKey{}).(requestHost)
	if h.remote && h.name != "" {
		return strings.ToLower(h.name)
	}
	if len(o.PanelHosts) > 0 {
		return strings.ToLower(o.PanelHosts[0])
	}
	return ""
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
