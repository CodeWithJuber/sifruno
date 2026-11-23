package api

import (
	"context"
	"net/http"
	"regexp"
	"time"

	"github.com/danielgtaylor/huma/v2"
	"sifruno/internal/hostaccounts"
	"sifruno/internal/wizard"
)

// Website is one site the New website wizard made. The broker's account
// list is the authority for the domain, the state and the certificate; the
// rest comes from the newest succeeded wizard job for that account.
type Website struct {
	AccountID        string       `json:"account_id"`
	Username         string       `json:"username"`
	Domain           string       `json:"domain"`
	State            string       `json:"state" doc:"The hosting account's state: active, suspended or recovery_required."`
	HTTPS            WebsiteHTTPS `json:"https"`
	PHPVersion       string       `json:"php_version" doc:"Empty for a site made before the panel recorded it."`
	WordPressVersion string       `json:"wordpress_version"`
	URL              string       `json:"url"`
	AdminURL         string       `json:"admin_url"`
	CreatedAt        string       `json:"created_at" doc:"When the wizard job started, RFC 3339."`
}

// WebsiteHTTPS says whether the account has a certificate installed, and
// until when it is valid (RFC 3339, empty without one).
type WebsiteHTTPS struct {
	On       bool   `json:"on"`
	NotAfter string `json:"not_after"`
}

type websiteListBody struct {
	Sites []Website `json:"sites"`
}
type websiteListOutput struct{ Body websiteListBody }
type websiteInput struct {
	AccountID string `path:"account_id"`
}
type websiteOutput struct{ Body Website }

const (
	websitesNotSetUp   = "WordPress websites are not set up on this server. The panel needs the account service and the database service for them."
	websitesNoBroker   = "The account service did not answer, so the panel cannot show the websites."
	websiteNotFound    = "That website was not found. It may have been removed, or it was not made with New website."
	websiteAccountForm = `^[a-f0-9]{32}$`
)

var websiteAccountID = regexp.MustCompile(websiteAccountForm)

// registerWebsites adds the Websites list's reads. They sit under
// /api/v1/websites/, so the wizard's admission applies: an admin session for
// these GETs, as for the job reads.
func registerWebsites(a huma.API, o Options) {
	op := func(id, path string) huma.Operation {
		return huma.Operation{OperationID: id, Method: http.MethodGet, Path: path, SkipValidateParams: true}
	}
	huma.Register(a, op("list-websites", "/api/v1/websites/sites"), func(ctx context.Context, _ *struct{}) (*websiteListOutput, error) {
		sites, err := listWebsites(ctx, o)
		if err != nil {
			return nil, err
		}
		return &websiteListOutput{Body: websiteListBody{Sites: sites}}, nil
	})
	huma.Register(a, op("get-website", "/api/v1/websites/sites/{account_id}"), func(ctx context.Context, in *websiteInput) (*websiteOutput, error) {
		if !websiteAccountID.MatchString(in.AccountID) {
			return nil, huma.Error404NotFound(websiteNotFound)
		}
		sites, err := listWebsites(ctx, o)
		if err != nil {
			return nil, err
		}
		for _, s := range sites {
			if s.AccountID == in.AccountID {
				return &websiteOutput{Body: s}, nil
			}
		}
		return nil, huma.Error404NotFound(websiteNotFound)
	})
}

// listWebsites joins the broker's accounts with the wizard's succeeded jobs,
// newest job first, one entry per account. An account the broker no longer
// has is left out, and so is one no kept job made.
func listWebsites(ctx context.Context, o Options) ([]Website, error) {
	if o.Accounts == nil || o.Wizard == nil {
		return nil, huma.Error503ServiceUnavailable(websitesNotSetUp)
	}
	accounts, err := o.Accounts.List(ctx)
	if err != nil {
		return nil, huma.Error503ServiceUnavailable(websitesNoBroker)
	}
	byID := make(map[string]hostaccounts.Account, len(accounts))
	for _, a := range accounts {
		byID[a.ID] = a
	}
	sites := []Website{}
	listed := map[string]bool{}
	for _, j := range o.Wizard.Succeeded() {
		a, ok := byID[j.Result.AccountID]
		if !ok || listed[a.ID] {
			continue
		}
		listed[a.ID] = true
		sites = append(sites, website(a, j))
	}
	return sites, nil
}

func website(a hostaccounts.Account, j wizard.Job) Website {
	https := WebsiteHTTPS{On: a.Certificate != (hostaccounts.CertificateState{})}
	if a.Certificate.NotAfter > 0 {
		https.NotAfter = time.Unix(a.Certificate.NotAfter, 0).UTC().Format(time.RFC3339)
	}
	return Website{
		AccountID: a.ID, Username: a.Username, Domain: a.Domain, State: a.State, HTTPS: https,
		PHPVersion: j.PHPVersion, WordPressVersion: j.Result.WordPressVersion, URL: j.Result.URL, AdminURL: j.Result.AdminURL, CreatedAt: j.CreatedAt,
	}
}
