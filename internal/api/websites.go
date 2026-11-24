package api

import (
	"context"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/danielgtaylor/huma/v2"
	"sifruno/internal/hostaccounts"
	"sifruno/internal/olsweb"
	"sifruno/internal/wizard"
)

// Website is one site the New website wizard made. The broker's account
// list is the authority for the domain, the state, the certificate, the PHP
// version and the revision; the rest comes from the newest succeeded wizard
// job for that account. A site whose delete removed the account but not yet
// its database comes from the job alone, as partly_deleted.
type Website struct {
	AccountID        string       `json:"account_id"`
	Username         string       `json:"username"`
	Domain           string       `json:"domain"`
	Kind             string       `json:"kind" enum:"wordpress,php" doc:"What the wizard made: wordpress, or php for a PHP site with no WordPress (its wordpress_version and admin_url are empty)."`
	State            string       `json:"state" doc:"The hosting account's state: active, suspended or recovery_required; partly_deleted when a delete removed the hosting account but not yet the site's database."`
	HTTPS            WebsiteHTTPS `json:"https"`
	PHPVersion       string       `json:"php_version" doc:"The PHP version the site runs with. Empty when the account service reports none."`
	WordPressVersion string       `json:"wordpress_version"`
	URL              string       `json:"url"`
	AdminURL         string       `json:"admin_url"`
	CreatedAt        string       `json:"created_at" doc:"When the wizard job started, RFC 3339."`
	Revision         uint64       `json:"revision" doc:"The hosting account's revision, or for a partly deleted site the one its delete was asked at. A change sends it back as expected_revision."`
	// SiteFolderChanged comes from the broker's account list.
	SiteFolderChanged bool `json:"site_folder_changed" doc:"The hosting account itself renamed, replaced or removed public_html, or changed the permissions of its home or public_html. Until the folder is back or the current one is used (the folder action), the site's PHP version, HTTPS and WordPress cannot change. Other websites are not affected."`
	// Limits come from the broker's account list; a partly deleted site has
	// no account and none.
	Limits *WebsiteLimits `json:"limits,omitempty" doc:"What all of the hosting account's processes may use together: the site's PHP, SFTP sessions and scheduled jobs. Left out for a partly deleted site."`
	// Usage comes from the broker's usage read (site_tools.go), in the list
	// only.
	Usage *WebsiteUsage `json:"usage,omitempty" doc:"Disk use and this month's traffic. In the list only, and left out when the account service could not say within a few seconds."`
}

// WebsiteLimits are the hosting account's limits, read only here: the
// account's plan sets them.
type WebsiteLimits struct {
	Processes  int `json:"processes" doc:"Processes and threads the account may run at once."`
	MemoryMiB  int `json:"memory_mib" doc:"Memory the account may use, in MiB, file cache included."`
	CPUPercent int `json:"cpu_percent" doc:"CPU time the account may use; 100 is one CPU."`
}

// WebsiteHTTPS says whether the account has a certificate installed, and
// until when it is valid (RFC 3339, empty without one).
type WebsiteHTTPS struct {
	On       bool   `json:"on"`
	NotAfter string `json:"not_after"`
}

// WebsiteDetail is one site as its own page needs it.
type WebsiteDetail struct {
	Website
	PHPVersions []string `json:"php_versions" doc:"The PHP versions installed on this server, which the site can change to."`
}

// WebsitePHPBody, WebsiteStateBody and WebsiteDeleteBody are the site page's
// three changes. The middleware has already checked that each holds only
// its own keys, each once, text as text and the revision as a whole number.
type WebsitePHPBody struct {
	PHPVersion       string `json:"php_version" enum:"8.1,8.2,8.3,8.4" doc:"The PHP version to run the site with. The disk quota is kept."`
	ExpectedRevision uint64 `json:"expected_revision" minimum:"1" doc:"The revision the site entry had."`
}
type WebsiteStateBody struct {
	State            string `json:"state" enum:"active,suspended" doc:"suspended stops the site from serving; active serves it again."`
	ExpectedRevision uint64 `json:"expected_revision" minimum:"1" doc:"The revision the site entry had."`
}
type WebsiteDeleteBody struct {
	ConfirmDomain    string `json:"confirm_domain" maxLength:"253" doc:"The site's domain, typed by the person to confirm."`
	ExpectedRevision uint64 `json:"expected_revision" minimum:"1" doc:"The revision the site entry had."`
}

// WebsiteFolderBody asks the account service to use the hosting account's
// current public_html as the site's folder.
type WebsiteFolderBody struct {
	ExpectedRevision uint64 `json:"expected_revision" minimum:"1" doc:"The revision the site entry had."`
}

// WebsiteDeleted says what a finished delete removed, in order, and what it
// left alone: a database or database user with the site's name that is not
// registered to it. SuspendedFirst: the site's processes kept running, so the
// panel suspended the site and asked for the delete again.
type WebsiteDeleted struct {
	Domain         string   `json:"domain"`
	Removed        []string `json:"removed"`
	Kept           []string `json:"kept"`
	SuspendedFirst bool     `json:"suspended_first,omitempty"`
}

type websiteListBody struct {
	Sites []Website `json:"sites"`
}
type websiteListOutput struct{ Body websiteListBody }
type websiteInput struct {
	AccountID string `path:"account_id"`
}
type websiteOutput struct{ Body WebsiteDetail }
type websitePHPInput struct {
	AccountID string `path:"account_id"`
	Body      WebsitePHPBody
}
type websiteStateInput struct {
	AccountID string `path:"account_id"`
	Body      WebsiteStateBody
}
type websiteDeleteInput struct {
	AccountID string `path:"account_id"`
	Body      WebsiteDeleteBody
}
type websiteFolderInput struct {
	AccountID string `path:"account_id"`
	Body      WebsiteFolderBody
}
type websiteDeletedOutput struct{ Body WebsiteDeleted }

const (
	websitesNotSetUp   = "WordPress websites are not set up on this server. The panel needs the account service and the database service for them."
	websitesNoBroker   = "The account service did not answer, so the panel cannot show the websites."
	websiteNotFound    = "That website was not found. It may have been removed, or it was not made with New website."
	websiteAccountForm = `^[a-f0-9]{32}$`

	websiteStale       = "This website changed after the page loaded it, so nothing changed. Reload the page, check the website, then try again."
	websiteNoRevision  = "expected_revision must be the revision the website's entry had."
	websiteBusy        = "The hosting account was busy with another change, or its folders were changed, so the account service refused and nothing changed."
	websiteRecovery    = "The account service has an unfinished change and refuses every other change until someone has checked it. Nothing changed."
	websiteNoAnswer    = "The account service did not answer, so the panel cannot tell whether the change was made. Reload the page to see the website as it is now."
	websiteRefused     = "The account service refused the request as invalid, so nothing changed."
	websiteNoQuota     = "The account service did not report this site's disk quota, so the panel cannot change PHP and keep the quota. Update and restart the account service, then try again."
	websiteNotActive   = "Only a live website can change its PHP version. Resume the website first."
	websitePartly      = "This website's hosting account is already deleted, so nothing else can change. Delete the website again to remove what is left."
	partlyDeleted      = "partly_deleted"
	websitePHPChanged  = "PHP version changed on the website's page"
	websiteSuspended   = "Suspended on the website's page"
	websiteResuspended = "Suspension applied again on the website's page"
	websiteResumed     = "Resumed on the website's page"
	websiteFolderUsed  = "Current public_html used on the website's page"
	websiteChangeLimit = 6 * time.Minute  // the least a broker web change gets: its apply alone may take 4
	websiteActionWait  = 11 * time.Minute // the response deadline of a site action: a delete may take 10
)

// What the folder action says when the account service did not use the
// current public_html.
const (
	websiteFolderRefused    = "The account service did not use the folder, so nothing changed. public_html is missing, is a link or a file, or does not belong to the hosting account; or the account was busy with another change. Ask the site's owner to make public_html a normal folder in the account's home, or to put the old one back, then try again."
	websiteFolderNeedsCheck = "The account service did not use the folder, so nothing changed. Either the hosting account itself changed outside Sifruno (its Linux user, group, home or sign-in lock), or the account service has another unfinished change. A new folder does not fix that. Ask whoever runs this server to check the hosting account."
)

var (
	websiteAccountID  = regexp.MustCompile(websiteAccountForm)
	websiteActionPath = regexp.MustCompile(`^/api/v1/websites/sites/[a-f0-9]{32}/(php|state|folder|delete)$`)
	websitePHP        = []string{"8.1", "8.2", "8.3", "8.4"}
	// phpRoot holds the lsphpNN packages; tests point it at a directory of
	// their own.
	phpRoot = olsweb.ServerRoot
)

// websiteAction names the site action a path is for: "php", "state",
// "folder", "delete", or "" for any other path.
func websiteAction(path string) string {
	if m := websiteActionPath.FindStringSubmatch(path); m != nil {
		return m[1]
	}
	return ""
}

// installedPHP lists the PHP versions whose lsphp binary is on this server,
// which is what the site page offers. It only looks; the broker's config
// test stays the judge of a change.
func installedPHP() []string {
	out := []string{}
	for _, v := range websitePHP {
		info, err := os.Stat(filepath.Join(phpRoot, "lsphp"+strings.ReplaceAll(v, ".", ""), "bin", "lsphp"))
		if err == nil && info.Mode().IsRegular() {
			out = append(out, v)
		}
	}
	return out
}

// registerWebsites adds the Websites list's reads and the site page's four
// changes. They sit under /api/v1/websites/, so the wizard's admission
// applies: an admin session, and for a change also Origin and CSRF.
func registerWebsites(a huma.API, o Options) {
	op := func(id, path string) huma.Operation {
		return huma.Operation{OperationID: id, Method: http.MethodGet, Path: path, SkipValidateParams: true}
	}
	change := func(id, action string) huma.Operation {
		return huma.Operation{OperationID: id, Method: http.MethodPost, Path: "/api/v1/websites/sites/{account_id}/" + action, MaxBodyBytes: 4096, BodyReadTimeout: 5 * time.Second, SkipValidateBody: true, SkipValidateParams: true}
	}
	detail := func(site Website) *websiteOutput {
		return &websiteOutput{Body: WebsiteDetail{Website: site, PHPVersions: installedPHP()}}
	}
	huma.Register(a, op("list-websites", "/api/v1/websites/sites"), func(ctx context.Context, _ *struct{}) (*websiteListOutput, error) {
		sites, err := listWebsites(ctx, o)
		if err != nil {
			return nil, err
		}
		return &websiteListOutput{Body: websiteListBody{Sites: sites}}, nil
	})
	huma.Register(a, op("get-website", "/api/v1/websites/sites/{account_id}"), func(ctx context.Context, in *websiteInput) (*websiteOutput, error) {
		site, _, err := findWebsite(ctx, o, in.AccountID)
		if err != nil {
			return nil, err
		}
		return detail(site), nil
	})
	huma.Register(a, change("set-website-php", "php"), func(ctx context.Context, in *websitePHPInput) (*websiteOutput, error) {
		site, account, err := findWebsite(ctx, o, in.AccountID)
		if err != nil {
			return nil, err
		}
		if site.State == partlyDeleted {
			return nil, huma.Error409Conflict(websitePartly)
		}
		version := in.Body.PHPVersion
		web, ok := o.Accounts.(hostaccounts.WebService)
		switch {
		case !ok:
			return nil, huma.Error503ServiceUnavailable(websitesNotSetUp)
		case !slices.Contains(websitePHP, version):
			return nil, huma.Error422UnprocessableEntity("php_version must be 8.1, 8.2, 8.3 or 8.4.")
		case in.Body.ExpectedRevision == 0:
			return nil, huma.Error422UnprocessableEntity(websiteNoRevision)
		case in.Body.ExpectedRevision != account.Revision:
			return nil, huma.Error409Conflict(websiteStale)
		case account.State == "recovery_required":
			return nil, huma.Error503ServiceUnavailable(websiteRecovery)
		case account.State != "active":
			return nil, huma.Error409Conflict(websiteNotActive)
		case account.Web.QuotaMiB == 0:
			return nil, huma.Error503ServiceUnavailable(websiteNoQuota)
		}
		ctx, cancel := context.WithTimeout(ctx, websiteChangeLimit)
		defer cancel()
		res, err := web.SetWeb(ctx, account.ID, hostaccounts.WebInput{PHPVersion: version, QuotaMiB: account.Web.QuotaMiB, ExpectedRevision: in.Body.ExpectedRevision, Reason: websitePHPChanged}, siteActor(ctx))
		if err != nil {
			return nil, websiteChangeError(err, "The web server's configuration test failed with PHP "+version+", so the site kept PHP "+account.Web.PHPVersion+". PHP "+version+" may not be installed on this server.")
		}
		site.PHPVersion, site.Revision = res.Web.PHPVersion, res.Account.Revision
		return detail(site), nil
	})
	huma.Register(a, change("set-website-state", "state"), func(ctx context.Context, in *websiteStateInput) (*websiteOutput, error) {
		site, account, err := findWebsite(ctx, o, in.AccountID)
		if err != nil {
			return nil, err
		}
		if site.State == partlyDeleted {
			return nil, huma.Error409Conflict(websitePartly)
		}
		reason, rejected := websiteSuspended, "The web server's configuration test failed with the site suspended, so the site was not suspended and nothing changed. Ask whoever runs this server to check the web server."
		switch {
		case in.Body.State == "active":
			reason, rejected = websiteResumed, "The web server's configuration test failed with the site resumed, so the site stays suspended and nothing changed. Ask whoever runs this server to check the web server."
		case in.Body.State != "suspended":
			return nil, huma.Error422UnprocessableEntity("state must be active or suspended.")
		case account.State == "suspended":
			// A suspend of a suspended site installs its suspended web server
			// settings again, journaled like any change.
			reason, rejected = websiteResuspended, "The web server's configuration test failed, so the suspension was not applied again and nothing changed. The site stays suspended. Ask whoever runs this server to check the web server."
		}
		switch {
		case in.Body.ExpectedRevision == 0:
			return nil, huma.Error422UnprocessableEntity(websiteNoRevision)
		case in.Body.ExpectedRevision != account.Revision:
			return nil, huma.Error409Conflict(websiteStale)
		}
		ctx, cancel := context.WithTimeout(ctx, websiteChangeLimit)
		defer cancel()
		changed, err := o.Accounts.SetState(ctx, account.ID, hostaccounts.StateInput{State: in.Body.State, ExpectedRevision: in.Body.ExpectedRevision, Reason: reason}, siteActor(ctx))
		if err != nil {
			return nil, websiteChangeError(err, rejected)
		}
		site.State, site.Revision = changed.State, changed.Revision
		return detail(site), nil
	})
	huma.Register(a, change("use-website-folder", "folder"), func(ctx context.Context, in *websiteFolderInput) (*websiteOutput, error) {
		site, account, err := findWebsite(ctx, o, in.AccountID)
		if err != nil {
			return nil, err
		}
		if site.State == partlyDeleted {
			return nil, huma.Error409Conflict(websitePartly)
		}
		folders, ok := o.Accounts.(hostaccounts.SiteFolderService)
		switch {
		case !ok:
			return nil, huma.Error503ServiceUnavailable(websitesNotSetUp)
		case in.Body.ExpectedRevision == 0:
			return nil, huma.Error422UnprocessableEntity(websiteNoRevision)
		case in.Body.ExpectedRevision != account.Revision:
			return nil, huma.Error409Conflict(websiteStale)
		}
		ctx, cancel := context.WithTimeout(ctx, websiteChangeLimit)
		defer cancel()
		changed, err := folders.AdoptPublicHTML(ctx, account.ID, hostaccounts.AdoptInput{ExpectedRevision: in.Body.ExpectedRevision, Reason: websiteFolderUsed}, siteActor(ctx))
		if err != nil {
			technical := errors.New("account service: " + err.Error())
			switch {
			case errors.Is(err, hostaccounts.ErrConflict):
				return nil, huma.Error409Conflict(websiteFolderRefused, technical)
			case errors.Is(err, hostaccounts.ErrRecovery):
				return nil, huma.Error503ServiceUnavailable(websiteFolderNeedsCheck, technical)
			}
			return nil, websiteChangeError(err, "")
		}
		site.State, site.Revision, site.SiteFolderChanged = changed.State, changed.Revision, changed.SiteFolderChanged
		return detail(site), nil
	})
	huma.Register(a, change("delete-website", "delete"), func(ctx context.Context, in *websiteDeleteInput) (*websiteDeletedOutput, error) {
		switch {
		case !websiteAccountID.MatchString(in.AccountID):
			return nil, huma.Error404NotFound(websiteNotFound)
		case o.Accounts == nil || o.Wizard == nil:
			return nil, huma.Error503ServiceUnavailable(websitesNotSetUp)
		case in.Body.ConfirmDomain == "":
			return nil, huma.Error422UnprocessableEntity("confirm_domain must be the website's domain.")
		case in.Body.ExpectedRevision == 0:
			return nil, huma.Error422UnprocessableEntity(websiteNoRevision)
		}
		done, err := o.Wizard.RemoveSite(ctx, in.AccountID, in.Body.ConfirmDomain, in.Body.ExpectedRevision, siteActor(ctx))
		if err != nil {
			return nil, websiteRemoveError(err)
		}
		out := WebsiteDeleted{Domain: done.Domain, Removed: done.Removed, Kept: done.Kept, SuspendedFirst: done.SuspendedFirst}
		if out.Kept == nil {
			out.Kept = []string{}
		}
		return &websiteDeletedOutput{Body: out}, nil
	})
}

// websiteChangeError explains the broker's answer to a PHP or state change.
// The detail says why in plain words; the broker's own word for it rides
// along for "Technical details".
func websiteChangeError(err error, rejected string) error {
	technical := errors.New("account service: " + err.Error())
	switch {
	case errors.Is(err, hostaccounts.ErrWebRejected):
		return huma.Error422UnprocessableEntity(rejected, technical)
	case errors.Is(err, hostaccounts.ErrConflict):
		return huma.Error409Conflict(websiteBusy, technical)
	case errors.Is(err, hostaccounts.ErrNotFound):
		return huma.Error404NotFound(websiteNotFound, technical)
	case errors.Is(err, hostaccounts.ErrInvalid):
		return huma.Error422UnprocessableEntity(websiteRefused, technical)
	case errors.Is(err, hostaccounts.ErrRecovery):
		return huma.Error503ServiceUnavailable(websiteRecovery, technical)
	default:
		return huma.Error503ServiceUnavailable(websiteNoAnswer, technical)
	}
}

// websiteRemoveError passes on a refused or stopped delete: the detail says
// why, what was removed and what is still on the server.
func websiteRemoveError(err error) error {
	var failure *wizard.RemoveFailure
	if !errors.As(err, &failure) {
		return huma.Error503ServiceUnavailable("The panel could not delete the website. Reload the page to see what is left of it.")
	}
	var technical []error
	if failure.Technical != "" {
		technical = append(technical, errors.New(failure.Technical))
	}
	switch {
	case errors.Is(err, wizard.ErrNotFound):
		return huma.Error404NotFound(failure.Why, technical...)
	case errors.Is(err, wizard.ErrInvalid):
		return huma.Error422UnprocessableEntity(failure.Why, technical...)
	case errors.Is(err, wizard.ErrConflict):
		return huma.Error409Conflict(failure.Why, technical...)
	default:
		return huma.Error503ServiceUnavailable(failure.Why, technical...)
	}
}

// listWebsites joins the broker's accounts with the wizard's succeeded jobs,
// newest job first, one entry per account. An account the broker no longer
// has is left out, unless a delete from the site's page removed it and the
// site's database is still to go; so is one no kept job made.
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
		id := j.Result.AccountID
		if listed[id] {
			continue
		}
		if a, ok := byID[id]; ok {
			sites = append(sites, website(a, j))
		} else if j.DeleteRevision > 0 {
			sites = append(sites, partlyDeletedWebsite(j))
		} else {
			continue
		}
		listed[id] = true
	}
	if usage := listUsage(ctx, o); usage != nil {
		for i := range sites {
			if sites[i].State != partlyDeleted {
				sites[i].Usage = usage[sites[i].AccountID]
			}
		}
	}
	return sites, nil
}

// findWebsite is the list's entry for one account, with the broker's account
// behind it: 404 for an account that is not a listed website.
func findWebsite(ctx context.Context, o Options, id string) (Website, hostaccounts.Account, error) {
	if !websiteAccountID.MatchString(id) {
		return Website{}, hostaccounts.Account{}, huma.Error404NotFound(websiteNotFound)
	}
	if o.Accounts == nil || o.Wizard == nil {
		return Website{}, hostaccounts.Account{}, huma.Error503ServiceUnavailable(websitesNotSetUp)
	}
	accounts, err := o.Accounts.List(ctx)
	if err != nil {
		return Website{}, hostaccounts.Account{}, huma.Error503ServiceUnavailable(websitesNoBroker)
	}
	for _, j := range o.Wizard.Succeeded() {
		if j.Result.AccountID != id {
			continue
		}
		for _, a := range accounts {
			if a.ID == id {
				return website(a, j), a, nil
			}
		}
		if j.DeleteRevision > 0 {
			return partlyDeletedWebsite(j), hostaccounts.Account{}, nil
		}
		break
	}
	return Website{}, hostaccounts.Account{}, huma.Error404NotFound(websiteNotFound)
}

// partlyDeletedWebsite is a site whose delete removed its hosting account
// but not yet its database: the job is all that is left to describe it.
func partlyDeletedWebsite(j wizard.Job) Website {
	return Website{
		AccountID: j.Result.AccountID, Username: j.Username, Domain: j.Domain, Kind: j.Kind, State: partlyDeleted,
		WordPressVersion: j.Result.WordPressVersion, URL: j.Result.URL, AdminURL: j.Result.AdminURL, CreatedAt: j.CreatedAt, Revision: j.DeleteRevision,
	}
}

func website(a hostaccounts.Account, j wizard.Job) Website {
	https := WebsiteHTTPS{On: a.Certificate != (hostaccounts.CertificateState{})}
	if a.Certificate.NotAfter > 0 {
		https.NotAfter = time.Unix(a.Certificate.NotAfter, 0).UTC().Format(time.RFC3339)
	}
	return Website{
		AccountID: a.ID, Username: a.Username, Domain: a.Domain, Kind: j.Kind, State: a.State, HTTPS: https,
		PHPVersion: a.Web.PHPVersion, WordPressVersion: j.Result.WordPressVersion, URL: j.Result.URL, AdminURL: j.Result.AdminURL, CreatedAt: j.CreatedAt, Revision: a.Revision,
		SiteFolderChanged: a.SiteFolderChanged, Limits: websiteLimits(a.Limits),
	}
}

// websiteLimits is nil when the account service reports no limits (a
// broker before limits), so the page says so rather than show zeros.
func websiteLimits(l hostaccounts.AccountLimits) *WebsiteLimits {
	if l == (hostaccounts.AccountLimits{}) {
		return nil
	}
	return &WebsiteLimits{Processes: l.Processes, MemoryMiB: l.MemoryMiB, CPUPercent: l.CPUPercent}
}
