package api

import (
	"context"
	"errors"
	"net/http"
	"regexp"
	"time"

	"github.com/danielgtaylor/huma/v2"
	"sifruno/internal/hostaccounts"
	"sifruno/internal/wizard"
)

// "Move a website here": migration v1 from a cPanel server over root SSH
// (hostaccounts README, Migration). The routes sit under
// /api/v1/websites/migrations, so the wizard's admission applies (an admin
// session, and for a change also Origin and CSRF), and an API token may not
// use them (tokenRefused): a migration holds a key to another server's root.

const (
	migrationsUnavailable = "Moving websites is not set up on this server."
	migrationReason       = "Move a website here"
	// migrationWait is the response deadline of a route that reads the old
	// server: its account list or the removal of the key.
	migrationWait = 4 * time.Minute
)

var (
	migrationStalePath  = regexp.MustCompile(`^/api/v1/websites/migrations/stale-keys/[a-f0-9]{32}/cleared$`)
	migrationSourcePath = regexp.MustCompile(`^/api/v1/websites/migrations/sources/[a-f0-9]{32}/(host-key|cancel)$`)
	migrationJobPath    = regexp.MustCompile(`^/api/v1/websites/migrations/[a-f0-9]{32}/(verify|accept|ready)$`)
	migrationReadPath   = regexp.MustCompile(`^/api/v1/websites/migrations/sources/[a-f0-9]{32}/accounts$`)
)

// migrationRoute names a migration POST as wizardFields keys it, or "".
func migrationRoute(p string) string {
	switch p {
	case "/api/v1/websites/migrations/sources":
		return "migration-source"
	case "/api/v1/websites/migrations":
		return "migration"
	}
	if migrationStalePath.MatchString(p) {
		return "migration-stale-cleared"
	}
	if m := migrationSourcePath.FindStringSubmatch(p); m != nil {
		return "migration-" + m[1]
	}
	if m := migrationJobPath.FindStringSubmatch(p); m != nil {
		return "migration-" + m[1]
	}
	return ""
}

// isMigrationSlow is a route that talks to the old server.
func isMigrationSlow(r *http.Request) bool {
	return migrationReadPath.MatchString(r.URL.Path) || migrationRoute(r.URL.Path) == "migration-source" || migrationRoute(r.URL.Path) == "migration-cancel"
}

// MigrationSource is the old server as the page shows it: the key line the
// admin adds there and the host keys whose fingerprint they confirm.
type MigrationSource struct {
	ID             string                          `json:"id"`
	Host           string                          `json:"host"`
	Port           int                             `json:"port"`
	KeyLine        string                          `json:"key_line" doc:"The line root's authorized_keys on the old server gets; it ends with the migration's name."`
	InstallCommand string                          `json:"install_command" doc:"Run as root on the old server to add the key line."`
	HostKeys       []hostaccounts.MigrationHostKey `json:"host_keys"`
	Pinned         string                          `json:"pinned_fingerprint" doc:"The confirmed fingerprint; empty until the admin confirms one."`
	ExpiresAt      time.Time                       `json:"expires_at"`
}

func migrationSource(m hostaccounts.Migration) MigrationSource {
	return MigrationSource{ID: m.ID, Host: m.Host, Port: m.Port, KeyLine: m.PublicKey, InstallCommand: m.InstallCommand, HostKeys: m.HostKeys, Pinned: m.Pinned, ExpiresAt: m.ExpiresAt}
}

type migrationSourceBody struct {
	Host string `json:"host" maxLength:"253" doc:"The old server's host name or IPv4 address."`
	Port int    `json:"port" minimum:"1" maximum:"65535" doc:"Its SSH port, usually 22."`
}
type migrationSourceInput struct{ Body migrationSourceBody }
type migrationSourceIDInput struct {
	ID string `path:"id"`
}
type migrationHostKeyInput struct {
	ID   string `path:"id"`
	Body struct {
		Fingerprint string `json:"fingerprint" maxLength:"64" doc:"The SHA256 fingerprint the old server shows for its key."`
	}
}
type migrationEmptyInput struct {
	ID   string `path:"id"`
	Body struct{}
}
type migrationSourceOutput struct {
	Body struct {
		Source MigrationSource `json:"source"`
	}
}

// MigrationAccount is one account on the old server; Problem says why it
// cannot move, or is empty.
type MigrationAccount struct {
	User         string `json:"user"`
	Domain       string `json:"domain"`
	DiskUsedMiB  int64  `json:"disk_used_mib"`
	DiskLimitMiB int64  `json:"disk_limit_mib" doc:"0 means unlimited."`
	Suspended    bool   `json:"suspended"`
	Problem      string `json:"problem,omitempty"`
}

type migrationAccountsOutput struct {
	Body struct {
		Accounts []MigrationAccount `json:"accounts"`
	}
}
type migrationCancelOutput struct {
	Body hostaccounts.MigrationFinishResult
}

// StaleKey is a migration key line that may still be in root's
// authorized_keys on an old server: the broker could not prove it removed.
type StaleKey struct {
	ID     string    `json:"id"`
	Host   string    `json:"host"`
	Port   int       `json:"port"`
	Line   string    `json:"line" doc:"The line ends with this text."`
	Detail string    `json:"detail"`
	Since  time.Time `json:"since"`
}
type staleKeysOutput struct {
	Body struct {
		Keys []StaleKey `json:"keys"`
	}
}
type staleClearedOutput struct {
	Body struct {
		Cleared string `json:"cleared"`
	}
}

type migrationStartInput struct {
	Body struct {
		Source   string `json:"source" pattern:"^[a-f0-9]{32}$" doc:"The old server's migration ID."`
		Username string `json:"username" maxLength:"32" doc:"The account to move; it keeps this name here."`
	}
}
type migrationAcceptInput struct {
	ID   string `path:"id"`
	Body struct {
		Reason string `json:"reason" maxLength:"500" doc:"Why the red lines are accepted; the activity log keeps it."`
	}
}

// siteKind is what a website is: a moved one is WordPress or a PHP site by
// what its files hold.
func siteKind(j wizard.Job) string {
	if j.Kind != wizard.KindMigration {
		return j.Kind
	}
	if j.Migration != nil && j.Migration.WordPress {
		return wizard.KindWordPress
	}
	return wizard.KindPHP
}

// migrationBrokerError explains the broker's answers in plain words.
func migrationBrokerError(err error) error {
	var failed *hostaccounts.MigrationError
	switch {
	case errors.As(err, &failed):
		return huma.Error422UnprocessableEntity(migrationStepWords(failed.Step) + " " + failed.Detail)
	case errors.Is(err, hostaccounts.ErrNotFound):
		return huma.Error404NotFound("That connection to the old server has ended (it lasts 24 hours). Connect again.")
	case errors.Is(err, hostaccounts.ErrInvalid):
		return huma.Error422UnprocessableEntity("The old server's address must be a host name or IPv4 address and the port 1 to 65535.")
	case errors.Is(err, hostaccounts.ErrConflict):
		return huma.Error409Conflict("Too many connections to old servers are open, or this one changed. Finish or cancel one, then try again.")
	}
	return huma.Error503ServiceUnavailable("The account service is not answering. Check that it is running, then try again.")
}

func migrationStepWords(step string) string {
	switch step {
	case "connect":
		return "Sifruno could not reach the old server over SSH."
	case "host_key":
		return "The fingerprint was not confirmed."
	case "source":
		return "The old server's answer could not be used."
	}
	return "A step on the old server failed."
}

func registerMigrations(a huma.API, o Options) {
	op := func(id, method, path string, status int) huma.Operation {
		return huma.Operation{OperationID: id, Method: method, Path: path, DefaultStatus: status, MaxBodyBytes: 4096, BodyReadTimeout: 5 * time.Second, SkipValidateBody: true, SkipValidateParams: true}
	}
	broker := func() (hostaccounts.MigrationService, error) {
		if o.Migrations == nil || o.Wizard == nil {
			return nil, huma.Error503ServiceUnavailable(migrationsUnavailable)
		}
		return o.Migrations, nil
	}
	huma.Register(a, op("open-migration-source", http.MethodPost, "/api/v1/websites/migrations/sources", http.StatusOK), func(ctx context.Context, in *migrationSourceInput) (*migrationSourceOutput, error) {
		b, err := broker()
		if err != nil {
			return nil, err
		}
		m, err := b.OpenMigration(ctx, hostaccounts.MigrationOpenInput{Host: in.Body.Host, Port: in.Body.Port, Reason: migrationReason}, siteActor(ctx))
		if err != nil {
			return nil, migrationBrokerError(err)
		}
		out := &migrationSourceOutput{}
		out.Body.Source = migrationSource(m)
		return out, nil
	})
	huma.Register(a, op("get-migration-source", http.MethodGet, "/api/v1/websites/migrations/sources/{id}", http.StatusOK), func(ctx context.Context, in *migrationSourceIDInput) (*migrationSourceOutput, error) {
		b, err := broker()
		if err != nil {
			return nil, err
		}
		m, err := b.GetMigration(ctx, in.ID)
		if err != nil {
			return nil, migrationBrokerError(err)
		}
		out := &migrationSourceOutput{}
		out.Body.Source = migrationSource(m)
		return out, nil
	})
	huma.Register(a, op("confirm-migration-host-key", http.MethodPost, "/api/v1/websites/migrations/sources/{id}/host-key", http.StatusOK), func(ctx context.Context, in *migrationHostKeyInput) (*migrationSourceOutput, error) {
		b, err := broker()
		if err != nil {
			return nil, err
		}
		m, err := b.PinMigrationHostKey(ctx, in.ID, hostaccounts.MigrationPinInput{Fingerprint: in.Body.Fingerprint, Reason: migrationReason}, siteActor(ctx))
		if err != nil {
			var failed *hostaccounts.MigrationError
			if errors.As(err, &failed) && failed.Step == "host_key" {
				return nil, huma.Error422UnprocessableEntity("That fingerprint is not one the old server showed. Compare it again with ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub on the old server; if it does not match any, stop: something else answered.")
			}
			return nil, migrationBrokerError(err)
		}
		out := &migrationSourceOutput{}
		out.Body.Source = migrationSource(m)
		return out, nil
	})
	huma.Register(a, op("list-migration-accounts", http.MethodGet, "/api/v1/websites/migrations/sources/{id}/accounts", http.StatusOK), func(ctx context.Context, in *migrationSourceIDInput) (*migrationAccountsOutput, error) {
		b, err := broker()
		if err != nil {
			return nil, err
		}
		items, err := b.MigrationAccounts(ctx, in.ID)
		if err != nil {
			return nil, migrationBrokerError(err)
		}
		out := &migrationAccountsOutput{}
		out.Body.Accounts = make([]MigrationAccount, 0, len(items))
		for _, a := range items {
			out.Body.Accounts = append(out.Body.Accounts, MigrationAccount(a))
		}
		return out, nil
	})
	huma.Register(a, op("cancel-migration-source", http.MethodPost, "/api/v1/websites/migrations/sources/{id}/cancel", http.StatusOK), func(ctx context.Context, in *migrationEmptyInput) (*migrationCancelOutput, error) {
		b, err := broker()
		if err != nil {
			return nil, err
		}
		res, err := b.FinishMigration(ctx, in.ID, hostaccounts.MigrationFinishInput{Reason: migrationReason}, siteActor(ctx))
		if err != nil {
			return nil, migrationBrokerError(err)
		}
		return &migrationCancelOutput{Body: res}, nil
	})
	huma.Register(a, op("list-stale-migration-keys", http.MethodGet, "/api/v1/websites/migrations/stale-keys", http.StatusOK), func(ctx context.Context, _ *struct{}) (*staleKeysOutput, error) {
		b, err := broker()
		if err != nil {
			return nil, err
		}
		items, err := b.StaleMigrationKeys(ctx)
		if err != nil {
			return nil, migrationBrokerError(err)
		}
		out := &staleKeysOutput{}
		out.Body.Keys = make([]StaleKey, 0, len(items))
		for _, k := range items {
			out.Body.Keys = append(out.Body.Keys, StaleKey{ID: k.ID, Host: k.Host, Port: k.Port, Line: k.Comment, Detail: k.Detail, Since: k.At})
		}
		return out, nil
	})
	huma.Register(a, op("clear-stale-migration-key", http.MethodPost, "/api/v1/websites/migrations/stale-keys/{id}/cleared", http.StatusOK), func(ctx context.Context, in *migrationEmptyInput) (*staleClearedOutput, error) {
		b, err := broker()
		if err != nil {
			return nil, err
		}
		if err = b.ClearStaleMigrationKey(ctx, in.ID, hostaccounts.MigrationFinishInput{Reason: "The admin removed the key line by hand"}, siteActor(ctx)); err != nil {
			if errors.Is(err, hostaccounts.ErrNotFound) {
				return nil, huma.Error404NotFound("That key line is not listed any more.")
			}
			return nil, migrationBrokerError(err)
		}
		out := &staleClearedOutput{}
		out.Body.Cleared = in.ID
		return out, nil
	})
	huma.Register(a, op("start-migration", http.MethodPost, "/api/v1/websites/migrations", http.StatusAccepted), func(ctx context.Context, in *migrationStartInput) (*websiteJobOutput, error) {
		if _, err := broker(); err != nil {
			return nil, err
		}
		job, err := o.Wizard.StartMigration(ctx, wizard.MigrationInput{Source: in.Body.Source, Username: in.Body.Username}, siteActor(ctx))
		if err != nil {
			return nil, wizardError(err)
		}
		return &websiteJobOutput{Body: websiteJobBody{Job: job}}, nil
	})
	change := func(id, action string, run func(context.Context, string, string, string) (wizard.Job, error)) {
		huma.Register(a, op(id, http.MethodPost, "/api/v1/websites/migrations/{id}/"+action, http.StatusOK), func(ctx context.Context, in *migrationAcceptInput) (*websiteJobOutput, error) {
			if _, err := broker(); err != nil {
				return nil, err
			}
			job, err := run(ctx, in.ID, in.Body.Reason, siteActor(ctx))
			if err != nil {
				if errors.Is(err, wizard.ErrNotFound) {
					return nil, huma.Error404NotFound(err.Error())
				}
				return nil, wizardError(err)
			}
			return &websiteJobOutput{Body: websiteJobBody{Job: job}}, nil
		})
	}
	change("verify-migration", "verify", func(ctx context.Context, id, _, actor string) (wizard.Job, error) {
		return o.Wizard.VerifyMigration(ctx, id, actor)
	})
	change("accept-migration", "accept", func(ctx context.Context, id, reason, actor string) (wizard.Job, error) {
		return o.Wizard.AcceptMigration(ctx, id, reason, actor)
	})
	change("ready-migration", "ready", func(ctx context.Context, id, _, actor string) (wizard.Job, error) {
		return o.Wizard.ReadyMigration(ctx, id, actor)
	})
}
