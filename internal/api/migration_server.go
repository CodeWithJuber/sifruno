package api

import (
	"context"
	"errors"
	"net/http"
	"time"

	"github.com/danielgtaylor/huma/v2"
	"sifruno/internal/hostaccounts"
	"sifruno/internal/keyinstall"
)

// Moving a website from another Linux server (hostaccounts README, "From
// another Linux server"): the page opens the source with via "server",
// the admin confirms its SSH fingerprint, and Sifruno's key gets onto it
// one of three ways: the admin runs the install command as root there, or
// gives root's password, or a private key root accepts. The password or
// key reaches this handler in the request body, signs in once from this
// process (internal/keyinstall), and is dropped: never stored, logged,
// returned, put in a job, or handed to the broker or a program. Then the
// page lists the server's websites, each with what moves and what does
// not, and starts the move of one.

// maxInstallKeyBody bounds the install-key request: a private key of up to
// 16 KiB with JSON's escapes, and a passphrase.
const maxInstallKeyBody = 40 << 10

type migrationInstallKeyInput struct {
	ID   string `path:"id"`
	Body struct {
		Password   string `json:"password,omitempty" maxLength:"1024" doc:"Root's password on the old server. Used in memory for one sign-in; never stored, logged or returned."`
		PrivateKey string `json:"private_key,omitempty" maxLength:"16384" doc:"Instead of the password: a private key root accepts, in OpenSSH or PEM form. Used in memory for one sign-in; never stored, logged or returned."`
		Passphrase string `json:"passphrase,omitempty" maxLength:"1024" doc:"The private key's passphrase, when it has one."`
	}
}

type migrationSitesOutput struct {
	Body struct {
		Sites []hostaccounts.MigrationSite `json:"sites"`
	}
}

// installKeyProblem explains a key install that did not happen.
func installKeyProblem(err error, host string) error {
	var failed *keyinstall.Error
	technical := ""
	if errors.As(err, &failed) {
		technical = failed.Output
	}
	unprocessable := func(why, next string) error {
		return newMigrationProblem(http.StatusUnprocessableEntity, why, next, technical)
	}
	switch {
	case errors.Is(err, keyinstall.ErrHostKey):
		return unprocessable("The server at "+host+" showed another SSH host key than the one you confirmed, so your password or key was not sent.", "Stop until you know why. If the old server was reinstalled, press Stop and remove the key, connect again and confirm its new fingerprint.")
	case errors.Is(err, keyinstall.ErrLogin):
		return unprocessable("The old server refused the sign-in as root: the password or key is wrong, or its SSH server does not let root sign in that way (PermitRootLogin prohibit-password allows keys only).", "Check the password or key, or run the command shown here as root on the old server yourself and press I ran it.")
	case errors.Is(err, keyinstall.ErrKey):
		return unprocessable("The private key could not be read: it is not an OpenSSH or PEM private key, or it needs a passphrase that was not given or is wrong.", "Paste the whole key with its BEGIN and END lines, and its passphrase if it has one, then press Add the key again.")
	case errors.Is(err, keyinstall.ErrUnreachable):
		return unprocessable("Sifruno could not reach the old server's SSH port, or the connection broke.", "Check that the old server runs and that its firewall accepts this server, then press Add the key again.")
	case errors.Is(err, keyinstall.ErrCommand):
		return unprocessable("Sifruno signed in as root, but adding the key failed on the old server.", "Open Technical details for the old server's own words and fix that there, or run the command shown here yourself.")
	}
	return unprocessable("Give root's password or a private key, not both and not neither; a password without line breaks.", "Correct it, then press Add the key again.")
}

// pinnedKeyType is the type of the host key whose fingerprint was
// confirmed.
func pinnedKeyType(m hostaccounts.Migration) string {
	for _, k := range m.HostKeys {
		if k.Fingerprint == m.Pinned {
			return k.Type
		}
	}
	return ""
}

func registerServerMigrations(a huma.API, op func(id, method, path string, status int) huma.Operation, broker func() (hostaccounts.MigrationService, error)) {
	huma.Register(a, op("list-migration-sites", http.MethodGet, "/api/v1/websites/migrations/sources/{id}/sites", http.StatusOK), func(ctx context.Context, in *migrationSourceIDInput) (*migrationSitesOutput, error) {
		b, err := broker()
		if err != nil {
			return nil, err
		}
		items, err := b.MigrationSites(ctx, in.ID)
		if err != nil {
			return nil, migrationBrokerError(err)
		}
		out := &migrationSitesOutput{}
		out.Body.Sites = items
		return out, nil
	})
	install := op("install-migration-key", http.MethodPost, "/api/v1/websites/migrations/sources/{id}/install-key", http.StatusOK)
	install.MaxBodyBytes, install.BodyReadTimeout = maxInstallKeyBody, 10*time.Second
	huma.Register(a, install, func(ctx context.Context, in *migrationInstallKeyInput) (*migrationSourceOutput, error) {
		login := keyinstall.Login{Password: in.Body.Password, PrivateKey: []byte(in.Body.PrivateKey), Passphrase: []byte(in.Body.Passphrase)}
		// The handler drops its references to the secret when it returns.
		in.Body.Password, in.Body.PrivateKey, in.Body.Passphrase = "", "", ""
		defer login.Clear()
		b, err := broker()
		if err != nil {
			return nil, err
		}
		m, err := b.GetMigration(ctx, in.ID)
		if err != nil {
			return nil, migrationBrokerError(err)
		}
		switch {
		case m.Via != "" && m.Via != hostaccounts.ViaServer:
			return nil, newMigrationProblem(http.StatusConflict, "This connection adds its key another way (WHM, or a backup file has none).", "Go on with the step the page shows.", "")
		case m.Pinned == "" || pinnedKeyType(m) == "":
			return nil, newMigrationProblem(http.StatusConflict, "The old server's fingerprint has not been confirmed yet. Sifruno sends a password or key only to the server you confirmed.", "Confirm the fingerprint first.", "")
		case !login.Valid():
			return nil, installKeyProblem(keyinstall.ErrInvalid, m.Host)
		}
		target := keyinstall.Target{Host: m.Host, Port: m.Port, KeyType: pinnedKeyType(m), Fingerprint: m.Pinned}
		if err := keyinstall.Run(ctx, target, login, m.InstallCommand); err != nil {
			return nil, installKeyProblem(err, m.Host)
		}
		out := &migrationSourceOutput{}
		out.Body.Source = migrationSource(m)
		return out, nil
	})
}
