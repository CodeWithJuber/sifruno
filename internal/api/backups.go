package api

import (
	"context"
	"errors"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/danielgtaylor/huma/v2"
	"sifruno/internal/hostaccounts"
	"sifruno/internal/sitebackups"
)

// BackupStorage is the Backup storage page: the broker's key to install on
// the storage server, the target, the schedule and the last drill and
// prune. It never carries the repository password.
type BackupStorage struct {
	Ready      bool                      `json:"ready" doc:"restic is installed and is the version the panel was built for."`
	PublicKey  string                    `json:"public_key" doc:"This server's backup key. Install it for the storage user on the storage server."`
	Configured bool                      `json:"configured"`
	Target     *BackupStorageTarget      `json:"target"`
	NightlyAt  string                    `json:"nightly_at" doc:"When the nightly backup of every site starts, HH:MM in the server's timezone."`
	Timezone   string                    `json:"timezone"`
	LastDrill  *sitebackups.RestoreDrill `json:"last_drill"`
	LastPrune  *sitebackups.BackupPrune  `json:"last_prune"`
}

// BackupStorageTarget is the configured SFTP storage server.
type BackupStorageTarget struct {
	Host     string   `json:"host"`
	Port     int      `json:"port"`
	User     string   `json:"user"`
	Path     string   `json:"path"`
	HostKeys []string `json:"host_keys"`
}

// BackupStorageBody sets the storage server. The middleware has already
// checked that it holds exactly these keys, text, and the port as a whole
// number.
type BackupStorageBody struct {
	Host       string `json:"host" maxLength:"253" doc:"The storage server's DNS name or IP address."`
	Port       int    `json:"port" doc:"Its SSH port, 1 to 65535."`
	User       string `json:"user" maxLength:"32" doc:"The SFTP user on the storage server."`
	Path       string `json:"path" maxLength:"512" doc:"The absolute folder on the storage server that holds the backups."`
	KnownHosts string `json:"known_hosts" maxLength:"3500" doc:"The storage server's host key, as ssh-keyscan prints it."`
}

// BackupStorageSaved answers a saved target. Password is the repository
// password, filled in only the first time a repository is made or opened:
// it is never shown again.
type BackupStorageSaved struct {
	BackupStorage
	Initialized bool   `json:"initialized" doc:"A new repository was made; false when an existing one was opened."`
	Password    string `json:"password,omitempty" doc:"Shown once. Without it the backups cannot be restored on another server."`
}

// SiteBackups is a site's Backups section.
type SiteBackups struct {
	Configured bool   `json:"configured"`
	Ready      bool   `json:"ready"`
	Domain     string `json:"domain"`
	Revision   uint64 `json:"revision" doc:"The hosting account's revision. A restore sends it back as expected_revision."`
	NightlyAt  string `json:"nightly_at"`
	Timezone   string `json:"timezone"`
	sitebackups.Site
	Snapshots      []hostaccounts.Snapshot `json:"snapshots" doc:"The site's backups, newest first."`
	SnapshotsError string                  `json:"snapshots_error" doc:"Why the list could not be read, or empty."`
}

// SiteBackupRestoreBody restores a site from one of its backups.
type SiteBackupRestoreBody struct {
	Snapshot         string `json:"snapshot" doc:"The backup's id, as the list gives it."`
	What             string `json:"what" enum:"files,database,both"`
	ConfirmDomain    string `json:"confirm_domain" maxLength:"253" doc:"The site's domain, typed by the person to confirm."`
	ExpectedRevision uint64 `json:"expected_revision" doc:"The revision the site had when the page loaded."`
}

type backupStorageOutput struct{ Body BackupStorage }
type backupStorageSavedOutput struct{ Body BackupStorageSaved }
type backupStorageInput struct{ Body BackupStorageBody }
type websiteBackupsInput struct {
	AccountID string `path:"account_id"`
}
type websiteBackupsOutput struct{ Body SiteBackups }
type websiteBackupRestoreInput struct {
	AccountID string `path:"account_id"`
	Body      SiteBackupRestoreBody
}
type websiteBackupStartedBody struct {
	Running sitebackups.BackupJob `json:"running"`
}
type websiteBackupStartedOutput struct{ Body websiteBackupStartedBody }

const (
	backupsNotSetUp   = "Backups are not set up on this server. The panel needs the account service and the database service for them."
	backupsNoStorage  = "Backup storage is not set up, so nothing was started. Set it up on the Backup storage page first."
	backupsBusy       = "This site already has a backup, restore or drill running. Wait for it to finish, then try again."
	backupsNoAnswer   = "The account service did not answer, so the panel cannot show the backups. Reload the page to try again."
	backupNotFound    = "That backup was not found among this site's backups. It may have been removed by the weekly clean-up. Reload the page to see the backups there are now."
	backupStorageRule = "Check the fields: the host is a DNS name or IP address, the port 1 to 65535, the user lowercase letters, digits, _ . or -, the folder an absolute path of letters, digits and . _ - /, and the host key one or more lines from ssh-keyscan for that host."
	backupStorageWait = 5 * time.Minute // the broker allows three for opening or making a repository
	backupListWait    = 2 * time.Minute
)

var backupSnapshotID = regexp.MustCompile(`^[a-f0-9]{64}$`)

// backupMutationKeys answers the fields a backup POST's body takes; ok is
// false for every other request.
func backupMutationKeys(r *http.Request) (fields []wizardField, ok bool) {
	if r.Method != http.MethodPost {
		return nil, false
	}
	if r.URL.Path == "/api/v1/websites/backup-storage" {
		return []wizardField{{name: "host"}, {name: "port", whole: true}, {name: "user"}, {name: "path"}, {name: "known_hosts"}}, true
	}
	rest, found := strings.CutPrefix(r.URL.Path, "/api/v1/websites/sites/")
	if !found {
		return nil, false
	}
	parts := strings.Split(rest, "/")
	if len(parts) < 2 || !websiteAccountID.MatchString(parts[0]) || parts[1] != "backups" {
		return nil, false
	}
	switch p := parts[2:]; {
	case len(p) == 0:
		return []wizardField{}, true
	case len(p) == 1 && p[0] == "drill":
		return []wizardField{}, true
	case len(p) == 1 && p[0] == "restore":
		return []wizardField{{name: "snapshot"}, {name: "what"}, {name: "confirm_domain"}, {name: "expected_revision", whole: true}}, true
	}
	return nil, false
}

func allowedBackupMutation(r *http.Request) bool {
	_, ok := backupMutationKeys(r)
	return ok
}

// prepareBackupJSON applies the wizard's body rules with this route's
// fields.
func prepareBackupJSON(w http.ResponseWriter, r *http.Request) bool {
	fields, _ := backupMutationKeys(r)
	return prepareStrictJSON(w, r, fields)
}

// backupWait is how long a backup POST's answer may take: saving the
// storage target waits for the broker to open or make the repository.
func backupWait(r *http.Request) time.Duration {
	if r.URL.Path == "/api/v1/websites/backup-storage" {
		return backupStorageWait
	}
	return 60 * time.Second
}

// registerSiteBackups adds the Backup storage page and a site's Backups
// section. They sit under /api/v1/websites/, so the wizard's admission
// applies: an admin session, and for a POST also Origin, CSRF and the
// strict body check.
func registerSiteBackups(a huma.API, o Options) {
	op := func(id, method, path string, status int) huma.Operation {
		return huma.Operation{OperationID: id, Method: method, Path: path, DefaultStatus: status, MaxBodyBytes: 4096, BodyReadTimeout: 5 * time.Second, SkipValidateBody: true, SkipValidateParams: true}
	}
	storage := func(ctx context.Context) (BackupStorage, error) {
		status, err := o.Backups.Status(ctx)
		if err != nil {
			return BackupStorage{}, huma.Error503ServiceUnavailable(backupsNoAnswer, errors.New("account service: "+err.Error()))
		}
		server := o.Backups.Server()
		out := BackupStorage{Ready: status.Ready, PublicKey: status.PublicKey, Configured: status.Configured, NightlyAt: server.NightlyAt, Timezone: server.Timezone, LastDrill: server.LastDrill, LastPrune: server.LastPrune}
		if t := status.Target; t != nil {
			out.Target = &BackupStorageTarget{Host: t.Host, Port: t.Port, User: t.User, Path: t.Path, HostKeys: t.HostKeys}
		}
		return out, nil
	}
	huma.Register(a, op("get-backup-storage", http.MethodGet, "/api/v1/websites/backup-storage", http.StatusOK), func(ctx context.Context, _ *struct{}) (*backupStorageOutput, error) {
		if o.Backups == nil {
			return nil, huma.Error503ServiceUnavailable(backupsNotSetUp)
		}
		out, err := storage(ctx)
		if err != nil {
			return nil, err
		}
		return &backupStorageOutput{Body: out}, nil
	})
	huma.Register(a, op("set-backup-storage", http.MethodPost, "/api/v1/websites/backup-storage", http.StatusOK), func(ctx context.Context, in *backupStorageInput) (*backupStorageSavedOutput, error) {
		if o.Backups == nil {
			return nil, huma.Error503ServiceUnavailable(backupsNotSetUp)
		}
		b := in.Body
		ctx, cancel := context.WithTimeout(ctx, backupStorageWait-30*time.Second)
		defer cancel()
		res, err := o.Backups.SetTarget(ctx, hostaccounts.BackupTargetInput{Host: strings.TrimSpace(b.Host), Port: b.Port, User: strings.TrimSpace(b.User), Path: strings.TrimSpace(b.Path), KnownHosts: b.KnownHosts, Reason: "Backup storage set on the Backup storage page"}, siteActor(ctx))
		if err != nil {
			return nil, backupError(err, "backup", backupStorageRule)
		}
		out, err := storage(ctx)
		if err != nil {
			// The target is saved; show what the broker answered.
			out = BackupStorage{Ready: res.Status.Ready, PublicKey: res.Status.PublicKey, Configured: true}
		}
		if t := res.Status.Target; t != nil {
			out.Target = &BackupStorageTarget{Host: t.Host, Port: t.Port, User: t.User, Path: t.Path, HostKeys: t.HostKeys}
		}
		return &backupStorageSavedOutput{Body: BackupStorageSaved{BackupStorage: out, Initialized: res.Initialized, Password: res.Password}}, nil
	})
	huma.Register(a, op("get-website-backups", http.MethodGet, "/api/v1/websites/sites/{account_id}/backups", http.StatusOK), func(ctx context.Context, in *websiteBackupsInput) (*websiteBackupsOutput, error) {
		site, account, err := backupSite(ctx, o, in.AccountID)
		if err != nil {
			return nil, err
		}
		status, err := o.Backups.Status(ctx)
		if err != nil {
			return nil, huma.Error503ServiceUnavailable(backupsNoAnswer, errors.New("account service: "+err.Error()))
		}
		at, zone := o.Backups.Schedule()
		out := SiteBackups{Configured: status.Configured, Ready: status.Ready, Domain: site.Domain, Revision: account.Revision, NightlyAt: at, Timezone: zone, Site: o.Backups.Site(account.ID), Snapshots: []hostaccounts.Snapshot{}}
		if status.Configured {
			list, cancel := context.WithTimeout(ctx, backupListWait)
			defer cancel()
			items, err := o.Backups.Snapshots(list, account.ID)
			if err != nil {
				out.SnapshotsError, _, _ = sitebackups.Explain(err, "list")
			} else {
				out.Snapshots = items
			}
		}
		return &websiteBackupsOutput{Body: out}, nil
	})
	huma.Register(a, op("back-up-website", http.MethodPost, "/api/v1/websites/sites/{account_id}/backups", http.StatusAccepted), func(ctx context.Context, in *websiteBackupsInput) (*websiteBackupStartedOutput, error) {
		_, account, err := backupReadySite(ctx, o, in.AccountID)
		if err != nil {
			return nil, err
		}
		started, err := o.Backups.BackUpNow(account, siteActor(ctx))
		if err != nil {
			return nil, backupStartError(err)
		}
		return &websiteBackupStartedOutput{Body: websiteBackupStartedBody{Running: started}}, nil
	})
	huma.Register(a, op("drill-website-backup", http.MethodPost, "/api/v1/websites/sites/{account_id}/backups/drill", http.StatusAccepted), func(ctx context.Context, in *websiteBackupsInput) (*websiteBackupStartedOutput, error) {
		_, account, err := backupReadySite(ctx, o, in.AccountID)
		if err != nil {
			return nil, err
		}
		started, err := o.Backups.DrillNow(account, siteActor(ctx))
		if err != nil {
			return nil, backupStartError(err)
		}
		return &websiteBackupStartedOutput{Body: websiteBackupStartedBody{Running: started}}, nil
	})
	huma.Register(a, op("restore-website-backup", http.MethodPost, "/api/v1/websites/sites/{account_id}/backups/restore", http.StatusAccepted), func(ctx context.Context, in *websiteBackupRestoreInput) (*websiteBackupStartedOutput, error) {
		site, account, err := backupReadySite(ctx, o, in.AccountID)
		if err != nil {
			return nil, err
		}
		b := in.Body
		switch {
		case b.What != "files" && b.What != "database" && b.What != "both":
			return nil, huma.Error422UnprocessableEntity("what must be files, database or both.")
		case !backupSnapshotID.MatchString(b.Snapshot):
			return nil, huma.Error422UnprocessableEntity("snapshot must be a backup's id as the list gives it: 64 lowercase hexadecimal characters.")
		case b.ConfirmDomain != site.Domain:
			return nil, huma.Error422UnprocessableEntity("Type the site's domain, " + site.Domain + ", exactly to confirm the restore. Nothing changed.")
		case b.ExpectedRevision == 0:
			return nil, huma.Error422UnprocessableEntity(websiteNoRevision)
		case b.ExpectedRevision != account.Revision:
			return nil, huma.Error409Conflict(websiteStale)
		}
		list, cancel := context.WithTimeout(ctx, backupListWait)
		defer cancel()
		items, err := o.Backups.Snapshots(list, account.ID)
		if err != nil {
			return nil, backupError(err, "restore", websiteRefused)
		}
		var snap *hostaccounts.Snapshot
		for i := range items {
			if items[i].ID == b.Snapshot {
				snap = &items[i]
			}
		}
		if snap == nil {
			return nil, huma.Error404NotFound(backupNotFound)
		}
		started, err := o.Backups.Restore(ctx, account, *snap, b.What, siteActor(ctx))
		if err != nil {
			return nil, backupStartError(err)
		}
		return &websiteBackupStartedOutput{Body: websiteBackupStartedBody{Running: started}}, nil
	})
}

// backupSite is the site in the address with its account: 404 for one that
// is not a listed website, 409 for a partly deleted one.
func backupSite(ctx context.Context, o Options, id string) (Website, hostaccounts.Account, error) {
	if o.Backups == nil {
		return Website{}, hostaccounts.Account{}, huma.Error503ServiceUnavailable(backupsNotSetUp)
	}
	site, account, err := findWebsite(ctx, o, id)
	if err != nil {
		return Website{}, hostaccounts.Account{}, err
	}
	if site.State == partlyDeleted {
		return Website{}, hostaccounts.Account{}, huma.Error409Conflict(websitePartly)
	}
	return site, account, nil
}

// backupReadySite is backupSite for a job: the account must be active or
// suspended and the storage set up.
func backupReadySite(ctx context.Context, o Options, id string) (Website, hostaccounts.Account, error) {
	site, account, err := backupSite(ctx, o, id)
	if err != nil {
		return Website{}, hostaccounts.Account{}, err
	}
	if account.State == "recovery_required" {
		return Website{}, hostaccounts.Account{}, huma.Error503ServiceUnavailable(websiteRecovery)
	}
	status, err := o.Backups.Status(ctx)
	if err != nil {
		return Website{}, hostaccounts.Account{}, huma.Error503ServiceUnavailable(backupsNoAnswer, errors.New("account service: "+err.Error()))
	}
	if !status.Configured {
		return Website{}, hostaccounts.Account{}, huma.Error409Conflict(backupsNoStorage)
	}
	return site, account, nil
}

// backupError explains a broker answer: the message says what happened,
// why and what next; the step and the broker's words ride along for
// "Technical details".
func backupError(err error, kind, invalid string) error {
	if errors.Is(err, hostaccounts.ErrInvalid) {
		return huma.Error422UnprocessableEntity(invalid, errors.New("account service: "+err.Error()))
	}
	message, step, detail := sitebackups.Explain(err, kind)
	var technical []error
	if step != "" {
		technical = append(technical, errors.New("step: "+step))
	}
	if detail != "" {
		technical = append(technical, errors.New(detail))
	}
	switch {
	case errors.Is(err, hostaccounts.ErrBackupFailed):
		return huma.Error422UnprocessableEntity(message, technical...)
	case errors.Is(err, hostaccounts.ErrConflict):
		return huma.Error409Conflict(message, technical...)
	case errors.Is(err, hostaccounts.ErrNotFound):
		return huma.Error404NotFound(message, technical...)
	default:
		return huma.Error503ServiceUnavailable(message, technical...)
	}
}

func backupStartError(err error) error {
	switch {
	case errors.Is(err, sitebackups.ErrBusy):
		return huma.Error409Conflict(backupsBusy)
	case errors.Is(err, sitebackups.ErrNoDatabase):
		return huma.Error422UnprocessableEntity("That backup holds none of this site's current databases, so there is no database to restore. Restore the files only, or choose another backup.")
	default:
		message, _, detail := sitebackups.Explain(err, "restore")
		return huma.Error503ServiceUnavailable(message, errors.New(detail))
	}
}
