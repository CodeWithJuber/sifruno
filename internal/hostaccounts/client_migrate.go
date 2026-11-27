package hostaccounts

import (
	"bytes"
	"context"
	"encoding/json"
	"io"

	"sifruno/internal/cpsource"
)

// maxMigrationAnswer bounds a source's account list: up to 5000 accounts.
const maxMigrationAnswer = 4 << 20

type migrationBody[T any] struct {
	Input T      `json:"input"`
	Actor string `json:"actor"`
}

// OpenMigration makes a migration's key and reads the source's host keys.
func (c *client) OpenMigration(ctx context.Context, in MigrationOpenInput, actor string) (Migration, error) {
	if !validMigrationOpen(in, actor) {
		return Migration{}, ErrInvalid
	}
	var out Migration
	err := c.send(ctx, c.http, "POST", "/v1/migrations", migrationBody[MigrationOpenInput]{in, actor}, &out, maxResponseBytes)
	return out, err
}

// OpenArchiveMigration streams an uploaded cPanel backup file of exactly
// in.Size bytes to the broker, which keeps and reads it: one framing line
// with the size and reason, then the bytes.
func (c *client) OpenArchiveMigration(ctx context.Context, in MigrationArchiveInput, body io.Reader, actor string) (Migration, error) {
	if body == nil || !validArchiveOpen(in, actor) {
		return Migration{}, ErrInvalid
	}
	head, err := json.Marshal(migrationBody[MigrationArchiveInput]{in, actor})
	if err != nil || len(head)+1 > MaxRequestBytes {
		return Migration{}, ErrInvalid
	}
	head = append(head, '\n')
	stream := io.MultiReader(bytes.NewReader(head), &exactReader{r: body, left: in.Size})
	var out Migration
	err = c.exchangeStream(ctx, c.long, "/v1/migrations/archive", stream, int64(len(head))+in.Size, &out, maxMigrationAnswer)
	return out, err
}

// GetMigration reads one migration.
func (c *client) GetMigration(ctx context.Context, id string) (Migration, error) {
	if !idPattern.MatchString(id) {
		return Migration{}, ErrInvalid
	}
	var out Migration
	err := c.send(ctx, c.http, "GET", "/v1/migrations/"+id, nil, &out, maxResponseBytes)
	return out, err
}

// PinMigrationHostKey confirms the source's host key by its fingerprint.
func (c *client) PinMigrationHostKey(ctx context.Context, id string, in MigrationPinInput, actor string) (Migration, error) {
	if !idPattern.MatchString(id) || !validMigrationPin(in, actor) {
		return Migration{}, ErrInvalid
	}
	var out Migration
	err := c.send(ctx, c.http, "POST", "/v1/migrations/"+id+"/host-key", migrationBody[MigrationPinInput]{in, actor}, &out, maxResponseBytes)
	return out, err
}

// MigrationSites lists another Linux server's websites, each with what
// moves and what does not.
func (c *client) MigrationSites(ctx context.Context, id string) ([]MigrationSite, error) {
	if !idPattern.MatchString(id) {
		return nil, ErrInvalid
	}
	var out struct {
		Items []MigrationSite `json:"items"`
	}
	if err := c.send(ctx, c.slow, "GET", "/v1/migrations/"+id+"/sites", nil, &out, maxMigrationAnswer); err != nil {
		return nil, err
	}
	if out.Items == nil {
		out.Items = []MigrationSite{}
	}
	return out.Items, nil
}

// MigrationAccounts lists the source's cPanel accounts.
func (c *client) MigrationAccounts(ctx context.Context, id string) ([]cpsource.Account, error) {
	if !idPattern.MatchString(id) {
		return nil, ErrInvalid
	}
	var out struct {
		Items []cpsource.Account `json:"items"`
	}
	if err := c.send(ctx, c.slow, "GET", "/v1/migrations/"+id+"/accounts", nil, &out, maxMigrationAnswer); err != nil {
		return nil, err
	}
	if out.Items == nil {
		out.Items = []cpsource.Account{}
	}
	return out.Items, nil
}

// PlanMigration reads what the source holds for one account.
func (c *client) PlanMigration(ctx context.Context, id string, in MigrationPlanInput, actor string) (MigrationPlan, error) {
	if !idPattern.MatchString(id) || !validMigrationPlan(in, actor) {
		return MigrationPlan{}, ErrInvalid
	}
	var out MigrationPlan
	err := c.exchange(ctx, c.slow, "POST", "/v1/migrations/"+id+"/plan", migrationBody[MigrationPlanInput]{in, actor}, maxCPanelRequest, &out, maxMigrationAnswer)
	return out, err
}

// MigrateFiles copies the source account's home into the account's.
func (c *client) MigrateFiles(ctx context.Context, id string, in MigrateFilesInput, actor string) (MigrateFilesResult, error) {
	if !idPattern.MatchString(id) || !validMigrateFiles(in, actor) {
		return MigrateFilesResult{}, ErrInvalid
	}
	var out MigrateFilesResult
	err := c.exchange(ctx, c.long, "POST", "/v1/accounts/"+id+"/migrate-files", migrationBody[MigrateFilesInput]{in, actor}, maxCPanelRequest, &out, maxResponseBytes)
	return out, err
}

// MigrateDatabase copies one source database into the one of the same name.
func (c *client) MigrateDatabase(ctx context.Context, id string, in MigrateDatabaseInput, actor string) (MigrateDatabaseResult, error) {
	if !idPattern.MatchString(id) || !validMigrateDatabase(in, actor) {
		return MigrateDatabaseResult{}, ErrInvalid
	}
	var out MigrateDatabaseResult
	err := c.exchange(ctx, c.long, "POST", "/v1/accounts/"+id+"/migrate-database", migrationBody[MigrateDatabaseInput]{in, actor}, maxCPanelRequest, &out, maxMigrationAnswer)
	return out, err
}

// MigrateCertificate copies the old site's certificate into the account's
// live site, or answers why it was not copied.
func (c *client) MigrateCertificate(ctx context.Context, id string, in MigrateCertificateInput, actor string) (MigrateCertificateResult, error) {
	if !idPattern.MatchString(id) || !validMigrateCertificate(in, actor) {
		return MigrateCertificateResult{}, ErrInvalid
	}
	var out MigrateCertificateResult
	err := c.exchange(ctx, c.long, "POST", "/v1/accounts/"+id+"/migrate-certificate", migrationBody[MigrateCertificateInput]{in, actor}, maxCPanelRequest, &out, maxResponseBytes)
	return out, err
}

// FinishMigration removes the key from the source and from this server.
func (c *client) FinishMigration(ctx context.Context, id string, in MigrationFinishInput, actor string) (MigrationFinishResult, error) {
	if !idPattern.MatchString(id) || !validText(in.Reason, 500) || !validText(actor, 120) {
		return MigrationFinishResult{}, ErrInvalid
	}
	var out MigrationFinishResult
	err := c.send(ctx, c.slow, "POST", "/v1/migrations/"+id+"/finish", migrationBody[MigrationFinishInput]{in, actor}, &out, maxResponseBytes)
	return out, err
}

// StaleMigrationKeys lists key lines that may still be in root's
// authorized_keys on old servers.
func (c *client) StaleMigrationKeys(ctx context.Context) ([]StaleMigrationKey, error) {
	var out struct {
		Items []StaleMigrationKey `json:"items"`
	}
	if err := c.send(ctx, c.http, "GET", "/v1/migrations/stale", nil, &out, maxResponseBytes); err != nil {
		return nil, err
	}
	if out.Items == nil {
		out.Items = []StaleMigrationKey{}
	}
	return out.Items, nil
}

// ClearStaleMigrationKey records that the admin removed that line.
func (c *client) ClearStaleMigrationKey(ctx context.Context, id string, in MigrationFinishInput, actor string) error {
	if !idPattern.MatchString(id) || !validText(in.Reason, 500) || !validText(actor, 120) {
		return ErrInvalid
	}
	var out struct{}
	return c.send(ctx, c.http, "POST", "/v1/migrations/"+id+"/stale-cleared", migrationBody[MigrationFinishInput]{in, actor}, &out, maxResponseBytes)
}

var _ MigrationService = (*client)(nil)
