package hostaccounts

import (
	"context"

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
	err := c.send(ctx, c.slow, "POST", "/v1/migrations/"+id+"/plan", migrationBody[MigrationPlanInput]{in, actor}, &out, maxMigrationAnswer)
	return out, err
}

// MigrateFiles copies the source account's home into the account's.
func (c *client) MigrateFiles(ctx context.Context, id string, in MigrateFilesInput, actor string) (MigrateFilesResult, error) {
	if !idPattern.MatchString(id) || !validMigrateFiles(in, actor) {
		return MigrateFilesResult{}, ErrInvalid
	}
	var out MigrateFilesResult
	err := c.send(ctx, c.long, "POST", "/v1/accounts/"+id+"/migrate-files", migrationBody[MigrateFilesInput]{in, actor}, &out, maxResponseBytes)
	return out, err
}

// MigrateDatabase copies one source database into the one of the same name.
func (c *client) MigrateDatabase(ctx context.Context, id string, in MigrateDatabaseInput, actor string) (MigrateDatabaseResult, error) {
	if !idPattern.MatchString(id) || !validMigrateDatabase(in, actor) {
		return MigrateDatabaseResult{}, ErrInvalid
	}
	var out MigrateDatabaseResult
	err := c.send(ctx, c.long, "POST", "/v1/accounts/"+id+"/migrate-database", migrationBody[MigrateDatabaseInput]{in, actor}, &out, maxMigrationAnswer)
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

var _ MigrationService = (*client)(nil)
