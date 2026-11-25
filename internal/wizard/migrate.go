package wizard

import (
	"context"
	"errors"
	"fmt"
	"net"
	"regexp"
	"slices"
	"strings"
	"time"

	"sifruno/internal/cpsource"
	"sifruno/internal/dbhost"
	"sifruno/internal/hostaccounts"
	"sifruno/internal/migrateverify"
)

// Migration v1 as a website job (hostaccounts README, Migration): one
// account from a cPanel server, over root SSH, into an account of the same
// name. The broker does every root step; this job orders them, undoes what
// it made when a step fails, compares the copy with the old site, and holds
// the cutover gate. Mail and DNS stay where they are: cutover here means the
// site is marked ready and the panel names the DNS records to change.

// KindMigration is a website moved from another server.
const KindMigration = "migration"

// A migration's own steps; account, web and database are the wizard's.
const (
	StepSource = "source"
	StepFiles  = "files"
	StepCron   = "cron"
	StepVerify = "verify"
	StepKey    = "key"
)

var migrationStepTitles = []stepTitle{
	{StepSource, "Read the website on the old server"},
	{StepAccount, "Create the hosting account"},
	{StepWeb, "Put the site live with PHP"},
	{StepFiles, "Copy the website's files"},
	{StepDatabase, "Copy the databases"},
	{StepCron, "Copy the scheduled jobs"},
	{StepVerify, "Compare the copy with the old site"},
	{StepKey, "Remove the migration key from the old server"},
}

// Gate states. A migration's cutover gate is closed until verify is green
// with nothing left to check, or a person accepts what is red, with a
// reason the activity log keeps; ready is the operator's cutover.
const (
	GateClosed   = "closed"
	GateOpen     = "open"
	GateAccepted = "accepted"
	GateReady    = "ready"
)

// Migration is what a migration job records beyond the steps. It never
// holds a password, a hash or a command from the old server's crontab.
type Migration struct {
	Source     string `json:"source"`
	SourceHost string `json:"source_host"`
	SourceUser string `json:"source_user"`
	Tier       string `json:"tier,omitempty"`
	// WWW says the old site answered for www.<domain> too, so the DNS
	// records name it.
	WWW       bool   `json:"www,omitempty"`
	PHPSource string `json:"php_source,omitempty"`
	WordPress bool   `json:"wordpress"`
	// Databases and DatabaseUsers are what the job made here, so a delete
	// from the site's page can remove them.
	Databases     []string `json:"databases"`
	DatabaseUsers []string `json:"database_users"`
	// Tables lists the tables whose rows differ between the old server
	// (counted after its dump) and the copy.
	Tables []TableDifference `json:"tables"`
	// Notes are what a person must check; each keeps the gate closed until
	// it is accepted.
	Notes []string `json:"notes"`
	// Converted lists the .htaccess files whose access rules were converted
	// into the site's web server config, and what each became: the plan's,
	// then the copy's.
	Converted []hostaccounts.MigrationFolder `json:"converted"`
	// Probes are the URLs of the converted rules verify checks: 403, 401,
	// and 200 for files a closed folder leaves open.
	Probes   []migrateverify.Probe `json:"probes"`
	Verify   *VerifySummary        `json:"verify,omitempty"`
	Gate     string                `json:"gate"`
	Accepted *Acceptance           `json:"accepted,omitempty"`
	// Address is this server's address for the DNS records and for a
	// person's hosts file while they preview the copy.
	Address    string      `json:"address"`
	DNS        []DNSRecord `json:"dns,omitempty"`
	KeyRemoved bool        `json:"key_removed"`
	Activity   []Activity  `json:"activity"`
}

// clone copies the record so callers never share its slices.
func (m *Migration) clone() *Migration {
	c := *m
	c.Databases = slices.Clone(m.Databases)
	c.DatabaseUsers = slices.Clone(m.DatabaseUsers)
	c.Tables = slices.Clone(m.Tables)
	c.Notes = slices.Clone(m.Notes)
	c.Probes = slices.Clone(m.Probes)
	c.Converted = slices.Clone(m.Converted)
	c.DNS = slices.Clone(m.DNS)
	c.Activity = slices.Clone(m.Activity)
	if m.Verify != nil {
		v := *m.Verify
		v.Lines = slices.Clone(m.Verify.Lines)
		c.Verify = &v
	}
	if m.Accepted != nil {
		a := *m.Accepted
		c.Accepted = &a
	}
	return &c
}

// TableDifference is one table whose rows differ.
type TableDifference struct {
	Database string `json:"database"`
	Table    string `json:"table"`
	Source   int64  `json:"source"`
	Copy     int64  `json:"copy"`
}

// VerifySummary is the last verify run, reduced for the job record.
type VerifySummary struct {
	Running        bool     `json:"running"`
	Ran            bool     `json:"ran"`
	CutoverAllowed bool     `json:"cutover_allowed"`
	Verdict        string   `json:"verdict"`
	PagesCompared  int      `json:"pages_compared"`
	PagesPass      int      `json:"pages_pass"`
	PagesWarn      int      `json:"pages_warn"`
	PagesFail      int      `json:"pages_fail"`
	ProbesPass     int      `json:"probes_pass"`
	ProbesFail     int      `json:"probes_fail"`
	Lines          []string `json:"lines"`
	FinishedAt     string   `json:"finished_at"`
}

// Acceptance is a person's decision to cut over with red lines.
type Acceptance struct {
	Actor  string `json:"actor"`
	At     string `json:"at"`
	Reason string `json:"reason"`
}

// DNSRecord is one record the operator points at this server.
type DNSRecord struct {
	Name  string `json:"name"`
	Type  string `json:"type"`
	Value string `json:"value"`
}

// Activity is one line of the migration's activity log.
type Activity struct {
	At    string `json:"at"`
	Actor string `json:"actor"`
	What  string `json:"what"`
}

const (
	migrateReason     = "Website migration"
	migrateUndoReason = "Website migration: removed after a later step failed"
	migrationLimit    = 4 * time.Hour // the copy of a large site
	verifyLimit       = 30 * time.Minute
	maxActivity       = 60
	maxVerifyLines    = 40
	maxNotes          = 30
	maxDifferences    = 50
)

// MigrationBroker is the broker's migration surface and cron, as the job
// uses them.
type MigrationBroker interface {
	GetMigration(context.Context, string) (hostaccounts.Migration, error)
	PlanMigration(context.Context, string, hostaccounts.MigrationPlanInput, string) (hostaccounts.MigrationPlan, error)
	MigrateFiles(context.Context, string, hostaccounts.MigrateFilesInput, string) (hostaccounts.MigrateFilesResult, error)
	MigrateDatabase(context.Context, string, hostaccounts.MigrateDatabaseInput, string) (hostaccounts.MigrateDatabaseResult, error)
	FinishMigration(context.Context, string, hostaccounts.MigrationFinishInput, string) (hostaccounts.MigrationFinishResult, error)
	SetCron(context.Context, string, hostaccounts.CronInput, string) (hostaccounts.CronResult, error)
}

// MigrationDatabases makes a moved database user from its password hash.
type MigrationDatabases interface {
	CreateUserWithHashStrict(ctx context.Context, owner, name, hash string) error
}

// Verifier compares the copy with the old site; migrateverify.Run is the
// real one.
type Verifier func(context.Context, migrateverify.Options) (migrateverify.Report, error)

// MigrationOptions turns migrations on.
type MigrationOptions struct {
	Broker    MigrationBroker
	Databases MigrationDatabases
	Verify    Verifier
	// Connect is HOST:PORT where this server's web server answers, for
	// verify's requests to the copy (127.0.0.1:80 on the server itself).
	Connect string
	// Address is this server's public address, for the DNS records.
	Address string
}

// EnableMigrations turns migrations on for this runner.
func (r *Runner) EnableMigrations(o MigrationOptions) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.migrations = &o
}

func (r *Runner) migrationOptions() *MigrationOptions {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.migrations
}

var sourceIDPattern = regexp.MustCompile(`^[a-f0-9]{32}$`)

// MigrationInput names the confirmed source and the account to move.
type MigrationInput struct {
	Source   string
	Username string
}

// StartMigration checks the request, records a migration job and runs it
// in the background. A refusal is a *Refusal.
func (r *Runner) StartMigration(ctx context.Context, in MigrationInput, actor string) (Job, error) {
	o := r.migrationOptions()
	if o == nil {
		return Job{}, refuse(ErrUnavailable, "Moving websites is not set up on this server.")
	}
	switch {
	case !sourceIDPattern.MatchString(in.Source):
		return Job{}, refuse(ErrInvalid, "source must be the old server's migration ID.")
	case !validUsername(in.Username):
		return Job{}, refuse(ErrInvalid, "username must be the old server's account name: 3 to 32 lowercase letters, digits or _, starting with a letter.")
	case !validText(actor, 120):
		return Job{}, refuse(ErrInvalid, "The signed-in admin could not be identified. Sign in again, then try again.")
	}
	key := "migrate:" + in.Username
	if err := r.reserve(key); err != nil {
		return Job{}, err
	}
	reserved := true
	defer func() {
		if reserved {
			r.release(key)
		}
	}()
	source, err := o.Broker.GetMigration(ctx, in.Source)
	switch {
	case errors.Is(err, hostaccounts.ErrNotFound):
		return Job{}, refuse(ErrConflict, "That connection to the old server has ended (it lasts 24 hours). Connect to the old server again.")
	case err != nil:
		return Job{}, refuse(ErrUnavailable, "The account service is not answering, so nothing was moved. Check that it is running, then try again.")
	case source.Pinned == "":
		return Job{}, refuse(ErrConflict, "Confirm the old server's fingerprint first, so Sifruno knows it talks to the right server.")
	}
	accounts, err := r.accounts.List(ctx)
	if err != nil {
		return Job{}, refuse(ErrUnavailable, "The account service is not answering, so nothing was moved. Check that it is running, then try again.")
	}
	if slices.ContainsFunc(accounts, func(a hostaccounts.Account) bool { return a.Username == in.Username }) {
		return Job{}, refuse(ErrConflict, "This server already has an account named %s. The moved site keeps its name, so remove that account first or move another site.", in.Username)
	}
	id, err := newJobID()
	if err != nil {
		return Job{}, refuse(ErrUnavailable, "The panel could not create a job ID, so nothing was moved. Try again.")
	}
	now := time.Now()
	job := newKindJob(id, KindMigration, "", actor, now)
	job.Username = in.Username
	job.Migration = &Migration{Source: in.Source, SourceHost: source.Host, SourceUser: in.Username, Gate: GateClosed, Address: o.Address,
		Databases: []string{}, DatabaseUsers: []string{}, Tables: []TableDifference{}, Notes: []string{}, Probes: []migrateverify.Probe{},
		Activity: []Activity{{At: timestamp(now), Actor: actor, What: "Started moving the account " + in.Username + " from " + source.Host + "."}}}
	if err = r.store.put(job); err != nil {
		r.store.forget(id)
		return Job{}, refuse(ErrUnavailable, "The panel could not save the job record, so nothing was moved. Check the panel's state directory, then try again.")
	}
	r.mu.Lock()
	r.running[key] = id
	r.mu.Unlock()
	reserved = false
	runCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), migrationLimit)
	j := &run{runner: r, job: job.clone(), in: Input{Kind: KindMigration}, actor: actor, migration: &migrationRun{options: o}}
	r.wg.Add(1)
	go func() {
		defer r.wg.Done()
		defer cancel()
		defer r.release(key)
		j.executeMigration(runCtx)
	}()
	return job, nil
}

// migrationRun is what a migration job holds while it runs: the plan, with
// the database users' hashes, which never reach the job record.
type migrationRun struct {
	options   *MigrationOptions
	plan      hostaccounts.MigrationPlan
	php       string
	madeDBs   []string
	madeUsers []string
	wordpress bool
	cronJobs  []hostaccounts.CronJob
	dbDiffers int
	dbTables  int
	dbRows    int64
}

func (j *run) executeMigration(ctx context.Context) {
	defer func() {
		// The hashes are credentials; drop the run's references when it ends.
		if j.migration != nil {
			j.migration.plan = hostaccounts.MigrationPlan{}
		}
		j.secrets = nil
	}()
	steps := []func(context.Context) (string, *stepError){j.migrateSource, j.migrateAccount, j.migrateWeb, j.migrateFiles, j.migrateDatabases, j.migrateCron}
	failed := false
	for i, step := range steps {
		j.begin(i)
		message, failure := step(ctx)
		if failure != nil {
			if ctx.Err() != nil {
				failure.why = "It took longer than the panel waits for a migration (" + migrationLimit.String() + "), so it stopped."
				failure.next = "Check the old server's size and this server's load, then move the website again."
			}
			j.fail(i, failure)
			failed = true
			break
		}
		if message == "" {
			continue // the step recorded its own state
		}
		j.finish(i, message)
	}
	if !failed {
		j.job.State = StateSucceeded
		scheme := "http://"
		j.job.Result = &Result{URL: scheme + j.job.Domain + "/", AccountID: j.accountID}
		if j.migration.wordpress {
			j.job.Result.AdminURL = scheme + j.job.Domain + "/wp-admin/"
		}
		if len(j.job.Migration.Databases) > 0 {
			j.job.Result.Database = j.job.Migration.Databases[0]
		}
		j.touch()
		j.verifyStep(ctx)
	}
	j.removeKey()
}

func (j *run) note(text string) {
	m := j.job.Migration
	if len(m.Notes) < maxNotes && !slices.Contains(m.Notes, text) {
		m.Notes = append(m.Notes, text)
	}
}

// migrationFailure explains a broker migration error.
func (j *run) migrationFailure(err error) *stepError {
	var failed *hostaccounts.MigrationError
	if errors.As(err, &failed) {
		why, next := migrationStepText(failed.Step)
		return &stepError{why: why + " " + failed.Detail, next: next, technical: j.technical(err)}
	}
	return j.brokerFailure(err)
}

func migrationStepText(step string) (why, next string) {
	switch step {
	case "connect":
		return "Sifruno could not sign in to the old server with the migration key.", "Check that the key line is in /root/.ssh/authorized_keys on the old server and that its SSH port is open to this server, then move the website again."
	case "host_key":
		return "The old server's host key is not the one you confirmed.", "Connect to the old server again and compare the fingerprint."
	case "source":
		return "The old server's answer stopped the move.", "Fix what the message names on the old server, then move the website again."
	case "tier":
		return "The site's .htaccess rules need a web server this server does not run yet.", "Leave the website on the old server for now."
	case "space":
		return "This server does not have room for the copy.", "Free space on this server, then move the website again."
	case "fetch", "copy":
		return "The website's files could not be copied.", "Open Technical details to see why, fix the cause, then move the website again."
	case "database", "dump", "import", "compare":
		return "A database could not be copied.", "Open Technical details to see why, fix the cause, then move the website again."
	}
	return "A migration step failed.", "Open Technical details to see why, then move the website again."
}

// tierCauses says in plain words why a site is not Native.
var tierCauses = map[string]string{
	"access_control":       "password-protected folders or deny rules this server cannot convert yet",
	"unknown":              "directives this panel does not know",
	"malformed":            "lines it cannot read",
	"unreadable_file":      "files it could not read",
	"oversize_file":        "a file over 1 MiB",
	"irregular_file":       "an .htaccess that is not a plain file",
	"symlink_not_followed": "folders reached through links",
	"scan_truncated":       "more files than the check reads",
	"unreadable_dir":       "folders it could not read",
	"home_htaccess":        "an .htaccess in the home folder above public_html",
}

func (j *run) migrateSource(ctx context.Context) (string, *stepError) {
	m, mr := j.job.Migration, j.migration
	plan, err := mr.options.Broker.PlanMigration(ctx, m.Source, hostaccounts.MigrationPlanInput{Username: m.SourceUser, Reason: migrateReason}, j.actor)
	if err != nil {
		return "", j.migrationFailure(err)
	}
	mr.plan = plan
	for _, u := range plan.Users {
		if u.Hash != "" {
			j.secrets = append(j.secrets, u.Hash)
		}
	}
	j.job.Domain, j.in.Domain = plan.Domain, plan.Domain
	m.Tier, m.PHPSource, m.WWW = plan.Tier, plan.PHPSource, plan.WWW && !strings.HasPrefix(plan.Domain, "www.")
	j.touch()
	if !validDomain(plan.Domain) || plan.Username != m.SourceUser {
		return "", &stepError{why: "The old server named a domain or account this server cannot take.", next: "Check the account on the old server.", technical: "domain " + clip(plan.Domain)}
	}
	if owner, taken := j.domainOwner(ctx); taken {
		return "", &stepError{why: plan.Domain + " already belongs to the hosting account " + owner + " on this server.", next: "Remove that website first, or move another one."}
	}
	if plan.Tier != "native" {
		causes := make([]string, 0, len(plan.TierCauses))
		for _, c := range plan.TierCauses {
			if text, ok := tierCauses[c]; ok {
				causes = append(causes, text)
			}
		}
		if len(causes) == 0 {
			causes = append(causes, "rules OpenLiteSpeed does not act on")
		}
		return "", &stepError{
			why:       "The site's .htaccess files have " + strings.Join(causes, ", ") + ". This server's web server, OpenLiteSpeed, ignores those rules, so a protected folder would open to everyone. Nothing was created here.",
			next:      "Leave this website on the old server for now: it needs the Apache tier, which this server does not offer yet. Websites whose .htaccess has only rewrite rules can move now.",
			technical: clip("tier " + plan.Tier + "; causes " + strings.Join(plan.TierCauses, ",") + "; " + strings.Join(plan.TierRefusals, " | "))}
	}
	for _, u := range plan.Users {
		if u.Hash == "" {
			return "", &stepError{why: u.Problem, next: "Give the database user " + u.Name + " a new password on the old server with the mysql_native_password method (cPanel's MySQL Databases page does), update the site's configuration there, then move the website again.", technical: "user " + u.Name + " has no mysql_native_password hash"}
		}
	}
	php, exact := cpsource.PHPVersion(plan.PHPSource)
	mr.php = php
	if !exact {
		j.note(fmt.Sprintf("The old server runs PHP %q; this server offers 8.1 to 8.4, so the copy runs PHP %s. Check the preview for errors.", clip(plan.PHPSource), php))
	}
	if len(plan.Aliases) > 0 {
		j.note("The site's other domains (" + strings.Join(plan.Aliases, ", ") + ") were not added; this version moves the main domain. Add them on the website's Domains tab.")
	}
	for _, s := range plan.GrantsSkipped {
		j.note("A database grant was not copied: " + s + ".")
	}
	for _, s := range plan.CronSkipped {
		j.note("A scheduled-job line was not copied: " + s + ".")
	}
	for _, line := range plan.Cron {
		job := hostaccounts.CronJob{Schedule: line.Schedule, Command: line.Command}
		if hostaccounts.CronJobProblem(job) != "" {
			j.note("A scheduled job was not copied because this server's job rules refuse it (for example a % in the command). Add it again on the website's Jobs tab.")
			continue
		}
		if strings.Contains(line.Command, "/opt/cpanel/") || strings.Contains(line.Command, "/usr/local/cpanel/") || strings.Contains(line.Command, "/usr/local/bin/php") {
			j.note("A scheduled job calls a program path from cPanel (such as /usr/local/bin/php or /opt/cpanel). It was copied as it is; change the path on the website's Jobs tab.")
		}
		mr.cronJobs = append(mr.cronJobs, job)
	}
	m.Probes = probesOf(plan.Probes)
	m.Converted = slices.Clone(plan.Converted)
	converted := ""
	if len(plan.Converted) > 0 {
		converted = fmt.Sprintf(" %d .htaccess file(s) with access rules are converted into the web server's config: %s.", len(plan.Converted), folderPaths(plan.Converted))
	}
	return fmt.Sprintf("Found %s: %d database(s), %d scheduled job(s), PHP %s (%s), .htaccess rules OpenLiteSpeed acts on.%s", plan.Domain, len(plan.Databases), len(plan.Cron), php, plan.PHPSource, converted), nil
}

func probesOf(in []hostaccounts.MigrationProbe) []migrateverify.Probe {
	out := []migrateverify.Probe{}
	for _, p := range in {
		if len(out) < migrateverify.MaxProbes {
			out = append(out, migrateverify.Probe{Path: p.Path, Kind: migrateverify.ProbeKind(p.Kind)})
		}
	}
	return out
}

// folderPaths names converted folders and what they became, for a step
// message.
func folderPaths(folders []hostaccounts.MigrationFolder) string {
	parts := make([]string, 0, len(folders))
	for _, f := range folders {
		parts = append(parts, f.Path+" ("+f.Rule+")")
	}
	return clip(strings.Join(parts, "; "))
}

func (j *run) migrateAccount(ctx context.Context) (string, *stepError) {
	a, err := j.runner.accounts.Create(ctx, hostaccounts.CreateInput{Username: j.job.Username, Domain: j.job.Domain, Reason: migrateReason}, j.actor)
	if err != nil {
		if errors.Is(err, hostaccounts.ErrConflict) {
			return "", &stepError{why: "This server already has an account named " + j.job.Username + " or one for " + j.job.Domain + ".", next: "Remove it first, or move another website.", technical: j.technical(err)}
		}
		if errors.Is(err, hostaccounts.ErrUnavailable) {
			return "", &stepError{why: "The account service did not answer, so the panel cannot tell whether the account was made.", next: checkAccounts(j.job.Domain), technical: j.technical(err)}
		}
		return "", j.brokerFailure(err)
	}
	j.accountID, j.revision = a.ID, a.Revision
	return "Created the hosting account " + a.Username + ", the same name as on the old server.", nil
}

// migrationQuota is the old account's quota, or room for twice what it
// uses, within the broker's 64 MiB to 1 TiB.
func migrationQuota(used, limit int64) int {
	q := max(int64(quotaMiB), used*2+256)
	if limit > 0 {
		q = max(limit, used+256)
	}
	return int(min(max(q, 64), 1<<20))
}

func (j *run) migrateWeb(ctx context.Context) (string, *stepError) {
	plan := j.migration.plan
	quota := migrationQuota(plan.DiskUsedMiB, plan.DiskLimitMiB)
	res, err := j.runner.accounts.SetWeb(ctx, j.accountID, hostaccounts.WebInput{PHPVersion: j.migration.php, QuotaMiB: quota, ExpectedRevision: j.revision, Reason: migrateReason}, j.actor)
	if err != nil {
		if errors.Is(err, hostaccounts.ErrWebRejected) {
			return "", &stepError{why: "The web server's configuration test failed with the new site, so the server kept its old configuration.", next: "Ask whoever runs this server to check the web server, then move the website again.", technical: j.technical(err)}
		}
		return "", j.brokerFailure(err)
	}
	j.revision = res.Account.Revision
	return fmt.Sprintf("The site is on this server with PHP %s and %d MiB of disk. Visitors still reach the old server: DNS has not changed.", j.migration.php, quota), nil
}

func (j *run) migrateFiles(ctx context.Context) (string, *stepError) {
	res, err := j.migration.options.Broker.MigrateFiles(ctx, j.accountID, hostaccounts.MigrateFilesInput{Migration: j.job.Migration.Source, ExpectedRevision: j.revision, Reason: migrateReason}, j.actor)
	if err != nil {
		return "", j.migrationFailure(err)
	}
	// Protected folders going live raised the account's revision. Zero is
	// no revision: a broker from before it answered one.
	if res.Revision != 0 {
		j.revision = res.Revision
	}
	j.migration.wordpress = res.WordPress
	j.job.Migration.WordPress = res.WordPress
	protected := ""
	// The copy's conversion is the one in force; it replaces the plan's.
	if res.Probes != nil {
		j.job.Migration.Probes = probesOf(res.Probes)
		j.job.Migration.Converted = slices.Clone(res.Folders)
	}
	if len(res.Folders) > 0 {
		protected = " Protected folders went into the web server's config before the files did: " + folderPaths(res.Folders) + "."
	}
	if res.WordPress {
		return "Copied the home folder with public_html. It is a WordPress site." + protected, nil
	}
	return "Copied the home folder with public_html. Mail, logs and the old server's settings stayed there." + protected, nil
}

func (j *run) migrateDatabases(ctx context.Context) (string, *stepError) {
	plan, m := j.migration.plan, j.job.Migration
	if len(plan.Databases) == 0 {
		j.skip(j.index(StepDatabase), "The account has no databases.")
		return "", nil
	}
	dbs := j.runner.databases
	owner := j.job.Username
	for _, d := range plan.Databases {
		err := dbs.CreateDatabaseStrict(ctx, owner, d.Name)
		if err == nil || errors.Is(err, dbhost.ErrNotRegistered) {
			j.migration.madeDBs = append(j.migration.madeDBs, d.Name)
			m.Databases = append(m.Databases, d.Name)
		}
		if err != nil {
			return "", j.createFailure(d.Name, err)
		}
	}
	for _, u := range plan.Users {
		err := j.migration.options.Databases.CreateUserWithHashStrict(ctx, owner, u.Name, u.Hash)
		if err == nil || errors.Is(err, dbhost.ErrNotRegistered) {
			j.migration.madeUsers = append(j.migration.madeUsers, u.Name)
			m.DatabaseUsers = append(m.DatabaseUsers, u.Name)
		}
		if err != nil {
			return "", j.createFailure(u.Name, err)
		}
		for _, g := range u.Grants {
			if err = dbs.SetPrivileges(ctx, owner, u.Name, g.Database, g.Privileges); err != nil {
				return "", j.databaseFailure(err)
			}
		}
	}
	j.touch()
	for _, d := range plan.Databases {
		res, err := j.migration.options.Broker.MigrateDatabase(ctx, j.accountID, hostaccounts.MigrateDatabaseInput{Migration: m.Source, Database: d.Name, ExpectedRevision: j.revision, Reason: migrateReason}, j.actor)
		if err != nil {
			return "", j.migrationFailure(err)
		}
		for _, t := range res.Tables {
			j.migration.dbTables++
			if t.Copy > 0 {
				j.migration.dbRows += t.Copy
			}
			if t.Source != t.Copy {
				j.migration.dbDiffers++
				if len(m.Tables) < maxDifferences {
					m.Tables = append(m.Tables, TableDifference{Database: d.Name, Table: clip(t.Table), Source: t.Source, Copy: t.Copy})
				}
			}
		}
	}
	if j.migration.dbDiffers > 0 {
		j.note(fmt.Sprintf("%d table(s) have a different number of rows on the old server than in the copy. The old site may have changed during the copy; check them.", j.migration.dbDiffers))
		return fmt.Sprintf("Copied %d database(s) with the same names and users (same passwords), %d tables; %d table(s) differ in rows.", len(plan.Databases), j.migration.dbTables, j.migration.dbDiffers), nil
	}
	return fmt.Sprintf("Copied %d database(s) with the same names and users (same passwords): %d tables, %d rows, every table's rows match.", len(plan.Databases), j.migration.dbTables, j.migration.dbRows), nil
}

func (j *run) migrateCron(ctx context.Context) (string, *stepError) {
	jobs := j.migration.cronJobs
	if len(jobs) == 0 {
		j.skip(j.index(StepCron), "No scheduled jobs to copy.")
		return "", nil
	}
	res, err := j.migration.options.Broker.SetCron(ctx, j.accountID, hostaccounts.CronInput{Jobs: jobs, ExpectedRevision: j.revision, Reason: migrateReason}, j.actor)
	if err != nil {
		return "", j.brokerFailure(err)
	}
	j.revision = res.Account.Revision
	return fmt.Sprintf("Copied %d scheduled job(s); they run as the site's user on this server's clock.", len(jobs)), nil
}

// verifyStep compares the copy with the old site. It never undoes the
// copy: a red line is for a person to fix or accept.
func (j *run) verifyStep(ctx context.Context) {
	i := j.index(StepVerify)
	j.begin(i)
	summary := j.runner.runVerify(ctx, j.job)
	j.job.Migration.Verify = &summary
	state, message := StepDone, summary.Verdict
	if !summary.Ran {
		state = StepFailed
	}
	j.job.Migration.Gate = gateFor(j.job.Migration)
	j.end(i, state, message)
}

// runVerify runs one comparison: the old site by its domain, the copy on
// this server with the same Host header (curl --resolve), the closed URLs
// the .htaccess scan found, and WordPress's login and admin pages.
func (r *Runner) runVerify(ctx context.Context, job Job) VerifySummary {
	o := r.migrationOptions()
	ctx, cancel := context.WithTimeout(ctx, verifyLimit)
	defer cancel()
	opts := migrateverify.Options{Old: "http://" + job.Domain, New: "http://" + job.Domain, NewConnect: o.Connect, Probes: job.Migration.Probes}
	if job.Migration.WordPress {
		opts.Paths = []string{"/wp-login.php", "/wp-admin/"}
	}
	report, err := o.Verify(ctx, opts)
	now := timestamp(time.Now())
	if err != nil {
		return VerifySummary{Verdict: "The comparison could not run: " + scrub(err.Error()), Lines: []string{}, FinishedAt: now}
	}
	s := VerifySummary{Ran: true, CutoverAllowed: report.CutoverAllowed, Verdict: report.Verdict, PagesCompared: report.Counts.PagesCompared, PagesPass: report.Counts.PagesPass,
		PagesWarn: report.Counts.PagesWarn, PagesFail: report.Counts.PagesFail, ProbesPass: report.Counts.ProbesPass, ProbesFail: report.Counts.ProbesFail, Lines: []string{}, FinishedAt: now}
	for _, line := range strings.Split(report.Text(), "\n") {
		if strings.HasPrefix(line, "CRITICAL ") || strings.HasPrefix(line, "FAIL ") || strings.HasPrefix(line, "WARN ") || strings.HasPrefix(line, "PASS closed URL ") {
			if len(s.Lines) < maxVerifyLines {
				s.Lines = append(s.Lines, scrub(line))
			}
		}
	}
	return s
}

// gateFor opens the gate only when verify ran green and nothing is left
// to check; an acceptance or a cutover stays as it is.
func gateFor(m *Migration) string {
	if m.Gate == GateAccepted || m.Gate == GateReady {
		return m.Gate
	}
	if m.Verify != nil && m.Verify.Ran && m.Verify.CutoverAllowed && len(m.Notes) == 0 && len(m.Tables) == 0 {
		return GateOpen
	}
	return GateClosed
}

// removeKey ends the migration at the broker: the key leaves the old
// server and this one, after a success or a failure alike.
func (j *run) removeKey() {
	i := j.index(StepKey)
	j.begin(i)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	m := j.job.Migration
	// Only a removal the old server proved is reported as one; anything
	// else names the line to remove and the server.
	manual := "Remove the line ending in sifruno-migration-" + m.Source + " from /root/.ssh/authorized_keys on " + m.SourceHost + "."
	res, err := j.migration.options.Broker.FinishMigration(ctx, m.Source, hostaccounts.MigrationFinishInput{Reason: migrateReason}, j.actor)
	var message string
	switch {
	case errors.Is(err, hostaccounts.ErrNotFound):
		message = "The account service no longer knows this migration, so the panel cannot tell whether the old server still has its key line. " + manual
		j.end(i, StepFailed, message)
	case err != nil:
		message = "The account service did not answer, so the key was not removed. It ends the migration 24 hours after you connected and removes the line then, or lists it for you to remove. " + manual
		j.end(i, StepFailed, message+" "+j.technical(err))
	case res.RemovedFromSource:
		m.KeyRemoved = true
		message = "The old server no longer accepts the migration key, and this server deleted it."
		j.end(i, StepDone, message)
	default:
		message = "This server deleted the migration key, but the old server was not shown to refuse it. " + clip(res.Detail)
		if !strings.Contains(res.Detail, "sifruno-migration-"+m.Source) {
			message += " " + manual
		}
		j.end(i, StepFailed, message)
	}
	j.activity(j.actor, message)
}

func (j *run) activity(actor, what string) {
	addActivity(j.job.Migration, actor, what)
	j.touch()
}

func addActivity(m *Migration, actor, what string) {
	if len(m.Activity) >= maxActivity {
		m.Activity = append(m.Activity[:1], m.Activity[2:]...)
	}
	m.Activity = append(m.Activity, Activity{At: timestamp(time.Now()), Actor: actor, What: clip(what)})
}

// undoMigration drops the databases and users the job made, newest first;
// the hosting account goes in undo.
func (j *run) undoMigration(ctx context.Context) (left, notes []string) {
	mr := j.migration
	owner := j.job.Username
	for k := len(mr.madeUsers) - 1; k >= 0; k-- {
		if err := j.runner.databases.DropUser(ctx, owner, mr.madeUsers[k]); err != nil {
			left = append(left, "the database user "+mr.madeUsers[k])
			notes = append(notes, "undo database user: "+j.technical(err))
		}
	}
	for k := len(mr.madeDBs) - 1; k >= 0; k-- {
		if err := j.runner.databases.DropDatabase(ctx, owner, mr.madeDBs[k]); err != nil {
			left = append(left, "the database "+mr.madeDBs[k])
			notes = append(notes, "undo database: "+j.technical(err))
		}
	}
	if i := j.index(StepDatabase); i >= 0 && j.job.Steps[i].State == StepDone {
		j.job.Steps[i].State, j.job.Steps[i].Message = StepUndone, "Removed after a later step failed."
		if len(left) > 0 {
			j.job.Steps[i].State, j.job.Steps[i].Message = StepDone, "Could not be removed after a later step failed."
		}
	}
	for _, name := range []string{StepFiles, StepCron} {
		if i := j.index(name); i >= 0 && j.job.Steps[i].State == StepDone {
			j.job.Steps[i].State, j.job.Steps[i].Message = StepUndone, "Removed with the hosting account after a later step failed."
		}
	}
	return left, notes
}

// VerifyMigration runs the comparison again, in the background.
func (r *Runner) VerifyMigration(ctx context.Context, id, actor string) (Job, error) {
	job, err := r.migrationJob(id, actor)
	if err != nil {
		return Job{}, err
	}
	m := job.Migration
	if m.Verify != nil && m.Verify.Running {
		return Job{}, refuse(ErrConflict, "The comparison is running already. Wait for it to finish.")
	}
	if m.Gate == GateReady {
		return Job{}, refuse(ErrConflict, "This website is marked ready; DNS may point here already, so the old site cannot be compared any more.")
	}
	m.Verify = &VerifySummary{Running: true, Lines: []string{}}
	addActivity(m, actor, "Asked to compare the copy with the old site again.")
	r.save(job)
	r.wg.Add(1)
	go func() {
		defer r.wg.Done()
		summary := r.runVerify(context.WithoutCancel(ctx), job)
		latest, ok := r.store.Get(id)
		if !ok || latest.Migration == nil {
			return
		}
		latest.Migration.Verify = &summary
		latest.Migration.Gate = gateFor(latest.Migration)
		addActivity(latest.Migration, actor, "The comparison finished: "+summary.Verdict)
		latest.UpdatedAt = timestamp(time.Now())
		r.save(latest)
	}()
	return job, nil
}

// AcceptMigration records that a person accepts the red lines and opens
// the gate, with the reason in the activity log.
func (r *Runner) AcceptMigration(ctx context.Context, id, reason, actor string) (Job, error) {
	job, err := r.migrationJob(id, actor)
	if err != nil {
		return Job{}, err
	}
	m := job.Migration
	reason = strings.TrimSpace(reason)
	switch {
	case !validText(reason, 500):
		return Job{}, refuse(ErrInvalid, "Write why you accept the red lines, in 1 to 500 characters.")
	case m.Verify == nil || m.Verify.Running:
		return Job{}, refuse(ErrConflict, "Wait for the comparison to finish first.")
	case !m.Verify.Ran:
		return Job{}, refuse(ErrConflict, "The comparison did not run, so there is nothing to accept yet. Compare again.")
	case m.Gate != GateClosed:
		return Job{}, refuse(ErrConflict, "Nothing is waiting for acceptance: the gate is %s.", m.Gate)
	}
	now := timestamp(time.Now())
	m.Accepted = &Acceptance{Actor: actor, At: now, Reason: clip(reason)}
	m.Gate = GateAccepted
	addActivity(m, actor, "Accepted the red lines and opened the cutover gate: "+reason)
	job.UpdatedAt = now
	r.save(job)
	return job, nil
}

// ReadyMigration is v1's cutover: the site is marked ready and the job
// names the DNS records to point here. Nothing changes in DNS or mail.
func (r *Runner) ReadyMigration(ctx context.Context, id, actor string) (Job, error) {
	job, err := r.migrationJob(id, actor)
	if err != nil {
		return Job{}, err
	}
	m := job.Migration
	if m.Gate != GateOpen && m.Gate != GateAccepted {
		return Job{}, refuse(ErrConflict, "The cutover gate is %s. Fix what the comparison found and compare again, or accept the red lines with a reason.", m.Gate)
	}
	if ip := net.ParseIP(m.Address); ip == nil || ip.IsLoopback() || ip.IsUnspecified() {
		return Job{}, refuse(ErrUnavailable, "This server's public address is not set, so the panel cannot name the DNS records. Start the panel with --dns-ip set to it, then mark the website ready again.")
	}
	m.Gate = GateReady
	// www.<domain> only when the old site answered for it, and never
	// www.www.<domain>.
	m.DNS = []DNSRecord{{Name: job.Domain, Type: dnsType(m.Address), Value: m.Address}}
	names := job.Domain
	if m.WWW && !strings.HasPrefix(job.Domain, "www.") {
		m.DNS = append(m.DNS, DNSRecord{Name: "www." + job.Domain, Type: dnsType(m.Address), Value: m.Address})
		names += " and www." + job.Domain
	}
	addActivity(m, actor, "Marked the website ready for cutover. Point "+names+" at "+m.Address+"; mail records stay as they are.")
	job.UpdatedAt = timestamp(time.Now())
	r.save(job)
	return job, nil
}

func dnsType(address string) string {
	if strings.Contains(address, ":") {
		return "AAAA"
	}
	return "A"
}

func (r *Runner) migrationJob(id, actor string) (Job, error) {
	if r.migrationOptions() == nil {
		return Job{}, refuse(ErrUnavailable, "Moving websites is not set up on this server.")
	}
	if !ValidID(id) || !validText(actor, 120) {
		return Job{}, refuse(ErrInvalid, "That migration was not found.")
	}
	job, ok := r.store.Get(id)
	if !ok || job.Kind != KindMigration || job.Migration == nil {
		return Job{}, refuse(ErrNotFound, "That migration was not found. The panel keeps the newest 50 jobs.")
	}
	if job.State != StateSucceeded || job.RemovedAt != "" {
		return Job{}, refuse(ErrConflict, "This migration did not finish its copy, or its website was removed.")
	}
	return job, nil
}
