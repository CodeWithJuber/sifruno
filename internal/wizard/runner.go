package wizard

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"slices"
	"strings"
	"sync"
	"time"

	"sifruno/internal/acme"
	"sifruno/internal/dbhost"
	"sifruno/internal/hostaccounts"
)

// Accounts is the part of the account broker a job uses. Every call is one
// of the broker's typed operations; the panel runs nothing itself.
type Accounts interface {
	List(context.Context) ([]hostaccounts.Account, error)
	Create(context.Context, hostaccounts.CreateInput, string) (hostaccounts.Account, error)
	Delete(context.Context, string, hostaccounts.DeleteInput, string) (hostaccounts.Account, error)
	// SetState suspends a site whose delete was refused because its
	// processes kept running, before the delete is asked once more.
	SetState(context.Context, string, hostaccounts.StateInput, string) (hostaccounts.Account, error)
	SetWeb(context.Context, string, hostaccounts.WebInput, string) (hostaccounts.WebResult, error)
	InstallWordPress(context.Context, string, hostaccounts.WordPressInput, string) (hostaccounts.WordPressResult, error)
	InstallPlaceholder(context.Context, string, hostaccounts.PlaceholderInput, string) (hostaccounts.PlaceholderResult, error)
}

// Broker joins the broker client's interfaces into Accounts.
type Broker struct {
	hostaccounts.Service
	hostaccounts.WebService
	hostaccounts.WordPressService
	hostaccounts.PlaceholderService
}

// Certificates gets a certificate for the site and installs it on the
// account at its revision, answering the account's new revision and the
// certificate's expiry. acme.Manager is the real one. A failure wraps one of
// acme's error kinds; the job explains it and carries on over http. Copied
// records that a moved site's certificate, valid until notAfter, was copied
// from its old server, so the renewal loop replaces it in time.
type Certificates interface {
	Secure(ctx context.Context, accountID, domain string, revision uint64) (uint64, time.Time, error)
	Copied(accountID, domain string, notAfter time.Time)
}

// Databases is the part of dbhost a job uses. The creates are strict: a
// database or user already on the server, registered or not, is
// dbhost.ErrExists and is never adopted, so undo drops only what the job
// made. The registry views and ServerHas let a job skip a taken name before
// it creates anything.
type Databases interface {
	Probe(context.Context) (string, error)
	AllDatabases(context.Context) ([]dbhost.Database, error)
	AllUsers(context.Context) ([]dbhost.User, error)
	ServerHas(ctx context.Context, kind, name string) (bool, error)
	CreateDatabaseStrict(ctx context.Context, owner, name string) error
	CreateUserStrict(ctx context.Context, owner, name, password string) error
	SetPrivileges(ctx context.Context, owner, user, db string, privs []string) error
	DropDatabase(ctx context.Context, owner, name string) error
	DropUser(ctx context.Context, owner, name string) error
}

const (
	// One job at a time: a web change can hold the broker for minutes, and
	// a second job would wait behind it and time out.
	maxRunning     = 1
	usernameTries  = 5                // broker creates tried per job
	jobLimit       = 15 * time.Minute // all five steps together
	webWait        = 6 * time.Minute  // the least SetWeb gets: the broker's web apply alone may take 4
	sslWait        = 6 * time.Minute  // the least the certificate step gets: issuing takes at most 3, then the broker applies it as it does a web change
	refreshLimit   = 30 * time.Second // reading the account's revision after the certificate step
	installWait    = 12 * time.Minute // the least InstallWordPress gets: the broker allows the install 10
	pageWait       = 2 * time.Minute  // the least InstallPlaceholder gets: the broker allows it 1
	undoLimit      = 3 * time.Minute  // removing what a failed job created
	quotaMiB       = 1024
	brokerReason   = "WordPress wizard"
	undoReason     = "WordPress wizard: removed after a later step failed"
	phpReason      = "PHP site wizard"
	phpUndoReason  = "PHP site wizard: removed after a later step failed"
	dbSuffix       = "_wp" // both kinds of site: site delete (remove.go) finds the database and its user by this name
	dbPasswordLen  = 24
	technicalLimit = 512
)

// Runner starts jobs and runs them in the background.
type Runner struct {
	accounts     Accounts
	databases    Databases
	certificates Certificates // nil: certificates are not set up, and sites use http
	store        *Store

	mu       sync.Mutex
	running  map[string]string // domain -> job ID
	wg       sync.WaitGroup
	removing sync.Mutex // one site delete at a time

	digits func() string // two digits for a username retry
	limit  time.Duration
	// waits is the least time a slow broker step gets, by step name, even
	// past limit: giving up while the broker is still changing the account
	// would fail a step that may yet succeed and leave undo racing it.
	waits map[string]time.Duration
	// migrations is nil until EnableMigrations (migrate.go).
	migrations *MigrationOptions
}

// New returns a runner over the broker, the database service, a store and
// the certificate service. certificates may be nil: the "ssl" step is then
// skipped and sites use http.
func New(accounts Accounts, databases Databases, store *Store, certificates Certificates) *Runner {
	return &Runner{accounts: accounts, databases: databases, certificates: certificates, store: store, running: map[string]string{}, digits: randomDigits, limit: jobLimit, waits: map[string]time.Duration{StepWeb: webWait, StepSSL: sslWait, StepWordPress: installWait, StepPlaceholder: pageWait}}
}

// stepContext is the job's context with its deadline moved, if need be, to
// at least wait from now.
func stepContext(ctx context.Context, wait time.Duration) (context.Context, context.CancelFunc) {
	least := time.Now().Add(wait)
	if d, ok := ctx.Deadline(); !ok || wait <= 0 || !d.Before(least) {
		return context.WithCancel(ctx)
	}
	return context.WithDeadline(context.WithoutCancel(ctx), least)
}

// Get returns one job.
func (r *Runner) Get(id string) (Job, bool) { return r.store.Get(id) }

// List returns the newest jobs, newest first, at most 20.
func (r *Runner) List() []Job { return r.store.List(maxListed) }

// Succeeded returns every kept job that made a site, newest first: all the
// store keeps (up to maxSucceeded), not only the newest jobs that List
// answers. A job whose site was deleted since is left out.
func (r *Runner) Succeeded() []Job { return r.store.sites() }

// Wait blocks until every started job has finished.
func (r *Runner) Wait() { r.wg.Wait() }

// Start checks the request and the server, records a new job and runs it in
// the background, detached from ctx. A refusal is a *Refusal.
func (r *Runner) Start(ctx context.Context, in Input, actor string) (Job, error) {
	in, err := Validate(in)
	if err != nil {
		return Job{}, err
	}
	if !validText(actor, 120) {
		return Job{}, refuse(ErrInvalid, "The signed-in admin could not be identified. Sign in again, then try again.")
	}
	if err = r.reserve(in.Domain); err != nil {
		return Job{}, err
	}
	reserved := true
	defer func() {
		if reserved {
			r.release(in.Domain)
		}
	}()
	accounts, err := r.accounts.List(ctx)
	if err != nil {
		return Job{}, refuse(ErrUnavailable, "The account service is not answering, so no website was started. Check that it is running, then try again.")
	}
	for _, a := range accounts {
		if a.Domain == in.Domain {
			return Job{}, refuse(ErrConflict, "%s already belongs to the hosting account %s. Use another domain, or remove that account first.", in.Domain, a.Username)
		}
		if a.SiteDomains != nil && slices.Contains(a.SiteDomains.Aliases, in.Domain) {
			return Job{}, refuse(ErrConflict, "%s is already a domain of the website %s. Use another domain, or remove it from that website first.", in.Domain, a.Domain)
		}
	}
	if in.wantsDatabase() {
		if _, err = r.databases.Probe(ctx); err != nil {
			return Job{}, refuse(ErrUnavailable, "The database server is not answering, so no website was started. Check that it is running, then try again.")
		}
	}
	id, err := newJobID()
	if err != nil {
		return Job{}, refuse(ErrUnavailable, "The panel could not create a job ID, so no website was started. Try again.")
	}
	job := newKindJob(id, in.Kind, in.Domain, actor, time.Now())
	job.PHPVersion = in.PHPVersion
	if err = r.store.put(job); err != nil {
		r.store.forget(id)
		return Job{}, refuse(ErrUnavailable, "The panel could not save the job record, so no website was started. Check the panel's state directory, then try again.")
	}
	r.mu.Lock()
	r.running[in.Domain] = id
	r.mu.Unlock()
	reserved = false
	runCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), r.limit)
	// The run keeps the passwords; the goroutine captures the domain, not
	// the input, and Start drops its own references. Go strings cannot be
	// zeroed: dropping a reference lets the memory be reused, it does not
	// erase it.
	j := &run{runner: r, job: job.clone(), in: in, actor: actor, secrets: []string{in.AdminPassword, in.DBPassword}}
	domain := in.Domain
	in.AdminPassword, in.DBPassword = "", ""
	r.wg.Add(1)
	go func() {
		defer r.wg.Done()
		defer cancel()
		defer r.release(domain)
		j.execute(runCtx)
	}()
	return job, nil
}

// reserve takes a running slot for the domain before any broker contact.
func (r *Runner) reserve(domain string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, ok := r.running[domain]; ok {
		return refuse(ErrConflict, "A website for %s is being created right now. Wait for that job to finish.", domain)
	}
	if len(r.running) >= maxRunning {
		return refuse(ErrConflict, "Another website is being created right now. Wait for it to finish, then try again.")
	}
	r.running[domain] = ""
	return nil
}

func (r *Runner) release(domain string) {
	r.mu.Lock()
	delete(r.running, domain)
	r.mu.Unlock()
}

// save records the job. Memory stays current when the write fails, and the
// next save writes everything; the failure is reported on stderr, where the
// panel's other start-up messages go.
func (r *Runner) save(j Job) {
	if err := r.store.put(j); err != nil {
		fmt.Fprintf(logOutput, "website job %s: saving the job record failed: %v\n", j.ID, err)
	}
}

// run is one job in progress, and holds the passwords while it needs them.
type run struct {
	runner *Runner
	job    Job
	in     Input
	actor  string

	dbPassword string
	wpVersion  string
	https      bool // the site has its certificate, so WordPress is installed with https
	// secrets is every password the run has held, kept only to scrub them
	// out of what the job records: error text from the broker or the
	// database server can echo them, even after the install step.
	secrets []string

	// What this job created, for undo.
	accountID   string
	revision    uint64
	dbName      string
	dbCreated   bool
	userCreated bool

	// migration is a migration job's own state (migrate.go), nil otherwise.
	migration *migrationRun
	// skipDetail is the technical detail of the step about to be skipped:
	// the certificate authority's answer when the ssl step got none.
	skipDetail string
}

// stepError is a failed step in plain words.
type stepError struct {
	why, next, technical string
}

func (j *run) execute(ctx context.Context) {
	defer func() {
		// Drop the run's last references to the passwords when it ends,
		// whatever happened: right after the install step, or after a failed
		// job's undo. This does not erase the bytes; Go cannot zero a string.
		j.in.AdminPassword, j.in.DBPassword, j.dbPassword, j.secrets = "", "", "", nil
	}()
	last := j.wordpress
	if j.in.Kind == KindPHP {
		last = j.placeholder
	}
	steps := []func(context.Context) (string, *stepError){j.account, j.web, j.ssl, j.database, last}
	for i, step := range steps {
		j.begin(i)
		stepCtx, cancel := stepContext(ctx, j.runner.waits[j.job.Steps[i].Name])
		message, failure := step(stepCtx)
		expired := stepCtx.Err() != nil
		cancel()
		if failure != nil {
			if expired {
				failure.why = "It took longer than the panel waits for this step, so it stopped waiting."
				failure.next = "Try again. If it is slow again, check the server's load and its connection to wordpress.org."
				if j.in.Kind == KindPHP {
					failure.next = "Try again. If it is slow again, check the server's load."
				}
				if j.job.Steps[i].Name == StepDatabase && j.job.Username != "" {
					// MariaDB may have made the database or user after the
					// panel stopped waiting; the job cannot tell, so undo
					// leaves them.
					failure.next = "The database or user " + j.job.Username + dbSuffix + " may have been left on the server. Remove it if it is there, then create the website again."
				}
				if j.job.Steps[i].Name == StepAccount {
					// The broker may have made the account after the panel
					// stopped waiting; the job never learnt its ID, so undo
					// cannot remove it.
					failure.why = "It took longer than the panel waits for this step, so it stopped waiting and cannot tell whether the account was made."
					failure.next = checkAccounts(j.in.Domain)
				}
			}
			j.fail(i, failure)
			return
		}
		if name := j.job.Steps[i].Name; (name == StepSSL && !j.https) || (name == StepDatabase && !j.in.wantsDatabase()) {
			j.skip(i, message)
			continue
		}
		j.finish(i, message)
	}
	scheme := "http://"
	if j.https {
		scheme = "https://"
	}
	j.job.State = StateSucceeded
	if j.in.Kind == KindPHP {
		j.job.Result = &Result{URL: scheme + j.in.Domain + "/", AccountID: j.accountID}
		if j.dbCreated {
			j.job.Result.Database = j.dbName
		}
	} else {
		j.job.Result = &Result{URL: scheme + j.in.Domain + "/", AdminURL: scheme + j.in.Domain + "/wp-admin/", WordPressVersion: j.wpVersion, AccountID: j.accountID}
	}
	j.touch()
}

// reasons are what the job tells the broker it is doing, for the journal.
func (j *run) reasons() (create, undo string) {
	if j.in.Kind == KindPHP {
		return phpReason, phpUndoReason
	}
	return brokerReason, undoReason
}

func (j *run) touch() {
	j.job.UpdatedAt = timestamp(time.Now())
	j.runner.save(j.job)
}

func (j *run) begin(i int) {
	j.job.Steps[i].State = StepRunning
	j.job.Steps[i].StartedAt = timestamp(time.Now())
	j.touch()
}

func (j *run) finish(i int, message string) { j.end(i, StepDone, message) }

// skip ends a step that did not do its work but does not stop the job.
func (j *run) skip(i int, message string) {
	j.job.Steps[i].Technical, j.skipDetail = j.skipDetail, ""
	j.end(i, StepSkipped, message)
}

func (j *run) end(i int, state, message string) {
	j.job.Steps[i].State = state
	j.job.Steps[i].Message = redact(message, j.secrets...)
	j.job.Steps[i].FinishedAt = timestamp(time.Now())
	j.touch()
}

// account creates the hosting account, trying a new name on a conflict.
func (j *run) account(ctx context.Context) (string, *stepError) {
	base := usernameBase(j.in.Domain)
	var last error
	for try := 0; try < usernameTries; try++ {
		name := usernameCandidate(base, try, j.runner.digits)
		// A name whose database or database user already exists, registered
		// or only on the server, counts as taken: the job would neither reuse
		// it nor remove it. If that cannot be checked now, the database step
		// checks again and the strict creates refuse an existing name.
		taken, terr := j.nameTaken(ctx, name+dbSuffix)
		if !validUsername(name) || (terr == nil && taken) {
			last = errNameInUse
			continue
		}
		reason, _ := j.reasons()
		a, err := j.runner.accounts.Create(ctx, hostaccounts.CreateInput{Username: name, Domain: j.in.Domain, Reason: reason}, j.actor)
		if err == nil {
			j.accountID, j.revision = a.ID, a.Revision
			j.job.Username = a.Username
			return "Created the hosting account " + a.Username + ".", nil
		}
		last = err
		if !errors.Is(err, hostaccounts.ErrConflict) || ctx.Err() != nil {
			break
		}
		// A conflict is either the name or the domain; only a new name helps.
		if owner, taken := j.domainOwner(ctx); taken {
			return "", &stepError{why: j.in.Domain + " was added to the hosting account " + owner + " while this job was starting.", next: "Use another domain, or remove that account first.", technical: j.technical(err)}
		}
	}
	switch {
	case errors.Is(last, hostaccounts.ErrConflict) || errors.Is(last, errNameInUse):
		return "", &stepError{why: fmt.Sprintf("The %d account names tried (starting with %s) are already in use on this server.", usernameTries, base), next: "Try again; the panel picks new names each time.", technical: j.technical(last)}
	case errors.Is(last, hostaccounts.ErrRecovery):
		return "", &stepError{why: "The account service stopped part-way and needs a check before anything else changes.", next: "Open Accounts and review the account for " + j.in.Domain + " before you try again.", technical: j.technical(last)}
	case errors.Is(last, hostaccounts.ErrUnavailable):
		return "", &stepError{why: "The account service did not answer, so the panel cannot tell whether the account was made.", next: checkAccounts(j.in.Domain), technical: j.technical(last)}
	default:
		return "", j.brokerFailure(last)
	}
}

// checkAccounts is the advice when the broker may have made an account the
// job does not know about, so undo cannot remove it.
func checkAccounts(domain string) string {
	return "Open Accounts. If an account for " + domain + " is listed, remove it, then create the website again."
}

var errNameInUse = errors.New("account name or its database name already in use")

// nameTaken reports whether a database or database user with this name is in
// the registry or on the database server, registered or not.
func (j *run) nameTaken(ctx context.Context, name string) (bool, error) {
	dbs, err := j.runner.databases.AllDatabases(ctx)
	if err != nil {
		return false, err
	}
	users, err := j.runner.databases.AllUsers(ctx)
	if err != nil {
		return false, err
	}
	if slices.ContainsFunc(dbs, func(d dbhost.Database) bool { return d.Name == name }) || slices.ContainsFunc(users, func(u dbhost.User) bool { return u.Name == name }) {
		return true, nil
	}
	for _, kind := range []string{"database", "user"} {
		if has, err := j.runner.databases.ServerHas(ctx, kind, name); err != nil || has {
			return has, err
		}
	}
	return false, nil
}

func (j *run) domainOwner(ctx context.Context) (string, bool) {
	items, err := j.runner.accounts.List(ctx)
	if err != nil {
		return "", false
	}
	for _, a := range items {
		if a.Domain == j.in.Domain {
			return a.Username, true
		}
	}
	return "", false
}

// web puts the account's site live with the chosen PHP.
func (j *run) web(ctx context.Context) (string, *stepError) {
	reason, _ := j.reasons()
	res, err := j.runner.accounts.SetWeb(ctx, j.accountID, hostaccounts.WebInput{PHPVersion: j.in.PHPVersion, QuotaMiB: quotaMiB, ExpectedRevision: j.revision, Reason: reason}, j.actor)
	if err != nil {
		if errors.Is(err, hostaccounts.ErrWebRejected) {
			return "", &stepError{why: "The web server's configuration test failed with the new site, so the server kept its old configuration.", next: "Ask whoever runs this server to check the web server, then create the website again.", technical: j.technical(err)}
		}
		return "", j.brokerFailure(err)
	}
	j.revision = res.Account.Revision
	return "The site is live with PHP " + j.in.PHPVersion + ".", nil
}

const sslNotSetUp = "Certificates are not set up on this server."

// sslWhy says why a site stays on http, from what stopped its certificate:
// what happened, why, and what to do. The certificate authority's own words
// go to the step's technical detail. The renewal loop tries a failed site
// again 6 hours after the try, and a week after a refused install.
func sslWhy(reason acme.Reason, domain string) string {
	switch reason {
	case acme.ReasonContact:
		return "Let's Encrypt refused the contact email address this server was installed with, so it issued no certificate and the site uses http. It refuses addresses at domains that receive no mail, such as example.com. Run the installer again on the server with --acme-email set to an address at a domain you own; the panel then asks again by itself within 6 hours."
	case acme.ReasonRateLimit:
		return "Let's Encrypt is not issuing more certificates for " + domain + " right now: one of its rate limits was reached, so the site uses http. The panel tries again within 6 hours; if this lasts more than a day, read https://letsencrypt.org/docs/rate-limits/."
	case acme.ReasonName:
		return "Let's Encrypt does not issue certificates for " + domain + ": the name is reserved or on its list of names it refuses, so the site uses http. Check the spelling; a domain you have registered gets a certificate, this one cannot."
	case acme.ReasonCAA:
		return "The DNS of " + domain + " has a CAA record that does not allow Let's Encrypt, so it issued no certificate and the site uses http. At your DNS provider, add a CAA record for letsencrypt.org or remove the CAA records; the panel tries again within 6 hours."
	case acme.ReasonDNS:
		return "Let's Encrypt could not find " + domain + " in DNS, so the site uses http. The domain has no A record yet, or its DNS servers did not answer. Add an A record for " + domain + " with this server's IP address at your DNS provider (Set up DNS shows it); the panel tries again within 6 hours."
	case acme.ReasonConnection:
		return "Let's Encrypt could not connect to " + domain + " on port 80, so the site uses http. The domain points at an address that does not answer there: another server, or this one with port 80 closed. Point the domain's A record at this server and open TCP port 80 to the internet; the panel tries again within 6 hours."
	case acme.ReasonElsewhere:
		return "Let's Encrypt reached " + domain + ", but another server answered there, so the site uses http. The domain, or its IPv6 (AAAA) record, still points at another server. Point every A and AAAA record of " + domain + " at this server, or remove an old AAAA record; the panel tries again within 6 hours."
	case acme.ReasonNoAnswer:
		return "The panel could not reach Let's Encrypt, or it did not answer in time, so the site uses http. This server's outgoing connections on port 443 may be blocked, or Let's Encrypt may be busy. Check that the server can open https://acme-v02.api.letsencrypt.org/directory; the panel tries again within 6 hours."
	case acme.ReasonRefused:
		return "Let's Encrypt refused to issue a certificate for " + domain + ", so the site uses http. Its reason is under Technical details. The panel tries again within 6 hours; if the same reason comes back, check https://letsencrypt.status.io/."
	case acme.ReasonInstall:
		return "A certificate was issued, but the web server did not take it, so the site uses http. The account service's reason is under Technical details. Fix what it names on the server; the panel tries again in a week."
	}
	return "The panel could not get a certificate for " + domain + ", so the site uses http. The reason is under Technical details. The panel tries again within 6 hours."
}

// ssl gets the site a certificate and installs it. It never fails the job:
// without a certificate the step is skipped with the reason, the site stays
// on http, and nothing is undone.
func (j *run) ssl(ctx context.Context) (string, *stepError) {
	certs := j.runner.certificates
	if certs == nil {
		return sslNotSetUp, nil
	}
	revision, notAfter, err := certs.Secure(ctx, j.accountID, j.in.Domain, j.revision)
	if err == nil {
		j.revision, j.https = revision, true
		return "Installed a certificate for " + j.in.Domain + ", valid until " + notAfter.UTC().Format(time.DateOnly) + ".", nil
	}
	// The broker may have applied the certificate after the panel stopped
	// waiting, which moves the account's revision; the install step needs
	// the current one.
	j.refreshRevision(ctx)
	j.skipDetail = j.technical(err)
	return sslWhy(acme.ReasonOf(err), j.in.Domain), nil
}

// refreshRevision reads the account's current revision from the broker,
// keeping the one the job has if the list cannot be read.
func (j *run) refreshRevision(ctx context.Context) {
	ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), refreshLimit)
	defer cancel()
	items, err := j.runner.accounts.List(ctx)
	if err != nil {
		return
	}
	for _, a := range items {
		if a.ID == j.accountID {
			j.revision = a.Revision
			return
		}
	}
}

// database creates the database and its user, with every privilege on it.
// A WordPress site's user gets a password the panel makes; a PHP site's the
// one the person chose, and a PHP site without a database skips the step.
func (j *run) database(ctx context.Context) (string, *stepError) {
	if !j.in.wantsDatabase() {
		return "No database was asked for.", nil
	}
	owner := j.job.Username
	name := dbhost.PrefixedName(owner, strings.TrimPrefix(dbSuffix, "_"))
	j.dbName = name
	// The account step skipped names in use; this catches one made since.
	taken, err := j.nameTaken(ctx, name)
	if err != nil {
		return "", j.databaseFailure(err)
	}
	if taken {
		return "", nameExists(name, "registry or server already has "+name)
	}
	// The creates are strict, so one made by someone else after the check
	// fails here and is never adopted. Each counts as the job's, for undo,
	// once the server has made it: on success, or when only the registry
	// write failed.
	err = j.runner.databases.CreateDatabaseStrict(ctx, owner, name)
	j.dbCreated = err == nil || errors.Is(err, dbhost.ErrNotRegistered)
	if err != nil {
		return "", j.createFailure(name, err)
	}
	if j.in.Kind == KindPHP {
		j.dbPassword = j.in.DBPassword
	} else {
		j.dbPassword, err = newDBPassword()
		if err != nil {
			return "", &stepError{why: "The panel could not make a password for the database.", next: "Try again.", technical: j.technical(err)}
		}
		j.secrets = append(j.secrets, j.dbPassword)
	}
	err = j.runner.databases.CreateUserStrict(ctx, owner, name, j.dbPassword)
	if j.in.Kind == KindPHP {
		// The user's create is the last use of the person's password.
		j.in.DBPassword, j.dbPassword = "", ""
	}
	j.userCreated = err == nil || errors.Is(err, dbhost.ErrNotRegistered)
	if err != nil {
		return "", j.createFailure(name, err)
	}
	if err = j.runner.databases.SetPrivileges(ctx, owner, name, name, []string{"ALL PRIVILEGES"}); err != nil {
		return "", j.databaseFailure(err)
	}
	if j.in.Kind == KindPHP {
		return "Created the database " + name + " and its user " + name + ".", nil
	}
	return "Created the database " + name + " and its user.", nil
}

// placeholder puts the placeholder page into the PHP site's public_html,
// if the folder is empty.
func (j *run) placeholder(ctx context.Context) (string, *stepError) {
	res, err := j.runner.accounts.InstallPlaceholder(ctx, j.accountID, hostaccounts.PlaceholderInput{ExpectedRevision: j.revision}, j.actor)
	if err != nil {
		var install *hostaccounts.InstallError
		if errors.As(err, &install) {
			return "", &stepError{why: "The site's PHP could not write the placeholder page into public_html as the site's user.", next: "Open Technical details to see why, fix the cause, then create the website again.", technical: scrub(install.Step+": "+install.Detail, j.secrets...)}
		}
		return "", j.brokerFailure(err)
	}
	if !res.Written {
		return "public_html already had files, so the panel left them as they are and added no placeholder page.", nil
	}
	return "Added a placeholder page, public_html/index.php. Replace it with your website's files.", nil
}

// wordpress installs WordPress with the person's admin details.
func (j *run) wordpress(ctx context.Context) (string, *stepError) {
	in := hostaccounts.WordPressInput{
		ExpectedRevision: j.revision,
		HTTPS:            j.https,
		Title:            j.in.Title,
		AdminUser:        j.in.AdminUser,
		AdminEmail:       j.in.AdminEmail,
		AdminPassword:    j.in.AdminPassword,
		DBName:           j.dbName,
		DBUser:           j.dbName,
		DBPassword:       j.dbPassword,
	}
	res, err := j.runner.accounts.InstallWordPress(ctx, j.accountID, in, j.actor)
	// The install is the last use of either password, so the run drops its
	// references to them here. j.secrets stays, only to scrub error text,
	// until the run ends.
	in.AdminPassword, in.DBPassword = "", ""
	j.in.AdminPassword, j.dbPassword = "", ""
	if err != nil {
		var install *hostaccounts.InstallError
		if errors.As(err, &install) {
			// Redact before quoting: %q escapes characters a password may hold.
			step := redact(install.Step, j.secrets...)
			if install.Installed {
				// WordPress itself works; the job still fails and its undo
				// removes the new website, so it says both.
				return "", &stepError{why: fmt.Sprintf("WordPress was installed, but its LiteSpeed Cache plugin could not be set up: the %q step failed.", step), next: "The panel removes the new website again, as it does when any step fails. Open Technical details to see why the cache step failed, fix the cause, then create the website again.", technical: scrub(install.Step+": "+install.Detail, j.secrets...)}
			}
			return "", &stepError{why: fmt.Sprintf("The WordPress installer stopped at its %q step.", step), next: "Open Technical details to see where it stopped, fix the cause, then create the website again.", technical: scrub(install.Step+": "+install.Detail, j.secrets...)}
		}
		return "", j.brokerFailure(err)
	}
	j.wpVersion = res.Version
	return "Installed WordPress " + res.Version + " with the LiteSpeed Cache plugin " + hostaccounts.LSCachePluginVersion + ".", nil
}

// brokerFailure explains the broker's typed errors.
func (j *run) brokerFailure(err error) *stepError {
	switch {
	case errors.Is(err, hostaccounts.ErrConflict):
		return &stepError{why: "The hosting account changed or was busy while this step ran.", next: "Wait a minute, then create the website again.", technical: j.technical(err)}
	case errors.Is(err, hostaccounts.ErrNotFound):
		return &stepError{why: "The hosting account was removed while the website was being set up.", next: "Create the website again.", technical: j.technical(err)}
	case errors.Is(err, hostaccounts.ErrInvalid):
		return &stepError{why: "The account service refused the request as invalid.", next: "Check the details you entered, then create the website again.", technical: j.technical(err)}
	case errors.Is(err, hostaccounts.ErrRecovery):
		return &stepError{why: "The account service stopped part-way and needs a check before anything else changes.", next: "Open Accounts and review the account before you try again.", technical: j.technical(err)}
	default:
		return &stepError{why: "The account service did not answer.", next: "Check that the account service is running, then create the website again.", technical: j.technical(err)}
	}
}

// nameExists is the clean failure for a database or user the job did not make.
func nameExists(name, detail string) *stepError {
	return &stepError{why: "A database or user named " + name + " already exists on this server and was not made by this job, so the panel will not reuse it or remove it.", next: "Create the website again; the panel will pick another name.", technical: detail}
}

// createFailure explains a strict create that failed.
func (j *run) createFailure(name string, err error) *stepError {
	switch {
	case errors.Is(err, dbhost.ErrExists):
		return nameExists(name, j.technical(err))
	case errors.Is(err, dbhost.ErrNotRegistered):
		return &stepError{why: "The database server made " + name + ", but the panel could not record it in its list of databases.", next: "Check that the panel's state directory can be written, then create the website again.", technical: j.technical(err)}
	default:
		return j.databaseFailure(err)
	}
}

func (j *run) databaseFailure(err error) *stepError {
	if errors.Is(err, dbhost.ErrUnavailable) {
		return &stepError{why: "The database server is not answering.", next: "Check that the database server is running, then create the website again.", technical: j.technical(err)}
	}
	return &stepError{why: "The database server refused the request.", next: "Open Technical details to see why, fix the cause, then create the website again.", technical: j.technical(err)}
}

var stepWhat = map[string]string{
	StepAccount:     "The hosting account could not be created.",
	StepWeb:         "The site could not be put live.",
	StepDatabase:    "The database could not be created.",
	StepWordPress:   "WordPress could not be installed.",
	StepPlaceholder: "The placeholder page could not be added.",
	StepSource:      "The website on the old server cannot be moved as it is.",
	StepFiles:       "The website's files could not be copied.",
	StepCron:        "The scheduled jobs could not be copied.",
}

// what says what failed, for a migration's database step in its own words.
func (j *run) what(step string) string {
	if j.migration != nil && step == StepDatabase {
		return "The databases could not be copied."
	}
	return stepWhat[step]
}

// fail records the failed step, skips the rest, and undoes what the job
// created, newest first.
func (j *run) fail(i int, f *stepError) {
	now := timestamp(time.Now())
	// Every text the job records passes the scrub, whichever path built it.
	why, next := redact(f.why, j.secrets...), redact(f.next, j.secrets...)
	step := &j.job.Steps[i]
	step.State = StepFailed
	step.Message = why
	step.FinishedAt = now
	for k := i + 1; k < len(j.job.Steps); k++ {
		j.job.Steps[k].State = StepSkipped
	}
	j.job.Error = &Failure{Step: step.Name, What: j.what(step.Name), Why: why, Next: next, Technical: scrub(f.technical, j.secrets...)}
	j.touch()
	left, notes := j.undo()
	if len(left) > 0 {
		again := "create the website again"
		if j.migration != nil {
			again = "move the website again"
		}
		j.job.Error.Next = "These could not be removed and are still on the server: " + strings.Join(left, ", ") + ". Remove them by hand, then " + again + "."
	}
	if len(notes) > 0 {
		j.job.Error.Technical = clip(strings.TrimPrefix(j.job.Error.Technical+"; "+strings.Join(notes, "; "), "; "))
	}
	j.job.State = StateFailed
	j.touch()
}

// undo removes what this job created and nothing else: the database user,
// the database, then the hosting account (which also takes its site off the
// web server). Each removal is tried even if an earlier one failed. It has
// its own time limit, so a job that ran out of time can still clean up.
func (j *run) undo() (left, notes []string) {
	ctx, cancel := context.WithTimeout(context.Background(), undoLimit)
	defer cancel()
	owner := j.job.Username
	if j.migration != nil {
		left, notes = j.undoMigration(ctx)
	}
	partial := j.dbCreated || j.userCreated
	dbLeft := false
	if j.userCreated {
		if err := j.runner.databases.DropUser(ctx, owner, j.dbName); err != nil {
			dbLeft = true
			left = append(left, "the database user "+j.dbName)
			notes = append(notes, "undo database user: "+j.technical(err))
		} else {
			j.userCreated = false
		}
	}
	if j.dbCreated {
		if err := j.runner.databases.DropDatabase(ctx, owner, j.dbName); err != nil {
			dbLeft = true
			left = append(left, "the database "+j.dbName)
			notes = append(notes, "undo database: "+j.technical(err))
		} else {
			j.dbCreated = false
		}
	}
	if i := j.index(StepDatabase); i >= 0 && partial {
		step := &j.job.Steps[i]
		switch {
		case step.State == StepDone && dbLeft:
			step.Message = "Could not be removed after a later step failed."
		case step.State == StepDone:
			step.State = StepUndone
			step.Message = "Removed after a later step failed."
		case dbLeft:
			step.Message += " What this step had created could not be removed."
		default:
			step.Message += " What this step had created was removed."
		}
		j.touch()
	}
	if j.accountID == "" {
		return left, notes
	}
	// Delete at the account's current revision: a step that timed out may
	// have changed the account after the job last saw it. If the list cannot
	// be read, the newest revision the job saw is the best guess.
	revision, gone := j.revision, false
	if items, err := j.runner.accounts.List(ctx); err == nil {
		gone = true
		for _, a := range items {
			if a.ID == j.accountID {
				revision, gone = a.Revision, false
				break
			}
		}
	}
	var err error
	if !gone {
		_, reason := j.reasons()
		_, err = j.runner.accounts.Delete(ctx, j.accountID, hostaccounts.DeleteInput{ExpectedRevision: revision, Reason: reason}, j.actor)
		if errors.Is(err, hostaccounts.ErrNotFound) {
			gone, err = true, nil
		}
	}
	// The certificate goes with the account: the broker removes its files.
	for _, name := range []string{StepSSL, StepWeb, StepAccount} {
		i := j.index(name)
		if i < 0 {
			continue // a job without that step
		}
		step := &j.job.Steps[i]
		if step.State != StepDone {
			continue
		}
		switch {
		case err != nil:
			step.Message = "Could not be removed after a later step failed."
		case gone:
			step.State = StepUndone
			step.Message = "Was already gone when the job came to remove it."
		default:
			step.State = StepUndone
			step.Message = "Removed after a later step failed."
		}
	}
	switch {
	case err != nil:
		left = append(left, "the hosting account "+owner)
		notes = append(notes, "undo account: "+j.technical(err))
	case gone:
		notes = append(notes, "undo account: already removed")
		j.accountID = ""
	default:
		j.accountID = ""
	}
	j.touch()
	return left, notes
}

func (j *run) index(name string) int {
	for i, s := range j.job.Steps {
		if s.Name == name {
			return i
		}
	}
	return -1
}

// newDBPassword is 24 URL-safe characters from crypto/rand.
func newDBPassword() (string, error) {
	b := make([]byte, dbPasswordLen*3/4)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// technical is an error's text for the job record, scrubbed of every
// password the run has held.
func (j *run) technical(err error) string { return scrub(err.Error(), j.secrets...) }

// redact replaces each password in text with "[secret]".
func redact(text string, secrets ...string) string {
	for _, s := range secrets {
		if s != "" {
			text = strings.ReplaceAll(text, s, "[secret]")
		}
	}
	return text
}

// scrub makes error text safe for the job record: the passwords removed,
// MariaDB's statement echo ("near '...'") cut off because it can quote the
// password, printable ASCII only, at most 512 bytes.
func scrub(text string, secrets ...string) string {
	text = redact(text, secrets...)
	if i := strings.Index(text, " near '"); i >= 0 {
		text = text[:i] + " near [statement removed]"
	}
	b := make([]byte, 0, len(text))
	for i := 0; i < len(text); i++ {
		c := text[i]
		switch {
		case c == '\n' || c == '\t' || c == '\r':
			b = append(b, ' ')
		case c >= 0x20 && c < 0x7f:
			b = append(b, c)
		}
	}
	return clip(strings.Join(strings.Fields(string(b)), " "))
}

func clip(text string) string {
	if len(text) > technicalLimit {
		return text[:technicalLimit]
	}
	return text
}
