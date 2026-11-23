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
	SetWeb(context.Context, string, hostaccounts.WebInput, string) (hostaccounts.WebResult, error)
	InstallWordPress(context.Context, string, hostaccounts.WordPressInput, string) (hostaccounts.WordPressResult, error)
}

// Broker joins the broker client's interfaces into Accounts.
type Broker struct {
	hostaccounts.Service
	hostaccounts.WebService
	hostaccounts.WordPressService
}

// Certificates gets a certificate for the site and installs it on the
// account at its revision, answering the account's new revision and the
// certificate's expiry. acme.Manager is the real one. A failure wraps one of
// acme's error kinds; the job explains it and carries on over http.
type Certificates interface {
	Secure(ctx context.Context, accountID, domain string, revision uint64) (uint64, time.Time, error)
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
	undoLimit      = 3 * time.Minute  // removing what a failed job created
	quotaMiB       = 1024
	brokerReason   = "WordPress wizard"
	undoReason     = "WordPress wizard: removed after a later step failed"
	dbSuffix       = "_wp"
	dbPasswordLen  = 24
	technicalLimit = 512
)

// Runner starts jobs and runs them in the background.
type Runner struct {
	accounts     Accounts
	databases    Databases
	certificates Certificates // nil: certificates are not set up, and sites use http
	store        *Store

	mu      sync.Mutex
	running map[string]string // domain -> job ID
	wg      sync.WaitGroup

	digits func() string // two digits for a username retry
	limit  time.Duration
	// waits is the least time a slow broker step gets, by step name, even
	// past limit: giving up while the broker is still changing the account
	// would fail a step that may yet succeed and leave undo racing it.
	waits map[string]time.Duration
}

// New returns a runner over the broker, the database service, a store and
// the certificate service. certificates may be nil: the "ssl" step is then
// skipped and sites use http.
func New(accounts Accounts, databases Databases, store *Store, certificates Certificates) *Runner {
	return &Runner{accounts: accounts, databases: databases, certificates: certificates, store: store, running: map[string]string{}, digits: randomDigits, limit: jobLimit, waits: map[string]time.Duration{StepWeb: webWait, StepSSL: sslWait, StepWordPress: installWait}}
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

// Succeeded returns every kept job that made a site, newest first: all
// 50 the store keeps, not only the 20 that List answers.
func (r *Runner) Succeeded() []Job {
	out := []Job{}
	for _, j := range r.store.List(maxJobs) {
		if j.State == StateSucceeded && j.Result != nil && j.Result.AccountID != "" {
			out = append(out, j)
		}
	}
	return out
}

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
	}
	if _, err = r.databases.Probe(ctx); err != nil {
		return Job{}, refuse(ErrUnavailable, "The database server is not answering, so no website was started. Check that it is running, then try again.")
	}
	id, err := newJobID()
	if err != nil {
		return Job{}, refuse(ErrUnavailable, "The panel could not create a job ID, so no website was started. Try again.")
	}
	job := newJob(id, in.Domain, actor, time.Now())
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
	// The run keeps the password; the goroutine captures the domain, not
	// the input, and Start drops its own reference. Go strings cannot be
	// zeroed: dropping a reference lets the memory be reused, it does not
	// erase it.
	j := &run{runner: r, job: job.clone(), in: in, actor: actor, secrets: []string{in.AdminPassword}}
	domain := in.Domain
	in.AdminPassword = ""
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
		j.in.AdminPassword, j.dbPassword, j.secrets = "", "", nil
	}()
	steps := []func(context.Context) (string, *stepError){j.account, j.web, j.ssl, j.database, j.wordpress}
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
		if j.job.Steps[i].Name == StepSSL && !j.https {
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
	j.job.Result = &Result{URL: scheme + j.in.Domain + "/", AdminURL: scheme + j.in.Domain + "/wp-admin/", WordPressVersion: j.wpVersion, AccountID: j.accountID}
	j.touch()
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
func (j *run) skip(i int, message string) { j.end(i, StepSkipped, message) }

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
		a, err := j.runner.accounts.Create(ctx, hostaccounts.CreateInput{Username: name, Domain: j.in.Domain, Reason: brokerReason}, j.actor)
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
	res, err := j.runner.accounts.SetWeb(ctx, j.accountID, hostaccounts.WebInput{PHPVersion: j.in.PHPVersion, QuotaMiB: quotaMiB, ExpectedRevision: j.revision, Reason: brokerReason}, j.actor)
	if err != nil {
		if errors.Is(err, hostaccounts.ErrWebRejected) {
			return "", &stepError{why: "The web server's configuration test failed with the new site, so the server kept its old configuration.", next: "Ask whoever runs this server to check the web server, then create the website again.", technical: j.technical(err)}
		}
		return "", j.brokerFailure(err)
	}
	j.revision = res.Account.Revision
	return "The site is live with PHP " + j.in.PHPVersion + ".", nil
}

// Plain reasons for a site that stays on http. The panel's renewal loop tries
// again every few hours.
const (
	sslNotSetUp    = "Certificates are not set up on this server."
	sslNotPointing = "The domain does not point at this server yet, so the site uses http. The panel tries again every few hours."
	sslLimited     = "The certificate authority is not issuing more certificates for this domain right now, so the site uses http. The panel tries again every few hours."
	sslNotTaken    = "A certificate was issued, but the web server did not take it, so the site uses http. The panel tries again every few hours."
	sslNoAnswer    = "The certificate authority could not be reached or did not issue a certificate, so the site uses http. The panel tries again every few hours."
)

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
	switch {
	case errors.Is(err, acme.ErrValidation):
		return sslNotPointing, nil
	case errors.Is(err, acme.ErrRateLimited):
		return sslLimited, nil
	case errors.Is(err, acme.ErrInstall):
		return sslNotTaken, nil
	default:
		return sslNoAnswer, nil
	}
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
func (j *run) database(ctx context.Context) (string, *stepError) {
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
	j.dbPassword, err = newDBPassword()
	if err != nil {
		return "", &stepError{why: "The panel could not make a password for the database.", next: "Try again.", technical: j.technical(err)}
	}
	j.secrets = append(j.secrets, j.dbPassword)
	err = j.runner.databases.CreateUserStrict(ctx, owner, name, j.dbPassword)
	j.userCreated = err == nil || errors.Is(err, dbhost.ErrNotRegistered)
	if err != nil {
		return "", j.createFailure(name, err)
	}
	if err = j.runner.databases.SetPrivileges(ctx, owner, name, name, []string{"ALL PRIVILEGES"}); err != nil {
		return "", j.databaseFailure(err)
	}
	return "Created the database " + name + " and its user.", nil
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
			return "", &stepError{why: fmt.Sprintf("The WordPress installer stopped at its %q step.", redact(install.Step, j.secrets...)), next: "Open Technical details to see where it stopped, fix the cause, then create the website again.", technical: scrub(install.Step+": "+install.Detail, j.secrets...)}
		}
		return "", j.brokerFailure(err)
	}
	j.wpVersion = res.Version
	return "Installed WordPress " + res.Version + ".", nil
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
	StepAccount:   "The hosting account could not be created.",
	StepWeb:       "The site could not be put live.",
	StepDatabase:  "The database could not be created.",
	StepWordPress: "WordPress could not be installed.",
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
	j.job.Error = &Failure{Step: step.Name, What: stepWhat[step.Name], Why: why, Next: next, Technical: scrub(f.technical, j.secrets...)}
	j.touch()
	left, notes := j.undo()
	if len(left) > 0 {
		j.job.Error.Next = "These could not be removed and are still on the server: " + strings.Join(left, ", ") + ". Remove them by hand, then create the website again."
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
	if step := &j.job.Steps[j.index(StepDatabase)]; partial {
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
		_, err = j.runner.accounts.Delete(ctx, j.accountID, hostaccounts.DeleteInput{ExpectedRevision: revision, Reason: undoReason}, j.actor)
		if errors.Is(err, hostaccounts.ErrNotFound) {
			gone, err = true, nil
		}
	}
	// The certificate goes with the account: the broker removes its files.
	for _, name := range []string{StepSSL, StepWeb, StepAccount} {
		step := &j.job.Steps[j.index(name)]
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
