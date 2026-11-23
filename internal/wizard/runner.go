package wizard

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"slices"
	"strings"
	"sync"
	"time"

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

// Databases is the part of dbhost a job uses. The registry views let a job
// refuse a name that already exists: dbhost creates with IF NOT EXISTS, so
// an old database would otherwise be adopted, and then dropped on undo.
type Databases interface {
	Probe(context.Context) (string, error)
	AllDatabases(context.Context) ([]dbhost.Database, error)
	AllUsers(context.Context) ([]dbhost.User, error)
	CreateDatabase(ctx context.Context, owner, name string) error
	CreateUser(ctx context.Context, owner, name, password string) error
	SetPrivileges(ctx context.Context, owner, user, db string, privs []string) error
	DropDatabase(ctx context.Context, owner, name string) error
	DropUser(ctx context.Context, owner, name string) error
}

const (
	maxRunning     = 2                // jobs running at once
	usernameTries  = 5                // broker creates tried per job
	jobLimit       = 15 * time.Minute // all four steps together
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
	accounts  Accounts
	databases Databases
	store     *Store

	mu      sync.Mutex
	running map[string]string // domain -> job ID
	wg      sync.WaitGroup

	digits func() string // two digits for a username retry
	limit  time.Duration
}

// New returns a runner over the broker, the database service and a store.
func New(accounts Accounts, databases Databases, store *Store) *Runner {
	return &Runner{accounts: accounts, databases: databases, store: store, running: map[string]string{}, digits: randomDigits, limit: jobLimit}
}

// Get returns one job.
func (r *Runner) Get(id string) (Job, bool) { return r.store.Get(id) }

// List returns the newest jobs, newest first, at most 20.
func (r *Runner) List() []Job { return r.store.List(maxListed) }

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
	if err = r.store.put(job); err != nil {
		r.store.forget(id)
		return Job{}, refuse(ErrUnavailable, "The panel could not save the job record, so no website was started. Check the panel's state directory, then try again.")
	}
	r.mu.Lock()
	r.running[in.Domain] = id
	r.mu.Unlock()
	reserved = false
	runCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), r.limit)
	// The run holds the only copy of the password from here on; the
	// goroutine captures the domain, not the input.
	j := &run{runner: r, job: job.clone(), in: in, actor: actor}
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
		return refuse(ErrConflict, "%d websites are being created right now. Wait for one to finish, then try again.", maxRunning)
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
		fmt.Fprintf(os.Stderr, "website job %s: saving the job record failed: %v\n", j.ID, err)
	}
}

// run is one job in progress. It alone holds the passwords.
type run struct {
	runner *Runner
	job    Job
	in     Input
	actor  string

	dbPassword string
	wpVersion  string

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
		// Drop the passwords as soon as the run ends, whatever happened.
		j.in.AdminPassword = ""
		j.dbPassword = ""
	}()
	steps := []func(context.Context) (string, *stepError){j.account, j.web, j.database, j.wordpress}
	for i, step := range steps {
		j.begin(i)
		message, failure := step(ctx)
		if failure != nil {
			if ctx.Err() != nil {
				failure.why = "It took longer than 15 minutes, so the panel stopped waiting."
				failure.next = "Try again. If it is slow again, check the server's load and its connection to wordpress.org."
			}
			j.fail(i, failure)
			return
		}
		j.finish(i, message)
	}
	j.job.State = StateSucceeded
	j.job.Result = &Result{URL: "http://" + j.in.Domain + "/", AdminURL: "http://" + j.in.Domain + "/wp-admin/", WordPressVersion: j.wpVersion, AccountID: j.accountID}
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

func (j *run) finish(i int, message string) {
	j.job.Steps[i].State = StepDone
	j.job.Steps[i].Message = message
	j.job.Steps[i].FinishedAt = timestamp(time.Now())
	j.touch()
}

// account creates the hosting account, trying a new name on a conflict.
func (j *run) account(ctx context.Context) (string, *stepError) {
	base := usernameBase(j.in.Domain)
	var last error
	for try := 0; try < usernameTries; try++ {
		name := usernameCandidate(base, try, j.runner.digits)
		// A name whose database is already registered counts as taken: the
		// job would neither reuse that database nor remove it.
		if !validUsername(name) || j.databaseNameTaken(ctx, name+dbSuffix) {
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
			return "", &stepError{why: j.in.Domain + " was added to the hosting account " + owner + " while this job was starting.", next: "Use another domain, or remove that account first.", technical: technical(err)}
		}
	}
	switch {
	case errors.Is(last, hostaccounts.ErrConflict) || errors.Is(last, errNameInUse):
		return "", &stepError{why: fmt.Sprintf("The %d account names tried (starting with %s) are already in use on this server.", usernameTries, base), next: "Try again; the panel picks new names each time.", technical: technical(last)}
	case errors.Is(last, hostaccounts.ErrRecovery):
		return "", &stepError{why: "The account service stopped part-way and needs a check before anything else changes.", next: "Open Accounts and review the account for " + j.in.Domain + " before you try again.", technical: technical(last)}
	case errors.Is(last, hostaccounts.ErrUnavailable):
		return "", &stepError{why: "The account service did not answer, so the panel cannot tell whether the account was made.", next: "Open Accounts. If an account for " + j.in.Domain + " is listed, remove it, then create the website again.", technical: technical(last)}
	default:
		return "", brokerFailure(last)
	}
}

var errNameInUse = errors.New("account name or its database name already in use")

// databaseNameTaken reports whether the registry lists a database or user
// with this name. If it cannot be read, the database step checks again.
func (j *run) databaseNameTaken(ctx context.Context, name string) bool {
	dbs, err := j.runner.databases.AllDatabases(ctx)
	if err != nil {
		return false
	}
	users, err := j.runner.databases.AllUsers(ctx)
	if err != nil {
		return false
	}
	return slices.ContainsFunc(dbs, func(d dbhost.Database) bool { return d.Name == name }) || slices.ContainsFunc(users, func(u dbhost.User) bool { return u.Name == name })
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
			return "", &stepError{why: "The web server's configuration test failed with the new site, so the server kept its old configuration.", next: "Ask whoever runs this server to check the web server, then create the website again.", technical: technical(err)}
		}
		return "", brokerFailure(err)
	}
	j.revision = res.Account.Revision
	return "The site is live with PHP " + j.in.PHPVersion + ".", nil
}

// database creates the database and its user, with every privilege on it.
func (j *run) database(ctx context.Context) (string, *stepError) {
	owner := j.job.Username
	name := dbhost.PrefixedName(owner, strings.TrimPrefix(dbSuffix, "_"))
	j.dbName = name
	// The account step skipped names whose database exists; this catches
	// one registered since.
	dbs, err := j.runner.databases.AllDatabases(ctx)
	if err != nil {
		return "", databaseFailure(err, j.secrets())
	}
	users, err := j.runner.databases.AllUsers(ctx)
	if err != nil {
		return "", databaseFailure(err, j.secrets())
	}
	if slices.ContainsFunc(dbs, func(d dbhost.Database) bool { return d.Name == name }) || slices.ContainsFunc(users, func(u dbhost.User) bool { return u.Name == name }) {
		return "", &stepError{why: "A database or database user named " + name + " was added to this server while the job ran, so the panel will not reuse it or remove it.", next: "Create the website again; the panel will pick another name.", technical: "registry already lists " + name}
	}
	if err = j.runner.databases.CreateDatabase(ctx, owner, name); err != nil {
		return "", databaseFailure(err, j.secrets())
	}
	j.dbCreated = true
	j.dbPassword, err = newDBPassword()
	if err != nil {
		return "", &stepError{why: "The panel could not make a password for the database.", next: "Try again.", technical: technical(err)}
	}
	if err = j.runner.databases.CreateUser(ctx, owner, name, j.dbPassword); err != nil {
		return "", databaseFailure(err, j.secrets())
	}
	j.userCreated = true
	if err = j.runner.databases.SetPrivileges(ctx, owner, name, name, []string{"ALL PRIVILEGES"}); err != nil {
		return "", databaseFailure(err, j.secrets())
	}
	return "Created the database " + name + " and its user.", nil
}

// wordpress installs WordPress with the person's admin details.
func (j *run) wordpress(ctx context.Context) (string, *stepError) {
	in := hostaccounts.WordPressInput{
		ExpectedRevision: j.revision,
		HTTPS:            false,
		Title:            j.in.Title,
		AdminUser:        j.in.AdminUser,
		AdminEmail:       j.in.AdminEmail,
		AdminPassword:    j.in.AdminPassword,
		DBName:           j.dbName,
		DBUser:           j.dbName,
		DBPassword:       j.dbPassword,
	}
	res, err := j.runner.accounts.InstallWordPress(ctx, j.accountID, in, j.actor)
	secrets := j.secrets()
	// The install is the last use of either password.
	in.AdminPassword, in.DBPassword = "", ""
	j.in.AdminPassword, j.dbPassword = "", ""
	if err != nil {
		var install *hostaccounts.InstallError
		if errors.As(err, &install) {
			return "", &stepError{why: fmt.Sprintf("The WordPress installer stopped at its %q step.", install.Step), next: "Open Technical details to see where it stopped, fix the cause, then create the website again.", technical: scrub(install.Step+": "+install.Detail, secrets...)}
		}
		return "", brokerFailure(err)
	}
	j.wpVersion = res.Version
	return "Installed WordPress " + res.Version + ".", nil
}

func (j *run) secrets() []string { return []string{j.in.AdminPassword, j.dbPassword} }

// brokerFailure explains the broker's typed errors.
func brokerFailure(err error) *stepError {
	switch {
	case errors.Is(err, hostaccounts.ErrConflict):
		return &stepError{why: "The hosting account changed or was busy while this step ran.", next: "Wait a minute, then create the website again.", technical: technical(err)}
	case errors.Is(err, hostaccounts.ErrNotFound):
		return &stepError{why: "The hosting account was removed while the website was being set up.", next: "Create the website again.", technical: technical(err)}
	case errors.Is(err, hostaccounts.ErrInvalid):
		return &stepError{why: "The account service refused the request as invalid.", next: "Check the details you entered, then create the website again.", technical: technical(err)}
	case errors.Is(err, hostaccounts.ErrRecovery):
		return &stepError{why: "The account service stopped part-way and needs a check before anything else changes.", next: "Open Accounts and review the account before you try again.", technical: technical(err)}
	default:
		return &stepError{why: "The account service did not answer.", next: "Check that the account service is running, then create the website again.", technical: technical(err)}
	}
}

func databaseFailure(err error, secrets []string) *stepError {
	if errors.Is(err, dbhost.ErrUnavailable) {
		return &stepError{why: "The database server is not answering.", next: "Check that the database server is running, then create the website again.", technical: scrub(err.Error(), secrets...)}
	}
	return &stepError{why: "The database server refused the request.", next: "Open Technical details to see why, fix the cause, then create the website again.", technical: scrub(err.Error(), secrets...)}
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
	step := &j.job.Steps[i]
	step.State = StepFailed
	step.Message = f.why
	step.FinishedAt = now
	for k := i + 1; k < len(j.job.Steps); k++ {
		j.job.Steps[k].State = StepSkipped
	}
	j.job.Error = &Failure{Step: step.Name, What: stepWhat[step.Name], Why: f.why, Next: f.next, Technical: f.technical}
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
			notes = append(notes, "undo database user: "+scrub(err.Error()))
		} else {
			j.userCreated = false
		}
	}
	if j.dbCreated {
		if err := j.runner.databases.DropDatabase(ctx, owner, j.dbName); err != nil {
			dbLeft = true
			left = append(left, "the database "+j.dbName)
			notes = append(notes, "undo database: "+scrub(err.Error()))
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
	_, err := j.runner.accounts.Delete(ctx, j.accountID, hostaccounts.DeleteInput{ExpectedRevision: j.revision, Reason: undoReason}, j.actor)
	for _, name := range []string{StepWeb, StepAccount} {
		step := &j.job.Steps[j.index(name)]
		if step.State != StepDone {
			continue
		}
		if err != nil {
			step.Message = "Could not be removed after a later step failed."
		} else {
			step.State = StepUndone
			step.Message = "Removed after a later step failed."
		}
	}
	if err != nil {
		left = append(left, "the hosting account "+owner)
		notes = append(notes, "undo account: "+technical(err))
	} else {
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

func technical(err error) string { return scrub(err.Error()) }

// scrub makes error text safe for the job record: the passwords removed,
// MariaDB's statement echo ("near '...'") cut off because it can quote the
// password, printable ASCII only, at most 512 bytes.
func scrub(text string, secrets ...string) string {
	for _, s := range secrets {
		if s != "" {
			text = strings.ReplaceAll(text, s, "[secret]")
		}
	}
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
