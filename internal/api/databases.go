package api

import (
	"context"
	"errors"
	"net/http"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/danielgtaylor/huma/v2"
	"sifruno/internal/dbhost"
)

// Databases is the part of dbhost a site's Databases page uses; dbhost's
// LocalService is the real one. Every call names an owner, and the owner is
// always the broker's username for the account in the address. The creates
// are strict: a name already in the registry or on the server is
// dbhost.ErrExists and is never adopted.
type Databases interface {
	ListDatabases(ctx context.Context, owner string) ([]dbhost.Database, error)
	ListUsers(ctx context.Context, owner string) ([]dbhost.User, error)
	CreateDatabaseStrict(ctx context.Context, owner, name string) error
	CreateUserStrict(ctx context.Context, owner, name, password string) error
	SetPrivileges(ctx context.Context, owner, user, db string, privs []string) error
	SetPassword(ctx context.Context, owner, name, password string) error
	DropDatabase(ctx context.Context, owner, name string) error
	DropUser(ctx context.Context, owner, name string) error
}

// SiteDatabase is one of a site's databases and the users granted on it.
type SiteDatabase struct {
	Name  string   `json:"name"`
	Users []string `json:"users" doc:"Database users with access to this database."`
}

// SiteDatabaseUser is one of a site's database users. It never carries a
// password: the panel does not keep one.
type SiteDatabaseUser struct {
	Name string `json:"name"`
}

type siteDatabasesBody struct {
	Databases []SiteDatabase     `json:"databases"`
	Users     []SiteDatabaseUser `json:"users"`
}
type siteDatabasesOutput struct{ Body siteDatabasesBody }

// The middleware has already checked that each body holds exactly its keys,
// each once, each a string.
type siteDatabaseCreateBody struct {
	NameSuffix string `json:"name_suffix" pattern:"^[a-z0-9_]{1,16}$" doc:"The part after the hosting account's name and an underscore: the database is named <username>_<name_suffix>."`
}
type siteDatabaseUserCreateBody struct {
	NameSuffix string `json:"name_suffix" pattern:"^[a-z0-9_]{1,16}$" doc:"The part after the hosting account's name and an underscore: the user is named <username>_<name_suffix>, at most 47 characters in all."`
	Password   string `json:"password" minLength:"12" maxLength:"128" format:"password" writeOnly:"true" doc:"12 to 128 bytes, no control characters, no space at the start or end. Sent to the database server and never stored, logged or returned."`
	Database   string `json:"database" doc:"One of this site's databases. The new user gets every privilege on it."`
}
type siteDatabasePasswordBody struct {
	Password string `json:"password" minLength:"12" maxLength:"128" format:"password" writeOnly:"true" doc:"The user's new password: 12 to 128 bytes, no control characters, no space at the start or end. Never stored, logged or returned."`
}
type siteDatabaseConfirmBody struct {
	ConfirmName string `json:"confirm_name" doc:"The name in the address, typed again exactly."`
}

type siteDatabasesInput struct {
	AccountID string `path:"account_id"`
}
type siteDatabaseCreateInput struct {
	AccountID string `path:"account_id"`
	Body      siteDatabaseCreateBody
}
type siteDatabaseUserCreateInput struct {
	AccountID string `path:"account_id"`
	Body      siteDatabaseUserCreateBody
}
type siteDatabasePasswordInput struct {
	AccountID string `path:"account_id"`
	User      string `path:"user"`
	Body      siteDatabasePasswordBody
}
type siteDatabaseDeleteInput struct {
	AccountID string `path:"account_id"`
	Name      string `path:"name"`
	Body      siteDatabaseConfirmBody
}
type siteDatabaseUserDeleteInput struct {
	AccountID string `path:"account_id"`
	User      string `path:"user"`
	Body      siteDatabaseConfirmBody
}

// siteDatabaseNameBody names what a POST created, changed or deleted.
type siteDatabaseNameBody struct {
	Name string `json:"name"`
}
type siteDatabaseNameOutput struct{ Body siteDatabaseNameBody }

const (
	databasesNotSetUp    = "Databases are not set up on this server. The panel needs the account service and the database service for them."
	databasesNoBroker    = "The account service did not answer, so the panel cannot tell which databases belong to this website."
	databaseSiteNotFound = "That website was not found. It may have been removed."
	databaseOwnerUnknown = "The account service gave this website a hosting account name the panel cannot use, so its databases cannot be told apart from other websites'."
	databaseNotFound     = "That database was not found on this website. It may have been deleted."
	databaseUserNotFound = "That database user was not found on this website. It may have been deleted."
	databaseServerDown   = "The database server is not answering. Check that it is running, then try again."
	databaseRefused      = "The database server refused the request. Open Technical details to see why."
	databaseSuffixRule   = "name_suffix must be 1 to 16 characters: lowercase letters, numbers and underscores."
	databasePasswordRule = "password must be 12 to 128 characters, with no control characters and no space at the start or end."
	databaseWait         = 30 * time.Second
	databaseUndoWait     = 15 * time.Second
	databaseTextLimit    = 512
)

var (
	databaseSuffix = regexp.MustCompile(`^[a-z0-9_]{1,16}$`)
	// databaseOwner is the broker's rule for a hosting account's name.
	databaseOwner = regexp.MustCompile(`^[a-z][a-z0-9_]{2,31}$`)

	// The bodies' keys, exactly as the contract spells them.
	databaseCreateKeys     = []string{"name_suffix"}
	databaseUserCreateKeys = []string{"name_suffix", "password", "database"}
	databasePasswordKeys   = []string{"password"}
	databaseConfirmKeys    = []string{"confirm_name"}
)

// databaseMutationKeys answers the keys a database POST's body takes; ok is
// false for every other request. The address is matched by its parts, so
// nothing else under /api/v1/websites/sites/ becomes a mutation.
func databaseMutationKeys(r *http.Request) (keys []string, ok bool) {
	rest, found := strings.CutPrefix(r.URL.Path, "/api/v1/websites/sites/")
	if r.Method != http.MethodPost || !found {
		return nil, false
	}
	parts := strings.Split(rest, "/")
	if len(parts) < 2 || parts[1] != "databases" || slices.Contains(parts, "") {
		return nil, false
	}
	switch p := parts[2:]; {
	case len(p) == 0:
		return databaseCreateKeys, true
	case len(p) == 1 && p[0] == "users":
		return databaseUserCreateKeys, true
	case len(p) == 3 && p[0] == "users" && p[2] == "password":
		return databasePasswordKeys, true
	case len(p) == 3 && p[0] == "users" && p[2] == "delete":
		return databaseConfirmKeys, true
	case len(p) == 2 && p[1] == "delete":
		return databaseConfirmKeys, true
	}
	return nil, false
}

func allowedDatabaseMutation(r *http.Request) bool {
	_, ok := databaseMutationKeys(r)
	return ok
}

// isSiteDatabasePath reports whether a route is one of a site's database
// routes, for the spec's description.
func isSiteDatabasePath(p string) bool {
	rest, found := strings.CutPrefix(p, "/api/v1/websites/sites/")
	return found && (strings.HasSuffix(rest, "/databases") || strings.Contains(rest, "/databases/"))
}

// prepareDatabaseJSON applies the wizard's body rules with this route's keys.
func prepareDatabaseJSON(w http.ResponseWriter, r *http.Request) bool {
	keys, _ := databaseMutationKeys(r)
	return prepareStrictJSON(w, r, keys)
}

// registerSiteDatabases adds a site's Databases page. The routes sit under
// /api/v1/websites/, so the wizard's admission applies: an admin session for
// the GET, and Origin, CSRF and the strict body check for each POST.
func registerSiteDatabases(a huma.API, o Options) {
	const base = "/api/v1/websites/sites/{account_id}/databases"
	op := func(id, method, path string, status int) huma.Operation {
		return huma.Operation{OperationID: id, Method: method, Path: path, DefaultStatus: status, MaxBodyBytes: 4096, BodyReadTimeout: 5 * time.Second, SkipValidateBody: true, SkipValidateParams: true}
	}
	named := func(name string) *siteDatabaseNameOutput {
		return &siteDatabaseNameOutput{Body: siteDatabaseNameBody{Name: name}}
	}
	huma.Register(a, op("list-site-databases", http.MethodGet, base, http.StatusOK), func(ctx context.Context, in *siteDatabasesInput) (*siteDatabasesOutput, error) {
		ctx, cancel := context.WithTimeout(ctx, databaseWait)
		defer cancel()
		owner, err := siteDatabaseOwner(ctx, o, in.AccountID)
		if err != nil {
			return nil, err
		}
		databases, users, err := ownDatabases(ctx, o.Databases, owner)
		if err != nil {
			return nil, databaseFailure(err)
		}
		body := siteDatabasesBody{Databases: []SiteDatabase{}, Users: []SiteDatabaseUser{}}
		for _, d := range databases {
			body.Databases = append(body.Databases, SiteDatabase{Name: d.Name, Users: append([]string{}, d.Users...)})
		}
		for _, u := range users {
			body.Users = append(body.Users, SiteDatabaseUser{Name: u.Name})
		}
		return &siteDatabasesOutput{Body: body}, nil
	})
	huma.Register(a, op("create-site-database", http.MethodPost, base, http.StatusCreated), func(ctx context.Context, in *siteDatabaseCreateInput) (*siteDatabaseNameOutput, error) {
		ctx, cancel := context.WithTimeout(ctx, databaseWait)
		defer cancel()
		owner, others, err := siteDatabaseOwners(ctx, o, in.AccountID)
		if err != nil {
			return nil, err
		}
		name, err := newDatabaseName("database", owner, in.Body.NameSuffix, dbhost.MaxDatabaseLen, others)
		if err != nil {
			return nil, err
		}
		if err = o.Databases.CreateDatabaseStrict(ctx, owner, name); err != nil {
			// Made on the server but not recorded: remove it again, so the
			// page never hides a database.
			removed := errors.Is(err, dbhost.ErrNotRegistered) && undoDatabase(ctx, func(ctx context.Context) error { return o.Databases.DropDatabase(ctx, owner, name) })
			return nil, databaseCreateFailure("database", name, removed, err)
		}
		return named(name), nil
	})
	huma.Register(a, op("create-site-database-user", http.MethodPost, base+"/users", http.StatusCreated), func(ctx context.Context, in *siteDatabaseUserCreateInput) (*siteDatabaseNameOutput, error) {
		// The handler drops its reference to the password when it returns. Go
		// strings cannot be zeroed, so this lets the memory be reused; it
		// does not erase it.
		password := in.Body.Password
		defer func() { in.Body.Password, password = "", "" }()
		ctx, cancel := context.WithTimeout(ctx, databaseWait)
		defer cancel()
		owner, others, err := siteDatabaseOwners(ctx, o, in.AccountID)
		if err != nil {
			return nil, err
		}
		name, err := newDatabaseName("user", owner, in.Body.NameSuffix, dbhost.MaxUserLen, others)
		if err != nil {
			return nil, err
		}
		if !validDatabasePassword(password) {
			return nil, huma.Error422UnprocessableEntity(databasePasswordRule)
		}
		database := in.Body.Database
		if database == "" {
			return nil, huma.Error422UnprocessableEntity("database must name one of this website's databases.")
		}
		if err = ownsDatabase(ctx, o.Databases, owner, database); err != nil {
			return nil, err
		}
		// The user is this request's to remove once the server has made it:
		// when only the registry write failed, or when the grant failed.
		dropUser := func(ctx context.Context) error { return o.Databases.DropUser(ctx, owner, name) }
		if err = o.Databases.CreateUserStrict(ctx, owner, name, password); err != nil {
			removed := errors.Is(err, dbhost.ErrNotRegistered) && undoDatabase(ctx, dropUser)
			return nil, databaseCreateFailure("database user", name, removed, err, password)
		}
		if err = o.Databases.SetPrivileges(ctx, owner, name, database, []string{"ALL PRIVILEGES"}); err != nil {
			message := "The database user " + name + " could not be given access to " + database + ", so the panel removed it again."
			if !undoDatabase(ctx, dropUser) {
				message = "The database user " + name + " could not be given access to " + database + ", and the panel could not remove it again. Delete it here if it is listed, then try again."
			}
			return nil, databaseFailureWith(message, err, password)
		}
		return named(name), nil
	})
	huma.Register(a, op("set-site-database-user-password", http.MethodPost, base+"/users/{user}/password", http.StatusOK), func(ctx context.Context, in *siteDatabasePasswordInput) (*siteDatabaseNameOutput, error) {
		password := in.Body.Password
		defer func() { in.Body.Password, password = "", "" }()
		ctx, cancel := context.WithTimeout(ctx, databaseWait)
		defer cancel()
		owner, err := siteDatabaseOwner(ctx, o, in.AccountID)
		if err != nil {
			return nil, err
		}
		if !validDatabasePassword(password) {
			return nil, huma.Error422UnprocessableEntity(databasePasswordRule)
		}
		if err = ownsDatabaseUser(ctx, o.Databases, owner, in.User); err != nil {
			return nil, err
		}
		if err = o.Databases.SetPassword(ctx, owner, in.User, password); err != nil {
			return nil, databaseFailure(err, password)
		}
		return named(in.User), nil
	})
	huma.Register(a, op("delete-site-database", http.MethodPost, base+"/{name}/delete", http.StatusOK), func(ctx context.Context, in *siteDatabaseDeleteInput) (*siteDatabaseNameOutput, error) {
		ctx, cancel := context.WithTimeout(ctx, databaseWait)
		defer cancel()
		owner, err := siteDatabaseOwner(ctx, o, in.AccountID)
		if err != nil {
			return nil, err
		}
		if in.Body.ConfirmName != in.Name {
			return nil, huma.Error422UnprocessableEntity("confirm_name must be the database's name, exactly as shown.")
		}
		if err = ownsDatabase(ctx, o.Databases, owner, in.Name); err != nil {
			return nil, err
		}
		// Only the database goes. Its users stay, and are deleted on their own.
		if err = o.Databases.DropDatabase(ctx, owner, in.Name); err != nil {
			return nil, databaseFailure(err)
		}
		return named(in.Name), nil
	})
	huma.Register(a, op("delete-site-database-user", http.MethodPost, base+"/users/{user}/delete", http.StatusOK), func(ctx context.Context, in *siteDatabaseUserDeleteInput) (*siteDatabaseNameOutput, error) {
		ctx, cancel := context.WithTimeout(ctx, databaseWait)
		defer cancel()
		owner, err := siteDatabaseOwner(ctx, o, in.AccountID)
		if err != nil {
			return nil, err
		}
		if in.Body.ConfirmName != in.User {
			return nil, huma.Error422UnprocessableEntity("confirm_name must be the user's name, exactly as shown.")
		}
		if err = ownsDatabaseUser(ctx, o.Databases, owner, in.User); err != nil {
			return nil, err
		}
		if err = o.Databases.DropUser(ctx, owner, in.User); err != nil {
			return nil, databaseFailure(err)
		}
		return named(in.User), nil
	})
}

// siteDatabaseOwner answers the database owner for the account in the
// address: the broker's username for it. Nothing in a request names the
// owner. dbhost reads an empty owner as "every account", so a username the
// broker's own rule would refuse is never passed on.
func siteDatabaseOwner(ctx context.Context, o Options, accountID string) (string, error) {
	owner, _, err := siteDatabaseOwners(ctx, o, accountID)
	return owner, err
}

// siteDatabaseOwners is siteDatabaseOwner that also returns the usernames
// of the broker's other accounts, which a create needs.
func siteDatabaseOwners(ctx context.Context, o Options, accountID string) (owner string, others []string, err error) {
	if o.Databases == nil || o.Accounts == nil {
		return "", nil, huma.Error503ServiceUnavailable(databasesNotSetUp)
	}
	if !websiteAccountID.MatchString(accountID) {
		return "", nil, huma.Error404NotFound(databaseSiteNotFound)
	}
	accounts, err := o.Accounts.List(ctx)
	if err != nil {
		return "", nil, huma.Error503ServiceUnavailable(databasesNoBroker)
	}
	found := false
	for _, a := range accounts {
		if a.ID != accountID {
			others = append(others, a.Username)
			continue
		}
		if !databaseOwner.MatchString(a.Username) {
			return "", nil, huma.Error503ServiceUnavailable(databaseOwnerUnknown)
		}
		owner, found = a.Username, true
	}
	if !found {
		return "", nil, huma.Error404NotFound(databaseSiteNotFound)
	}
	return owner, others, nil
}

// newDatabaseName builds <owner>_<suffix> for a create. The suffix is always
// appended, so no suffix can make a name outside the owner's prefix.
// Usernames may hold "_", so a name can also fall inside another account's
// prefix: bob's bob_x_wp is inside account bob_x's. Such a name is refused
// before the server is asked, so that account keeps its own names and the
// answer never tells whether that account has the name already.
func newDatabaseName(kind, owner, suffix string, max int, others []string) (string, error) {
	if !databaseSuffix.MatchString(suffix) {
		return "", huma.Error422UnprocessableEntity(databaseSuffixRule)
	}
	name := owner + "_" + suffix
	if len(name) > max || dbhost.ValidateIdentifier(kind, name, max) != nil {
		return "", huma.Error422UnprocessableEntity("name_suffix is too long for this website: the whole " + kind + " name, " + owner + "_ and the suffix, can have at most " + strconv.Itoa(max) + " characters.")
	}
	for _, other := range others {
		if strings.HasPrefix(name, other+"_") {
			return "", huma.Error422UnprocessableEntity("The " + kind + " name " + name + " begins with another website's prefix, " + other + "_, so it is kept for that website. Choose a name_suffix that does not make that prefix.")
		}
	}
	return name, nil
}

// ownDatabases reads the owner's databases and users, and keeps only the
// entries recorded for that owner whatever the service answered.
func ownDatabases(ctx context.Context, db Databases, owner string) ([]dbhost.Database, []dbhost.User, error) {
	databases, err := db.ListDatabases(ctx, owner)
	if err != nil {
		return nil, nil, err
	}
	users, err := db.ListUsers(ctx, owner)
	if err != nil {
		return nil, nil, err
	}
	databases = slices.DeleteFunc(slices.Clone(databases), func(d dbhost.Database) bool { return d.Owner != owner })
	users = slices.DeleteFunc(slices.Clone(users), func(u dbhost.User) bool { return u.Owner != owner })
	return databases, users, nil
}

// ownsDatabase is the panel's own fence before the service's: the name must
// carry the owner's prefix and be in the owner's list. A name that belongs to
// another website answers exactly as one that does not exist.
func ownsDatabase(ctx context.Context, db Databases, owner, name string) error {
	if dbhost.ValidateIdentifier("database", name, dbhost.MaxDatabaseLen) != nil || !strings.HasPrefix(name, owner+"_") {
		return huma.Error404NotFound(databaseNotFound)
	}
	databases, _, err := ownDatabases(ctx, db, owner)
	if err != nil {
		return databaseFailure(err)
	}
	if !slices.ContainsFunc(databases, func(d dbhost.Database) bool { return d.Name == name }) {
		return huma.Error404NotFound(databaseNotFound)
	}
	return nil
}

// ownsDatabaseUser is ownsDatabase for a database user.
func ownsDatabaseUser(ctx context.Context, db Databases, owner, name string) error {
	if dbhost.ValidateIdentifier("user", name, dbhost.MaxUserLen) != nil || !strings.HasPrefix(name, owner+"_") {
		return huma.Error404NotFound(databaseUserNotFound)
	}
	_, users, err := ownDatabases(ctx, db, owner)
	if err != nil {
		return databaseFailure(err)
	}
	if !slices.ContainsFunc(users, func(u dbhost.User) bool { return u.Name == name }) {
		return huma.Error404NotFound(databaseUserNotFound)
	}
	return nil
}

// validDatabasePassword is the wizard's rule for a password: 12 to 128
// bytes, no outer space, no control characters.
func validDatabasePassword(s string) bool {
	if len(s) < 12 || len(s) > 128 || strings.Trim(s, " ") != s || !utf8.ValidString(s) {
		return false
	}
	for _, r := range s {
		if r < 0x20 || r == 0x7f || unicode.IsControl(r) {
			return false
		}
	}
	return true
}

// undoDatabase removes what a failed create left on the server, and reports
// whether that worked. It does not stop when the request does.
func undoDatabase(ctx context.Context, drop func(context.Context) error) bool {
	ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), databaseUndoWait)
	defer cancel()
	return drop(ctx) == nil
}

// databaseCreateFailure explains a strict create that failed. removed says
// that what the server made without the registry recording it is gone again.
func databaseCreateFailure(kind, name string, removed bool, err error, secrets ...string) error {
	switch {
	case errors.Is(err, dbhost.ErrExists):
		// A plain message only: whose the name is stays unsaid.
		return huma.Error409Conflict("A " + kind + " named " + name + " already exists on this server. Choose another name.")
	case errors.Is(err, dbhost.ErrNotRegistered) && removed:
		return huma.Error500InternalServerError("The database server made the "+kind+" "+name+", but the panel could not record it, so the panel removed it again. Check that the panel's state directory can be written, then try again.", databaseTechnical(err, secrets...))
	case errors.Is(err, dbhost.ErrNotRegistered):
		return huma.Error500InternalServerError("The database server made the "+kind+" "+name+", but the panel could not record it and could not remove it again. Check that the panel's state directory can be written, then delete it here if it is listed.", databaseTechnical(err, secrets...))
	default:
		return databaseFailure(err, secrets...)
	}
}

// databaseFailure turns a database service error into the panel's answer.
func databaseFailure(err error, secrets ...string) error {
	return databaseFailureWith("", err, secrets...)
}

// databaseFailureWith is databaseFailure with its own plain message.
func databaseFailureWith(message string, err error, secrets ...string) error {
	if errors.Is(err, dbhost.ErrUnavailable) {
		if message == "" {
			message = databaseServerDown
		}
		return huma.Error503ServiceUnavailable(message, databaseTechnical(err, secrets...))
	}
	if message == "" {
		message = databaseRefused
	}
	return huma.Error502BadGateway(message, databaseTechnical(err, secrets...))
}

// databaseTechnical is the service's own text for "Technical details",
// scrubbed of the request's password.
func databaseTechnical(err error, secrets ...string) error {
	return errors.New(scrubDatabaseText(err.Error(), secrets...))
}

// scrubDatabaseText makes the database service's error text safe to answer
// with, the way the wizard scrubs it for a job record: each password
// removed, as typed and as the SQL statement escapes it, MariaDB's statement
// echo ("near '...'") cut off because it can quote the password, printable
// ASCII only, at most 512 bytes.
func scrubDatabaseText(text string, secrets ...string) string {
	escape := strings.NewReplacer(`\`, `\\`, `'`, `\'`)
	for _, s := range secrets {
		if s != "" {
			text = strings.ReplaceAll(strings.ReplaceAll(text, escape.Replace(s), "[secret]"), s, "[secret]")
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
	text = strings.Join(strings.Fields(string(b)), " ")
	if len(text) > databaseTextLimit {
		text = text[:databaseTextLimit]
	}
	return text
}
