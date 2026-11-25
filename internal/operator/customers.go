package operator

import (
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"regexp"
	"slices"
	"time"
)

// Customer logins. A customer (a site owner) signs in like an admin, with a
// username, a password and an authenticator code, and reaches only the
// websites (hosting accounts) an admin gave it. The admin never sees or
// sets the customer's password: the customer chooses it, and connects an
// authenticator app, through a one-time setup link the admin sends
// (customer_setup.go).
//
// customers.json sits next to admins.json and is kept the same way: 0600,
// bounded, written atomically, every field checked on read. A customer and
// an admin never share a username, so one sign-in form serves both.
//
// What a customer session may do is decided in two places: the operator
// package says who the session acts for (Principal), and the API's route
// table (internal/api/customer_routes.go) says which routes that may use.

const (
	customersFile     = "customers.json"
	maxCustomersBytes = 1 << 20
	maxCustomers      = 500
	// maxCustomerSites bounds one customer's websites, and with them the
	// request that sets them.
	maxCustomerSites = 64
	// setupLinkLifetime: a link is a credential sent over mail or chat, so it
	// works for a day only (Jev, 0.75). The admin can make a new one.
	setupLinkLifetime = 24 * time.Hour
)

var accountIDPattern = regexp.MustCompile(`^[a-f0-9]{32}$`)

// setupLink is the stored half of a setup link: the SHA-256 of its 256-bit
// secret, never the secret. The secret is random, so a plain hash is enough.
type setupLink struct {
	Hash      string    `json:"hash"`
	ExpiresAt time.Time `json:"expires_at"`
}

// customerRecord: Password and TOTP are set together once setup is done;
// until then Setup holds the link. Exactly one of the two is present.
type customerRecord struct {
	Username  string        `json:"username"`
	Websites  []string      `json:"websites"`
	Password  *passwordHash `json:"password,omitempty"`
	TOTP      *adminTOTP    `json:"totp,omitempty"`
	Setup     *setupLink    `json:"setup,omitempty"`
	Disabled  bool          `json:"disabled"`
	CreatedAt time.Time     `json:"created_at"`
}

type customerFile struct {
	Version   int              `json:"version"`
	Customers []customerRecord `json:"customers"`
}

// ready reports whether the customer can sign in: set up and not disabled.
func (c customerRecord) ready() bool { return c.Password != nil && c.TOTP != nil && !c.Disabled }

func (f *customerFile) find(username string) (int, bool) {
	if f == nil {
		return -1, false
	}
	for i, c := range f.Customers {
		if c.Username == username {
			return i, true
		}
	}
	return -1, false
}

// clone copies every record deeply. The manager publishes customer files as
// read-only snapshots (Manager.customers), so a change is always made on a
// clone and then stored whole.
func (f *customerFile) clone() customerFile {
	out := customerFile{Version: 1, Customers: make([]customerRecord, len(f.Customers))}
	for i, c := range f.Customers {
		c.Websites = slices.Clone(c.Websites)
		if c.Password != nil {
			p := *c.Password
			c.Password = &p
		}
		if c.TOTP != nil {
			t := *c.TOTP
			c.TOTP = &t
		}
		if c.Setup != nil {
			s := *c.Setup
			c.Setup = &s
		}
		out.Customers[i] = c
	}
	return out
}

// normalWebsites checks a list of hosting account IDs and returns it sorted
// and without repeats; ok is false for a malformed ID or too many.
func normalWebsites(ids []string) ([]string, bool) {
	if len(ids) > maxCustomerSites {
		return nil, false
	}
	out := make([]string, 0, len(ids))
	for _, id := range ids {
		if !accountIDPattern.MatchString(id) {
			return nil, false
		}
		out = append(out, id)
	}
	slices.Sort(out)
	return slices.Compact(out), true
}

func (f customerFile) validate(admins adminFile) error {
	if f.Version != 1 || len(f.Customers) > maxCustomers {
		return errors.New("unsupported customer file")
	}
	seen := map[string]bool{}
	for _, c := range f.Customers {
		websites, ok := normalWebsites(c.Websites)
		_, isAdmin := admins.find(c.Username)
		if !validUsername(c.Username) || seen[c.Username] || isAdmin || c.CreatedAt.IsZero() || !ok || !slices.Equal(websites, c.Websites) {
			return errors.New("invalid customer record")
		}
		switch {
		case c.Password != nil && c.TOTP != nil && c.Setup == nil:
			_, _, hashOK := c.Password.decode()
			_, secretOK := decodeTOTPSecret(c.TOTP.Secret)
			if !hashOK || !secretOK || c.TOTP.LastStep < 0 {
				return errors.New("invalid customer record")
			}
		case c.Password == nil && c.TOTP == nil && c.Setup != nil:
			hash, err := base64.RawStdEncoding.Strict().DecodeString(c.Setup.Hash)
			if err != nil || len(hash) != sha256.Size || c.Setup.ExpiresAt.IsZero() {
				return errors.New("invalid customer record")
			}
		default:
			return errors.New("invalid customer record")
		}
		seen[c.Username] = true
	}
	return nil
}

// loadCustomers reads customers.json with the checks admins.json gets. A
// missing file means no customer exists yet.
func loadCustomers(dir string, admins adminFile) (customerFile, error) {
	var out customerFile
	found, err := readPrivateJSON(dir, customersFile, maxCustomersBytes, &out)
	if err != nil {
		return customerFile{}, err
	}
	if !found {
		return customerFile{Version: 1, Customers: []customerRecord{}}, nil
	}
	for i := range out.Customers {
		if out.Customers[i].Websites == nil {
			out.Customers[i].Websites = []string{}
		}
	}
	if err := out.validate(admins); err != nil {
		return customerFile{}, err
	}
	return out, nil
}

// saveCustomers replaces customers.json atomically, after the same checks a
// read makes. Called with adminMu held.
func saveCustomers(dir string, file customerFile, admins adminFile) error {
	if err := file.validate(admins); err != nil {
		return err
	}
	return writePrivateJSON(dir, customersFile, maxCustomersBytes, file)
}
