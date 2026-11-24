// Package phpmyadmin opens phpMyAdmin for one website, already signed in.
//
// A click on the website's Databases page makes a temporary MariaDB user
// (dbhost's SifrunoPMA_ users) with every privilege on that website's
// databases only and a random password, and a handoff code. The browser
// opens phpMyAdmin's sign-in script (scripts/install/phpmyadmin) with the
// code; the script, running as phpMyAdmin's own system user, redeems it once
// on a Unix socket only that user may use (redeem.go), puts the login in
// phpMyAdmin's signon session and sends the browser on. The password lives
// in this process's memory until the code is redeemed, then only in that
// session; it is never in a URL, a log, the browser or a process argument.
//
// A code works once and for CodeTTL. A temporary user lasts LoginTTL; its
// name and expiry are recorded in StateDir before the user is made, and the
// sweeper drops expired users, ends their connections, and drops any
// SifrunoPMA_ user the record does not hold (left by a crash).
//
// phpMyAdmin has its own origin: the panel's host names on another HTTPS
// port (origin.go), never the panel's. A phpMyAdmin page can therefore read
// nothing from the panel, whose API refuses its Origin. A browser is let in
// there by an admission cookie made when its code is redeemed, bound to the
// temporary user and ending with it; the proxy in proxy.go passes admitted
// requests to OpenLiteSpeed's loopback listener.
//
// Known limits:
//   - Browsers keep cookies apart by host name and path, not by port. A
//     script on a phpMyAdmin page (an XSS from a tenant's table names or
//     data) can therefore set cookies the browser also sends to the panel's
//     host, a sifruno_operator for a /api/v1 path among them, and so sign
//     the admin out of the panel or make its requests fail. It cannot read
//     the panel's session cookie (HttpOnly, sent only to /api/v1, which
//     phpMyAdmin's origin never serves), cannot read the panel's answers,
//     and cannot forge a session: the cookie is sealed with the panel's own
//     keys.
//   - OpenLiteSpeed's phpMyAdmin listener is on loopback, so any local
//     user, a tenant's PHP or cron job included, can reach phpMyAdmin there
//     directly. It admits no one without a code: phpMyAdmin then sends the
//     browser to the sign-in script, and a code redeems only once, only for
//     phpMyAdmin's own user on the socket.
package phpmyadmin

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"sifruno/internal/dbhost"
)

const (
	// SignonPath is the shipped sign-in script on phpMyAdmin's origin, where
	// phpMyAdmin is served at the root.
	SignonPath = "/sifruno-signon.php"

	// LoginTTL is how long a temporary user lasts.
	LoginTTL = time.Hour
	// CodeTTL is how long a handoff code can be redeemed.
	CodeTTL = 60 * time.Second
	// SweepEvery is how often the sweeper looks for expired users.
	SweepEvery = time.Minute
	// MaxLogins bounds the temporary users at one time; each click makes one.
	MaxLogins = 100
	// MaxLoginsPerOwner bounds the open temporary users of one hosting
	// account for one actor, so no one can use up MaxLogins for everyone.
	MaxLoginsPerOwner = 3
	// MaxLoginsPerActor bounds one actor's open temporary users across all
	// accounts, so a customer with many websites cannot use up MaxLogins
	// either.
	MaxLoginsPerActor = 10
	// MaxAdmissions bounds the admission cookies at one time; each redeemed
	// code makes one.
	MaxAdmissions = 4 * MaxLogins

	stateFile = "logins.json"
	maxState  = 1 << 20
)

var (
	// ErrTooMany is returned when MaxLogins temporary users exist already.
	ErrTooMany = errors.New("too many phpMyAdmin sign-ins are open")
	// ErrTooManyForOwner is returned when the account already has
	// MaxLoginsPerOwner open temporary users for this actor.
	ErrTooManyForOwner = errors.New("this website has the most phpMyAdmin sign-ins open that one person may have")
	// ErrTooManyForActor is returned when the actor already has
	// MaxLoginsPerActor open temporary users across all accounts.
	ErrTooManyForActor = errors.New("this person has the most phpMyAdmin sign-ins open across all websites")
	// ErrCodeRefused covers a code that is unknown, used or expired: the
	// answer never tells which.
	ErrCodeRefused = errors.New("the code is unknown, used or expired")
	// ErrNotRecorded is returned when the record of temporary users cannot be
	// written, so no user is made.
	ErrNotRecorded = errors.New("the record of phpMyAdmin sign-ins could not be written")

	codePattern = regexp.MustCompile(`^[A-Za-z0-9_-]{43}$`)
)

// Database is the part of dbhost.LocalService the sign-ins use.
type Database interface {
	CreateSignonUser(ctx context.Context, owner, name, password string, databases []string) error
	DropSignonUser(ctx context.Context, name string) error
	SignonUsers(ctx context.Context) ([]string, error)
}

// Config sets up a Service. Zero durations take the package defaults.
type Config struct {
	StateDir string
	Database Database
	// PublicPort is the port of phpMyAdmin's HTTPS origin.
	PublicPort int
	LoginTTL   time.Duration
	CodeTTL    time.Duration
	Now        func() time.Time
}

// Handoff is what the browser needs to open phpMyAdmin: the sign-in
// script's path with the code (SignonURL makes the address), and when the
// code and the login end.
type Handoff struct {
	Path         string
	CodeExpires  time.Time
	LoginExpires time.Time
}

// Login is what a redeemed code hands to the sign-in script.
type Login struct {
	User     string
	Password string
	Expires  time.Time
}

type record struct {
	User    string    `json:"user"`
	Owner   string    `json:"owner"`
	Actor   string    `json:"actor,omitempty"`
	Expires time.Time `json:"expires_at"`
}

type stateData struct {
	Logins []record `json:"logins"`
}

type pending struct {
	login   Login
	expires time.Time
}

// Service makes and sweeps the temporary users and holds the codes.
type Service struct {
	cfg  Config
	path string

	mu     sync.Mutex
	logins map[string]record
	codes  map[string]pending
	// admissions maps an admission cookie's value to its temporary user.
	admissions map[string]string
	sweepMu    sync.Mutex
}

// New reads the record in StateDir, made 0700 if absent.
func New(cfg Config) (*Service, error) {
	if cfg.Database == nil || cfg.StateDir == "" {
		return nil, errors.New("phpmyadmin: a database service and a state folder are required")
	}
	if cfg.PublicPort < 1 || cfg.PublicPort > 65535 {
		return nil, errors.New("phpmyadmin: the port of phpMyAdmin's origin is required")
	}
	if cfg.LoginTTL <= 0 {
		cfg.LoginTTL = LoginTTL
	}
	if cfg.CodeTTL <= 0 {
		cfg.CodeTTL = CodeTTL
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	if err := os.MkdirAll(cfg.StateDir, 0o700); err != nil {
		return nil, err
	}
	s := &Service{cfg: cfg, path: filepath.Join(cfg.StateDir, stateFile), logins: map[string]record{}, codes: map[string]pending{}, admissions: map[string]string{}}
	raw, err := os.ReadFile(s.path)
	switch {
	case errors.Is(err, os.ErrNotExist):
	case err != nil:
		return nil, err
	case len(raw) > maxState:
		return nil, fmt.Errorf("phpmyadmin: %s is larger than %d bytes", s.path, maxState)
	default:
		var data stateData
		if err := json.Unmarshal(raw, &data); err != nil {
			return nil, fmt.Errorf("phpmyadmin: %s: %w", s.path, err)
		}
		for _, r := range data.Logins {
			// A name that is not a temporary user's is never dropped.
			if dbhost.ValidSignonUser(r.User) {
				s.logins[r.User] = r
			}
		}
	}
	return s, nil
}

// LoginTTL is how long the temporary users this service makes last.
func (s *Service) LoginTTL() time.Duration { return s.cfg.LoginTTL }

// flushLocked writes the record atomically, 0600. s.mu is held.
func (s *Service) flushLocked() error {
	data := stateData{Logins: make([]record, 0, len(s.logins))}
	for _, r := range s.logins {
		data.Logins = append(data.Logins, r)
	}
	raw, err := json.Marshal(data)
	if err != nil {
		return err
	}
	tmp := s.path + ".tmp"
	if err := os.WriteFile(tmp, raw, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, s.path)
}

func random(n int) ([]byte, error) {
	b := make([]byte, n)
	_, err := rand.Read(b)
	return b, err
}

type actorKey struct{}

// WithActor names who asks to open phpMyAdmin (the panel's actor for the
// request), for MaxLoginsPerOwner.
func WithActor(ctx context.Context, actor string) context.Context {
	return context.WithValue(ctx, actorKey{}, actor)
}

func actorFrom(ctx context.Context) string {
	actor, _ := ctx.Value(actorKey{}).(string)
	return actor
}

// Open makes a temporary user with every privilege on databases, which must
// all be owner's, and a code for it. The user is recorded before it is made,
// so a crash in between leaves nothing the sweeper does not find.
func (s *Service) Open(ctx context.Context, owner string, databases []string) (Handoff, error) {
	if owner == "" || len(databases) == 0 {
		return Handoff{}, errors.New("phpmyadmin: an owner and at least one database are required")
	}
	for attempt := 0; ; attempt++ {
		h, err := s.open(ctx, owner, databases)
		// A random name the server already has: try another, once.
		if errors.Is(err, dbhost.ErrExists) && attempt == 0 {
			continue
		}
		return h, err
	}
}

func (s *Service) open(ctx context.Context, owner string, databases []string) (Handoff, error) {
	nameBytes, err := random(10)
	if err != nil {
		return Handoff{}, err
	}
	secret, err := random(32)
	if err != nil {
		return Handoff{}, err
	}
	codeBytes, err := random(32)
	if err != nil {
		return Handoff{}, err
	}
	user := dbhost.SignonUserPrefix + hex.EncodeToString(nameBytes)
	password := base64.RawURLEncoding.EncodeToString(secret)
	code := base64.RawURLEncoding.EncodeToString(codeBytes)
	now := s.cfg.Now()
	actor := actorFrom(ctx)
	login := record{User: user, Owner: owner, Actor: actor, Expires: now.Add(s.cfg.LoginTTL).UTC().Truncate(time.Second)}

	s.mu.Lock()
	if len(s.logins) >= MaxLogins {
		s.mu.Unlock()
		return Handoff{}, ErrTooMany
	}
	open, openByActor := 0, 0
	for _, r := range s.logins {
		if r.Actor == actor && now.Before(r.Expires) {
			openByActor++
			if r.Owner == owner {
				open++
			}
		}
	}
	if open >= MaxLoginsPerOwner {
		s.mu.Unlock()
		return Handoff{}, ErrTooManyForOwner
	}
	if openByActor >= MaxLoginsPerActor {
		s.mu.Unlock()
		return Handoff{}, ErrTooManyForActor
	}
	s.logins[user] = login
	if err := s.flushLocked(); err != nil {
		delete(s.logins, user)
		s.mu.Unlock()
		return Handoff{}, fmt.Errorf("%w: %v", ErrNotRecorded, err)
	}
	s.mu.Unlock()

	if err := s.cfg.Database.CreateSignonUser(ctx, owner, user, password, databases); err != nil {
		// dbhost drops a user whose grant failed, and a refused create made
		// nothing, so the record can go. If the drop failed, the sweeper
		// finds the user on the server.
		s.mu.Lock()
		delete(s.logins, user)
		_ = s.flushLocked()
		s.mu.Unlock()
		return Handoff{}, scrub(err, password)
	}

	codeExpires := now.Add(s.cfg.CodeTTL)
	s.mu.Lock()
	s.pruneCodesLocked(now)
	s.codes[code] = pending{login: Login{User: user, Password: password, Expires: login.Expires}, expires: codeExpires}
	s.mu.Unlock()
	return Handoff{Path: SignonPath + "?code=" + code, CodeExpires: codeExpires, LoginExpires: login.Expires}, nil
}

// SignonURL is h's address on phpMyAdmin's origin for host, one of the
// panel's host names.
func (s *Service) SignonURL(host string, h Handoff) string {
	return "https://" + net.JoinHostPort(host, strconv.Itoa(s.cfg.PublicPort)) + h.Path
}

// scrub keeps a database error's kind but takes the password out of its
// text: MariaDB can quote the statement that failed.
func scrub(err error, password string) error {
	for _, kind := range []error{dbhost.ErrUnavailable, dbhost.ErrExists} {
		if errors.Is(err, kind) {
			if err == kind {
				return kind
			}
			return fmt.Errorf("%w: %s", kind, strings.ReplaceAll(err.Error(), password, "[secret]"))
		}
	}
	return errors.New(strings.ReplaceAll(err.Error(), password, "[secret]"))
}

func (s *Service) pruneCodesLocked(now time.Time) {
	for code, p := range s.codes {
		if !now.Before(p.expires) {
			delete(s.codes, code)
		}
	}
}

// liveLocked reports whether user's login is recorded and unexpired.
func (s *Service) liveLocked(user string, now time.Time) (record, bool) {
	r, ok := s.logins[user]
	return r, ok && now.Before(r.Expires)
}

// Peek reports the temporary user a code would sign in as, without using the
// code up: phpMyAdmin's origin admits the sign-in request that carries it.
func (s *Service) Peek(code string) (string, bool) {
	if !codePattern.MatchString(code) {
		return "", false
	}
	now := s.cfg.Now()
	s.mu.Lock()
	defer s.mu.Unlock()
	p, ok := s.codes[code]
	if !ok || !now.Before(p.expires) {
		return "", false
	}
	if _, live := s.liveLocked(p.login.User, now); !live {
		return "", false
	}
	return p.login.User, true
}

// Admit makes an admission cookie's value for user's live login, after its
// code was redeemed. It ends when the login does.
func (s *Service) Admit(user string) (string, time.Time, error) {
	raw, err := random(32)
	if err != nil {
		return "", time.Time{}, err
	}
	token := base64.RawURLEncoding.EncodeToString(raw)
	now := s.cfg.Now()
	s.mu.Lock()
	defer s.mu.Unlock()
	r, live := s.liveLocked(user, now)
	if !live {
		return "", time.Time{}, ErrCodeRefused
	}
	if len(s.admissions) >= MaxAdmissions {
		s.pruneAdmissionsLocked(now)
		if len(s.admissions) >= MaxAdmissions {
			return "", time.Time{}, ErrTooMany
		}
	}
	s.admissions[token] = user
	return token, r.Expires, nil
}

// Admitted reports whether an admission cookie's value lets a browser in:
// it was made here and its temporary user is still recorded and unexpired.
func (s *Service) Admitted(token string) bool {
	if !codePattern.MatchString(token) {
		return false
	}
	now := s.cfg.Now()
	s.mu.Lock()
	defer s.mu.Unlock()
	user, ok := s.admissions[token]
	if !ok {
		return false
	}
	if _, live := s.liveLocked(user, now); !live {
		delete(s.admissions, token)
		return false
	}
	return true
}

// Revoke ends an admission cookie's value, at sign-out.
func (s *Service) Revoke(token string) {
	s.mu.Lock()
	delete(s.admissions, token)
	s.mu.Unlock()
}

func (s *Service) pruneAdmissionsLocked(now time.Time) {
	for token, user := range s.admissions {
		if _, live := s.liveLocked(user, now); !live {
			delete(s.admissions, token)
		}
	}
}

// Redeem hands out the login for code once. The code is gone after the first
// attempt, whatever its outcome; an unknown, used or expired code, or one
// whose temporary user has expired or was dropped, is ErrCodeRefused.
func (s *Service) Redeem(code string) (Login, error) {
	if !codePattern.MatchString(code) {
		return Login{}, ErrCodeRefused
	}
	now := s.cfg.Now()
	s.mu.Lock()
	defer s.mu.Unlock()
	p, ok := s.codes[code]
	delete(s.codes, code)
	if !ok || !now.Before(p.expires) {
		return Login{}, ErrCodeRefused
	}
	if _, live := s.liveLocked(p.login.User, now); !live {
		return Login{}, ErrCodeRefused
	}
	return p.login, nil
}

// Sweep drops every expired temporary user and ends its connections, then
// drops any temporary user on the server the record does not hold. A user
// whose drop fails stays recorded and is tried again at the next sweep.
func (s *Service) Sweep(ctx context.Context) error {
	s.sweepMu.Lock()
	defer s.sweepMu.Unlock()
	now := s.cfg.Now()
	var expired []string
	s.mu.Lock()
	for user, r := range s.logins {
		if !now.Before(r.Expires) {
			expired = append(expired, user)
		}
	}
	s.pruneCodesLocked(now)
	s.pruneAdmissionsLocked(now)
	s.mu.Unlock()

	var errs []error
	for _, user := range expired {
		if err := s.cfg.Database.DropSignonUser(ctx, user); err != nil {
			errs = append(errs, fmt.Errorf("drop %s: %w", user, err))
			continue
		}
		s.mu.Lock()
		delete(s.logins, user)
		if err := s.flushLocked(); err != nil {
			errs = append(errs, fmt.Errorf("record: %w", err))
		}
		s.mu.Unlock()
	}

	// Listed first, compared after: Open records a user before it makes it,
	// so any user the server has by now is in the record unless it is an
	// orphan.
	onServer, err := s.cfg.Database.SignonUsers(ctx)
	if err != nil {
		return errors.Join(append(errs, fmt.Errorf("list: %w", err))...)
	}
	for _, user := range onServer {
		s.mu.Lock()
		_, known := s.logins[user]
		s.mu.Unlock()
		if known {
			continue
		}
		if err := s.cfg.Database.DropSignonUser(ctx, user); err != nil {
			errs = append(errs, fmt.Errorf("drop unrecorded %s: %w", user, err))
		}
	}
	return errors.Join(errs...)
}

// Run sweeps now and then every SweepEvery until ctx ends; report gets each
// failed sweep's error.
func (s *Service) Run(ctx context.Context, report func(error)) {
	sweep := func() {
		c, cancel := context.WithTimeout(ctx, 30*time.Second)
		defer cancel()
		if err := s.Sweep(c); err != nil && report != nil {
			report(err)
		}
	}
	sweep()
	t := time.NewTicker(SweepEvery)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			sweep()
		}
	}
}
