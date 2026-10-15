package mailhost

// mail.lifecycle batch 3: autoresponders. The reference stores them under
// ~/.autorespond/; sifruno stores one JSON document per account in the
// panel state dir (autorespond/<account>.json), keyed by mailbox address.
// An autoresponder may only target an existing mailbox of the account.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// AutoResponder is one autoresponder configuration.
type AutoResponder struct {
	Email    string `json:"email"`    // mailbox that answers
	From     string `json:"from"`     // From: display value
	Subject  string `json:"subject"`  // reply subject
	Body     string `json:"body"`     // reply body
	IsHTML   bool   `json:"is_html"`  // body is HTML
	Interval int    `json:"interval"` // seconds between replies to the same sender (0 = every mail)
	Start    int64  `json:"start"`    // unix start; 0 = immediately
	Stop     int64  `json:"stop"`     // unix stop; 0 = never
}

// Validate checks an autoresponder before it is stored.
func (a AutoResponder) Validate() error {
	if a.Email == "" || !strings.Contains(a.Email, "@") {
		return errors.New("email is required")
	}
	if strings.ContainsAny(a.From, "\r\n") || strings.ContainsAny(a.Subject, "\r\n") {
		return errors.New("from/subject cannot contain line breaks")
	}
	if len(a.Subject) > 998 {
		return errors.New("subject exceeds RFC 5322 line limit")
	}
	if a.Interval < 0 {
		return errors.New("interval cannot be negative")
	}
	if a.Stop != 0 && a.Start != 0 && a.Stop < a.Start {
		return errors.New("stop time precedes start time")
	}
	return nil
}

func (s *LocalService) arPath(account string) string {
	return filepath.Join(s.State, "autorespond", account+".json")
}

func (s *LocalService) loadAR(account string) (map[string]AutoResponder, error) {
	out := map[string]AutoResponder{}
	raw, err := os.ReadFile(s.arPath(account))
	if errors.Is(err, os.ErrNotExist) {
		return out, nil
	}
	if err != nil {
		return nil, err
	}
	if err := json.Unmarshal(raw, &out); err != nil {
		return nil, err
	}
	return out, nil
}

func (s *LocalService) flushAR(account string, ars map[string]AutoResponder) error {
	if err := os.MkdirAll(filepath.Dir(s.arPath(account)), 0o700); err != nil {
		return err
	}
	raw, err := json.MarshalIndent(ars, "", "  ")
	if err != nil {
		return err
	}
	tmp := s.arPath(account) + ".tmp"
	if err := os.WriteFile(tmp, raw, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, s.arPath(account))
}

// AddAutoResponder stores an autoresponder for an existing mailbox of the
// account. Returns an error if the mailbox does not exist or belongs to
// another account.
func (s *LocalService) AddAutoResponder(ctx context.Context, account string, ar AutoResponder) error {
	if err := ar.Validate(); err != nil {
		return err
	}
	if err := s.load(); err != nil {
		return err
	}
	s.mu.Lock()
	m, ok := s.mailboxes[ar.Email]
	s.mu.Unlock()
	if !ok || m.Account != account {
		return fmt.Errorf("mailbox not found: %s", ar.Email)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	ars, err := s.loadAR(account)
	if err != nil {
		return err
	}
	ars[ar.Email] = ar
	return s.flushAR(account, ars)
}

// GetAutoResponder returns one autoresponder.
func (s *LocalService) GetAutoResponder(ctx context.Context, account, email string) (AutoResponder, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	ars, err := s.loadAR(account)
	if err != nil {
		return AutoResponder{}, err
	}
	ar, ok := ars[email]
	if !ok {
		return AutoResponder{}, errors.New("no autoresponder for " + email)
	}
	return ar, nil
}

// ListAutoResponders returns all autoresponders of the account. Active
// marks responders whose window includes now.
func (s *LocalService) ListAutoResponders(ctx context.Context, account string) ([]AutoResponder, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	ars, err := s.loadAR(account)
	if err != nil {
		return nil, err
	}
	out := make([]AutoResponder, 0, len(ars))
	for _, ar := range ars {
		out = append(out, ar)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Email < out[j].Email })
	return out, nil
}

// CountAutoResponders returns the number of autoresponders of the account.
func (s *LocalService) CountAutoResponders(ctx context.Context, account string) (int, error) {
	ars, err := s.ListAutoResponders(ctx, account)
	return len(ars), err
}

// DeleteAutoResponder removes the autoresponder of a mailbox.
func (s *LocalService) DeleteAutoResponder(ctx context.Context, account, email string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	ars, err := s.loadAR(account)
	if err != nil {
		return err
	}
	if _, ok := ars[email]; !ok {
		return errors.New("no autoresponder for " + email)
	}
	delete(ars, email)
	if len(ars) == 0 {
		if err := os.Remove(s.arPath(account)); err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
		return nil
	}
	return s.flushAR(account, ars)
}

// IsActiveNow reports whether the responder window includes t.
func (a AutoResponder) IsActiveNow(t time.Time) bool {
	u := t.Unix()
	if a.Start != 0 && u < a.Start {
		return false
	}
	if a.Stop != 0 && u > a.Stop {
		return false
	}
	return true
}
