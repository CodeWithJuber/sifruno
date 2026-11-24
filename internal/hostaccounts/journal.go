package hostaccounts

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"time"

	bolt "go.etcd.io/bbolt"
)

const MaxHistoryRows = 256

var historyBucket = []byte("hostaccount-operation-events-v1")

type operationEvent struct {
	Version     int       `json:"version"`
	Sequence    uint64    `json:"sequence"`
	OperationID string    `json:"operation_id"`
	AccountID   string    `json:"account_id"`
	Action      string    `json:"action"`
	Status      string    `json:"status"`
	Actor       string    `json:"actor"`
	Reason      string    `json:"reason"`
	Before      *Account  `json:"before"`
	After       Account   `json:"after"`
	RecordedAt  time.Time `json:"recorded_at"`
}

func randomID() (string, error) {
	var b [16]byte
	if _, e := rand.Read(b[:]); e != nil {
		return "", ErrUnavailable
	}
	return hex.EncodeToString(b[:]), nil
}
func eventKey(id string, sequence uint64) []byte {
	return []byte(fmt.Sprintf("%s/%020d", id, sequence))
}
func sameAccount(a, b Account) bool { return a == b }
func sameIdentity(a, b Account) bool {
	return a.ID == b.ID && a.Username == b.Username && a.Domain == b.Domain && a.Home == b.Home && a.PublicHTML == b.PublicHTML && a.UID == b.UID && a.GID == b.GID && a.CreatedAt.Equal(b.CreatedAt)
}
func (s *store) appendEvent(r record, e operationEvent) (record, error) {
	if r.HistorySequence >= MaxHistoryRows {
		return r, ErrRecovery
	}
	r.HistorySequence++
	e.Sequence = r.HistorySequence
	e.Version = 1
	e.AccountID = r.Account.ID
	e.RecordedAt = time.Now().UTC()
	raw, _ := json.Marshal(e)
	state, _ := json.Marshal(r)
	err := s.db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket(historyBucket)
		key := eventKey(r.Account.ID, e.Sequence)
		if b == nil || b.Get(key) != nil {
			return ErrRecovery
		}
		if err := b.Put(key, raw); err != nil {
			return err
		}
		return tx.Bucket(accountBucket).Put([]byte(r.Account.ID), state)
	})
	if err != nil {
		return r, ErrRecovery
	}
	return r, nil
}
func (s *store) beginOperation(r record, before *Account) (record, error) {
	if r.Pending == nil || r.HistorySequence > MaxHistoryRows-3 {
		return r, ErrConflict
	}
	id, e := randomID()
	if e != nil {
		return r, e
	}
	r.Pending.OperationID = id
	after := r.Account
	after.State = r.Pending.Target
	if before != nil && r.Pending.Action == "state" {
		after.Revision++
	}
	event := operationEvent{OperationID: id, Action: r.Pending.Action, Status: "intended", Actor: r.Pending.Actor, Reason: r.Pending.Reason, Before: before, After: after}
	return s.appendEvent(r, event)
}
func (s *store) operationIntent(r record, p pending) (operationEvent, error) {
	var intended operationEvent
	e := s.db.View(func(tx *bolt.Tx) error {
		cursor := tx.Bucket(historyBucket).Cursor()
		prefix := []byte(r.Account.ID + "/")
		for key, value := cursor.Seek(prefix); key != nil && bytes.HasPrefix(key, prefix); key, value = cursor.Next() {
			var row operationEvent
			if json.Unmarshal(value, &row) != nil {
				return ErrRecovery
			}
			if row.OperationID == p.OperationID && row.Status == "intended" {
				intended = row
				return nil
			}
		}
		return ErrRecovery
	})
	if e != nil {
		return intended, ErrRecovery
	}
	return intended, nil
}
func (s *store) resultEvent(r record, p pending, status string) (record, error) {
	intent, e := s.operationIntent(r, p)
	if e != nil {
		return r, e
	}
	after := r.Account
	if status == "recovery_required" {
		after.State = "recovery_required"
	}
	event := operationEvent{OperationID: p.OperationID, Action: p.Action, Status: status, Actor: p.Actor, Reason: p.Reason, Before: intent.Before, After: after}
	return s.appendEvent(r, event)
}
func verifyHistory(tx *bolt.Tx, r record) error {
	b := tx.Bucket(historyBucket)
	if b == nil || r.HistorySequence == 0 || r.HistorySequence > MaxHistoryRows {
		return ErrRecovery
	}
	cursor := b.Cursor()
	prefix := []byte(r.Account.ID + "/")
	sequence := uint64(0)
	var intent, lastSuccess operationEvent
	status := ""
	operations := map[string]bool{}
	for key, value := cursor.Seek(prefix); key != nil && bytes.HasPrefix(key, prefix); key, value = cursor.Next() {
		sequence++
		var e operationEvent
		if json.Unmarshal(value, &e) != nil || e.Version != 1 || e.Sequence != sequence || !bytes.Equal(key, eventKey(r.Account.ID, sequence)) || e.AccountID != r.Account.ID || !idPattern.MatchString(e.OperationID) || !validText(e.Actor, 120) || !validText(e.Reason, 500) || e.RecordedAt.IsZero() || !sameIdentity(e.After, r.Account) || (e.Before != nil && !sameIdentity(*e.Before, r.Account)) {
			return ErrRecovery
		}
		switch e.Status {
		case "intended":
			if operations[e.OperationID] || status == "intended" || status == "recovery_required" {
				return ErrRecovery
			}
			operations[e.OperationID] = true
			if sequence == 1 {
				if e.Action != "create" || e.Before != nil || e.After.Revision != 1 || e.After.State != "active" {
					return ErrRecovery
				}
			} else {
				if e.Before == nil || !sameAccount(*e.Before, lastSuccess.After) || e.Action != "state" && e.Action != "conflict" && e.Action != "plan" && e.Action != "delete" && e.Action != "ssh_keys" && e.Action != "web" && e.Action != "certificate" && e.Action != "adopt" && e.Action != "cron" && e.Action != "domains" {
					return ErrRecovery
				}
				if e.Action == "cron" && (e.After.Revision != e.Before.Revision+1 || e.After.State != e.Before.State) {
					return ErrRecovery
				}
				if e.Action == "state" && e.After.Revision != e.Before.Revision+1 || e.Action == "plan" && e.After.Revision != e.Before.Revision+1 || e.Action == "ssh_keys" && e.After.Revision != e.Before.Revision+1 || e.Action == "web" && e.After.Revision != e.Before.Revision+1 || e.Action == "certificate" && e.After.Revision != e.Before.Revision+1 || e.Action == "domains" && e.After.Revision != e.Before.Revision+1 || e.Action == "adopt" && (e.After.Revision != e.Before.Revision+1 || e.After.State != e.Before.State) || e.Action == "conflict" && e.After.Revision != e.Before.Revision || e.Action == "delete" && e.After.Revision != e.Before.Revision {
					return ErrRecovery
				}
			}
			intent = e
			status = e.Status
		case "succeeded", "reconciled", "recovery_required", "rejected":
			if e.OperationID != intent.OperationID || e.Action != intent.Action || e.Actor != intent.Actor || e.Reason != intent.Reason || status != "intended" && status != "recovery_required" {
				return ErrRecovery
			}
			beforeA, _ := json.Marshal(e.Before)
			beforeB, _ := json.Marshal(intent.Before)
			if !bytes.Equal(beforeA, beforeB) {
				return ErrRecovery
			}
			if e.Status == "recovery_required" {
				if status == "recovery_required" || e.After.State != "recovery_required" {
					return ErrRecovery
				}
			} else if e.Status == "rejected" {
				// Only an operation that rewrites the web config can end
				// rejected: the config test failed and the old files went back,
				// so the account is unchanged. A state change rewrites it for
				// an account with a live site, and also ends rejected when the
				// next start finds its account still in its old state. A
				// delete also ends rejected when it stopped before userdel
				// changed anything (a busy user, a failed /proc read, time
				// run out): nothing was removed and the site went back. A
				// plan change ends rejected when its limits could not be
				// written or loaded, or a live site's config with them failed
				// its test: the old drop-in and site list went back. A cron
				// change ends rejected when its crontab could not be written,
				// which changes nothing: the rename is the write's last step.
				// A domains change ends rejected when the site list with the
				// new set failed its test.
				if e.Action != "web" && e.Action != "delete" && e.Action != "certificate" && e.Action != "state" && e.Action != "plan" && e.Action != "cron" && e.Action != "domains" || e.Before == nil || !sameAccount(e.After, *e.Before) {
					return ErrRecovery
				}
				lastSuccess = e
			} else {
				if e.After.State != intent.After.State || e.After.Revision != intent.After.Revision {
					return ErrRecovery
				}
				lastSuccess = e
			}
			status = e.Status
		default:
			return ErrRecovery
		}
	}
	if sequence != r.HistorySequence {
		return ErrRecovery
	}
	if r.Pending == nil {
		if status != "succeeded" && status != "reconciled" && status != "rejected" || !sameAccount(lastSuccess.After, r.Account) {
			return ErrRecovery
		}
	} else {
		if r.Pending.OperationID != intent.OperationID || status != "intended" && status != "recovery_required" {
			return ErrRecovery
		}
		if intent.Before != nil && !sameAccount(*intent.Before, r.Account) {
			return ErrRecovery
		}
	}
	return nil
}
