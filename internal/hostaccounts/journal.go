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

// MaxHistoryRows bounds the rows one account's history holds; every request
// reads and checks them all (verifyHistory).
const MaxHistoryRows = 256

// The history is compacted so an account in use never runs out of rows. At
// the start of an operation, with no operation of any account unfinished,
// the history of every account that holds historyCompactAt rows or more is
// replaced, up to its last historyKeep rows, by one checkpoint row
// (compactHistory). The operations a tenant can reach stop operatorRows
// short of MaxHistoryRows; those rows stay for the operator's suspend,
// resume and delete and the broker's own conflict record. Compaction keeps
// every account far below both limits: they are the backstop for an
// account whose history could not be compacted.
const (
	historyCompactAt = 192
	historyKeep      = 32
	// operationRows is the room one operation needs: its intent, its
	// result, and a recovery_required row before a later result.
	operationRows = 3
	operatorRows  = 16
)

// A checkpoint row stands for the rows it replaced, the one at its own
// sequence included: its after is the account exactly as the last of them
// left it, settled. Only the first row of a compacted history is one, at the
// sequence the record names (HistoryStart), and the next intent's before
// must equal its after.
const (
	checkpointStatus = "checkpoint"
	checkpointActor  = "broker-compaction"
	checkpointReason = "Earlier history compacted into this row"
)

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

// firstHistorySequence is the sequence of an account's first kept row: its
// checkpoint's, or 1 (the create) for a history never compacted.
func firstHistorySequence(r record) uint64 {
	if r.HistoryStart == 0 {
		return 1
	}
	return r.HistoryStart
}

// historyLength is how many rows an account's history holds.
func historyLength(r record) uint64 { return r.HistorySequence + 1 - firstHistorySequence(r) }

// historyRoom reports whether an account's history has room for rows more:
// up to MaxHistoryRows for the operator's operations, and operatorRows
// fewer for those a tenant can reach.
func historyRoom(r record, rows uint64, operator bool) bool {
	limit := uint64(MaxHistoryRows)
	if !operator {
		limit -= operatorRows
	}
	return historyLength(r)+rows <= limit
}

func (s *store) appendEvent(r record, e operationEvent) (record, error) {
	if historyLength(r) >= MaxHistoryRows {
		return r, recovery(e.Action, r, "journal "+e.Status+" row: history full", ErrConflict)
	}
	r.HistorySequence++
	e.Sequence = r.HistorySequence
	e.Version = 1
	e.AccountID = r.Account.ID
	e.RecordedAt = time.Now().UTC()
	raw, _ := json.Marshal(e)
	state, _ := json.Marshal(r)
	// A record records() would refuse is never written: it would stop every
	// account. What tenants and the panel can send stays inside the bound
	// (TestLargestRecordFits); the broker's own paths are the operator's.
	if len(state) > maxRecordBytes {
		logRecovery(e.Action, r, "journal "+e.Status+" row: record too large", ErrInvalid)
		return r, ErrInvalid
	}
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
		return r, recovery(e.Action, r, "journal "+e.Status+" row", err)
	}
	return r, nil
}
func (s *store) beginOperation(r record, before *Account) (record, error) {
	if r.Pending == nil {
		return r, ErrConflict
	}
	if !historyRoom(r, operationRows, true) {
		logRecovery(r.Pending.Action, r, "journal intent: history full", ErrConflict)
		return r, ErrConflict
	}
	id, e := randomID()
	if e != nil {
		logRecovery(r.Pending.Action, r, "journal intent: operation ID", e)
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
		return r, recovery(p.Action, r, "journal "+status+" row: find its intent", e)
	}
	after := r.Account
	if status == "recovery_required" {
		after.State = "recovery_required"
	}
	event := operationEvent{OperationID: p.OperationID, Action: p.Action, Status: status, Actor: p.Actor, Reason: p.Reason, Before: intent.Before, After: after}
	return s.appendEvent(r, event)
}

// abandonedStatus ends a create the operator abandoned (endAbandonedCreate);
// finishedStatus a delete the operator finished (finishDelete).
const (
	abandonedStatus = "abandoned"
	finishedStatus  = "finished"
)

// endAbandonedCreate ends the unfinished create p of r, whose leftovers
// AbandonCreate removed: its last row is status abandoned, with the
// operator's actor and reason (endWithRecord).
func (s *store) endAbandonedCreate(r record, p pending, actor, reason string) error {
	if p.Action != "create" {
		return recovery("abandon_create", r, "find the create's intent", ErrRecovery)
	}
	return s.endWithRecord("abandon_create", r, p, abandonedStatus, actor, reason)
}

// endDelete ends the delete p of r, whose user, group, home, files and
// marker are gone: its last row is status (succeeded, reconciled at start,
// finished by the operator) with the actor and reason given
// (endWithRecord).
func (s *store) endDelete(r record, p pending, status, actor, reason string) error {
	if p.Action != "delete" {
		return recovery("delete", r, "find the delete's intent", ErrRecovery)
	}
	return s.endWithRecord("delete", r, p, status, actor, reason)
}

// endWithRecord ends p, r's pending operation, and removes its account. In
// one transaction it appends p's last row (this status, actor and reason,
// the account as the record left it) and removes the record and its cron
// sets. The record removed must be the stored one, read again in the
// transaction: r with p pending, unchanged. The rows stay for audit; replay
// reads only the histories of records that exist, so it never reads them
// again. A crash leaves the operation unfinished, or ended and its record
// gone: never one without the other. operation names it in the recovery
// log.
func (s *store) endWithRecord(operation string, r record, p pending, status, actor, reason string) error {
	intent, e := s.operationIntent(r, p)
	if e != nil || intent.Action != p.Action {
		return recovery(operation, r, "find the "+p.Action+"'s intent", ErrRecovery)
	}
	if historyLength(r) >= MaxHistoryRows {
		return recovery(operation, r, "journal "+status+" row: history full", ErrConflict)
	}
	row := operationEvent{Version: 1, Sequence: r.HistorySequence + 1, OperationID: p.OperationID, AccountID: r.Account.ID, Action: p.Action, Status: status, Actor: actor, Reason: reason, Before: intent.Before, After: r.Account, RecordedAt: time.Now().UTC()}
	raw, e := json.Marshal(row)
	if e != nil {
		return recovery(operation, r, "journal "+status+" row", e)
	}
	e = s.db.Update(func(tx *bolt.Tx) error {
		accounts, history := tx.Bucket(accountBucket), tx.Bucket(historyBucket)
		if accounts == nil || history == nil {
			return ErrRecovery
		}
		var stored record
		if v := accounts.Get([]byte(r.Account.ID)); v == nil || json.Unmarshal(v, &stored) != nil || stored.Pending == nil || *stored.Pending != p {
			return ErrRecovery
		}
		stored.Pending, r.Pending = nil, nil
		if stored != r {
			return ErrRecovery
		}
		key := eventKey(r.Account.ID, row.Sequence)
		if history.Get(key) != nil {
			return ErrRecovery
		}
		if err := history.Put(key, raw); err != nil {
			return err
		}
		if c := tx.Bucket(cronBucket); c != nil {
			if err := c.Delete([]byte(r.Account.ID)); err != nil {
				return err
			}
		}
		return accounts.Delete([]byte(r.Account.ID))
	})
	if e != nil {
		return recovery(operation, r, "journal "+status+" row and remove the record", e)
	}
	return nil
}

// compactHistories compacts the history of every settled account that holds
// s.compactAt rows or more, and answers the records as they are afterwards.
// The caller holds mu and has refreshed: no operation of any account is
// unfinished but a conflict adoptReady admits, whose account is skipped. A
// compaction that fails changes nothing (compactHistory runs in one
// transaction): the account keeps its history, which records() has just
// accepted, and the next operation tries again. Until then the account's
// own operations stop at the limits historyRoom sets, and no other
// account's do.
func (s *store) compactHistories(items []record) []record {
	if s.compactAt == 0 {
		return items
	}
	for i, r := range items {
		if r.Pending != nil || historyLength(r) < s.compactAt {
			continue
		}
		operationID, err := randomID()
		if err != nil {
			continue
		}
		var compacted record
		err = s.db.Update(func(tx *bolt.Tx) error {
			var e error
			compacted, e = compactHistory(tx, r, operationID, time.Now().UTC())
			return e
		})
		if err == nil {
			items[i] = compacted
		}
	}
	return items
}

// compactHistory replaces a settled account's rows before its last
// historyKeep with one checkpoint row, in tx, and answers the record with
// its new HistoryStart. The kept rows start at an intent, so the checkpoint
// takes the sequence just before it, and its after is that intent's before:
// the account as every earlier row left it, which verifyHistory has
// matched. The checkpoint, the removal of the rows it replaces and the
// record that names it are written in the one transaction, and they are
// verified before it commits, so a crash leaves the old history or the new
// one and never a mix. Sequences only grow: the next row follows the last
// kept one, as before.
func compactHistory(tx *bolt.Tx, r record, operationID string, now time.Time) (record, error) {
	accounts, history := tx.Bucket(accountBucket), tx.Bucket(historyBucket)
	if accounts == nil || history == nil || r.Pending != nil || !idPattern.MatchString(operationID) || now.IsZero() {
		return r, ErrRecovery
	}
	// The record compacted is the stored one, with a history records()
	// accepts.
	var stored record
	if raw := accounts.Get([]byte(r.Account.ID)); raw == nil || json.Unmarshal(raw, &stored) != nil || stored != r || verifyHistory(tx, r) != nil {
		return r, ErrRecovery
	}
	prefix := []byte(r.Account.ID + "/")
	var keys [][]byte
	var rows []operationEvent
	cursor := history.Cursor()
	for key, value := cursor.Seek(prefix); key != nil && bytes.HasPrefix(key, prefix); key, value = cursor.Next() {
		var row operationEvent
		if json.Unmarshal(value, &row) != nil {
			return r, ErrRecovery
		}
		keys, rows = append(keys, bytes.Clone(key)), append(rows, row)
	}
	cut := 0
	for i := max(1, len(rows)-historyKeep); i < len(rows); i++ {
		if rows[i].Status == "intended" {
			cut = i
			break
		}
	}
	if cut == 0 || rows[cut].Before == nil {
		return r, ErrRecovery
	}
	sequence := rows[cut].Sequence - 1
	if sequence <= r.HistoryStart {
		// Nothing before the kept rows but the checkpoint already there.
		return r, ErrConflict
	}
	checkpoint := operationEvent{Version: 1, Sequence: sequence, OperationID: operationID, AccountID: r.Account.ID, Action: checkpointStatus, Status: checkpointStatus, Actor: checkpointActor, Reason: checkpointReason, After: *rows[cut].Before, RecordedAt: now}
	raw, err := json.Marshal(checkpoint)
	if err != nil {
		return r, ErrRecovery
	}
	for _, key := range keys[:cut] {
		if err := history.Delete(key); err != nil {
			return r, err
		}
	}
	if err := history.Put(eventKey(r.Account.ID, sequence), raw); err != nil {
		return r, err
	}
	next := r
	next.HistoryStart = sequence
	state, err := json.Marshal(next)
	if err != nil || len(state) > maxRecordBytes {
		return r, ErrRecovery
	}
	if err := accounts.Put([]byte(r.Account.ID), state); err != nil {
		return r, err
	}
	if verifyHistory(tx, next) != nil {
		return r, ErrRecovery
	}
	return next, nil
}

func verifyHistory(tx *bolt.Tx, r record) error {
	b := tx.Bucket(historyBucket)
	first := firstHistorySequence(r)
	if b == nil || r.HistorySequence == 0 || r.HistorySequence < first || historyLength(r) > MaxHistoryRows {
		return ErrRecovery
	}
	cursor := b.Cursor()
	prefix := []byte(r.Account.ID + "/")
	sequence := first - 1
	var intent, lastSuccess operationEvent
	status := ""
	operations := map[string]bool{}
	for key, value := cursor.Seek(prefix); key != nil && bytes.HasPrefix(key, prefix); key, value = cursor.Next() {
		sequence++
		if sequence > r.HistorySequence {
			return ErrRecovery
		}
		var e operationEvent
		if json.Unmarshal(value, &e) != nil || e.Version != 1 || e.Sequence != sequence || !bytes.Equal(key, eventKey(r.Account.ID, sequence)) || e.AccountID != r.Account.ID || !idPattern.MatchString(e.OperationID) || !validText(e.Actor, 120) || !validText(e.Reason, 500) || e.RecordedAt.IsZero() || !sameIdentity(e.After, r.Account) || (e.Before != nil && !sameIdentity(*e.Before, r.Account)) {
			return ErrRecovery
		}
		// A compacted history starts at its checkpoint, the sequence its
		// record names, and has no other; one never compacted has none.
		if (e.Status == checkpointStatus) != (r.HistoryStart != 0 && sequence == r.HistoryStart) {
			return ErrRecovery
		}
		switch e.Status {
		case checkpointStatus:
			// It replaced the create's two rows at least, and stands for a
			// settled account.
			if sequence < 2 || e.Action != checkpointStatus || e.Actor != checkpointActor || e.Reason != checkpointReason || e.Before != nil || e.After.Revision == 0 || e.After.State != "active" && e.After.State != "suspended" {
				return ErrRecovery
			}
			operations[e.OperationID] = true
			lastSuccess = e
			status = e.Status
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
				if e.Before == nil || !sameAccount(*e.Before, lastSuccess.After) || e.Action != "state" && e.Action != "conflict" && e.Action != "plan" && e.Action != "delete" && e.Action != "ssh_keys" && e.Action != "web" && e.Action != "certificate" && e.Action != "adopt" && e.Action != "cron" && e.Action != "domains" && e.Action != "folders" {
					return ErrRecovery
				}
				// Neither a cron, a domains nor a folders change moves the
				// account's state: the last two are made only for an active
				// site.
				if (e.Action == "cron" || e.Action == "domains" || e.Action == "folders") && (e.After.Revision != e.Before.Revision+1 || e.After.State != e.Before.State) {
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
				// A domains or folders change ends rejected when the site list
				// with the new set failed its test.
				if e.Action != "web" && e.Action != "delete" && e.Action != "certificate" && e.Action != "state" && e.Action != "plan" && e.Action != "cron" && e.Action != "domains" && e.Action != "folders" || e.Before == nil || !sameAccount(e.After, *e.Before) {
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
		if status != "succeeded" && status != "reconciled" && status != "rejected" && status != checkpointStatus || !sameAccount(lastSuccess.After, r.Account) {
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
