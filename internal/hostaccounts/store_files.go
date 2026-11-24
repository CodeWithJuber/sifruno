package hostaccounts

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"io"

	"sifruno/internal/sitefiles"
)

// fileReady looks the account up under the broker lock and counts the run
// against the account's maxFileRuns; release gives the place back. The
// helper itself runs outside the lock.
//
// A file operation changes no record and touches nothing outside the
// tenant's home, so only this account must have no unfinished operation of
// its own (an account mid-delete runs nothing); another account's does not
// stop it, as for backups. What only root controls (the account's user,
// group, home object and ownership marker) is checked again here, so the
// helper starts only with the UID that belongs to this account now.
//
// Suspended: reads (list, read, download) are allowed, so an operator can
// look at a suspended site and take its files; changes are refused, so a
// suspension stays a freeze until the site is resumed. Changes are also
// refused while a WordPress install or a restore writes into the home.
func (s *store) fileReady(ctx context.Context, id string, write bool) (record, func(), error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.web == nil {
		return record{}, nil, ErrUnavailable
	}
	if ctx.Err() != nil || s.healthy() != nil {
		return record{}, nil, ErrUnavailable
	}
	if s.refresh(ctx, false) != nil {
		return record{}, nil, ErrRecovery
	}
	items, err := s.records()
	if err != nil {
		return record{}, nil, err
	}
	for _, r := range items {
		if r.Account.ID != id {
			continue
		}
		if r.Pending != nil || r.Account.State == "recovery_required" {
			return record{}, nil, ErrRecovery
		}
		switch {
		case r.Account.State != "active" && r.Account.State != "suspended":
			return record{}, nil, ErrConflict
		case write && (r.Account.State != "active" || s.installing[id]):
			return record{}, nil, ErrConflict
		case s.fileRuns[id] >= maxFileRuns:
			return record{}, nil, ErrConflict
		}
		if s.native.VerifyAccountIdentity(r) != nil {
			return record{}, nil, ErrConflict
		}
		if s.fileRuns == nil {
			s.fileRuns = map[string]int{}
		}
		s.fileRuns[id]++
		return r, func() {
			s.mu.Lock()
			if s.fileRuns[id]--; s.fileRuns[id] <= 0 {
				delete(s.fileRuns, id)
			}
			s.mu.Unlock()
		}, nil
	}
	return record{}, nil, ErrNotFound
}

// errFileStream stops a run whose answer was refused or whose reader went
// away.
var errFileStream = errors.New("file helper stream stopped")

// runFile runs one request through the helper and checks its answer.
// For write and upload, body holds exactly req.Size bytes. For read and
// download, sink is called with the checked answer and gets the file's
// bytes, exactly answer.File.Size of them; a sink that fails stops the
// helper. The answer comes from a process with the tenant's rights, so it
// is bounded and checked (sitefiles.ParseAnswer) before anything of it is
// used, and a helper that writes more than it promised is a failure.
func (s *store) runFile(ctx context.Context, id, actor string, req sitefiles.Request, body io.Reader, sink func(sitefiles.Answer) (io.Writer, error)) (sitefiles.Answer, error) {
	if ctx == nil {
		return sitefiles.Answer{}, ErrInvalid
	}
	if snapshotReentry(ctx, s) {
		return sitefiles.Answer{}, ErrConflict
	}
	if !validFileCall(id, actor, req) || sitefiles.Sends(req.Op) != (body != nil) || sitefiles.Streams(req.Op) != (sink != nil) {
		return sitefiles.Answer{}, ErrInvalid
	}
	r, release, err := s.fileReady(ctx, id, fileWrites(req.Op))
	if err != nil {
		return sitefiles.Answer{}, err
	}
	defer release()
	line, err := sitefiles.EncodeLine(req)
	if err != nil {
		return sitefiles.Answer{}, ErrInvalid
	}
	input := io.Reader(bytes.NewReader(line))
	if body != nil {
		input = io.MultiReader(input, io.LimitReader(body, req.Size))
	}
	run, cancel := context.WithTimeout(context.WithoutCancel(ctx), fileLimit(req.Op))
	defer cancel()
	pr, pw := io.Pipe()
	done := make(chan error, 1)
	go func() {
		e := s.native.RunFiles(run, r, input, pw)
		pw.CloseWithError(io.EOF)
		done <- e
	}()
	// stop ends the helper and waits for it, so nothing outlives the call.
	stop := func() {
		cancel()
		pr.CloseWithError(errFileStream)
		<-done
	}
	out := bufio.NewReaderSize(pr, 64<<10)
	answerLine, err := sitefiles.ReadLine(out, sitefiles.MaxAnswerLine)
	if err != nil {
		stop()
		return sitefiles.Answer{}, ErrUnavailable
	}
	a, err := sitefiles.ParseAnswer(req, answerLine)
	if err != nil {
		stop()
		return sitefiles.Answer{}, ErrUnavailable
	}
	if a.Error != "" {
		// A refusal stands even if the helper then ended badly: an upload it
		// refused before reading the bytes ends when the bytes cannot be
		// sent.
		stop()
		return sitefiles.Answer{}, &FileError{Code: a.Error}
	}
	if sink != nil {
		w, err := sink(a)
		if err != nil {
			stop()
			return sitefiles.Answer{}, err
		}
		if _, err := io.CopyN(w, out, a.File.Size); err != nil {
			stop()
			return sitefiles.Answer{}, ErrUnavailable
		}
	}
	if _, err := out.ReadByte(); !errors.Is(err, io.EOF) {
		stop()
		return sitefiles.Answer{}, ErrUnavailable
	}
	if err := <-done; err != nil {
		return sitefiles.Answer{}, ErrUnavailable
	}
	return a, nil
}
