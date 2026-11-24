package hostaccounts

import (
	"context"
	"io"
	"os"
	"sync"
	"syscall"

	"sifruno/internal/sitefiles"
)

// fakeFiles models the file helper for the fake: RunFiles runs the real
// helper code (sitefiles.Serve) in the account's home, which the fake makes
// as an ordinary folder of the test user. runs counts every run; when gate
// is set, each run signals started and waits for the gate, so a test can
// hold runs open.
type fakeFiles struct {
	mu      sync.Mutex
	runs    int
	fail    bool
	started chan string
	gate    chan struct{}
}

func (f *fakeNative) RunFiles(ctx context.Context, r record, stdin io.Reader, stdout io.Writer) error {
	f.files.mu.Lock()
	f.files.runs++
	fail, started, gate := f.files.fail, f.files.started, f.files.gate
	f.files.mu.Unlock()
	// The native run needs a deadline, as every site step does.
	if _, ok := ctx.Deadline(); !ok || fail {
		return ErrUnavailable
	}
	if started != nil {
		started <- r.Account.Username
		select {
		case <-gate:
		case <-ctx.Done():
			return ErrUnavailable
		}
	}
	if os.MkdirAll(r.Account.Home, 0o750) != nil {
		return ErrUnavailable
	}
	home, err := os.OpenFile(r.Account.Home, os.O_RDONLY|syscall.O_DIRECTORY, 0)
	if err != nil {
		return ErrUnavailable
	}
	defer home.Close()
	if sitefiles.Serve(home, stdin, stdout) != nil {
		return ErrUnavailable
	}
	return nil
}

func (f *fakeNative) fileRuns() int {
	f.files.mu.Lock()
	defer f.files.mu.Unlock()
	return f.files.runs
}
