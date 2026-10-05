//go:build windows

package hostwebruntime

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"sifruno/internal/hostwebgeneration"
)

func TestReviewWindowsCannotCreateOrActivateNativeRuntime(t *testing.T) {
	root := filepath.Join(t.TempDir(), "must-remain-absent")
	runtime, err := Open(Options{Root: root, Profile: reviewProfile()})
	if runtime != nil || !errors.Is(err, ErrUnavailable) {
		t.Fatalf("Windows admitted native runtime: %v", err)
	}
	if _, err := os.Lstat(root); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("unavailable Open created filesystem state")
	}
	var unavailable *Runtime
	var executor hostwebgeneration.Executor = unavailable
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	for _, input := range []context.Context{context.Background(), ctx, nil} {
		identity, err := executor.Observe(input)
		if identity != (hostwebgeneration.Identity{}) || !errors.Is(err, ErrUnavailable) {
			t.Fatal("Windows Observe returned serving identity")
		}
		if !errors.Is(unavailable.Bootstrap(input, hostwebgeneration.Generation{}), ErrUnavailable) || !errors.Is(executor.Apply(input, hostwebgeneration.Transition{}), ErrUnavailable) || !errors.Is(executor.Rollback(input, hostwebgeneration.Transition{}, hostwebgeneration.Generation{}), ErrUnavailable) || !errors.Is(unavailable.Shutdown(input), ErrUnavailable) {
			t.Fatal("Windows activation/cleanup path failed to reject unavailable runtime")
		}
	}
	if err := unavailable.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(root); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("Windows methods created filesystem state")
	}
}
