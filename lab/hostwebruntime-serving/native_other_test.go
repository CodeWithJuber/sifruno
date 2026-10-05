//go:build !linux

package main

import (
	"errors"
	"testing"

	"sifruno/internal/hostwebruntime"
)

func TestUnavailablePlatform(t *testing.T) {
	if !errors.Is(run(), hostwebruntime.ErrUnavailable) {
		t.Fatal("non-Linux driver admitted execution")
	}
}
