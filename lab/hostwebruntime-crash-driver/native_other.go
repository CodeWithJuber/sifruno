//go:build !linux

package main

import "sifruno/internal/hostwebruntime"

func run() error   { return hostwebruntime.ErrUnavailable }
func child() error { return hostwebruntime.ErrUnavailable }
