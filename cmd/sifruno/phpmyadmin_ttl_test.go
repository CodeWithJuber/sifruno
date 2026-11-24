//go:build !sifruno_proof

package main

import (
	"flag"
	"testing"
)

// A release build keeps the hour: it has no flag that shortens it.
func TestReleaseBuildHasNoShortPhpMyAdminLogin(t *testing.T) {
	if flag.Lookup("phpmyadmin-test-login-ttl") != nil {
		t.Fatal("the proof-only flag is in a build without the sifruno_proof tag")
	}
	if phpMyAdminLoginTTL() != 0 {
		t.Fatal("a build without the sifruno_proof tag changes the login lifetime")
	}
}
