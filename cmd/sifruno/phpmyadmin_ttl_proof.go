//go:build sifruno_proof

package main

import (
	"flag"
	"fmt"
	"os"
	"time"
)

// This file is built only with the sifruno_proof tag, which the dev VM's
// phpMyAdmin proof sets and scripts/install/build-release.sh never does, so
// a release binary has no such flag and cannot be given one by mistake.
var proofLoginTTL = flag.Duration("phpmyadmin-test-login-ttl", 0, "Proof builds only: how long a temporary phpMyAdmin user lasts, 1m to 1h, so the dev VM proof sees one expire; 0 is the normal hour")

func phpMyAdminLoginTTL() time.Duration {
	d := *proofLoginTTL
	if d != 0 && (d < time.Minute || d > time.Hour) {
		fmt.Fprintln(os.Stderr, "--phpmyadmin-test-login-ttl must be between 1m and 1h")
		os.Exit(2)
	}
	if d != 0 {
		fmt.Fprintf(os.Stderr, "PROOF BUILD: temporary phpMyAdmin users last %s, not an hour\n", d)
	}
	return d
}
