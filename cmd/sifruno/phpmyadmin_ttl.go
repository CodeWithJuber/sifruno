//go:build !sifruno_proof

package main

import "time"

// phpMyAdminLoginTTL is how long a temporary phpMyAdmin user lasts: zero is
// phpmyadmin.LoginTTL, one hour. A release build has no way to change it;
// only a binary built with the sifruno_proof tag (scripts/devvm/proof.sh
// phpmyadmin) takes a shorter one.
func phpMyAdminLoginTTL() time.Duration { return 0 }
