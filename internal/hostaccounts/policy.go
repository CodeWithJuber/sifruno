package hostaccounts

import (
	"bytes"
	"strings"
)

const maxNSSPolicyBytes = 4 << 20
const maxUseraddDefaultsBytes = 4096

// filesOnlyNSS accepts only the existing local account authority. NUL is
// refused anywhere because libc and Go must not interpret different inputs.
func filesOnlyNSS(b []byte) error {
	if len(b) > maxNSSPolicyBytes || bytes.IndexByte(b, 0) >= 0 {
		return ErrUnavailable
	}
	found := map[string]bool{}
	for _, line := range strings.Split(string(b), "\n") {
		line = strings.SplitN(line, "#", 2)[0]
		key, value, ok := strings.Cut(line, ":")
		key = strings.TrimSpace(key)
		if !ok || (key != "passwd" && key != "group" && key != "shadow") {
			continue
		}
		if found[key] || strings.TrimSpace(value) != "files" {
			return ErrUnavailable
		}
		found[key] = true
	}
	if !found["passwd"] || !found["group"] || !found["shadow"] {
		return ErrUnavailable
	}
	return nil
}

// Shadow reads this key from useradd defaults, not login.defs/-K. Require
// exactly the literal that the supported utility will interpret as disabled.
func mailDisabledDefaults(b []byte) error {
	if len(b) > maxUseraddDefaultsBytes || bytes.IndexByte(b, 0) >= 0 {
		return ErrUnavailable
	}
	found := false
	for _, line := range strings.Split(string(b), "\n") {
		// Shadow 4.9 fgets(1024) can interpret overlong line chunks as
		// separate settings. Refuse them before considering comments/keys.
		if len(line) >= 1023 {
			return ErrUnavailable
		}
		if strings.HasPrefix(strings.TrimSpace(line), "#") {
			continue
		}
		key, value, ok := strings.Cut(line, "=")
		if !ok || strings.TrimSpace(key) != "CREATE_MAIL_SPOOL" {
			continue
		}
		if found || key != "CREATE_MAIL_SPOOL" || value != "no" {
			return ErrUnavailable
		}
		found = true
	}
	if !found {
		return ErrUnavailable
	}
	return nil
}
