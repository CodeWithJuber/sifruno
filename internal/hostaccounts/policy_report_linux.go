//go:build linux

package hostaccounts

func hostPolicyProbes() [3]func() error {
	return [3]func() error{
		func() error { _, e := trustedUtilities(); return e },
		supportedNSS,
		supportedUseraddDefaults,
	}
}
