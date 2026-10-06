//go:build !linux

package hostaccounts

func hostPolicyProbes() [3]func() error { return [3]func() error{} }
