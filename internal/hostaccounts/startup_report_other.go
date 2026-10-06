//go:build !linux

package hostaccounts

func brokerAdmissionProbes(BrokerOptions) [9]func() error { return [9]func() error{} }
