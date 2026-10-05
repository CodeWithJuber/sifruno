//go:build !linux

package hostaccounts

import (
	"context"
	"net"
)

func connectBroker(context.Context, string) (net.Conn, error) { return nil, ErrUnavailable }
func RunBroker(context.Context, BrokerOptions) error          { return ErrUnavailable }
