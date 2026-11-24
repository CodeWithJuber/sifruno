//go:build !linux

package phpmyadmin

import (
	"errors"
	"net"
)

// peerUID has no peer check outside Linux, so no code is ever redeemed there.
func peerUID(net.Conn) (int, error) {
	return -1, errors.New("the peer's user ID is read on Linux only")
}
