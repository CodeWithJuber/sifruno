//go:build linux

package phpmyadmin

import (
	"errors"
	"net"

	"golang.org/x/sys/unix"
)

// peerUID is the user ID of the process at the other end of a Unix socket
// connection, as the kernel recorded it when the connection was made.
func peerUID(conn net.Conn) (int, error) {
	u, ok := conn.(*net.UnixConn)
	if !ok {
		return -1, errors.New("not a Unix socket connection")
	}
	raw, err := u.SyscallConn()
	if err != nil {
		return -1, err
	}
	var cred *unix.Ucred
	var credErr error
	if err := raw.Control(func(fd uintptr) {
		cred, credErr = unix.GetsockoptUcred(int(fd), unix.SOL_SOCKET, unix.SO_PEERCRED)
	}); err != nil {
		return -1, err
	}
	if credErr != nil {
		return -1, credErr
	}
	return int(cred.Uid), nil
}
