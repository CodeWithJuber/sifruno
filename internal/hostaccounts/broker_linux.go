//go:build linux

package hostaccounts

import (
	"context"
	"errors"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

func peer(conn *net.UnixConn) (*unix.Ucred, error) {
	raw, e := conn.SyscallConn()
	if e != nil {
		return nil, ErrUnavailable
	}
	var cred *unix.Ucred
	var inner error
	e = raw.Control(func(fd uintptr) { cred, inner = unix.GetsockoptUcred(int(fd), unix.SOL_SOCKET, unix.SO_PEERCRED) })
	if e != nil || inner != nil || cred == nil {
		return nil, ErrUnavailable
	}
	return cred, nil
}
func socketAuthority(socket string, uid uint32) error {
	if !validSocketName(socket) || authority(filepath.Dir(socket)) != nil {
		return ErrUnavailable
	}
	info, e := os.Lstat(socket)
	if e != nil || info.Mode()&os.ModeSocket == 0 || info.Mode().Perm() != 0600 {
		return ErrUnavailable
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok || st.Uid != uid || st.Nlink != 1 {
		return ErrUnavailable
	}
	return nil
}
func connectBroker(ctx context.Context, socket string) (net.Conn, error) {
	if ctx == nil || os.Geteuid() == 0 || socketAuthority(socket, uint32(os.Geteuid())) != nil {
		return nil, ErrUnavailable
	}
	conn, e := (&net.Dialer{Timeout: 3 * time.Second}).DialContext(ctx, "unix", socket)
	if e != nil {
		return nil, ErrUnavailable
	}
	u, ok := conn.(*net.UnixConn)
	if !ok {
		conn.Close()
		return nil, ErrUnavailable
	}
	cred, e := peer(u)
	if e != nil || cred.Uid != 0 || socketAuthority(socket, uint32(os.Geteuid())) != nil {
		conn.Close()
		return nil, ErrUnavailable
	}
	return conn, nil
}

type admittedListener struct {
	*net.UnixListener
	uid uint32
}

func (l admittedListener) Accept() (net.Conn, error) {
	for {
		conn, e := l.AcceptUnix()
		if e != nil {
			return nil, e
		}
		cred, e := peer(conn)
		if e != nil || cred.Uid == 0 || cred.Uid != l.uid {
			conn.Close()
			continue
		}
		return conn, nil
	}
}
func validBrokerPaths(opts BrokerOptions) bool {
	if opts.ControllerUID == 0 || !validSocketName(opts.SocketPath) {
		return false
	}
	for _, p := range []string{opts.StateDir, opts.HomesDir, filepath.Dir(opts.SocketPath)} {
		if !filepath.IsAbs(p) || filepath.Clean(p) != p || p == "/" || len(p) > 2048 || strings.ContainsAny(p, "\x00\r\n") {
			return false
		}
	}
	for _, pair := range [][2]string{{opts.StateDir, opts.HomesDir}, {opts.StateDir, filepath.Dir(opts.SocketPath)}, {opts.HomesDir, filepath.Dir(opts.SocketPath)}} {
		a, b := pair[0], pair[1]
		if a == b || strings.HasPrefix(a, b+"/") || strings.HasPrefix(b, a+"/") {
			return false
		}
	}
	return true
}
func declaredDir(p string, mode os.FileMode) error {
	if authority(filepath.Dir(p)) != nil {
		return ErrUnavailable
	}
	if e := os.Mkdir(p, mode); e != nil && !errors.Is(e, os.ErrExist) {
		return ErrUnavailable
	}
	if authority(p) != nil {
		return ErrUnavailable
	}
	info, e := os.Lstat(p)
	if e != nil || info.Mode() != os.ModeDir|mode {
		return ErrUnavailable
	}
	return nil
}
func RunBroker(ctx context.Context, opts BrokerOptions) error {
	return RunBrokerWithWebPreview(ctx, opts, nil)
}

func RunBrokerWithWebPreview(ctx context.Context, opts BrokerOptions, factory WebPreviewFactory) error {
	return RunBrokerWithWeb(ctx, opts, factory, nil)
}

// RunBrokerWithWeb also enables the web operation when web is non-nil. Web
// is not part of the pinned BrokerOptions: it can be turned on for a broker
// whose state already exists.
func RunBrokerWithWeb(ctx context.Context, opts BrokerOptions, factory WebPreviewFactory, web *WebOptions) error {
	if ctx == nil || !validBrokerPaths(opts) {
		return ErrInvalid
	}
	if ctx.Err() != nil {
		return ErrUnavailable
	}
	if os.Geteuid() != 0 {
		return ErrUnavailable
	}
	users, e := systemUsers()
	if e != nil {
		return ErrUnavailable
	}
	controllerCount := 0
	for _, u := range users {
		if u.UID == int(opts.ControllerUID) {
			controllerCount++
		}
	}
	if controllerCount != 1 {
		return ErrInvalid
	}
	system, e := newLinuxSystem(opts, web)
	if e != nil {
		return e
	}
	if e = admitBrokerPaths(opts); e != nil {
		return e
	}
	if ctx.Err() != nil {
		return ErrUnavailable
	}
	for _, d := range []struct {
		path string
		mode os.FileMode
	}{{opts.StateDir, 0700}, {opts.HomesDir, 0755}, {filepath.Dir(opts.SocketPath), 0755}} {
		if declaredDir(d.path, d.mode) != nil {
			return ErrUnavailable
		}
	}
	if _, e = os.Lstat(opts.SocketPath); !errors.Is(e, os.ErrNotExist) {
		return ErrConflict
	}
	opening, cancelOpening := context.WithTimeout(ctx, 45*time.Second)
	s, e := openStore(opening, opts, system)
	cancelOpening()
	if e != nil {
		return e
	}
	defer s.close()
	s.web = web
	listener, e := net.ListenUnix("unix", &net.UnixAddr{Name: opts.SocketPath, Net: "unix"})
	if e != nil {
		return ErrUnavailable
	}
	listener.SetUnlinkOnClose(false)
	defer listener.Close()
	socketInfo, e := os.Lstat(opts.SocketPath)
	if e != nil {
		return ErrUnavailable
	}
	defer func() {
		if info, e := os.Lstat(opts.SocketPath); e == nil && os.SameFile(socketInfo, info) && info.Mode()&os.ModeSocket != 0 {
			_ = os.Remove(opts.SocketPath)
		}
	}()
	if os.Chmod(opts.SocketPath, 0600) != nil || os.Chown(opts.SocketPath, int(opts.ControllerUID), -1) != nil {
		return ErrUnavailable
	}
	if socketAuthority(opts.SocketPath, opts.ControllerUID) != nil {
		return ErrUnavailable
	}
	var preview WebPreviewService
	if factory != nil {
		preview = factory(s.SnapshotProvider())
	}
	server := &http.Server{Handler: handlerWithWebPreview(s, preview), ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 45 * time.Second, WriteTimeout: 45 * time.Second, IdleTimeout: time.Second, MaxHeaderBytes: 8 << 10}
	done := make(chan error, 1)
	go func() { done <- server.Serve(admittedListener{listener, opts.ControllerUID}) }()
	select {
	case <-ctx.Done():
	case e = <-done:
		if !errors.Is(e, http.ErrServerClosed) {
			return ErrUnavailable
		}
	}
	stop, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if server.Shutdown(stop) != nil {
		server.Close()
		return ErrUnavailable
	}
	return nil
}
