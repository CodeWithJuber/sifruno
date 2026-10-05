//go:build linux

package hostwebruntime

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"golang.org/x/sys/unix"
	"sifruno/internal/hostaccounts"
	"sifruno/internal/hostwebgeneration"
)

func procNetwork(name string) ([]byte, error) {
	f, e := os.Open("/proc/net/" + name)
	if e != nil {
		return nil, ErrUnavailable
	}
	defer f.Close()
	b, e := io.ReadAll(io.LimitReader(f, (1<<20)+1))
	if e != nil || len(b) > 1<<20 {
		return nil, ErrLimit
	}
	return b, nil
}
func listener(ip string, port uint16) (string, error) {
	b, e := procNetwork("tcp")
	if e != nil {
		return "", e
	}
	v := net.ParseIP(ip).To4()
	if v == nil {
		return "", ErrInvalid
	}
	iphex := strings.ToUpper(hex.EncodeToString([]byte{v[3], v[2], v[1], v[0]}))
	address := fmt.Sprintf("%s:%04X", iphex, port)
	var found string
	for _, line := range strings.Split(string(b), "\n")[1:] {
		f := strings.Fields(line)
		if len(f) > 9 && f[1] == address && f[3] == "0A" {
			if found != "" {
				return "", ErrRecovery
			}
			found = f[9]
		}
	}
	return found, nil
}
func namespaceMembers(pin processPin) ([]int, error) {
	f, e := os.Open("/proc")
	if e != nil {
		return nil, ErrUnavailable
	}
	names, e := f.Readdirnames(32769)
	f.Close()
	if e != nil && e != io.EOF {
		return nil, ErrRecovery
	}
	if len(names) > 32768 {
		return nil, ErrLimit
	}
	var members []int
	for _, name := range names {
		pid, e := strconv.Atoi(name)
		if e != nil || pid <= 1 {
			continue
		}
		ns, e := namespaceID(pid)
		if e != nil {
			continue
		}
		if ns == pin.Namespace {
			members = append(members, pid)
			if len(members) > MaxGroupMembers {
				return nil, ErrLimit
			}
		}
	}
	if len(members) == 0 {
		return nil, ErrRecovery
	}
	return members, nil
}
func ownsSocket(members []int, inode string) bool {
	if inode == "" {
		return false
	}
	for _, pid := range members {
		f, e := os.Open(fmt.Sprintf("/proc/%d/fd", pid))
		if e != nil {
			continue
		}
		names, e := f.Readdirnames(257)
		f.Close()
		if e != nil && e != io.EOF || len(names) > 256 {
			return false
		}
		for _, name := range names {
			target, e := os.Readlink(fmt.Sprintf("/proc/%d/fd/%s", pid, name))
			if e == nil && target == "socket:["+inode+"]" {
				return true
			}
		}
	}
	return false
}
func unixSocket(path string, members []int, uid, gid int) error {
	var st unix.Stat_t
	if unix.Lstat(path, &st) != nil || st.Mode&unix.S_IFMT != unix.S_IFSOCK || st.Mode&0777 != 0600 || int(st.Uid) != uid || int(st.Gid) != gid {
		return ErrRecovery
	}
	b, e := procNetwork("unix")
	if e != nil {
		return e
	}
	found := ""
	for _, line := range strings.Split(string(b), "\n")[1:] {
		f := strings.Fields(line)
		if len(f) == 8 && f[7] == path {
			if found != "" {
				return ErrRecovery
			}
			found = f[6]
		}
	}
	if !ownsSocket(members, found) {
		return ErrRecovery
	}
	return nil
}
func worker(pid, uid, gid int, root string) error {
	v, e := statusFields(pid)
	if e != nil {
		return ErrRecovery
	}
	for k, want := range map[string]int{"Uid": uid, "Gid": gid} {
		if len(v[k]) != 4 {
			return ErrRecovery
		}
		for _, field := range v[k] {
			actual, e := strconv.Atoi(field)
			if e != nil || actual != want {
				return ErrRecovery
			}
		}
	}
	if len(v["Groups"]) > 32 {
		return ErrRecovery
	}
	seen := map[string]bool{}
	for _, s := range v["Groups"] {
		n, e := strconv.Atoi(s)
		if e != nil || n != gid || seen[s] {
			return ErrRecovery
		}
		seen[s] = true
	}
	for _, k := range []string{"CapEff", "CapPrm", "CapInh", "CapAmb"} {
		if len(v[k]) != 1 {
			return ErrRecovery
		}
		n, e := strconv.ParseUint(v[k][0], 16, 64)
		if e != nil || n != 0 {
			return ErrRecovery
		}
	}
	actual, e := os.Readlink(fmt.Sprintf("/proc/%d/root", pid))
	if e != nil || actual != root {
		return ErrRecovery
	}
	return nil
}
func (r *Runtime) absent(g hostwebgeneration.Generation) error {
	front, e := listener(r.opts.Profile.FrontendIP, r.opts.Profile.FrontendPort)
	if e != nil {
		return e
	}
	if front != "" {
		return ErrConflict
	}
	for _, a := range g.Accounts {
		found, e := listener(backendIP(a.UID), r.opts.Profile.BackendPort)
		if e != nil {
			return e
		}
		if found != "" {
			return ErrConflict
		}
	}
	return nil
}
func backendIP(uid int) string { return fmt.Sprintf("127.73.%d.%d", uid>>8, uid&255) }
func leafMatches(cert, peer []byte) bool {
	block, _ := pem.Decode(cert)
	return block != nil && block.Type == "CERTIFICATE" && string(block.Bytes) == string(peer)
}

func sameDirectory(a, b string, uid, gid int) error {
	var x, y unix.Stat_t
	if unix.Lstat(a, &x) != nil || unix.Lstat(b, &y) != nil || x.Mode&unix.S_IFMT != unix.S_IFDIR || y.Mode&unix.S_IFMT != unix.S_IFDIR || int(x.Uid) != uid || int(x.Gid) != gid || x.Dev != y.Dev || x.Ino != y.Ino {
		return ErrRecovery
	}
	return nil
}
func (r *Runtime) prepared(a hostaccounts.Account) error {
	p := r.opts.Profile
	keyDir, e := checkedDir(filepath.Join(p.TLSRoot, a.ID), false)
	if e != nil {
		return e
	}
	key, e := openBelow(keyDir, "key.pem", unix.O_RDONLY, 0)
	unix.Close(keyDir)
	if e != nil {
		return ErrRecovery
	}
	e = regular(key, 0600, 16<<10)
	unix.Close(key)
	if e != nil {
		return e
	}
	jail := filepath.Join(p.BackendChrootRoot, a.ID)
	fd, e := checkedDir(jail, false)
	if e != nil {
		return e
	}
	defer unix.Close(fd)
	for _, v := range []struct {
		name string
		data []byte
		mode uint32
	}{
		{"etc/passwd", []byte(fmt.Sprintf("root:x:0:0:root:/root:/usr/sbin/nologin\n%s:x:%d:%d::%s:/usr/sbin/nologin\n", a.Username, a.UID, a.GID, a.Home)), 0400},
		{"etc/group", []byte(fmt.Sprintf("root:x:0:\n%s:x:%d:\n", a.Username, a.GID)), 0400},
		{"etc/nsswitch.conf", []byte("passwd: files\ngroup: files\nshadow: files\n"), 0444},
	} {
		b, e := readBelow(fd, v.name, v.mode, 8192)
		if e != nil || string(b) != string(v.data) {
			return ErrRecovery
		}
	}
	if _, e := readBelow(fd, "etc/mime.types", 0444, 64<<10); e != nil {
		return ErrRecovery
	}
	for _, home := range []string{a.Home, a.PublicHTML} {
		if sameDirectory(home, filepath.Join(jail, strings.TrimPrefix(home, "/")), a.UID, a.GID) != nil {
			return ErrRecovery
		}
	}
	runtime := filepath.Join(p.RuntimeRoot, a.ID)
	if sameDirectory(runtime, filepath.Join(jail, strings.TrimPrefix(runtime, "/")), a.UID, a.GID) != nil {
		return ErrRecovery
	}
	var tmp unix.Stat_t
	if unix.Lstat(filepath.Join(a.Home, "tmp"), &tmp) != nil || tmp.Mode&unix.S_IFMT != unix.S_IFDIR || tmp.Mode&0777 != 0700 || int(tmp.Uid) != a.UID || int(tmp.Gid) != a.GID {
		return ErrRecovery
	}
	// No traversal through symlink ancestors in tenant-authorized paths.
	for _, target := range []string{a.Home, a.PublicHTML, runtime} {
		parent := r.opts.Root
		rel := strings.TrimPrefix(target, parent+"/")
		for _, part := range strings.Split(rel, "/") {
			parent = filepath.Join(parent, part)
			var st unix.Stat_t
			if unix.Lstat(parent, &st) != nil || st.Mode&unix.S_IFMT != unix.S_IFDIR {
				return ErrRecovery
			}
		}
	}
	return nil
}

func request(ctx context.Context, port uint16, host string) error {
	t := &http.Transport{Proxy: nil, DialContext: (&net.Dialer{Timeout: time.Second}).DialContext, DisableKeepAlives: true, ResponseHeaderTimeout: time.Second, MaxResponseHeaderBytes: 16 << 10}
	defer t.CloseIdleConnections()
	c := &http.Client{Transport: t, Timeout: 2 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	req, e := http.NewRequestWithContext(ctx, "GET", fmt.Sprintf("http://127.0.0.1:%d/", port), nil)
	if e != nil {
		return ErrRecovery
	}
	req.Host = host
	res, e := c.Do(req)
	if e != nil {
		return ErrRecovery
	}
	defer res.Body.Close()
	b, e := io.ReadAll(io.LimitReader(res.Body, (128<<10)+1))
	if e != nil || len(b) > 128<<10 || res.StatusCode != 403 {
		return ErrRecovery
	}
	return nil
}
func (r *Runtime) backendTLS(ctx context.Context, a hostaccounts.Account) error {
	p := r.opts.Profile
	ca, e := trustedRead(p.CAFile, 256<<10, false)
	if e != nil {
		return e
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(ca) {
		return ErrRecovery
	}
	cert, e := trustedRead(filepath.Join(p.TLSRoot, a.ID, "cert.pem"), 256<<10, false)
	if e != nil {
		return e
	}
	// Parse the exact selected leaf using the standard TLS certificate parser;
	// key bytes remain outside this executor's observation/report surface.
	leaves := x509.NewCertPool()
	if !leaves.AppendCertsFromPEM(cert) {
		return ErrRecovery
	}
	conn, e := (&tls.Dialer{NetDialer: &net.Dialer{Timeout: time.Second}, Config: &tls.Config{RootCAs: pool, ServerName: backendIP(a.UID), MinVersion: tls.VersionTLS12}}).DialContext(ctx, "tcp", fmt.Sprintf("%s:%d", backendIP(a.UID), p.BackendPort))
	if e != nil {
		return ErrRecovery
	}
	defer conn.Close()
	state := conn.(*tls.Conn).ConnectionState()
	if len(state.PeerCertificates) == 0 {
		return ErrRecovery
	}
	// Compare DER, not subject strings. Name/chain/expiry verification remains on.
	if !leafMatches(cert, state.PeerCertificates[0].Raw) {
		return ErrRecovery
	}
	return nil
}

func (r *Runtime) live(ctx context.Context, pins []processPin, g hostwebgeneration.Generation) error {
	byRole := map[string]processPin{}
	for _, p := range pins {
		if r.verifyPin(p) != nil {
			return ErrRecovery
		}
		byRole[p.Role+":"+p.AccountID] = p
	}
	expected := 1
	for _, a := range g.Accounts {
		if a.State == "active" && !g.Denied {
			expected += 2
		}
	}
	if len(pins) != expected {
		return ErrRecovery
	}
	front, ok := byRole["front:"]
	if !ok || front.Config != filepath.Join(r.opts.Profile.ManagedRoot, generationPath(g), "apache/front.conf") {
		return ErrRecovery
	}
	members, e := namespaceMembers(front)
	if e != nil {
		return e
	}
	found, e := listener(r.opts.Profile.FrontendIP, r.opts.Profile.FrontendPort)
	if e != nil || !ownsSocket(members, found) {
		return ErrRecovery
	}
	workers := 0
	for _, pid := range members {
		if pid == front.PID {
			continue
		}
		if worker(pid, int(r.opts.Profile.FrontUID), int(r.opts.Profile.FrontGID), "/") != nil {
			return ErrRecovery
		}
		workers++
	}
	if workers == 0 {
		return ErrRecovery
	}
	if request(ctx, r.opts.Profile.FrontendPort, "default.invalid") != nil {
		return ErrRecovery
	}
	for _, a := range g.Accounts {
		if a.State != "active" || g.Denied {
			if request(ctx, r.opts.Profile.FrontendPort, a.Domain) != nil {
				return ErrRecovery
			}
			if f, _ := listener(backendIP(a.UID), r.opts.Profile.BackendPort); f != "" {
				return ErrRecovery
			}
			continue
		}
		if r.prepared(a) != nil {
			return ErrRecovery
		}
		back, ok := byRole["backend:"+a.ID]
		if !ok || back.Config != filepath.Join(r.opts.Profile.ManagedRoot, generationPath(g), "apache/backends/"+a.ID+".conf") {
			return ErrRecovery
		}
		ids, e := namespaceMembers(back)
		if e != nil {
			return e
		}
		found, e := listener(backendIP(a.UID), r.opts.Profile.BackendPort)
		if e != nil || !ownsSocket(ids, found) {
			return ErrRecovery
		}
		n := 0
		for _, pid := range ids {
			if pid == back.PID {
				continue
			}
			if worker(pid, a.UID, a.GID, filepath.Join(r.opts.Profile.BackendChrootRoot, a.ID)) != nil {
				return ErrRecovery
			}
			n++
		}
		if n == 0 {
			return ErrRecovery
		}
		fpm, ok := byRole["fpm:"+a.ID]
		if !ok || fpm.Config != filepath.Join(r.opts.Profile.ManagedRoot, generationPath(g), "fpm/"+a.ID+".conf") {
			return ErrRecovery
		}
		ids, e = namespaceMembers(fpm)
		if e != nil {
			return e
		}
		if unixSocket(filepath.Join(r.opts.Profile.RuntimeRoot, a.ID, "php-fpm.sock"), ids, a.UID, a.GID) != nil {
			return ErrRecovery
		}
		// Ondemand pools can be idle. Existing workers are checked; this does not
		// assert that a PHP request/worker has executed when no worker exists.
		for _, pid := range ids {
			if pid != fpm.PID && worker(pid, a.UID, a.GID, filepath.Join(r.opts.Profile.BackendChrootRoot, a.ID)) != nil {
				return ErrRecovery
			}
		}
		if r.backendTLS(ctx, a) != nil {
			return ErrRecovery
		}
	}
	if r.verifyRecorded(pins, false) != nil || r.disk(g) != nil {
		return ErrRecovery
	}
	return ctx.Err()
}
