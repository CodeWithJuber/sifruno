package keyinstall

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/binary"
	"encoding/pem"
	"errors"
	"net"
	"strconv"
	"sync"
	"testing"

	"golang.org/x/crypto/ssh"
)

// fakeServer is an SSH server in this process: it takes root's password
// "right password" or the client key it is given, and answers an exec
// with exit 0, or with exit 1 and a message for the command "fail".
type fakeServer struct {
	addr      string
	hostKey   ssh.PublicKey
	mu        sync.Mutex
	commands  []string
	passwords int
}

func newFakeServer(t *testing.T, clientKey ssh.PublicKey) *fakeServer {
	t.Helper()
	_, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := ssh.NewSignerFromKey(private)
	if err != nil {
		t.Fatal(err)
	}
	f := &fakeServer{hostKey: signer.PublicKey()}
	config := &ssh.ServerConfig{
		PasswordCallback: func(meta ssh.ConnMetadata, password []byte) (*ssh.Permissions, error) {
			f.mu.Lock()
			f.passwords++
			f.mu.Unlock()
			if meta.User() == "root" && string(password) == "right password" {
				return nil, nil
			}
			return nil, errors.New("no")
		},
		PublicKeyCallback: func(meta ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
			if clientKey != nil && meta.User() == "root" && string(key.Marshal()) == string(clientKey.Marshal()) {
				return nil, nil
			}
			return nil, errors.New("no")
		},
	}
	config.AddHostKey(signer)
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { l.Close() })
	f.addr = l.Addr().String()
	go func() {
		for {
			conn, err := l.Accept()
			if err != nil {
				return
			}
			go f.serve(conn, config)
		}
	}()
	return f
}

func (f *fakeServer) serve(conn net.Conn, config *ssh.ServerConfig) {
	defer conn.Close()
	_, chans, reqs, err := ssh.NewServerConn(conn, config)
	if err != nil {
		return
	}
	go ssh.DiscardRequests(reqs)
	for nc := range chans {
		ch, requests, err := nc.Accept()
		if err != nil {
			return
		}
		for req := range requests {
			if req.Type != "exec" || len(req.Payload) < 4 {
				req.Reply(false, nil)
				continue
			}
			command := string(req.Payload[4:])
			f.mu.Lock()
			f.commands = append(f.commands, command)
			f.mu.Unlock()
			req.Reply(true, nil)
			status := uint32(0)
			if command == "fail" {
				ch.Stderr().Write([]byte("mkdir: cannot create directory '/root/.ssh': Read-only file system\n"))
				status = 1
			}
			payload := make([]byte, 4)
			binary.BigEndian.PutUint32(payload, status)
			ch.SendRequest("exit-status", false, payload)
			ch.Close()
		}
	}
}

func (f *fakeServer) target(t *testing.T) Target {
	host, port, _ := net.SplitHostPort(f.addr)
	n, _ := strconv.Atoi(port)
	return Target{Host: host, Port: n, KeyType: f.hostKey.Type(), Fingerprint: ssh.FingerprintSHA256(f.hostKey)}
}

func TestPasswordInstallsOnTheConfirmedServerOnly(t *testing.T) {
	f := newFakeServer(t, nil)
	ctx := context.Background()
	target := f.target(t)
	if err := Run(ctx, target, Login{Password: "right password"}, "install the key"); err != nil {
		t.Fatal(err)
	}
	if len(f.commands) != 1 || f.commands[0] != "install the key" {
		t.Fatalf("commands = %v", f.commands)
	}
	// Another host key: nothing is sent, the password included.
	before := f.passwords
	other := target
	other.Fingerprint = "SHA256:" + "A0aB1bC2cD3dE4eF5fG6gH7hI8iJ9jK0kL1lM2mN3n"
	if err := Run(ctx, other, Login{Password: "right password"}, "install the key"); !errors.Is(err, ErrHostKey) {
		t.Fatalf("another host key: %v", err)
	}
	if f.passwords != before || len(f.commands) != 1 {
		t.Fatal("the password reached a server whose host key was not the confirmed one")
	}
	if err := Run(ctx, target, Login{Password: "wrong"}, "install the key"); !errors.Is(err, ErrLogin) {
		t.Fatalf("a wrong password: %v", err)
	}
	var failed *Error
	if err := Run(ctx, target, Login{Password: "right password"}, "fail"); !errors.As(err, &failed) || failed.Kind != ErrCommand || failed.Output != "mkdir: cannot create directory '/root/.ssh': Read-only file system" {
		t.Fatalf("a failing command: %v", err)
	}
}

func TestPrivateKeyInstalls(t *testing.T) {
	_, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signer, _ := ssh.NewSignerFromKey(private)
	f := newFakeServer(t, signer.PublicKey())
	plain, _ := ssh.MarshalPrivateKey(private, "")
	locked, _ := ssh.MarshalPrivateKeyWithPassphrase(private, "", []byte("open sesame"))
	ctx := context.Background()
	if err := Run(ctx, f.target(t), Login{PrivateKey: pem.EncodeToMemory(plain)}, "install"); err != nil {
		t.Fatal(err)
	}
	if err := Run(ctx, f.target(t), Login{PrivateKey: pem.EncodeToMemory(locked), Passphrase: []byte("open sesame")}, "install"); err != nil {
		t.Fatal(err)
	}
	if err := Run(ctx, f.target(t), Login{PrivateKey: pem.EncodeToMemory(locked)}, "install"); !errors.Is(err, ErrKey) {
		t.Fatalf("a locked key without its passphrase: %v", err)
	}
	if err := Run(ctx, f.target(t), Login{PrivateKey: []byte("not a key")}, "install"); !errors.Is(err, ErrKey) {
		t.Fatalf("not a key: %v", err)
	}
	if len(f.commands) != 2 {
		t.Fatalf("commands = %v", f.commands)
	}
}

func TestRequestsAreChecked(t *testing.T) {
	ctx := context.Background()
	target := Target{Host: "192.0.2.1", Port: 22, KeyType: ssh.KeyAlgoED25519, Fingerprint: "SHA256:x"}
	for _, login := range []Login{{}, {Password: "a", PrivateKey: []byte("k")}, {Password: "line\nbreak"}, {Password: "p", Passphrase: []byte("x")}} {
		if err := Run(ctx, target, login, "true"); !errors.Is(err, ErrInvalid) {
			t.Errorf("%+v: %v", login, err)
		}
	}
	bad := target
	bad.KeyType = "ssh-dss"
	if err := Run(ctx, bad, Login{Password: "p"}, "true"); !errors.Is(err, ErrInvalid) {
		t.Errorf("a DSA host key: %v", err)
	}
	if err := Run(ctx, target, Login{Password: "p"}, "two\nlines"); !errors.Is(err, ErrInvalid) {
		t.Errorf("a command of two lines: %v", err)
	}
	l := Login{PrivateKey: []byte("key"), Passphrase: []byte("pass")}
	key, pass := l.PrivateKey, l.Passphrase
	l.Clear()
	if string(key) != "\x00\x00\x00" || string(pass) != "\x00\x00\x00\x00" || l.PrivateKey != nil {
		t.Fatalf("not cleared: %q %q", key, pass)
	}
}
