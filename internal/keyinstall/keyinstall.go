// Package keyinstall adds a migration's key line to root's authorized_keys
// on the old server with root's password or a private key the admin gives
// (docs/migration-design.md, "Another Linux server"): the other way to the
// command the admin runs there by hand. The panel, as itself and never as
// root, signs in once over SSH in this process (golang.org/x/crypto/ssh),
// so the password or key is never a process argument, never written to a
// file, a log, a job record or the state directory, and is held in memory
// for that one sign-in. The server must show the host key the admin
// confirmed first: no secret is sent to a server that does not.
package keyinstall

import (
	"bytes"
	"context"
	"errors"
	"net"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"golang.org/x/crypto/ssh"
)

// Login is root's password, or a private key in OpenSSH or PEM form with
// its passphrase when it has one. Exactly one of Password and PrivateKey is
// set.
type Login struct {
	Password   string
	PrivateKey []byte
	Passphrase []byte
}

// Bounds on what a login may hold.
const (
	MaxPassword   = 1024
	MaxPrivateKey = 16 << 10
	MaxPassphrase = 1024
)

// Valid reports a login with exactly one secret, each within its bound and
// without a NUL or line break in the password.
func (l Login) Valid() bool {
	switch {
	case l.Password != "" && len(l.PrivateKey) == 0 && len(l.Passphrase) == 0:
		return len(l.Password) <= MaxPassword && utf8.ValidString(l.Password) && !strings.ContainsAny(l.Password, "\x00\r\n")
	case l.Password == "" && len(l.PrivateKey) > 0:
		return len(l.PrivateKey) <= MaxPrivateKey && len(l.Passphrase) <= MaxPassphrase
	}
	return false
}

// Clear overwrites the key and passphrase; the password, a string, is
// dropped by the caller.
func (l *Login) Clear() {
	clear(l.PrivateKey)
	clear(l.Passphrase)
	l.Password, l.PrivateKey, l.Passphrase = "", nil, nil
}

// The ways a sign-in or the command fails, for the panel to explain.
var (
	// ErrHostKey: the server showed another host key than the confirmed
	// one, so nothing was sent.
	ErrHostKey = errors.New("the server's host key is not the confirmed one")
	// ErrLogin: the server refused the password or key.
	ErrLogin = errors.New("the server refused the login")
	// ErrKey: the private key could not be read, or needs a passphrase
	// that was not given or is wrong.
	ErrKey = errors.New("the private key could not be read")
	// ErrUnreachable: nothing answered, or the connection broke.
	ErrUnreachable = errors.New("the server could not be reached")
	// ErrCommand: the command ran and failed; Error.Output says how.
	ErrCommand = errors.New("the command failed on the server")
	// ErrInvalid: the request itself is not one this package runs.
	ErrInvalid = errors.New("invalid key install request")
)

// Error carries what the server printed on its error output when the
// command failed: printable ASCII, at most 512 bytes, for Technical
// details only.
type Error struct {
	Kind   error
	Output string
}

func (e *Error) Error() string        { return e.Kind.Error() }
func (e *Error) Is(target error) bool { return target == e.Kind }

// Target is the server and the host key the admin confirmed: its type
// ("ssh-ed25519") and its SHA-256 fingerprint ("SHA256:...").
type Target struct {
	Host        string
	Port        int
	KeyType     string
	Fingerprint string
}

// hostKeyAlgorithms are the signature algorithms that carry a key of each
// type, so the server is asked for the very key that was confirmed.
var hostKeyAlgorithms = map[string][]string{
	ssh.KeyAlgoED25519:  {ssh.KeyAlgoED25519},
	ssh.KeyAlgoECDSA256: {ssh.KeyAlgoECDSA256},
	ssh.KeyAlgoECDSA384: {ssh.KeyAlgoECDSA384},
	ssh.KeyAlgoECDSA521: {ssh.KeyAlgoECDSA521},
	ssh.KeyAlgoRSA:      {ssh.KeyAlgoRSASHA512, ssh.KeyAlgoRSASHA256},
}

const (
	dialTimeout = 20 * time.Second
	runTimeout  = time.Minute
	maxOutput   = 512
)

// Run signs in to the target as root with the login, after checking that
// the server shows the confirmed host key, and runs command there. It
// returns nil when the command exited 0.
func Run(ctx context.Context, t Target, login Login, command string) error {
	algorithms, ok := hostKeyAlgorithms[t.KeyType]
	if !ok || t.Port < 1 || t.Port > 65535 || t.Host == "" || !strings.HasPrefix(t.Fingerprint, "SHA256:") || command == "" || strings.ContainsAny(command, "\x00\r\n") || !login.Valid() {
		return &Error{Kind: ErrInvalid}
	}
	auth, err := methods(login)
	if err != nil {
		return err
	}
	config := &ssh.ClientConfig{
		User:              "root",
		Auth:              auth,
		HostKeyAlgorithms: algorithms,
		HostKeyCallback: func(_ string, _ net.Addr, key ssh.PublicKey) error {
			if key.Type() != t.KeyType || ssh.FingerprintSHA256(key) != t.Fingerprint {
				return ErrHostKey
			}
			return nil
		},
		Timeout: dialTimeout,
	}
	ctx, cancel := context.WithTimeout(ctx, dialTimeout+runTimeout)
	defer cancel()
	address := net.JoinHostPort(t.Host, strconv.Itoa(t.Port))
	conn, err := (&net.Dialer{Timeout: dialTimeout}).DialContext(ctx, "tcp", address)
	if err != nil {
		return &Error{Kind: ErrUnreachable, Output: printable([]byte(err.Error()))}
	}
	// The context's end closes the connection, which ends every read.
	stop := context.AfterFunc(ctx, func() { conn.Close() })
	defer stop()
	defer conn.Close()
	if err := conn.SetDeadline(time.Now().Add(dialTimeout + runTimeout)); err != nil {
		return &Error{Kind: ErrUnreachable}
	}
	c, chans, reqs, err := ssh.NewClientConn(conn, address, config)
	if err != nil {
		return handshakeError(err)
	}
	client := ssh.NewClient(c, chans, reqs)
	defer client.Close()
	session, err := client.NewSession()
	if err != nil {
		return &Error{Kind: ErrUnreachable, Output: printable([]byte(err.Error()))}
	}
	defer session.Close()
	var stderr bytes.Buffer
	session.Stderr = &limited{b: &stderr, max: 4096}
	if err := session.Run(command); err != nil {
		var exit *ssh.ExitError
		if errors.As(err, &exit) {
			return &Error{Kind: ErrCommand, Output: printable(stderr.Bytes())}
		}
		return &Error{Kind: ErrUnreachable, Output: printable([]byte(err.Error()))}
	}
	return nil
}

// methods are the sign-in methods for a login: a password both as
// "password" and as keyboard-interactive, which servers set to PAM use for
// the same password; or the private key.
func methods(login Login) ([]ssh.AuthMethod, error) {
	if login.Password != "" {
		password := login.Password
		answer := func(_, _ string, questions []string, _ []bool) ([]string, error) {
			answers := make([]string, len(questions))
			for i := range answers {
				answers[i] = password
			}
			return answers, nil
		}
		return []ssh.AuthMethod{ssh.Password(password), ssh.KeyboardInteractive(answer)}, nil
	}
	var signer ssh.Signer
	var err error
	if len(login.Passphrase) > 0 {
		signer, err = ssh.ParsePrivateKeyWithPassphrase(login.PrivateKey, login.Passphrase)
	} else {
		signer, err = ssh.ParsePrivateKey(login.PrivateKey)
	}
	if err != nil {
		return nil, &Error{Kind: ErrKey}
	}
	return []ssh.AuthMethod{ssh.PublicKeys(signer)}, nil
}

// handshakeError names how the sign-in failed.
func handshakeError(err error) error {
	switch {
	case errors.Is(err, ErrHostKey):
		return &Error{Kind: ErrHostKey}
	case strings.Contains(err.Error(), "unable to authenticate"):
		return &Error{Kind: ErrLogin}
	}
	return &Error{Kind: ErrUnreachable, Output: printable([]byte(err.Error()))}
}

// limited keeps the first max bytes written and drops the rest.
type limited struct {
	b   *bytes.Buffer
	max int
}

func (w *limited) Write(p []byte) (int, error) {
	if room := w.max - w.b.Len(); room > 0 {
		w.b.Write(p[:min(len(p), room)])
	}
	return len(p), nil
}

// printable keeps the end of an output in printable ASCII, at most 512
// bytes.
func printable(out []byte) string {
	b := make([]byte, 0, len(out))
	for _, c := range out {
		switch {
		case c == '\n' || c == '\r' || c == '\t':
			b = append(b, ' ')
		case c >= 0x20 && c < 0x7f:
			b = append(b, c)
		}
	}
	s := strings.TrimSpace(string(b))
	if len(s) > maxOutput {
		s = s[len(s)-maxOutput:]
	}
	return s
}
