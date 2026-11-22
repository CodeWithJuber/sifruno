package hostaccounts

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"regexp"
	"strings"
)

// MaxSSHKeys bounds one account's key set so the whole request stays inside
// MaxRequestBytes and the record stays inside the store's value bound.
const MaxSSHKeys = 10

const maxSSHKeyLine = 1200

// SSHKey is the public description of one admitted key. The key material is
// public by nature, but the panel only needs to show which keys exist.
type SSHKey struct {
	Type        string `json:"type"`
	Fingerprint string `json:"fingerprint"`
	Comment     string `json:"comment"`
}

// SSHKeysInput replaces the account's whole key set. An empty list removes
// SFTP access. Each entry is "type base64 [comment]" exactly as ssh-keygen
// prints a .pub file; an options prefix is refused.
type SSHKeysInput struct {
	Keys             []string `json:"keys"`
	ExpectedRevision uint64   `json:"expected_revision"`
	Reason           string   `json:"reason"`
}

// SSHKeysResult returns the updated account with the admitted keys.
type SSHKeysResult struct {
	Account Account  `json:"account"`
	Keys    []SSHKey `json:"keys"`
}

// SSHKeyService is the SFTP key surface of the broker. It is separate from
// Service so existing Service implementations keep compiling; callers that
// need keys assert for it.
type SSHKeyService interface {
	SSHKeys(ctx context.Context, id string) (SSHKeysResult, error)
	SetSSHKeys(ctx context.Context, id string, in SSHKeysInput, actor string) (SSHKeysResult, error)
}

var sshCommentPattern = regexp.MustCompile(`^[A-Za-z0-9@._+=:,/-]+( [A-Za-z0-9@._+=:,/-]+)*$`)
var sshDigestPattern = regexp.MustCompile(`^[a-f0-9]{64}$`)

// sshKeyOptions is prepended to every key the broker writes. "restrict" turns
// off forwarding, PTY and user rc, and the forced command limits the session
// to the in-process SFTP server, so a key can never yield a shell even if the
// host's sshd policy is later loosened.
const sshKeyOptions = `restrict,command="internal-sftp"`

const sshKeyFileHeader = "# Managed by Sifruno. This file is rewritten from the panel's key list.\n"

// normalizeSSHKey admits one public key line and returns its canonical form
// "type base64[ comment]" with its public description. Only the listed key
// types are accepted, and the blob must be exactly one well-formed key of
// the type the line names, re-encoding to the same base64 text.
func normalizeSSHKey(line string) (string, SSHKey, bool) {
	if len(line) == 0 || len(line) > maxSSHKeyLine || strings.ContainsAny(line, "\x00\r\n\t\"'\\#") {
		return "", SSHKey{}, false
	}
	fields := strings.Fields(line)
	if len(fields) < 2 {
		return "", SSHKey{}, false
	}
	kind, encoded := fields[0], fields[1]
	blob, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil || base64.StdEncoding.EncodeToString(blob) != encoded || !validSSHBlob(kind, blob) {
		return "", SSHKey{}, false
	}
	comment := strings.Join(fields[2:], " ")
	if comment != "" && (len(comment) > 80 || !sshCommentPattern.MatchString(comment)) {
		return "", SSHKey{}, false
	}
	sum := sha256.Sum256(blob)
	key := SSHKey{Type: kind, Fingerprint: "SHA256:" + base64.RawStdEncoding.EncodeToString(sum[:]), Comment: comment}
	canonical := kind + " " + encoded
	if comment != "" {
		canonical += " " + comment
	}
	return canonical, key, true
}

// normalizeSSHKeys admits a whole key set: bounded, no duplicates by
// fingerprint, canonical order preserved as given.
func normalizeSSHKeys(lines []string) ([]string, []SSHKey, bool) {
	if len(lines) > MaxSSHKeys {
		return nil, nil, false
	}
	canonical := make([]string, 0, len(lines))
	keys := make([]SSHKey, 0, len(lines))
	seen := map[string]bool{}
	for _, line := range lines {
		c, key, ok := normalizeSSHKey(line)
		if !ok || seen[key.Fingerprint] {
			return nil, nil, false
		}
		seen[key.Fingerprint] = true
		canonical = append(canonical, c)
		keys = append(keys, key)
	}
	return canonical, keys, true
}

// sshKeysDigest names a key set in the operation journal without copying the
// keys into audit rows.
func sshKeysDigest(canonical []string) string {
	sum := sha256.Sum256([]byte(strings.Join(canonical, "\n")))
	return hex.EncodeToString(sum[:])
}

// renderAuthorizedKeys is the exact file content for a canonical key set.
func renderAuthorizedKeys(canonical []string) []byte {
	var b bytes.Buffer
	b.WriteString(sshKeyFileHeader)
	for _, line := range canonical {
		b.WriteString(sshKeyOptions)
		b.WriteByte(' ')
		b.WriteString(line)
		b.WriteByte('\n')
	}
	return b.Bytes()
}

// sshString reads one RFC 4251 string and returns it with the rest.
func sshString(b []byte) ([]byte, []byte, bool) {
	if len(b) < 4 {
		return nil, nil, false
	}
	n := binary.BigEndian.Uint32(b)
	if uint64(n) > uint64(len(b)-4) {
		return nil, nil, false
	}
	return b[4 : 4+n], b[4+n:], true
}

// sshPositiveInt checks an RFC 4251 mpint is positive and minimally encoded
// and returns its bit length.
func sshPositiveInt(b []byte) (int, bool) {
	if len(b) == 0 || b[0]&0x80 != 0 {
		return 0, false
	}
	if b[0] == 0 {
		if len(b) == 1 || b[1]&0x80 == 0 {
			return 0, false
		}
		b = b[1:]
	}
	bits := (len(b) - 1) * 8
	for top := b[0]; top != 0; top >>= 1 {
		bits++
	}
	return bits, true
}

func validSSHBlob(kind string, blob []byte) bool {
	name, rest, ok := sshString(blob)
	if !ok || string(name) != kind {
		return false
	}
	switch kind {
	case "ssh-ed25519":
		key, rest, ok := sshString(rest)
		return ok && len(key) == 32 && len(rest) == 0
	case "ecdsa-sha2-nistp256", "ecdsa-sha2-nistp384", "ecdsa-sha2-nistp521":
		curve, rest, ok := sshString(rest)
		if !ok || string(curve) != strings.TrimPrefix(kind, "ecdsa-sha2-") {
			return false
		}
		point, rest, ok := sshString(rest)
		size := map[string]int{"nistp256": 65, "nistp384": 97, "nistp521": 133}[string(curve)]
		// Uncompressed points only, as OpenSSH writes them.
		return ok && len(rest) == 0 && len(point) == size && point[0] == 4
	case "ssh-rsa":
		e, rest, ok := sshString(rest)
		if !ok {
			return false
		}
		n, rest, ok := sshString(rest)
		if !ok || len(rest) != 0 {
			return false
		}
		eBits, eOK := sshPositiveInt(e)
		nBits, nOK := sshPositiveInt(n)
		return eOK && nOK && eBits >= 2 && eBits <= 33 && nBits >= 2048 && nBits <= 4096
	}
	return false
}
