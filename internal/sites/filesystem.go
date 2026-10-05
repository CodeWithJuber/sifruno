package sites

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"net"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"unicode/utf8"

	"golang.org/x/net/idna"
)

var identifier = regexp.MustCompile(`^[a-f0-9]{32}$`)
var hashPattern = regexp.MustCompile(`^[a-f0-9]{64}$`)
var segmentPattern = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9_.-]{0,79}$`)
var domainLabel = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$`)

func newID() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", ErrUnavailable
	}
	return hex.EncodeToString(b), nil
}
func sum(data []byte) string { h := sha256.Sum256(data); return hex.EncodeToString(h[:]) }
func validActor(actor string) bool {
	return actor == "local-operator"
}
func canonicalDomain(value string) (string, error) {
	if value != strings.TrimSpace(value) || strings.ContainsAny(value, "/\\:@?#%") {
		return "", ErrInvalid
	}
	d, err := idna.Lookup.ToASCII(strings.ToLower(value))
	if err != nil || len(d) > 253 || len(d) < 3 || net.ParseIP(d) != nil || strings.HasSuffix(d, ".") || strings.HasSuffix(d, ".localhost") {
		return "", ErrInvalid
	}
	parts := strings.Split(d, ".")
	if len(parts) < 2 {
		return "", ErrInvalid
	}
	for _, p := range parts {
		if !domainLabel.MatchString(p) {
			return "", ErrInvalid
		}
	}
	return d, nil
}
func validName(value string) bool {
	if value != strings.TrimSpace(value) || len(value) < 1 || len(value) > 80 || !utf8.ValidString(value) {
		return false
	}
	for _, r := range value {
		if r < 0x20 || r == 0x7f {
			return false
		}
	}
	return true
}
func staticExtension(name string) bool {
	switch strings.ToLower(path.Ext(name)) {
	case ".html", ".htm", ".css", ".js", ".mjs", ".txt", ".svg", ".png", ".jpg", ".jpeg", ".gif", ".webp", ".ico", ".woff", ".woff2", ".ttf", ".pdf":
		return true
	}
	return false
}
func safeFile(value string) error {
	if len(value) == 0 || len(value) > 200 || !utf8.ValidString(value) || strings.ContainsAny(value, "\\:%?#\x00") || path.Clean(value) != value || strings.HasPrefix(value, "/") || !filepath.IsLocal(filepath.FromSlash(value)) {
		return ErrInvalid
	}
	parts := strings.Split(value, "/")
	if len(parts) > 8 || !staticExtension(value) {
		return ErrInvalid
	}
	for _, p := range parts {
		if !segmentPattern.MatchString(p) || strings.HasSuffix(p, ".") {
			return ErrInvalid
		}
		base := strings.ToLower(strings.SplitN(p, ".", 2)[0])
		if base == "con" || base == "prn" || base == "aux" || base == "nul" || (len(base) == 4 && (strings.HasPrefix(base, "com") || strings.HasPrefix(base, "lpt")) && base[3] >= '0' && base[3] <= '9') || base == "credentials" || base == "password" || base == "secrets" || base == "kubeconfig" || base == "key" || strings.HasPrefix(base, "id_rsa") || strings.HasPrefix(base, "id_ed25519") {
			return ErrInvalid
		}
	}
	return nil
}

func checkParents(root *os.Root, name string) error {
	parts := strings.Split(filepath.ToSlash(name), "/")
	for i := range parts {
		p := filepath.Join(parts[:i+1]...)
		info, err := root.Lstat(p)
		if err != nil {
			return err
		}
		if info.Mode()&os.ModeSymlink != 0 || (!info.Mode().IsRegular() && !info.IsDir()) || (i < len(parts)-1 && !info.IsDir()) {
			return ErrUnavailable
		}
		f, err := root.Open(p)
		if err != nil {
			return err
		}
		opened, err := f.Stat()
		if err == nil && (!os.SameFile(info, opened) || guardHandle(f, opened) != nil) {
			err = ErrUnavailable
		}
		f.Close()
		if err != nil {
			return err
		}
	}
	return nil
}
func readRoot(root *os.Root, name string, limit int64) ([]byte, error) {
	if err := checkParents(root, name); err != nil {
		return nil, err
	}
	f, err := root.Open(name)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	before, err := f.Stat()
	if err != nil || !before.Mode().IsRegular() || before.Size() < 0 || before.Size() > limit || guardHandle(f, before) != nil {
		return nil, ErrUnavailable
	}
	data, err := io.ReadAll(io.LimitReader(f, limit+1))
	if err != nil || int64(len(data)) > limit {
		return nil, ErrUnavailable
	}
	after, err := f.Stat()
	if err != nil {
		return nil, ErrUnavailable
	}
	current, err := root.Lstat(name)
	if err != nil || current.Mode()&os.ModeSymlink != 0 || !os.SameFile(before, current) || !before.ModTime().Equal(after.ModTime()) || before.Size() != after.Size() || int64(len(data)) != after.Size() || guardHandle(f, after) != nil {
		return nil, ErrUnavailable
	}
	if err = checkParents(root, name); err != nil {
		return nil, ErrUnavailable
	}
	return data, nil
}
func atomicRoot(root *os.Root, name string, data []byte) error {
	parent := filepath.Dir(name)
	if parent != "." {
		if err := checkParents(root, parent); err != nil {
			return ErrUnavailable
		}
	}
	if _, err := root.Lstat(name); err == nil {
		if err = checkParents(root, name); err != nil {
			return ErrUnavailable
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return ErrUnavailable
	}
	id, err := newID()
	if err != nil {
		return err
	}
	temporary := filepath.Join(parent, ".site-write-"+id)
	f, err := root.OpenFile(temporary, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return ErrUnavailable
	}
	defer root.Remove(temporary)
	if _, err = f.Write(data); err == nil {
		err = f.Sync()
	}
	if closeErr := f.Close(); err == nil {
		err = closeErr
	}
	if err != nil {
		return ErrUnavailable
	}
	if err = root.Rename(temporary, name); err != nil {
		return ErrUnavailable
	}
	return syncRoot(root, parent)
}
func makeParents(root *os.Root, name string) error {
	parts := strings.Split(filepath.ToSlash(filepath.Dir(name)), "/")
	current := ""
	for _, part := range parts {
		if part == "." {
			continue
		}
		current = filepath.Join(current, part)
		if err := root.Mkdir(current, 0700); err != nil && !errors.Is(err, os.ErrExist) {
			return ErrUnavailable
		}
		if err := checkParents(root, current); err != nil {
			return ErrUnavailable
		}
	}
	return nil
}
func fileCatalog(data map[string][]byte) ([]FileInfo, error) {
	if len(data) < 1 || len(data) > MaxFiles {
		return nil, ErrInvalid
	}
	result := []FileInfo{}
	seen := map[string]bool{}
	var total int64
	for p, bytes := range data {
		key := strings.ToLower(p)
		if safeFile(p) != nil || seen[key] || len(bytes) > MaxFileBytes {
			return nil, ErrInvalid
		}
		seen[key] = true
		total += int64(len(bytes))
		if total > MaxSiteBytes {
			return nil, ErrInvalid
		}
		result = append(result, FileInfo{Path: p, Bytes: int64(len(bytes)), SHA256: sum(bytes)})
	}
	for p := range data {
		for other := range data {
			if p != other && strings.HasPrefix(strings.ToLower(other), strings.ToLower(p)+"/") {
				return nil, ErrInvalid
			}
		}
	}
	sort.Slice(result, func(i, j int) bool { return result[i].Path < result[j].Path })
	return result, nil
}
