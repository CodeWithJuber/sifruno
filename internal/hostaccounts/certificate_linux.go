//go:build linux

package hostaccounts

import (
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"time"

	"golang.org/x/sys/unix"
	"sifruno/internal/olsweb"
)

// The certificate operation's root effects, each a direct call on handles:
//   - the TLS root (olsweb.TLSRoot) and one directory per site in it are
//     made root-owned 0700 with mkdirat and opened with O_NOFOLLOW from a
//     handle on their parent, which must be a root-owned directory nobody
//     else may write, up to /. No tenant owns any part of the path;
//   - the staged pair, the live pair and the listener pair are written
//     root-owned 0600 with writeAt: a new file created with O_EXCL and
//     O_NOFOLLOW, synced, then renamed into place;
//   - the listener's self-signed certificate is made in Go (crypto/ecdsa,
//     crypto/x509); no openssl runs;
//   - the live pair joins the same configTxn as the config, so a failed
//     `openlitespeed -t` puts the old certificate back with the old config;
//   - a delete removes the site's directory once the site is out of the
//     config, and only the file names this code writes.

// rootPrivate is the owner and mode of every file in the TLS root.
var rootPrivate = fileMeta{uid: 0, gid: 0, mode: 0600}

// openTLSRoot opens the TLS root. With create it is made when missing;
// without, a missing root returns nil and no error.
func (n *linuxSystem) openTLSRoot(t *configTxn, create bool) (*os.File, error) {
	if !create {
		if _, e := os.Lstat(n.tlsDir); errors.Is(e, os.ErrNotExist) {
			return nil, nil
		}
	}
	parent := filepath.Dir(n.tlsDir)
	if authority(parent) != nil {
		return nil, ErrUnavailable
	}
	p, e := openRootDir(parent)
	if e != nil {
		return nil, ErrUnavailable
	}
	t.handles = append(t.handles, p)
	return privateDir(t, p, filepath.Base(n.tlsDir), create)
}

// privateDir opens parent/name without following a link. With create a
// missing directory is made root-owned 0700; without, a missing directory
// returns nil and no error. An existing directory must be root-owned with
// no access for group or others.
func privateDir(t *configTxn, parent *os.File, name string, create bool) (*os.File, error) {
	created := false
	if create {
		e := unix.Mkdirat(int(parent.Fd()), name, 0700)
		if e != nil && !errors.Is(e, unix.EEXIST) {
			return nil, ErrUnavailable
		}
		created = e == nil
	}
	fd, e := unix.Openat(int(parent.Fd()), name, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if errors.Is(e, unix.ENOENT) && !create {
		return nil, nil
	}
	if e != nil {
		return nil, ErrUnavailable
	}
	d := os.NewFile(uintptr(fd), name)
	t.handles = append(t.handles, d)
	if created && (unix.Fchown(fd, 0, 0) != nil || unix.Fchmod(fd, 0700) != nil) {
		return nil, ErrUnavailable
	}
	if uid, _, mode, e := ownerOfHandle(d); e != nil || uid != 0 || mode&0077 != 0 {
		return nil, ErrUnavailable
	}
	return d, nil
}

// StageCertificate writes the checked chain and key as the site's staged
// pair, key first; with both empty it removes the staged pair.
func (n *linuxSystem) StageCertificate(_ context.Context, r record, chainPEM, keyPEM []byte) error {
	if n.webUID <= 0 || !idPattern.MatchString(r.Account.ID) {
		return ErrUnavailable
	}
	unstage := len(chainPEM) == 0 && len(keyPEM) == 0
	if !unstage && (len(chainPEM) == 0 || len(keyPEM) == 0) {
		return ErrInvalid
	}
	t := &configTxn{}
	defer t.close()
	root, e := n.openTLSRoot(t, !unstage)
	if e != nil || root == nil {
		return e
	}
	site, e := privateDir(t, root, siteName(r.Account.ID), !unstage)
	if e != nil || site == nil {
		return e
	}
	if unstage {
		for _, name := range []string{stagedCertFile, stagedKeyFile} {
			if e := unix.Unlinkat(int(site.Fd()), name, 0); e != nil && !errors.Is(e, unix.ENOENT) {
				return ErrUnavailable
			}
		}
		if site.Sync() != nil {
			return ErrUnavailable
		}
		return nil
	}
	if writeAt(site, stagedKeyFile, keyPEM, rootPrivate) != nil || writeAt(site, stagedCertFile, chainPEM, rootPrivate) != nil {
		return ErrUnavailable
	}
	return nil
}

// ApplyCertificate reads the staged pair back, checks its form again and
// that its leaf is the one the journal names, then writes it as the site's
// live cert.pem and key.pem and installs the config in the same transaction.
// A missing or different staged pair is ErrRecovery: the operation stays
// pending for a person, because the broker cannot know what to install.
func (n *linuxSystem) ApplyCertificate(ctx context.Context, r record, next CertificateState, sites []olsweb.Site) error {
	if n.webUID <= 0 || !idPattern.MatchString(r.Account.ID) || !validCertificateState(next) {
		return ErrUnavailable
	}
	name := siteName(r.Account.ID)
	t := &configTxn{}
	abort := func(err error) error {
		if e := t.restore(); e != nil {
			err = e
		}
		t.close()
		return err
	}
	root, e := n.openTLSRoot(t, false)
	if e != nil || root == nil {
		return abort(ErrRecovery)
	}
	site, e := privateDir(t, root, name, false)
	if e != nil || site == nil {
		return abort(ErrRecovery)
	}
	chain, _, chainOK, chainErr := readAt(site, stagedCertFile)
	key, _, keyOK, keyErr := readAt(site, stagedKeyFile)
	if chainErr != nil || keyErr != nil || !chainOK || !keyOK {
		return abort(ErrRecovery)
	}
	bundle, e := parseCertificate(string(chain), string(key))
	if e != nil || bundle.state != next {
		return abort(ErrRecovery)
	}
	certChanged, e := t.write(site, siteCertFile, bundle.chainPEM, rootPrivate)
	if e != nil {
		return abort(e)
	}
	keyChanged, e := t.write(site, siteKeyFile, bundle.keyPEM, rootPrivate)
	if e != nil {
		return abort(e)
	}
	touched := ""
	if certChanged || keyChanged {
		touched = olsweb.NamePrefix + name
	}
	return n.installWith(ctx, t, sites, touched)
}

// ensureListenerCertificate keeps a usable listener pair in the TLS root, or
// writes a new one as part of t when either file is missing, they do not
// match, or the certificate is not valid now.
func (n *linuxSystem) ensureListenerCertificate(t *configTxn) error {
	root, e := n.openTLSRoot(t, true)
	if e != nil {
		return e
	}
	cert, _, certOK, certErr := readAt(root, listenerCertFile)
	key, _, keyOK, keyErr := readAt(root, listenerKeyFile)
	if certErr != nil || keyErr != nil {
		return ErrUnavailable
	}
	now := time.Now()
	if certOK && keyOK && listenerCertificateUsable(cert, key, now) {
		return nil
	}
	certPEM, keyPEM, e := newListenerCertificate(now)
	if e != nil {
		return e
	}
	if _, e := t.write(root, listenerKeyFile, keyPEM, rootPrivate); e != nil {
		return e
	}
	if _, e := t.write(root, listenerCertFile, certPEM, rootPrivate); e != nil {
		return e
	}
	return nil
}

// removeSiteTLS removes the site's TLS directory: the live and staged pairs
// and the temporary names writeAt leaves if the broker stops before a rename.
// Anything else in it is reported, not removed. A missing TLS root or site
// directory is a completed removal, so a retried delete passes.
func (n *linuxSystem) removeSiteTLS(r record) error {
	t := &configTxn{}
	defer t.close()
	root, e := n.openTLSRoot(t, false)
	if e != nil || root == nil {
		return e
	}
	name := siteName(r.Account.ID)
	site, e := privateDir(t, root, name, false)
	if e != nil || site == nil {
		return e
	}
	known := map[string]bool{}
	for _, f := range []string{siteCertFile, siteKeyFile, stagedCertFile, stagedKeyFile} {
		known[f] = true
		known[f+".sifruno-new"] = true // writeAt's temporary name
	}
	entries, e := site.ReadDir(len(known) + 1)
	if e != nil && !errors.Is(e, io.EOF) {
		return ErrUnavailable
	}
	if len(entries) > len(known) {
		return ErrRecovery
	}
	for _, entry := range entries {
		if !known[entry.Name()] || !entry.Type().IsRegular() {
			return ErrRecovery
		}
	}
	for _, entry := range entries {
		if e := unix.Unlinkat(int(site.Fd()), entry.Name(), 0); e != nil && !errors.Is(e, unix.ENOENT) {
			return ErrUnavailable
		}
	}
	if e := unix.Unlinkat(int(root.Fd()), name, unix.AT_REMOVEDIR); e != nil && !errors.Is(e, unix.ENOENT) {
		return ErrUnavailable
	}
	if root.Sync() != nil {
		return ErrUnavailable
	}
	return nil
}
