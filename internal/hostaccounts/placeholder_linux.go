//go:build linux

package hostaccounts

import "context"

// InstallPlaceholder runs the site's own PHP CLI as the account's user, in
// its public_html, with no php.ini (-n), a fixed script and the fixed page
// on stdin. Root writes nothing into the home: the file is made with the
// tenant's rights, so it can land only where the tenant could write itself.
func (n *linuxSystem) InstallPlaceholder(ctx context.Context, r record) (bool, error) {
	if n.webUID <= 0 || !r.Web.enabled() {
		return false, ErrUnavailable
	}
	php := wpPHP(r.Web.PHPVersion)
	if info, e := trustedFile(php, false); e != nil || info.Mode().Perm()&0001 == 0 {
		return false, ErrUnavailable
	}
	out, code, e := n.runAsSite(ctx, r, php, placeholderPage, "-n", "-r", placeholderScript)
	if e != nil {
		return false, ErrUnavailable
	}
	return placeholderOutcome(out, code)
}
