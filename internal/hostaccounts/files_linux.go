//go:build linux

package hostaccounts

import (
	"context"
	"io"
)

// RunFiles runs the file helper as the account's user, through the pinned
// systemd-run, setpriv and env, in one transient scope in the account's
// user slice with the plan's task limit, no_new_privs, no capability and
// the operation's time left (see siteRunArgsIn), started in the home. The
// helper's bytes are checked like the other fixed tools before every run,
// and it must be executable by the site user. It needs the web operation,
// which makes the empty root-owned HOME every site step gets. Its error
// output is kept only in a bounded buffer and never passed on.
func (n *linuxSystem) RunFiles(ctx context.Context, r record, stdin io.Reader, stdout io.Writer) error {
	if n.webUID <= 0 {
		return ErrUnavailable
	}
	if info, e := trustedFile(FilesHelper, false); e != nil || info.Mode().Perm()&0001 == 0 {
		return ErrUnavailable
	}
	code, e := n.runSiteProgram(ctx, r, r.Account.Home, FilesHelper, stdin, stdout, &tailBuffer{})
	if e != nil || code != 0 {
		return ErrUnavailable
	}
	return nil
}
