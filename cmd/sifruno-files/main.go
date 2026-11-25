// Command sifruno-files is the file manager's helper (internal/sitefiles).
// The account broker runs it as a website's own user, in that user's home,
// in a transient unit in the account's slice: it reads one request on
// stdin, writes one answer on stdout and exits. It takes no arguments and
// refuses to run as root, so a mistaken start cannot act with more than a
// tenant's rights.
package main

import (
	"bufio"
	"fmt"
	"os"
	"syscall"

	"sifruno/internal/sitefiles"
)

func main() {
	if os.Getuid() == 0 || os.Geteuid() == 0 || len(os.Args) != 1 {
		fmt.Fprintln(os.Stderr, "sifruno-files runs only as a website's user, started by the account broker")
		os.Exit(2)
	}
	// New folders are 0755 and new files get their mode set explicitly, so
	// the web server can read what the file manager makes.
	syscall.Umask(0o022)
	home, err := os.OpenFile(".", os.O_RDONLY|syscall.O_DIRECTORY, 0)
	if err != nil {
		fmt.Fprintln(os.Stderr, "sifruno-files: the home folder could not be opened")
		os.Exit(1)
	}
	out := bufio.NewWriterSize(os.Stdout, 64<<10)
	err = sitefiles.Serve(home, os.Stdin, out)
	if flushErr := out.Flush(); err == nil {
		err = flushErr
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "sifruno-files:", err)
		os.Exit(1)
	}
}
