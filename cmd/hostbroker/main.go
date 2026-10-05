package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"sifruno/internal/hostaccounts"
	"syscall"
)

func main() {
	f := flag.NewFlagSet("hostbroker", flag.ContinueOnError)
	f.SetOutput(io.Discard)
	opts := hostaccounts.BrokerOptions{}
	f.StringVar(&opts.StateDir, "state", "", "New dedicated root-only broker state")
	f.StringVar(&opts.SocketPath, "socket", "", "Exclusive absolute Unix socket")
	f.StringVar(&opts.HomesDir, "homes", "", "Dedicated managed home parent")
	uid := f.Uint("controller-uid", 0, "Existing non-root controller UID")
	if f.Parse(os.Args[1:]) != nil || f.NArg() != 0 || *uid == 0 || uint64(*uid) > uint64(^uint32(0)) {
		fmt.Fprintln(os.Stderr, "Invalid native broker configuration")
		os.Exit(2)
	}
	opts.ControllerUID = uint32(*uid)
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if hostaccounts.RunBroker(ctx, opts) != nil {
		fmt.Fprintln(os.Stderr, "Native broker unavailable or recovery required")
		os.Exit(1)
	}
}
