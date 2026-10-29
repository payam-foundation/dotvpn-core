// dotvpn is one binary with a role per subcommand.
package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"syscall"
)

// version is set at build time with -ldflags "-X main.version=...".
var version = "dev"

const usage = `dotvpn-core ` + "%s" + `

Usage: dotvpn-core <command> [flags]

  init        write a config and keys for a role (allinone, node, control)
  allinone    control plane and node in one process
  node        edge proxy (joins a control plane or trusts static keys)
  control     accounts, tokens, quota, server list, relay enrollment
  invite      print a client invite string
  token       mint a bearer token (static deployments)
  version     print version

The admin API listens on loopback or a unix socket only.
Run "dotvpn-core <command> -h" for flags.
`

type command struct {
	run func(ctx context.Context, args []string) error
}

// cmds is filled by register calls in each command file's init.
var cmds = map[string]command{
	"version": {func(context.Context, []string) error { fmt.Println(version); return nil }},
}

func register(name string, run func(ctx context.Context, args []string) error) {
	cmds[name] = command{run}
}

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintf(os.Stderr, usage, version)
		os.Exit(2)
	}
	name := os.Args[1]
	if name == "-h" || name == "--help" || name == "help" {
		fmt.Fprintf(os.Stdout, usage, version)
		return
	}
	c, ok := cmds[name]
	if !ok {
		fmt.Fprintf(os.Stderr, "dotvpn-core: unknown command %q\n\n", name)
		fmt.Fprintf(os.Stderr, usage, version)
		os.Exit(2)
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := c.run(ctx, os.Args[2:]); err != nil {
		if err == flag.ErrHelp {
			return
		}
		slog.Error(name+" failed", "err", err)
		os.Exit(1)
	}
}
