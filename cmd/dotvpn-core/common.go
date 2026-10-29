package main

import (
	"flag"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"runtime"

	"github.com/payam-foundation/dotvpn-core/internal/config"
)

// flagSet creates a FlagSet whose errors are returned, with the shared
// -config and -v flags.
func flagSet(name string) (*flag.FlagSet, *string, *bool) {
	fs := flag.NewFlagSet("dotvpn "+name, flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	cfg := fs.String("config", "", "config file (default: $DOTVPN_CONFIG, /etc/dotvpn/config.yaml as root, else the user config dir)")
	verbose := fs.Bool("v", false, "debug logging")
	return fs, cfg, verbose
}

func setupLog(verbose bool, w io.Writer) *slog.Logger {
	lvl := slog.LevelInfo
	if verbose {
		lvl = slog.LevelDebug
	}
	l := slog.New(slog.NewTextHandler(w, &slog.HandlerOptions{Level: lvl}))
	slog.SetDefault(l)
	return l
}

func isRoot() bool { return runtime.GOOS != "windows" && os.Geteuid() == 0 }

func userDir() string {
	d, err := os.UserConfigDir()
	if err != nil {
		d = "."
	}
	return filepath.Join(d, "dotvpn")
}

func configPath(flagVal string) string {
	if flagVal != "" {
		return flagVal
	}
	if v := os.Getenv("DOTVPN_CONFIG"); v != "" {
		return v
	}
	if isRoot() {
		return "/etc/dotvpn/config.yaml"
	}
	return filepath.Join(userDir(), "config.yaml")
}

func defaultDataDir() string {
	if isRoot() {
		return "/var/lib/dotvpn"
	}
	return userDir()
}

// loadConfig loads the config for a role command.
func loadConfig(flagVal string) (*config.Config, string, error) {
	p := configPath(flagVal)
	c, err := config.Load(p)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, p, fmt.Errorf("no config at %s: run `dotvpn-core init` first", p)
		}
		return nil, p, err
	}
	return c, p, nil
}

func stderr() io.Writer { return os.Stderr }
