package main

import (
	"context"
	"errors"
	"log/slog"
	"net"
	"net/http"
	"time"

	"github.com/payam-foundation/dotvpn-core/internal/config"
	"github.com/payam-foundation/dotvpn-core/internal/control"
	"github.com/payam-foundation/dotvpn-core/internal/node"
	"github.com/payam-foundation/dotvpn-wire/auth"
	"github.com/payam-foundation/dotvpn-wire/loopback"
	"github.com/payam-foundation/dotvpn-wire/transport"
)

func init() {
	register("control", cmdControl)
}

// newControl builds the control service from config.
func newControl(ctx context.Context, c *config.Config, static []transport.Endpoint) (*control.Service, control.Store, error) {
	if c.Control.PrivateKey == "" {
		return nil, nil, errors.New("control.private_key missing: run `dotvpn-core init -role control`")
	}
	priv, err := auth.DecodePrivateKey(c.Control.PrivateKey)
	if err != nil {
		return nil, nil, err
	}
	ttl, err := time.ParseDuration(c.Control.TokenTTL)
	if err != nil {
		return nil, nil, err
	}
	st, err := control.OpenStore(ctx, c.Control.Database)
	if err != nil {
		return nil, nil, err
	}
	svc := control.New(control.Options{
		Store:           st,
		Signer:          auth.NewSigner(priv),
		AdminToken:      c.Control.AdminToken,
		TokenTTL:        ttl,
		DefaultQuotaGB:  c.Control.DefaultQuotaGB,
		StaticEndpoints: static,
	})
	return svc, st, nil
}

func cmdControl(ctx context.Context, args []string) error {
	fs, cfgFlag, verbose := flagSet("control")
	if err := fs.Parse(args); err != nil {
		return err
	}
	log := setupLog(*verbose, stderr())
	c, _, err := loadConfig(*cfgFlag)
	if err != nil {
		return err
	}
	svc, st, err := newControl(ctx, c, nil)
	if err != nil {
		return err
	}
	defer st.Close()

	go serveAdmin(ctx, c.Control.AdminListen, svc.AdminHandler())
	srv := &http.Server{Handler: svc.Handler(), ReadHeaderTimeout: 10 * time.Second}
	var ln net.Listener
	if c.Control.Domain != "" {
		tc, terr := node.TLSConfig(ctx, c.Control.Domain, c.Node.ACMEEmail, c.DataDir)
		if terr != nil {
			return terr
		}
		if ln, err = net.Listen("tcp", c.Control.Listen); err != nil {
			return err
		}
		srv.TLSConfig = tc
		go func() { <-ctx.Done(); _ = srv.Close() }()
		log.Info("control listening (tls)", "addr", ln.Addr().String())
		err = srv.ServeTLS(ln, "", "")
	} else {
		if ln, err = net.Listen("tcp", c.Control.Listen); err != nil {
			return err
		}
		go func() { <-ctx.Done(); _ = srv.Close() }()
		log.Info("control listening (plain http: put TLS in front)", "addr", ln.Addr().String())
		err = srv.Serve(ln)
	}
	if errors.Is(err, http.ErrServerClosed) {
		return nil
	}
	return err
}

// serveAdmin serves the admin API on a loopback address or unix socket. The
// config validator already refused anything else; Listen checks again.
func serveAdmin(ctx context.Context, addr string, h http.Handler) {
	ln, err := loopback.Listen(addr)
	if err != nil {
		slog.Error("admin listener", "err", err)
		return
	}
	srv := &http.Server{Handler: h, ReadHeaderTimeout: 10 * time.Second}
	go func() { <-ctx.Done(); _ = srv.Close() }()
	slog.Info("admin listening", "addr", addr)
	_ = srv.Serve(ln)
}
