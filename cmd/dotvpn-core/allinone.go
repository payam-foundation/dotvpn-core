package main

import (
	"context"
	"net/http"
	"time"

	"github.com/payam-foundation/dotvpn-core/internal/control"
	"github.com/payam-foundation/dotvpn-core/internal/node"
)

// allinoneNodeID names the in-process node in reverse endpoints and pool tokens.
const allinoneNodeID = "allinone"

func init() {
	register("allinone", cmdAllInOne)
}

// cmdAllInOne runs control and node in one process on one port: the control
// API is mounted on the node mux, and node meters feed the store directly.
func cmdAllInOne(ctx context.Context, args []string) error {
	fs, cfgFlag, verbose := flagSet("allinone")
	if err := fs.Parse(args); err != nil {
		return err
	}
	setupLog(*verbose, stderr())
	c, _, err := loadConfig(*cfgFlag)
	if err != nil {
		return err
	}
	static, err := endpointsFor(c, allinoneNodeID)
	if err != nil {
		return err
	}
	svc, st, err := newControl(ctx, c, static)
	if err != nil {
		return err
	}
	defer st.Close()

	mount := c.Control.Mount
	if mount == "" {
		mount = "/dotvpn/api"
	}
	mounts := map[string]http.Handler{mount: http.StripPrefix(mount, svc.Handler())}
	rs := &relaySet{}
	rs.setStatic(c.Node.Relays)
	go serveAdmin(ctx, c.Control.AdminListen, svc.AdminHandler())
	return runNode(ctx, c, mounts, rs, func(b *node.Backend) {
		go func() {
			t := time.NewTicker(10 * time.Second)
			defer t.Stop()
			for {
				if infos, err := svc.ActiveRelays(ctx); err == nil {
					tok, _ := svc.PoolToken(allinoneNodeID)
					rs.set(infos, tok)
				}
				select {
				case <-ctx.Done():
					return
				case <-t.C:
				}
			}
		}()
		go func() {
			t := time.NewTicker(10 * time.Second)
			defer t.Stop()
			for {
				select {
				case <-ctx.Done():
					return
				case <-t.C:
				}
				p := control.Period(time.Now())
				for _, u := range b.Drain() {
					_ = st.AddUsage(ctx, u.User, u.Up+u.Down, p)
				}
				if ids, err := st.Blocked(ctx, p); err == nil {
					b.SetDenied(ids)
				}
			}
		}()
	})
}
