package node

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/payam-foundation/dotvpn-wire/loopback"
	"github.com/payam-foundation/dotvpn-wire/transport"
)

// Options configures a Node. Mounts and Extra let other modules plug into the
// single TLS port without the node knowing about them.
type Options struct {
	Name    string
	Listen  string
	Domain  string
	Email   string
	DataDir string
	Decoy   string
	Backend *Backend
	// TLS overrides certificate handling (tests). When nil, ACME or a
	// self-signed certificate is used.
	TLS *tls.Config
	// Mounts maps URL path prefixes to handlers (control API in allinone,
	// WebSocket carriers). Requests that match are not sent to the decoy.
	Mounts map[string]http.Handler
	// Extra are additional servers started with the node, each given the
	// bound TCP address (UDP listeners reuse its port), the TLS config and the
	// handler (the HTTP/3 listener uses this).
	Extra []func(ctx context.Context, addr string, tlsCfg *tls.Config, h http.Handler) error
	// AdminListen serves /healthz, /readyz and /metrics. Keep it on loopback.
	AdminListen string
	Log         *slog.Logger
}

// Node is a running edge proxy: HTTP/2 CONNECT data plane, mounted carrier
// handlers, and a decoy for everything else.
type Node struct {
	o       Options
	decoy   http.Handler
	handler http.Handler
}

// New assembles the edge handler from o. Serve runs the listeners.
func New(o Options) (*Node, error) {
	if o.Backend == nil {
		return nil, errors.New("node: backend required")
	}
	if o.Listen == "" {
		o.Listen = ":443"
	}
	if o.Log == nil {
		o.Log = slog.Default()
	}
	d, err := newDecoy(o.Decoy)
	if err != nil {
		return nil, err
	}
	n := &Node{o: o, decoy: d}
	n.handler = n.route()
	return n, nil
}

func (n *Node) route() http.Handler {
	connect := transport.ConnectHandler(n.o.Backend, n.decoy)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodConnect && r.ProtoMajor >= 2 {
			connect.ServeHTTP(w, r)
			return
		}
		for prefix, h := range n.o.Mounts {
			if r.URL.Path == prefix || strings.HasPrefix(r.URL.Path, strings.TrimSuffix(prefix, "/")+"/") {
				h.ServeHTTP(w, r)
				return
			}
		}
		n.decoy.ServeHTTP(w, r)
	})
}

// Serve blocks until ctx is cancelled or the listener fails.
func (n *Node) Serve(ctx context.Context) error {
	cs := &certSource{cfg: n.o.TLS}
	if cs.cfg == nil {
		var err error
		if cs, err = newCerts(ctx, n.o.Domain, n.o.Email, n.o.DataDir); err != nil {
			return fmt.Errorf("node: certificates: %w", err)
		}
	}
	ln, err := net.Listen("tcp", n.o.Listen)
	if err != nil {
		return err
	}
	srv := &http.Server{
		Handler:           n.handler,
		TLSConfig:         cs.cfg,
		ReadHeaderTimeout: 20 * time.Second,
		IdleTimeout:       5 * time.Minute,
		ErrorLog:          slog.NewLogLogger(n.o.Log.Handler(), slog.LevelDebug),
	}
	errc := make(chan error, 1+len(n.o.Extra))
	go func() { errc <- srv.ServeTLS(ln, "", "") }()
	for _, x := range n.o.Extra {
		go func() { errc <- x(ctx, ln.Addr().String(), cs.cfg, n.handler) }()
	}
	if n.o.AdminListen != "" {
		go func() { errc <- n.serveAdmin(ctx) }()
	}
	n.o.Log.Info("node listening", "addr", ln.Addr().String(), "domain", n.o.Domain, "pin", cs.pin)

	select {
	case <-ctx.Done():
	case err = <-errc:
	}
	sctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_ = srv.Shutdown(sctx)
	if err != nil && !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
}

func (n *Node) serveAdmin(ctx context.Context) error {
	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) { fmt.Fprintln(w, "ok") })
	mux.HandleFunc("/readyz", func(w http.ResponseWriter, _ *http.Request) { fmt.Fprintln(w, "ready") })
	mux.HandleFunc("/metrics", func(w http.ResponseWriter, _ *http.Request) {
		fmt.Fprintf(w, "# TYPE dotvpn_node_active_streams gauge\ndotvpn_node_active_streams %d\n", n.o.Backend.Active())
	})
	ln, err := loopback.Listen(n.o.AdminListen)
	if err != nil {
		return fmt.Errorf("node: admin listener: %w", err)
	}
	s := &http.Server{Handler: mux, ReadHeaderTimeout: 5 * time.Second}
	go func() {
		<-ctx.Done()
		_ = s.Close()
	}()
	return s.Serve(ln)
}
