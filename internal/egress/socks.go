package egress

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"sync/atomic"
	"time"

	"golang.org/x/net/proxy"
)

// upstream is a SOCKS5 or HTTP CONNECT proxy the operator runs next to the
// node (Tor, Psiphon, a corporate proxy). The node only dials it. Names go to
// the proxy unresolved, so the proxy does the DNS lookup, not the node.
type upstream struct {
	addr   string
	http   bool
	d      net.Dialer
	alive  atomic.Bool
	cancel context.CancelFunc
}

const probeEvery = 10 * time.Second

func newUpstream(e Exit) *upstream {
	u := &upstream{addr: e.Addr, http: e.Type == "http", d: net.Dialer{Timeout: 10 * time.Second, KeepAlive: 30 * time.Second}}
	u.alive.Store(true)
	ctx, cancel := context.WithCancel(context.Background())
	u.cancel = cancel
	go u.probe(ctx)
	return u
}

// probe marks the sidecar down when its port stops accepting connections, so
// metrics show it before users do.
func (u *upstream) probe(ctx context.Context) {
	t := time.NewTicker(probeEvery)
	defer t.Stop()
	for {
		pc, cancel := context.WithTimeout(ctx, 3*time.Second)
		c, err := u.d.DialContext(pc, "tcp", u.addr)
		cancel()
		if err == nil {
			_ = c.Close()
		}
		u.alive.Store(err == nil)
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

func (u *upstream) up() bool { return u.alive.Load() }

func (u *upstream) Close() error { u.cancel(); return nil }

func (u *upstream) dial(ctx context.Context, network, host, port string) (net.Conn, error) {
	if network != "tcp" {
		return nil, fmt.Errorf("egress: %s upstream carries TCP only", u.addr)
	}
	target := net.JoinHostPort(host, port)
	if u.http {
		return u.connect(ctx, target)
	}
	p, err := proxy.SOCKS5("tcp", u.addr, nil, &u.d)
	if err != nil {
		return nil, err
	}
	return p.(proxy.ContextDialer).DialContext(ctx, "tcp", target)
}

func (u *upstream) connect(ctx context.Context, target string) (net.Conn, error) {
	c, err := u.d.DialContext(ctx, "tcp", u.addr)
	if err != nil {
		return nil, err
	}
	if dl, ok := ctx.Deadline(); ok {
		_ = c.SetDeadline(dl)
	} else {
		_ = c.SetDeadline(time.Now().Add(15 * time.Second))
	}
	req := &http.Request{Method: http.MethodConnect, URL: &url.URL{Opaque: target}, Host: target, Header: http.Header{}}
	if err := req.Write(c); err != nil {
		_ = c.Close()
		return nil, err
	}
	br := bufio.NewReader(c)
	resp, err := http.ReadResponse(br, req)
	if err != nil {
		_ = c.Close()
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		_ = c.Close()
		return nil, fmt.Errorf("egress: upstream refused CONNECT: %s", resp.Status)
	}
	_ = c.SetDeadline(time.Time{})
	if br.Buffered() > 0 { // bytes the proxy sent right behind the 200
		return &bufConn{Conn: c, r: br}, nil
	}
	return c, nil
}

type bufConn struct {
	net.Conn
	r *bufio.Reader
}

func (b *bufConn) Read(p []byte) (int, error) { return b.r.Read(p) }

func (b *bufConn) CloseWrite() error {
	if cw, ok := b.Conn.(interface{ CloseWrite() error }); ok {
		return cw.CloseWrite()
	}
	return nil
}
