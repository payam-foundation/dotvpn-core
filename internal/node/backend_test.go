package node

import (
	"context"
	"errors"
	"net"
	"os"
	"strconv"
	"testing"
	"time"

	"github.com/payam-foundation/dotvpn-wire/auth"
	"github.com/payam-foundation/dotvpn-wire/transport"
)

// A hostname that resolves to loopback must be refused at dial time: the guard
// runs on the resolved address, which is what defeats DNS rebinding.
func TestDialRefusesHostnameResolvingToLoopback(t *testing.T) {
	b := NewBackend(auth.NewVerifier(), Policy{})
	_, err := b.Dial(context.Background(), transport.User{ID: "u"}, "localhost:80")
	if !errors.Is(err, transport.ErrForbidden) {
		t.Fatalf("got %v, want ErrForbidden", err)
	}
	if b.Active() != 0 {
		t.Fatal("concurrency slot leaked after refused dial")
	}
}

func udpEcho(t *testing.T) string {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = pc.Close() })
	go func() {
		b := make([]byte, 2048)
		for {
			n, from, err := pc.ReadFrom(b)
			if err != nil {
				return
			}
			_, _ = pc.WriteTo(b[:n], from)
		}
	}()
	return pc.LocalAddr().String()
}

func TestDialUDPEchoesAndMeters(t *testing.T) {
	addr := udpEcho(t)
	_, port, _ := net.SplitHostPort(addr)
	p, _ := strconv.Atoi(port)
	b := NewBackend(auth.NewVerifier(), Policy{AllowPrivate: true, AllowedUDPPorts: []int{p}})
	c, err := b.DialUDP(context.Background(), transport.User{ID: "u"}, addr)
	if err != nil {
		t.Fatal(err)
	}
	if b.Active() != 1 {
		t.Fatalf("active = %d", b.Active())
	}
	_, _ = c.Write([]byte("hello"))
	buf := make([]byte, 64)
	_ = c.SetReadDeadline(time.Now().Add(2 * time.Second))
	n, err := c.Read(buf)
	if err != nil || string(buf[:n]) != "hello" {
		t.Fatalf("got %q, %v", buf[:n], err)
	}
	_ = c.Close()
	if b.Active() != 0 {
		t.Fatal("slot leaked after close")
	}
	if u := b.Drain(); len(u) != 1 || u[0].Up != 5 || u[0].Down != 5 {
		t.Fatalf("usage = %+v", u)
	}
}

func TestDialUDPPolicy(t *testing.T) {
	b := NewBackend(auth.NewVerifier(), Policy{})
	u := transport.User{ID: "u"}
	for name, addr := range map[string]string{
		"port not allowed":      "8.8.8.8:9999",
		"tcp-only port":         "8.8.8.8:80",
		"no port":               "8.8.8.8",
		"empty host":            ":53",
		"bad port":              "8.8.8.8:abc",
		"loopback resolved":     "localhost:53",
		"private literal":       "10.0.0.1:53",
		"metadata literal":      "169.254.169.254:53",
		"ipv6 loopback literal": "[::1]:53",
		"cgnat literal":         "100.64.0.1:443",
	} {
		if _, err := b.DialUDP(context.Background(), u, addr); !errors.Is(err, transport.ErrForbidden) {
			t.Errorf("%s: got %v, want ErrForbidden", name, err)
		}
	}
	if b.Active() != 0 {
		t.Fatal("slot leaked after refused dials")
	}
}

func TestDialUDPConcurrencyAndFlowCap(t *testing.T) {
	addr := udpEcho(t)
	_, port, _ := net.SplitHostPort(addr)
	p, _ := strconv.Atoi(port)
	b := NewBackend(auth.NewVerifier(), Policy{AllowPrivate: true, AllowedUDPPorts: []int{p}, ConcPerUser: 2})
	u := transport.User{ID: "u"}
	var open []net.Conn
	for range 2 {
		c, err := b.DialUDP(context.Background(), u, addr)
		if err != nil {
			t.Fatal(err)
		}
		open = append(open, c)
	}
	if _, err := b.DialUDP(context.Background(), u, addr); !errors.Is(err, transport.ErrBusy) {
		t.Fatalf("third flow: %v, want ErrBusy", err)
	}
	// TCP and UDP share the concurrency slots.
	if _, err := b.Dial(context.Background(), u, "127.0.0.1:1"); !errors.Is(err, transport.ErrBusy) {
		t.Fatalf("tcp over cap: %v", err)
	}
	for _, c := range open {
		_ = c.Close()
	}
	// Per-user flow cap, independent of conc.
	b = NewBackend(auth.NewVerifier(), Policy{AllowPrivate: true, AllowedUDPPorts: []int{p}, ConcPerUser: -1})
	for range maxUDPFlows {
		c, err := b.DialUDP(context.Background(), u, addr)
		if err != nil {
			t.Fatal(err)
		}
		defer c.Close()
	}
	if _, err := b.DialUDP(context.Background(), u, addr); !errors.Is(err, transport.ErrBusy) {
		t.Fatalf("flow cap: %v", err)
	}
}

func TestBackendIsUDPBackend(t *testing.T) {
	var _ transport.UDPBackend = (*Backend)(nil)
}

// A denied user's streams already in flight must end, not only new ones.
func TestSetDeniedClosesLiveStreams(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() { _, _ = c.Write([]byte("x")); time.Sleep(time.Minute); _ = c.Close() }()
		}
	}()
	b := NewBackend(auth.NewVerifier(), Policy{AllowPrivate: true})
	u, other := transport.User{ID: "u"}, transport.User{ID: "other"}
	c, err := b.Dial(context.Background(), u, ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	o, err := b.Dial(context.Background(), other, ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer o.Close()
	buf := make([]byte, 1)
	if _, err := c.Read(buf); err != nil {
		t.Fatal(err)
	}
	b.SetDenied([]string{"u"})
	_ = c.SetReadDeadline(time.Now().Add(2 * time.Second))
	if _, err := c.Read(buf); err == nil || errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("denied user's stream still open: %v", err)
	}
	if _, err := o.Write([]byte("y")); err != nil {
		t.Fatalf("other user's stream was closed: %v", err)
	}
	if b.Active() != 1 {
		t.Fatalf("active = %d, want 1", b.Active())
	}
}
