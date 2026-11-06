package egress

import (
	"bufio"
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"testing"
	"time"
)

// echoBackServer accepts one connection at a time and echoes bytes back.
func echoBackServer(t *testing.T) string {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = l.Close() })
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			go func() { defer c.Close(); _, _ = io.Copy(c, c) }()
		}
	}()
	return l.Addr().String()
}

// socks5Server is a no-auth SOCKS5 proxy that records the requested targets.
func socks5Server(t *testing.T, targets chan<- string) string {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = l.Close() })
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				hdr := make([]byte, 2)
				if _, err := io.ReadFull(c, hdr); err != nil {
					return
				}
				if _, err := io.ReadFull(c, make([]byte, hdr[1])); err != nil {
					return
				}
				_, _ = c.Write([]byte{5, 0})
				req := make([]byte, 4)
				if _, err := io.ReadFull(c, req); err != nil {
					return
				}
				var host string
				switch req[3] {
				case 1:
					b := make([]byte, 4)
					_, _ = io.ReadFull(c, b)
					host = net.IP(b).String()
				case 3:
					n := make([]byte, 1)
					_, _ = io.ReadFull(c, n)
					b := make([]byte, n[0])
					_, _ = io.ReadFull(c, b)
					host = string(b)
				default:
					return
				}
				p := make([]byte, 2)
				_, _ = io.ReadFull(c, p)
				targets <- net.JoinHostPort(host, strconv.Itoa(int(p[0])<<8|int(p[1])))
				// Reach the echo server regardless of the requested name.
				up, err := net.Dial("tcp", echoAddr)
				if err != nil {
					_, _ = c.Write([]byte{5, 5, 0, 1, 0, 0, 0, 0, 0, 0})
					return
				}
				defer up.Close()
				_, _ = c.Write([]byte{5, 0, 0, 1, 0, 0, 0, 0, 0, 0})
				go func() { _, _ = io.Copy(up, c) }()
				_, _ = io.Copy(c, up)
			}()
		}
	}()
	return l.Addr().String()
}

var echoAddr string

func httpConnectServer(t *testing.T, targets chan<- string, status int) string {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = l.Close() })
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				req, err := http.ReadRequest(bufio.NewReader(c))
				if err != nil {
					return
				}
				targets <- req.Host
				if status != http.StatusOK {
					_, _ = c.Write([]byte("HTTP/1.1 403 Forbidden\r\n\r\n"))
					return
				}
				up, err := net.Dial("tcp", echoAddr)
				if err != nil {
					return
				}
				defer up.Close()
				_, _ = c.Write([]byte("HTTP/1.1 200 OK\r\n\r\n"))
				go func() { _, _ = io.Copy(up, c) }()
				_, _ = io.Copy(c, up)
			}()
		}
	}()
	return l.Addr().String()
}

func roundTrip(t *testing.T, c net.Conn) {
	t.Helper()
	_ = c.SetDeadline(time.Now().Add(3 * time.Second))
	if _, err := c.Write([]byte("ping")); err != nil {
		t.Fatal(err)
	}
	b := make([]byte, 4)
	if _, err := io.ReadFull(c, b); err != nil || string(b) != "ping" {
		t.Fatalf("echo = %q, %v", b, err)
	}
}

func TestUpstreamExits(t *testing.T) {
	echoAddr = echoBackServer(t)
	targets := make(chan string, 4)
	for name, tc := range map[string]struct {
		typ  string
		addr string
	}{
		"socks5": {"socks5", socks5Server(t, targets)},
		"http":   {"http", httpConnectServer(t, targets, http.StatusOK)},
	} {
		t.Run(name, func(t *testing.T) {
			r, err := New(Config{
				Exits: map[string]Exit{"up": {Type: tc.typ, Addr: tc.addr}},
				Rules: []Rule{{Match: Match{Domains: []string{"example.com"}}, Exit: "up"}},
			}, Options{})
			if err != nil {
				t.Fatal(err)
			}
			defer r.Close()
			c, err := r.Dial(context.Background(), "tcp", "example.com:443")
			if err != nil {
				t.Fatal(err)
			}
			defer c.Close()
			roundTrip(t, c)
			// The proxy got the name, not an address the node resolved.
			if got := <-targets; !strings.HasPrefix(got, "example.com") {
				t.Fatalf("proxy target = %q, want hostname", got)
			}
			var s ExitStatus
			for _, x := range r.Status() {
				if x.Name == "up" {
					s = x
				}
			}
			if s.OK != 1 || !s.Up {
				t.Fatalf("status = %+v", s)
			}
		})
	}
}

func TestUpstreamHTTPRefusal(t *testing.T) {
	targets := make(chan string, 1)
	addr := httpConnectServer(t, targets, http.StatusForbidden)
	r, err := New(Config{Exits: map[string]Exit{"up": {Type: "http", Addr: addr}}, Default: "up"}, Options{})
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	_, err = r.Dial(context.Background(), "tcp", "example.com:443")
	var de *DenyError
	if err == nil || errors.As(err, &de) {
		t.Fatalf("err = %v, want plain dial failure", err)
	}
}

func TestUpstreamProbeMarksDown(t *testing.T) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := l.Addr().String()
	_ = l.Close() // nothing listens
	r, err := New(Config{Exits: map[string]Exit{"up": {Type: "socks5", Addr: addr}}}, Options{})
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		for _, s := range r.Status() {
			if s.Name == "up" && !s.Up {
				return
			}
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal("exit still reported up with no listener")
}
