//go:build live

package egress

import (
	"context"
	"io"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"
)

// Run: go test -tags live -run TestWarpLive -v ./internal/egress
// Registers a free WARP account in a temp dir and fetches Cloudflare's trace
// through the router, over TCP, then sends a UDP DNS query.
func TestWarpLive(t *testing.T) {
	r, err := New(Config{
		Exits: map[string]Exit{"warp": {Type: "warp"}},
		Rules: []Rule{{Match: Match{Domains: []string{"www.cloudflare.com"}}, Exit: "warp"}},
		UDP:   "warp",
	}, Options{DataDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()

	deadline := time.Now().Add(90 * time.Second)
	for time.Now().Before(deadline) {
		for _, s := range r.Status() {
			if s.Name == "warp" && s.Up {
				goto up
			}
		}
		time.Sleep(time.Second)
	}
	t.Fatal("warp never came up")
up:
	cl := http.Client{Transport: &http.Transport{DialContext: func(ctx context.Context, n, a string) (net.Conn, error) {
		return r.Dial(ctx, n, a)
	}}, Timeout: 20 * time.Second}
	resp, err := cl.Get("https://www.cloudflare.com/cdn-cgi/trace")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	t.Logf("%s", b)
	if !strings.Contains(string(b), "warp=on") {
		t.Fatalf("not through warp:\n%s", b)
	}

	c, err := r.Dial(context.Background(), "udp", "1.1.1.1:53")
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	q := []byte{0x12, 0x34, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 3, 'c', 'o', 'm', 0, 0, 1, 0, 1}
	_ = c.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := c.Write(q); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 512)
	if n, err := c.Read(buf); err != nil || n < 12 || buf[0] != 0x12 {
		t.Fatalf("udp dns: n=%d err=%v", n, err)
	}
}
