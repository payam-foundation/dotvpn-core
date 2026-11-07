package egress

import (
	"context"
	"errors"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// fakeExit records what it was asked to dial and can be made to fail.
type fakeExit struct {
	mu    sync.Mutex
	calls []string
	err   error
}

func (f *fakeExit) dial(_ context.Context, network, host, port string) (net.Conn, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, network+" "+net.JoinHostPort(host, port))
	if f.err != nil {
		return nil, f.err
	}
	a, b := net.Pipe()
	go func() { _ = b.Close() }()
	return a, nil
}

func (f *fakeExit) got() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.calls...)
}

func newTestRouter(t *testing.T, c Config, o Options, fakes map[string]*fakeExit) *Router {
	t.Helper()
	o.build = func(name string, e Exit) (exit, error) {
		if f, ok := fakes[name]; ok {
			return f, nil
		}
		return nil, errors.New("no fake for " + name)
	}
	r, err := New(c, o)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = r.Close() })
	return r
}

func echoServer(t *testing.T) string {
	t.Helper()
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
			_ = c.Close()
		}
	}()
	return ln.Addr().String()
}

func isDeny(err error) bool {
	var de *DenyError
	return errors.As(err, &de)
}

func socksExits(names ...string) map[string]Exit {
	m := map[string]Exit{}
	for _, n := range names {
		m[n] = Exit{Type: "socks5", Addr: "127.0.0.1:9"}
	}
	return m
}

func TestRuleOrderAndDefault(t *testing.T) {
	tor, warp := &fakeExit{}, &fakeExit{}
	c := Config{
		Exits: socksExits("tor", "warp"),
		Rules: []Rule{
			{Match: Match{Domains: []string{"*.openai.com"}}, Exit: "warp"},
			{Match: Match{Domains: []string{"api.openai.com", "example.org"}}, Exit: "tor"},
		},
		Default: "tor",
	}
	r := newTestRouter(t, c, Options{}, map[string]*fakeExit{"tor": tor, "warp": warp})
	for _, a := range []string{"api.openai.com:443", "example.org:443", "other.net:443"} {
		conn, err := r.Dial(context.Background(), "tcp", a)
		if err != nil {
			t.Fatalf("%s: %v", a, err)
		}
		_ = conn.Close()
	}
	if got := warp.got(); len(got) != 1 || got[0] != "tcp api.openai.com:443" {
		t.Errorf("warp calls = %v: first matching rule must win", got)
	}
	if got := tor.got(); len(got) != 2 || got[0] != "tcp example.org:443" || got[1] != "tcp other.net:443" {
		t.Errorf("tor calls = %v", got)
	}
}

func TestWildcardExcludesApexAndLookalikes(t *testing.T) {
	s := newDomainSet([]string{"*.gov.ir", "evil.com"})
	for h, want := range map[string]bool{
		"a.gov.ir": true, "a.b.gov.ir": true, "gov.ir": false, "notgov.ir": false,
		"evil.com": true, "www.evil.com": false, "gov.ir.evil.net": false,
	} {
		if got := s.match(h); got != want {
			t.Errorf("%s = %v, want %v", h, got, want)
		}
	}
}

func TestBlockDomainCIDRAndCountryFile(t *testing.T) {
	dir := t.TempDir()
	ir := filepath.Join(dir, "ir.txt")
	if err := os.WriteFile(ir, []byte("# Iran\n5.22.0.0/16 # a block\n\n2001:db8:ff::/48\n203.0.113.9\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	f := &fakeExit{}
	c := Config{
		Exits:   socksExits("x"),
		Default: "x",
		Block:   Block{Domains: []string{"*.gov.ir"}, CIDRs: []string{"198.51.100.0/24"}, CIDRFiles: map[string]string{"IR": ir}},
	}
	r := newTestRouter(t, c, Options{}, map[string]*fakeExit{"x": f})
	for _, a := range []string{"www.gov.ir:443", "198.51.100.7:443", "5.22.9.9:443", "[2001:db8:ff::1]:443", "203.0.113.9:80"} {
		if _, err := r.Dial(context.Background(), "tcp", a); !isDeny(err) {
			t.Errorf("%s: err = %v, want DenyError", a, err)
		}
	}
	if len(f.got()) != 0 {
		t.Errorf("blocked destinations reached the exit: %v", f.got())
	}
	conn, err := r.Dial(context.Background(), "tcp", "8.8.8.8:443")
	if err != nil {
		t.Fatalf("allowed dial: %v", err)
	}
	_ = conn.Close()
	if s := status(r, ExitBlock); s.Denied != 5 {
		t.Errorf("denied = %d, want 5", s.Denied)
	}
}

func status(r *Router, name string) ExitStatus {
	for _, s := range r.Status() {
		if s.Name == name {
			return s
		}
	}
	return ExitStatus{}
}

// The SSRF guard covers every exit, not only direct: a proxy sidecar on the
// same machine would otherwise reach loopback and the metadata service.
func TestGuardAppliesToEveryExit(t *testing.T) {
	f := &fakeExit{}
	c := Config{Exits: socksExits("x"), Default: "x"}
	r := newTestRouter(t, c, Options{}, map[string]*fakeExit{"x": f})
	for _, a := range []string{
		"127.0.0.1:80", "10.0.0.1:80", "169.254.169.254:80", "[::1]:80", "[::ffff:10.0.0.1]:80", "[fe80::1%eth0]:80",
		"localhost:80", "intranet:80", "127.1:80", "2130706433:80", "0x7f.1:80", "foo.localhost:80",
	} {
		if _, err := r.Dial(context.Background(), "tcp", a); !isDeny(err) {
			t.Errorf("%s: err = %v, want DenyError", a, err)
		}
	}
	if len(f.got()) != 0 {
		t.Errorf("guarded destinations reached the exit: %v", f.got())
	}
	if _, err := r.Dial(context.Background(), "tcp", "Example.COM.:443"); err != nil {
		t.Fatalf("public name: %v", err)
	}
	if got := f.got(); len(got) != 1 || got[0] != "tcp example.com:443" {
		t.Errorf("calls = %v: host must be lowercased and unrooted", got)
	}
}

func TestFailClosedVersusFallbackDirect(t *testing.T) {
	srv := echoServer(t)
	host, _, _ := net.SplitHostPort(srv)
	down := &fakeExit{err: errors.New("exit down")}
	c := Config{
		Exits: socksExits("down"),
		Rules: []Rule{
			{Match: Match{CIDRs: []string{"127.0.0.0/8"}}, Exit: "down"},
			{Match: Match{Domains: []string{"open.test"}}, Exit: "down", Fallback: "direct"},
		},
	}
	r := newTestRouter(t, c, Options{AllowPrivate: true}, map[string]*fakeExit{"down": down})
	if _, err := r.Dial(context.Background(), "tcp", srv); err == nil || isDeny(err) {
		t.Fatalf("fail-closed: err = %v, want the exit error", err)
	}
	c.Rules = []Rule{{Match: Match{CIDRs: []string{host + "/32"}}, Exit: "down", Fallback: "direct"}}
	r = newTestRouter(t, c, Options{AllowPrivate: true}, map[string]*fakeExit{"down": down})
	conn, err := r.Dial(context.Background(), "tcp", srv)
	if err != nil {
		t.Fatalf("fallback direct: %v", err)
	}
	_ = conn.Close()
	if s := status(r, "down"); s.Failed != 1 {
		t.Errorf("down failed = %d, want 1", s.Failed)
	}
	if s := status(r, ExitDirect); s.OK != 1 {
		t.Errorf("direct ok = %d, want 1", s.OK)
	}
}

func TestFallbackNeverBypassesDeny(t *testing.T) {
	deny := &fakeExit{err: &DenyError{"x"}}
	c := Config{
		Exits: socksExits("x"),
		Rules: []Rule{{Match: Match{Domains: []string{"a.test"}}, Exit: "x", Fallback: "direct"}},
	}
	r := newTestRouter(t, c, Options{}, map[string]*fakeExit{"x": deny})
	if _, err := r.Dial(context.Background(), "tcp", "a.test:443"); !isDeny(err) {
		t.Fatalf("err = %v, want DenyError", err)
	}
	if s := status(r, ExitDirect); s.OK+s.Failed+s.Denied != 0 {
		t.Error("deny fell back to direct")
	}
}

func TestUDPRouting(t *testing.T) {
	w := &fakeExit{}
	c := Config{
		Exits: map[string]Exit{"w": {Type: "warp"}},
		UDP:   "direct",
		Rules: []Rule{
			{Match: Match{Domains: []string{"quic.test"}}, Exit: "w", UDP: "w"},
			{Match: Match{Domains: []string{"tcp-only.test"}}, Exit: "w"},
			{Match: Match{Domains: []string{"nope.test"}}, Exit: "block", UDP: "w"},
		},
	}
	r := newTestRouter(t, c, Options{}, map[string]*fakeExit{"w": w})
	for _, a := range []string{"quic.test:443", "tcp-only.test:443"} {
		conn, err := r.Dial(context.Background(), "udp", a)
		if err != nil {
			t.Logf("%s: %v (direct dial of a fake name)", a, err)
			continue
		}
		_ = conn.Close()
	}
	if got := w.got(); len(got) != 1 || got[0] != "udp quic.test:443" {
		t.Errorf("exit UDP calls = %v: only the rule with a udp override may use the exit", got)
	}
	if _, err := r.Dial(context.Background(), "udp", "nope.test:443"); !isDeny(err) {
		t.Errorf("block rule must block UDP too, got %v", err)
	}
}

func TestUDPBlock(t *testing.T) {
	r := newTestRouter(t, Config{UDP: ExitBlock}, Options{}, nil)
	if _, err := r.Dial(context.Background(), "udp", "8.8.8.8:53"); !isDeny(err) {
		t.Fatalf("err = %v, want DenyError", err)
	}
	// TCP is unaffected by udp: block, so it reaches the real dialer.
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	if _, err := r.Dial(ctx, "tcp", "192.0.2.1:80"); isDeny(err) {
		t.Fatalf("tcp wrongly denied: %v", err)
	}
}

func TestDirectFamilyFilter(t *testing.T) {
	srv := echoServer(t)
	_, port, _ := net.SplitHostPort(srv)
	v6, err := New(Config{IPFamily: "v6"}, Options{AllowPrivate: true})
	if err != nil {
		t.Fatal(err)
	}
	// localhost has a v4 address, so a v6-only router must not reach it over v4.
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if c, err := v6.Dial(ctx, "tcp", "127.0.0.1:"+port); err == nil {
		_ = c.Close()
		t.Fatal("ip_family v6 dialled an IPv4 literal")
	}
	v4, _ := New(Config{IPFamily: "v4"}, Options{AllowPrivate: true})
	c, err := v4.Dial(ctx, "tcp", "localhost:"+port)
	if err != nil {
		t.Fatalf("v4 localhost: %v", err)
	}
	_ = c.Close()
}

func TestDirectBlocksResolvedAddress(t *testing.T) {
	srv := echoServer(t)
	_, port, _ := net.SplitHostPort(srv)
	r, err := New(Config{Block: Block{CIDRs: []string{"127.0.0.0/8", "::1/128"}}}, Options{AllowPrivate: true})
	if err != nil {
		t.Fatal(err)
	}
	// The name carries no match; only the resolved address does.
	if _, err := r.Dial(context.Background(), "tcp", "localhost:"+port); !isDeny(err) {
		t.Fatalf("err = %v, want DenyError from the resolved-address check", err)
	}
}

func TestDirectGuardOnResolvedAddress(t *testing.T) {
	r := Direct(false)
	if _, err := r.Dial(context.Background(), "tcp", "localhost:80"); !isDeny(err) {
		t.Fatalf("err = %v, want DenyError", err)
	}
}

func TestValidate(t *testing.T) {
	ok := Config{
		IPFamily: "auto", Default: "tor", UDP: "w",
		Exits: map[string]Exit{"tor": {Type: "socks5", Addr: "127.0.0.1:9050"}, "w": {Type: "warp"}},
		Block: Block{Domains: []string{"*.gov.ir"}, CIDRs: []string{"10.0.0.0/8"}},
		Rules: []Rule{{Match: Match{Domains: []string{"a.com"}}, Exit: "w", Fallback: "direct"}},
	}
	if err := ok.Validate(); err != nil {
		t.Fatalf("valid config rejected: %v", err)
	}
	for name, mut := range map[string]func(*Config){
		"bad family":       func(c *Config) { c.IPFamily = "v5" },
		"unknown default":  func(c *Config) { c.Default = "nope" },
		"unknown rule":     func(c *Config) { c.Rules[0].Exit = "nope" },
		"udp to socks":     func(c *Config) { c.UDP = "tor" },
		"rule udp socks":   func(c *Config) { c.Rules[0].UDP = "tor" },
		"bad cidr":         func(c *Config) { c.Block.CIDRs = []string{"10.0.0.0/33"} },
		"bad rule cidr":    func(c *Config) { c.Rules[0].Match.CIDRs = []string{"x"} },
		"empty match":      func(c *Config) { c.Rules[0].Match = Match{} },
		"bad fallback":     func(c *Config) { c.Rules[0].Fallback = "tor" },
		"reserved name":    func(c *Config) { c.Exits["direct"] = Exit{Type: "socks5", Addr: "a:1"} },
		"bad type":         func(c *Config) { c.Exits["tor"] = Exit{Type: "wg"} },
		"no addr":          func(c *Config) { c.Exits["tor"] = Exit{Type: "socks5"} },
		"uppercase domain": func(c *Config) { c.Block.Domains = []string{"*.Gov.ir"} },
		"mid wildcard":     func(c *Config) { c.Block.Domains = []string{"a.*.ir"} },
		"empty file path":  func(c *Config) { c.Block.CIDRFiles = map[string]string{"IR": ""} },
	} {
		c := ok
		c.Exits = map[string]Exit{"tor": ok.Exits["tor"], "w": ok.Exits["w"]}
		c.Rules = append([]Rule(nil), ok.Rules...)
		mut(&c)
		if err := c.Validate(); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestBadCIDRFile(t *testing.T) {
	p := filepath.Join(t.TempDir(), "x.txt")
	if err := os.WriteFile(p, []byte("not-an-ip\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := New(Config{Block: Block{CIDRFiles: map[string]string{"IR": p}}}, Options{})
	if err == nil || !strings.Contains(err.Error(), "not a CIDR") {
		t.Fatalf("err = %v", err)
	}
	if _, err := New(Config{Block: Block{CIDRFiles: map[string]string{"IR": p + ".missing"}}}, Options{}); err == nil {
		t.Fatal("missing file accepted: a typo must not silently disable the blocklist")
	}
}
