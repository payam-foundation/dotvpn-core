// Package egress decides where each proxied connection leaves the node:
// straight from the server, through an upstream proxy or WARP, or nowhere.
//
// Interface: New(Config, Options) *Router; Router.Dial(ctx, network, authority)
// returns the egress connection or a *DenyError; Status and Close serve
// metrics and shutdown. Rules, the blocklist, the SSRF guard, address-family
// handling, health checks and the exit adapters are hidden behind it.
//
// Evaluation order: SSRF guard on IP literals, blocklist, first matching rule,
// then the default exit. Hostnames are matched before any DNS lookup, so a
// proxied exit resolves them itself and the node never leaks the query.
package egress

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"strings"
	"sync/atomic"
)

// exit is one way out. dial gets a validated, lowercase host and a port.
type exit interface {
	dial(ctx context.Context, network, host, port string) (net.Conn, error)
}

// Options are the parts of the router that do not come from the config file.
type Options struct {
	// AllowPrivate disables the SSRF guard. Tests only.
	AllowPrivate bool
	// DataDir holds exit state (the WARP account).
	DataDir string
	Log     *slog.Logger

	// build replaces exit construction in tests.
	build func(name string, e Exit) (exit, error)
}

type rule struct {
	domains  domainSet
	cidrs    prefixSet
	exit     string
	fallback string
	udp      string
}

type stat struct{ ok, failed, denied atomic.Int64 }

// ExitStatus is a point-in-time view of one exit for metrics.
type ExitStatus struct {
	Name   string
	Up     bool
	OK     int64
	Failed int64
	Denied int64
}

// Router routes egress dials. It is safe for concurrent use.
type Router struct {
	cfg          Config
	allowPrivate bool
	direct       *direct
	exits        map[string]exit
	blockDomains domainSet
	blockCIDRs   prefixSet
	rules        []rule
	stats        map[string]*stat
	order        []string
	closers      []io.Closer
}

// Direct is the router for a node with no egress block: every destination is
// dialled from the server, behind the SSRF guard.
func Direct(allowPrivate bool) *Router {
	r, err := New(Config{}, Options{AllowPrivate: allowPrivate})
	if err != nil {
		panic(err) // unreachable: the zero Config has nothing to load
	}
	return r
}

// New validates c, reads CIDR files and starts the exits.
func New(c Config, o Options) (*Router, error) {
	if err := c.Validate(); err != nil {
		return nil, err
	}
	if o.Log == nil {
		o.Log = slog.Default()
	}
	r := &Router{
		cfg:          c,
		allowPrivate: o.AllowPrivate,
		exits:        map[string]exit{},
		blockDomains: newDomainSet(c.Block.Domains),
		stats:        map[string]*stat{ExitDirect: {}},
		order:        []string{ExitDirect},
	}
	var err error
	if r.blockCIDRs, err = parsePrefixes(c.Block.CIDRs); err != nil {
		return nil, err
	}
	for label, path := range c.Block.CIDRFiles {
		ps, err := loadPrefixFile(path)
		if err != nil {
			return nil, fmt.Errorf("egress: block.cidr_files.%s: %w", label, err)
		}
		r.blockCIDRs = append(r.blockCIDRs, ps...)
	}
	r.direct = newDirect(c.IPFamily, o.AllowPrivate, r.blockCIDRs)
	for name, e := range c.Exits {
		x, err := r.newExit(name, e, o)
		if err != nil {
			_ = r.Close()
			return nil, fmt.Errorf("egress: exit %s: %w", name, err)
		}
		r.exits[name] = x
		r.stats[name] = &stat{}
		r.order = append(r.order, name)
	}
	r.stats[ExitBlock] = &stat{}
	for _, cr := range c.Rules {
		ru := rule{domains: newDomainSet(cr.Match.Domains), exit: cr.Exit, fallback: cr.Fallback, udp: cr.UDP}
		if ru.cidrs, err = parsePrefixes(cr.Match.CIDRs); err != nil {
			return nil, err
		}
		r.rules = append(r.rules, ru)
	}
	return r, nil
}

func (r *Router) newExit(name string, e Exit, o Options) (exit, error) {
	if o.build != nil {
		return o.build(name, e)
	}
	switch e.Type {
	case "socks5", "http":
		u := newUpstream(e)
		r.closers = append(r.closers, u)
		return u, nil
	}
	return nil, fmt.Errorf("type %q not supported", e.Type)
}

// Close stops background work held by the exits.
func (r *Router) Close() error {
	var errs []error
	for _, c := range r.closers {
		errs = append(errs, c.Close())
	}
	return errors.Join(errs...)
}

// Status reports every exit, direct first.
func (r *Router) Status() []ExitStatus {
	out := make([]ExitStatus, 0, len(r.order)+1)
	for _, n := range append(append([]string(nil), r.order...), ExitBlock) {
		s := r.stats[n]
		up := true
		if h, ok := r.exits[n].(interface{ up() bool }); ok {
			up = h.up()
		}
		out = append(out, ExitStatus{Name: n, Up: up, OK: s.ok.Load(), Failed: s.failed.Load(), Denied: s.denied.Load()})
	}
	return out
}

// Dial connects to authority ("host:port") over network ("tcp" or "udp").
// A destination the guard or the blocklist refuses returns a *DenyError.
func (r *Router) Dial(ctx context.Context, network, authority string) (net.Conn, error) {
	host, port, err := net.SplitHostPort(authority)
	if err != nil || host == "" {
		return nil, &DenyError{authority}
	}
	host = strings.ToLower(strings.TrimSuffix(host, "."))
	ip, _ := netip.ParseAddr(host)
	if ip.IsValid() && (ip.Zone() != "" || (!r.allowPrivate && forbiddenAddr(ip))) {
		r.stats[ExitBlock].denied.Add(1)
		return nil, &DenyError{authority}
	}
	if r.blocked(host, ip) {
		r.stats[ExitBlock].denied.Add(1)
		return nil, &DenyError{authority}
	}
	name, fallback := r.route(network, host, ip)
	if name == ExitBlock {
		r.stats[ExitBlock].denied.Add(1)
		return nil, &DenyError{authority}
	}
	c, err := r.dialExit(ctx, name, network, host, port, ip.IsValid())
	var de *DenyError
	if err != nil && fallback == ExitDirect && name != ExitDirect && !errors.As(err, &de) {
		c, err = r.dialExit(ctx, ExitDirect, network, host, port, ip.IsValid())
	}
	return c, err
}

func (r *Router) dialExit(ctx context.Context, name, network, host, port string, isIP bool) (net.Conn, error) {
	var (
		c   net.Conn
		err error
	)
	if name == ExitDirect {
		c, err = r.direct.dial(ctx, network, host, port)
	} else if !isIP && !r.allowPrivate && !proxySafeHost(host) {
		err = &DenyError{net.JoinHostPort(host, port)}
	} else {
		c, err = r.exits[name].dial(ctx, network, host, port)
	}
	var de *DenyError
	switch {
	case err == nil:
		r.stats[name].ok.Add(1)
	case errors.As(err, &de):
		r.stats[name].denied.Add(1)
	default:
		r.stats[name].failed.Add(1)
	}
	return c, err
}

func (r *Router) blocked(host string, ip netip.Addr) bool {
	if ip.IsValid() {
		return r.blockCIDRs.contains(ip)
	}
	return r.blockDomains.match(host)
}

// route returns the exit for a destination and the rule's fallback.
// CIDR rules apply to IP literals only: a hostname bound for a proxied exit
// is not resolved here, so its address is unknown.
func (r *Router) route(network, host string, ip netip.Addr) (name, fallback string) {
	udp := network == "udp"
	// UDP never follows a TCP-only exit: it uses the rule's udp override,
	// then the global one, then direct. A block rule still blocks both.
	pick := func(tcp, over string) string {
		if !udp || tcp == ExitBlock {
			return tcp
		}
		return first(over, r.cfg.UDP, ExitDirect)
	}
	for _, ru := range r.rules {
		if (ip.IsValid() && ru.cidrs.contains(ip)) || (!ip.IsValid() && ru.domains.match(host)) {
			return pick(ru.exit, ru.udp), ru.fallback
		}
	}
	return pick(first(r.cfg.Default, ExitDirect), ""), ""
}

func first(l ...string) string {
	for _, s := range l {
		if s != "" {
			return s
		}
	}
	return ""
}
