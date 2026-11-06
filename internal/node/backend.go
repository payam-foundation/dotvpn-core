// Package node is the edge proxy: it authenticates streams offline, enforces
// egress policy, and serves every carrier on one TLS port next to a decoy site.
//
// Interface: New(Options) *Node; Node implements transport.Backend; Serve runs
// the listeners. Everything else (limits, accounting, SSRF guard, certificates,
// decoy) is hidden.
package node

import (
	"context"
	"errors"
	"net"
	"os"
	"slices"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/time/rate"

	"github.com/payam-foundation/dotvpn-core/internal/egress"
	"github.com/payam-foundation/dotvpn-wire/auth"
	"github.com/payam-foundation/dotvpn-wire/transport"
)

// Policy is the egress and per-user limit policy.
type Policy struct {
	AllowedPorts []int
	// AllowedUDPPorts limits UDP flow destinations. It is separate because the
	// TCP list rarely holds 53 or 123; nil means DefaultUDPPorts.
	AllowedUDPPorts []int
	ConcPerUser     int
	MbpsPerUser     int
	// AllowPrivate disables the private-address guard. Tests only.
	AllowPrivate bool
	// Egress picks the exit per destination. Nil dials everything directly.
	Egress *egress.Router
}

// DefaultUDPPorts are DNS, QUIC/HTTP3 (443), NTP and STUN/TURN: what a
// browser or phone needs over UDP, nothing a scanner or amplifier wants.
var DefaultUDPPorts = []int{53, 123, 443, 3478}

const (
	// udpIdle ends a flow with no traffic in either direction.
	udpIdle = 30 * time.Second
	// maxUDPFlows caps simultaneous UDP flows per user (each holds a socket).
	maxUDPFlows = 256
)

// Usage is traffic since the last Drain, per user.
type Usage struct {
	User string `json:"user"`
	Up   int64  `json:"up"`
	Down int64  `json:"down"`
}

type userState struct {
	active  atomic.Int64
	udp     atomic.Int64 // open UDP flows, also counted in active
	up      atomic.Int64
	down    atomic.Int64
	limiter *rate.Limiter // nil when unlimited
	mbps    int
	open    sync.Map // *meteredConn: live egress conns, closed when the user is denied
}

// Backend implements transport.Backend.
type Backend struct {
	verifier atomic.Pointer[auth.Verifier]
	policy   Policy
	egress   *egress.Router

	mu     sync.Mutex
	users  map[string]*userState
	denied map[string]struct{} // subjects refused: disabled or over quota
}

// NewBackend creates a Backend that trusts the given verifier.
func NewBackend(v *auth.Verifier, p Policy) *Backend {
	b := &Backend{policy: p, users: map[string]*userState{}, denied: map[string]struct{}{}}
	b.verifier.Store(v)
	b.egress = p.Egress
	if b.egress == nil {
		b.egress = egress.Direct(p.AllowPrivate)
	}
	return b
}

// EgressStatus reports each egress exit for metrics.
func (b *Backend) EgressStatus() []egress.ExitStatus { return b.egress.Status() }

// SetVerifier swaps trusted keys (rotation) without restart.
func (b *Backend) SetVerifier(v *auth.Verifier) { b.verifier.Store(v) }

// SetDenied replaces the deny list pushed by the control plane. Denied users
// stop working immediately instead of when their token expires.
func (b *Backend) SetDenied(ids []string) {
	m := make(map[string]struct{}, len(ids))
	for _, id := range ids {
		m[id] = struct{}{}
	}
	b.mu.Lock()
	b.denied = m
	var live []*meteredConn
	for id := range m {
		if s, ok := b.users[id]; ok {
			s.open.Range(func(k, _ any) bool { live = append(live, k.(*meteredConn)); return true })
		}
	}
	b.mu.Unlock()
	for _, c := range live {
		_ = c.Close() // ends the splice, so a download in flight stops too
	}
}

func (b *Backend) isDenied(id string) bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	_, bad := b.denied[id]
	return bad
}

// Authenticate verifies a data-plane token offline and refuses denied users.
// Every failure is the same ErrUnauthorized.
func (b *Backend) Authenticate(token string) (transport.User, error) {
	if token == "" {
		return transport.User{}, transport.ErrUnauthorized
	}
	c, err := b.verifier.Load().Verify(token)
	if err != nil {
		return transport.User{}, transport.ErrUnauthorized
	}
	if b.isDenied(c.Sub) {
		return transport.User{}, transport.ErrUnauthorized
	}
	return transport.User{ID: c.Sub, Conc: c.Conc, Mbps: c.Mbps}, nil
}

func (b *Backend) state(u transport.User) *userState {
	b.mu.Lock()
	defer b.mu.Unlock()
	s, ok := b.users[u.ID]
	mbps := u.Mbps
	if mbps == 0 {
		mbps = b.policy.MbpsPerUser
	}
	if !ok || s.mbps != mbps {
		var l *rate.Limiter
		if mbps > 0 {
			bps := mbps * 125000
			l = rate.NewLimiter(rate.Limit(bps), max(bps/4, 65536))
		}
		if !ok {
			s = &userState{}
			b.users[u.ID] = s
		}
		s.limiter, s.mbps = l, mbps
	}
	return s
}

// Dial opens an egress connection for u. It enforces port policy, the
// per-user concurrency cap and the private-address guard (checked on the
// resolved IP, so DNS rebinding cannot reach internal hosts).
func (b *Backend) Dial(ctx context.Context, u transport.User, authority string) (net.Conn, error) {
	host, portStr, err := net.SplitHostPort(authority)
	if err != nil || host == "" {
		return nil, transport.ErrForbidden
	}
	port, err := strconv.Atoi(portStr)
	if err != nil || !b.portAllowed(port) {
		return nil, transport.ErrForbidden
	}
	st := b.state(u)
	conc := u.Conc
	if conc == 0 {
		conc = b.policy.ConcPerUser
	}
	if conc > 0 && st.active.Add(1) > int64(conc) {
		st.active.Add(-1)
		return nil, transport.ErrBusy
	} else if conc <= 0 {
		st.active.Add(1)
	}
	c, err := b.egress.Dial(ctx, "tcp", authority)
	if err != nil {
		st.active.Add(-1)
		var de *egress.DenyError
		if errors.As(err, &de) {
			return nil, transport.ErrForbidden
		}
		return nil, transport.ErrBadGateway
	}
	m := &meteredConn{Conn: c, st: st}
	return b.track(m, u), nil
}

// track registers m so SetDenied can close it. A user denied between
// Authenticate and the dial is closed here instead of slipping through.
func (b *Backend) track(m *meteredConn, u transport.User) net.Conn {
	m.st.open.Store(m, struct{}{})
	if b.isDenied(u.ID) {
		_ = m.Close()
	}
	return m
}

// DialUDP opens a UDP egress flow for u (transport.UDPBackend). It applies the
// same checks as Dial: UDP port allow-list, concurrency slot, private-address
// guard on the resolved IP, rate limit and byte metering, plus a per-user flow
// cap and an idle timeout. The returned conn preserves datagram boundaries.
func (b *Backend) DialUDP(ctx context.Context, u transport.User, authority string) (net.Conn, error) {
	host, portStr, err := net.SplitHostPort(authority)
	if err != nil || host == "" {
		return nil, transport.ErrForbidden
	}
	port, err := strconv.Atoi(portStr)
	if err != nil || !slices.Contains(b.udpPorts(), port) {
		return nil, transport.ErrForbidden
	}
	st := b.state(u)
	conc := u.Conc
	if conc == 0 {
		conc = b.policy.ConcPerUser
	}
	if st.udp.Add(1) > maxUDPFlows {
		st.udp.Add(-1)
		return nil, transport.ErrBusy
	}
	if conc > 0 && st.active.Add(1) > int64(conc) {
		st.active.Add(-1)
		st.udp.Add(-1)
		return nil, transport.ErrBusy
	} else if conc <= 0 {
		st.active.Add(1)
	}
	release := func() { st.active.Add(-1); st.udp.Add(-1) }
	c, err := b.egress.Dial(ctx, "udp", authority)
	if err != nil {
		release()
		var de *egress.DenyError
		if errors.As(err, &de) {
			return nil, transport.ErrForbidden
		}
		return nil, transport.ErrBadGateway
	}
	m := &meteredConn{Conn: c, st: st, release: release}
	ic := &idleConn{meteredConn: m}
	ic.last.Store(time.Now().UnixNano())
	b.track(m, u)
	return ic, nil
}

func (b *Backend) udpPorts() []int {
	if len(b.policy.AllowedUDPPorts) == 0 {
		return DefaultUDPPorts
	}
	return b.policy.AllowedUDPPorts
}

// idleConn closes a UDP flow after udpIdle without traffic either way.
type idleConn struct {
	*meteredConn
	last atomic.Int64 // unix nanos of the last read or write
}

func (c *idleConn) Read(p []byte) (int, error) {
	for {
		idle := time.Duration(time.Now().UnixNano() - c.last.Load())
		if idle >= udpIdle {
			return 0, os.ErrDeadlineExceeded
		}
		_ = c.Conn.SetReadDeadline(time.Now().Add(udpIdle - idle))
		n, err := c.meteredConn.Read(p)
		if n > 0 {
			c.last.Store(time.Now().UnixNano())
		}
		if errors.Is(err, os.ErrDeadlineExceeded) {
			continue // recheck: writes may have refreshed last
		}
		return n, err
	}
}

func (c *idleConn) Write(p []byte) (int, error) {
	c.last.Store(time.Now().UnixNano())
	return c.meteredConn.Write(p)
}

func (b *Backend) portAllowed(p int) bool {
	if len(b.policy.AllowedPorts) == 0 {
		return p > 0 && p < 65536
	}
	for _, a := range b.policy.AllowedPorts {
		if a == p {
			return true
		}
	}
	return false
}

// Drain returns usage accumulated since the previous call and resets it.
func (b *Backend) Drain() []Usage {
	b.mu.Lock()
	defer b.mu.Unlock()
	var out []Usage
	for id, s := range b.users {
		up, down := s.up.Swap(0), s.down.Swap(0)
		if up != 0 || down != 0 {
			out = append(out, Usage{User: id, Up: up, Down: down})
		}
		if s.active.Load() == 0 && up == 0 && down == 0 {
			delete(b.users, id)
		}
	}
	return out
}

// Active is the number of open streams across users.
func (b *Backend) Active() int64 {
	b.mu.Lock()
	defer b.mu.Unlock()
	var n int64
	for _, s := range b.users {
		n += s.active.Load()
	}
	return n
}

// meteredConn counts bytes, applies the user's rate limit and releases the
// concurrency slot on Close.
type meteredConn struct {
	net.Conn
	st      *userState
	release func() // nil: just drop the concurrency slot
	once    sync.Once
}

// Read is the upstream-to-client direction ("down").
func (m *meteredConn) Read(p []byte) (int, error) {
	n, err := m.Conn.Read(p)
	if n > 0 {
		m.st.down.Add(int64(n))
		m.wait(n)
	}
	return n, err
}

// Write is the client-to-upstream direction ("up").
func (m *meteredConn) Write(p []byte) (int, error) {
	n, err := m.Conn.Write(p)
	if n > 0 {
		m.st.up.Add(int64(n))
		m.wait(n)
	}
	return n, err
}

func (m *meteredConn) wait(n int) {
	l := m.st.limiter
	if l == nil {
		return
	}
	for n > 0 {
		chunk := min(n, l.Burst())
		_ = l.WaitN(context.Background(), chunk)
		n -= chunk
	}
}

func (m *meteredConn) CloseWrite() error {
	if cw, ok := m.Conn.(interface{ CloseWrite() error }); ok {
		return cw.CloseWrite()
	}
	return nil
}

func (m *meteredConn) Close() error {
	m.st.open.Delete(m)
	err := m.Conn.Close()
	m.once.Do(func() {
		if m.release != nil {
			m.release()
			return
		}
		m.st.active.Add(-1)
	})
	return err
}
