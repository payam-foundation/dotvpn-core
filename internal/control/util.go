package control

import (
	"net"
	"net/http"
	"strconv"
	"sync"
	"time"
)

func itoa(n int64) string { return strconv.FormatInt(n, 10) }

// clientIP is the TCP peer. Forwarding headers are deliberately ignored: they
// are client controlled and would let an attacker dodge the limiter.
func clientIP(r *http.Request) string {
	h, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return h
}

// ipLimiter is a fixed-window counter per key. Unauthenticated endpoints use
// it to slow down account-key guessing.
type ipLimiter struct {
	mu     sync.Mutex
	limit  int
	window time.Duration
	hits   map[string]*bucket
}

type bucket struct {
	n     int
	reset time.Time
}

func newIPLimiter(limit int, window time.Duration) *ipLimiter {
	return &ipLimiter{limit: limit, window: window, hits: map[string]*bucket{}}
}

func (l *ipLimiter) allow(key string) bool {
	now := time.Now()
	l.mu.Lock()
	defer l.mu.Unlock()
	if len(l.hits) > 10000 {
		for k, b := range l.hits {
			if now.After(b.reset) {
				delete(l.hits, k)
			}
		}
	}
	b, ok := l.hits[key]
	if !ok || now.After(b.reset) {
		b = &bucket{reset: now.Add(l.window)}
		l.hits[key] = b
	}
	b.n++
	return b.n <= l.limit
}
