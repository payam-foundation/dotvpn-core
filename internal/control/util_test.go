package control

import (
	"net/http/httptest"
	"testing"
	"time"
)

func TestClientIPIgnoresForwardedHeaders(t *testing.T) {
	r := httptest.NewRequest("GET", "/", nil)
	r.RemoteAddr = "203.0.113.7:5555"
	r.Header.Set("X-Forwarded-For", "1.2.3.4")
	r.Header.Set("X-Real-IP", "5.6.7.8")
	if got := clientIP(r); got != "203.0.113.7" {
		t.Fatalf("clientIP = %q, want the TCP peer", got)
	}
}

func TestIPLimiterWindow(t *testing.T) {
	l := newIPLimiter(2, time.Hour)
	if !l.allow("a") || !l.allow("a") || l.allow("a") {
		t.Fatal("limit of 2 not enforced")
	}
	if !l.allow("b") {
		t.Fatal("keys must be independent")
	}
}
