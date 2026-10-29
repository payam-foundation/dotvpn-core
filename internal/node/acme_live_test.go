package node

import (
	"context"
	"crypto/tls"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/caddyserver/certmagic"
)

// TestACMELive obtains a certificate from Let's Encrypt staging. It needs the
// domain to resolve to this host with ports 80 and 443 free, so it only runs
// with DOTVPN_ACME_DOMAIN set (and DOTVPN_ACME_EMAIL optionally).
func TestACMELive(t *testing.T) {
	domain := os.Getenv("DOTVPN_ACME_DOMAIN")
	if domain == "" {
		t.Skip("DOTVPN_ACME_DOMAIN not set")
	}
	certmagic.DefaultACME.CA = certmagic.LetsEncryptStagingCA
	dir := t.TempDir()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()

	start := time.Now()
	cs, err := newCerts(ctx, domain, os.Getenv("DOTVPN_ACME_EMAIL"), dir)
	if err != nil {
		t.Fatalf("issue: %v", err)
	}
	t.Logf("issued in %s", time.Since(start).Round(time.Millisecond))
	check := func(cs *certSource) {
		t.Helper()
		c, err := cs.cfg.GetCertificate(&tls.ClientHelloInfo{ServerName: domain})
		if err != nil {
			t.Fatalf("GetCertificate: %v", err)
		}
		leaf := c.Leaf
		if leaf == nil {
			t.Fatal("no leaf")
		}
		if err := leaf.VerifyHostname(domain); err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(leaf.Issuer.String(), "STAGING") && !strings.Contains(leaf.Issuer.String(), "Staging") {
			t.Fatalf("issuer %q is not the staging CA", leaf.Issuer)
		}
		t.Logf("issuer=%s notAfter=%s", leaf.Issuer, leaf.NotAfter.Format(time.RFC3339))
	}
	check(cs)

	// A restart with the same data dir must reuse the stored certificate
	// rather than order a new one (rate limits).
	start = time.Now()
	cs2, err := newCerts(ctx, domain, os.Getenv("DOTVPN_ACME_EMAIL"), dir)
	if err != nil {
		t.Fatalf("reload: %v", err)
	}
	if d := time.Since(start); d > 10*time.Second {
		t.Fatalf("reload took %s: certificate was re-ordered", d)
	}
	check(cs2)
}
