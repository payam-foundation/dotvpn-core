package node

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net"
	"testing"
	"time"

	"github.com/caddyserver/certmagic"
)

func testCert(t *testing.T, name string) tls.Certificate {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: name}, DNSNames: []string{name},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &k.PublicKey, k)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: k}
}

// ADR-020: a hostname no certificate covers (Cloudflare forwarding the visitor
// SNI, a scan, no SNI at all) must get the node's certificate, never an alert.
func TestUnknownSNIGetsNodeCertificate(t *testing.T) {
	const domain, alt = "node.example.com", "alt.example.org"
	for name, fix := range map[string]bool{"without fallback": false, "with fallback": true} {
		cache := certmagic.NewCache(certmagic.CacheOptions{GetConfigForCert: func(certmagic.Certificate) (*certmagic.Config, error) {
			return &certmagic.Config{}, nil
		}})
		magic := certmagic.New(cache, certmagic.Config{})
		for _, n := range []string{domain, alt} {
			if _, err := magic.CacheUnmanagedTLSCertificate(t.Context(), testCert(t, n), nil); err != nil {
				t.Fatal(err)
			}
		}
		if fix {
			answerUnknownSNI(magic, domain)
		}
		hello := func(sni string) *tls.ClientHelloInfo {
			c, _ := net.Pipe()
			t.Cleanup(func() { _ = c.Close() })
			return &tls.ClientHelloInfo{ServerName: sni, Conn: c}
		}
		for _, sni := range []string{"cdn.example.net", ""} {
			c, err := magic.GetCertificate(hello(sni))
			if !fix {
				if err == nil {
					t.Errorf("%s, sni %q: baseline unexpectedly served a certificate", name, sni)
				}
				continue
			}
			if err != nil {
				t.Fatalf("%s, sni %q: %v", name, sni, err)
			}
			if leaf, _ := x509.ParseCertificate(c.Certificate[0]); leaf.VerifyHostname(domain) != nil {
				t.Errorf("%s, sni %q: served %v, want certificate for %s", name, sni, leaf.DNSNames, domain)
			}
		}
		// An alt name still gets its own certificate, not the fallback.
		c, err := magic.GetCertificate(hello(alt))
		if err != nil {
			t.Fatal(err)
		}
		if leaf, _ := x509.ParseCertificate(c.Certificate[0]); leaf.VerifyHostname(alt) != nil {
			t.Errorf("%s: alt name served %v", name, leaf.DNSNames)
		}
	}
}
