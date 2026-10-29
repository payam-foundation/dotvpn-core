package node

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"time"

	"github.com/caddyserver/certmagic"

	"github.com/payam-foundation/dotvpn-wire/transport"
)

// certSource provides the node's TLS config and the pin clients can use when
// there is no domain.
type certSource struct {
	cfg *tls.Config
	pin string // only for self-signed
}

// newCerts returns ACME-managed certificates when domain is set, otherwise a
// persisted self-signed certificate whose SPKI pin goes into client configs.
func newCerts(ctx context.Context, domain, email, dataDir string) (*certSource, error) {
	if domain != "" {
		certmagic.DefaultACME.Agreed = true
		certmagic.DefaultACME.Email = email
		magic := certmagic.NewDefault()
		magic.Storage = &certmagic.FileStorage{Path: filepath.Join(dataDir, "acme")}
		if err := magic.ManageSync(ctx, []string{domain}); err != nil {
			return nil, err
		}
		return &certSource{cfg: magic.TLSConfig()}, nil
	}
	cert, err := loadOrCreateSelfSigned(dataDir)
	if err != nil {
		return nil, err
	}
	leaf, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		return nil, err
	}
	return &certSource{
		cfg: &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12},
		pin: transport.SPKIPin(leaf),
	}, nil
}

// TLSConfig returns a server TLS config for another listener (the control
// plane) using the same certificate policy as the node.
func TLSConfig(ctx context.Context, domain, email, dataDir string) (*tls.Config, error) {
	cs, err := newCerts(ctx, domain, email, dataDir)
	if err != nil {
		return nil, err
	}
	return cs.cfg, nil
}

// SelfSignedPin returns the pin of the node's self-signed certificate in
// dataDir, creating the certificate if needed. Used by `dotvpn invite`.
func SelfSignedPin(dataDir string) (string, error) {
	cert, err := loadOrCreateSelfSigned(dataDir)
	if err != nil {
		return "", err
	}
	leaf, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		return "", err
	}
	return transport.SPKIPin(leaf), nil
}

func loadOrCreateSelfSigned(dir string) (tls.Certificate, error) {
	crt, key := filepath.Join(dir, "node.crt"), filepath.Join(dir, "node.key")
	if c, err := tls.LoadX509KeyPair(crt, key); err == nil {
		return c, nil
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return tls.Certificate{}, err
	}
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, err
	}
	serial, _ := rand.Int(rand.Reader, big.NewInt(1<<62))
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: "localhost"},
		DNSNames:     []string{"localhost"},
		IPAddresses:  []net.IP{net.IPv4(127, 0, 0, 1)},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().AddDate(10, 0, 0),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &priv.PublicKey, priv)
	if err != nil {
		return tls.Certificate{}, err
	}
	kb, err := x509.MarshalECPrivateKey(priv)
	if err != nil {
		return tls.Certificate{}, err
	}
	if err := os.WriteFile(crt, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o644); err != nil { // #nosec G306 -- public certificate
		return tls.Certificate{}, err
	}
	if err := os.WriteFile(key, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: kb}), 0o600); err != nil {
		return tls.Certificate{}, err
	}
	c, err := tls.LoadX509KeyPair(crt, key)
	if err != nil {
		return tls.Certificate{}, errors.New("node: cannot reload generated certificate: " + err.Error())
	}
	return c, nil
}
