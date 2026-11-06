package egress

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"log/slog"
	"testing"

	"github.com/Diniboy1123/usque/config"
)

func testAccount(t *testing.T) config.Config {
	t.Helper()
	priv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	peer, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	privDER, _ := x509.MarshalECPrivateKey(priv)
	pubDER, _ := x509.MarshalPKIXPublicKey(&peer.PublicKey)
	return config.Config{
		PrivateKey:     base64.StdEncoding.EncodeToString(privDER),
		EndpointV4:     "162.159.198.1",
		EndpointV6:     "2606:4700:103::1",
		EndpointPubKey: string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubDER})),
		IPv4:           "172.16.0.2",
		IPv6:           "2606:4700:110:8000::2",
	}
}

func TestWarpTunnelParams(t *testing.T) {
	cfg := testAccount(t)
	w := &warp{}
	_, ep, addrs, err := w.tunnelParams(cfg)
	if err != nil || ep.IP.String() != "162.159.198.1" || ep.Port != 443 || len(addrs) != 2 {
		t.Fatalf("v4: %v %v %v", ep, addrs, err)
	}
	w.family = "v6"
	if _, ep, _, err = w.tunnelParams(cfg); err != nil || ep.IP.String() != "2606:4700:103::1" {
		t.Fatalf("v6: %v %v", ep, err)
	}
	cfg.EndpointPubKey = "junk"
	if _, _, _, err = w.tunnelParams(cfg); err == nil {
		t.Fatal("bad endpoint key accepted")
	}
}

func TestHostOf(t *testing.T) {
	for in, want := range map[string]string{"162.159.198.1:0": "162.159.198.1", "[2606:4700:103::1]:0": "2606:4700:103::1", "1.2.3.4": "1.2.3.4"} {
		if got := hostOf(in); got != want {
			t.Errorf("hostOf(%q) = %q, want %q", in, got, want)
		}
	}
}

// A WARP exit that has not connected fails closed and reports down.
func TestWarpNotConnected(t *testing.T) {
	w := &warp{name: "w"}
	if w.up() {
		t.Fatal("up before any tunnel")
	}
	if _, err := w.dial(t.Context(), "tcp", "example.com", "443"); err == nil {
		t.Fatal("dial succeeded without a tunnel")
	}
	if _, err := newWarp("w", Exit{Type: "warp"}, "", "", slog.Default()); err == nil {
		t.Fatal("empty data dir accepted")
	}
}
