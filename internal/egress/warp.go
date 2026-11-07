package egress

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math/big"
	"net"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"time"

	"github.com/Diniboy1123/usque/api"
	"github.com/Diniboy1123/usque/config"
	"golang.zx2c4.com/wireguard/tun/netstack"
)

// Cloudflare consumer WARP endpoints. usque keeps these in an internal
// package, so they are repeated here.
const (
	warpAPI       = "https://api.cloudflareclient.com/v0a4471"
	warpSNI       = "consumer-masque.cloudflareclient.com"
	warpConnect   = 443
	warpMTU       = 1280
	warpRetry     = 5 * time.Second
	warpProbeEach = 30 * time.Second
)

var warpHeaders = map[string]string{
	"User-Agent":        "WARP for Android",
	"CF-Client-Version": "a-6.35-4471",
	"Content-Type":      "application/json; charset=UTF-8",
}

// warp is an in-process Cloudflare WARP exit: a MASQUE (CONNECT-IP) tunnel
// from the usque library feeding a userspace TCP/IP stack. No root, no kernel
// TUN. Both TCP and UDP leave through it, and names are resolved inside the
// tunnel so the node's own resolver never sees them.
//
// The account is registered on first start and kept in DataDir; a free
// account is used unless the exit sets a license (WARP+ or Zero Trust).
// Cloudflare only permits full-tunnel use on consumer accounts, so the
// per-destination L4 proxy mode usque also offers is not used (it answers 403).
type warp struct {
	name    string
	license string
	path    string
	family  string
	log     *slog.Logger

	ctx    context.Context
	cancel context.CancelFunc

	mu  sync.RWMutex
	net *netstack.Net
	dev interface{ Close() error }

	alive atomic.Bool
}

func newWarp(name string, e Exit, dataDir, family string, log *slog.Logger) (*warp, error) {
	if dataDir == "" {
		return nil, errors.New("warp needs a data directory for its account")
	}
	ctx, cancel := context.WithCancel(context.Background())
	w := &warp{
		name:    name,
		license: e.License,
		path:    filepath.Join(dataDir, "warp-"+name+".json"),
		family:  family,
		log:     log.With("exit", name),
		ctx:     ctx,
		cancel:  cancel,
	}
	go w.run()
	return w, nil
}

func (w *warp) up() bool { return w.alive.Load() }

func (w *warp) Close() error {
	w.cancel()
	w.mu.Lock()
	if w.dev != nil {
		_ = w.dev.Close()
	}
	w.mu.Unlock()
	return nil
}

func (w *warp) dial(ctx context.Context, network, host, port string) (net.Conn, error) {
	w.mu.RLock()
	n := w.net
	w.mu.RUnlock()
	if n == nil {
		return nil, fmt.Errorf("egress: warp %s is not connected yet", w.name)
	}
	switch w.family {
	case "v4":
		network += "4"
	case "v6":
		network += "6"
	}
	return n.DialContext(ctx, network, net.JoinHostPort(host, port))
}

// run registers (once), builds the tunnel and keeps it connected. It retries
// every warpRetry until the exit is closed.
func (w *warp) run() {
	var cfg config.Config
	for w.ctx.Err() == nil {
		var err error
		if cfg, err = w.account(); err == nil {
			break
		}
		w.log.Warn("warp account unavailable, retrying", "err", err)
		if !sleep(w.ctx, warpRetry) {
			return
		}
	}
	if w.ctx.Err() != nil {
		return
	}
	tlsCfg, endpoint, addrs, err := w.tunnelParams(cfg)
	if err != nil {
		w.log.Error("warp account is unusable; delete "+w.path+" to register again", "err", err)
		return
	}
	dev, tnet, err := netstack.CreateNetTUN(addrs, []netip.Addr{netip.MustParseAddr("1.1.1.1"), netip.MustParseAddr("2606:4700:4700::1111")}, warpMTU)
	if err != nil {
		w.log.Error("warp netstack failed", "err", err)
		return
	}
	w.mu.Lock()
	w.dev, w.net = dev, tnet
	w.mu.Unlock()

	// ponytail: MaintainTunnel has no stop hook besides its context, which it
	// only honours while dialling. After Close its goroutine retries against a
	// dead context until process exit. Fine for a node that closes the router
	// once, at shutdown; move to a forked loop if the router is ever reloaded.
	go func() {
		api.MaintainTunnel(w.ctx, api.MaintainTunnelConfig{
			TLSConfig:         tlsCfg,
			KeepalivePeriod:   30 * time.Second,
			Endpoint:          endpoint,
			Device:            api.NewNetstackAdapter(dev),
			MTU:               warpMTU,
			ReconnectDelay:    warpRetry,
			AlwaysReconnect:   true,
			InitialPacketSize: 0,
		})
	}()
	w.probeLoop(tnet)
}

// probeLoop marks the exit down when a TCP connect through the tunnel fails.
func (w *warp) probeLoop(n *netstack.Net) {
	t := time.NewTicker(warpProbeEach)
	defer t.Stop()
	delay := time.Second
	for {
		pc, cancel := context.WithTimeout(w.ctx, 5*time.Second)
		c, err := n.DialContext(pc, "tcp", "1.1.1.1:443")
		cancel()
		if err == nil {
			_ = c.Close()
		}
		w.alive.Store(err == nil)
		if err != nil && w.ctx.Err() == nil { // look again soon while the tunnel comes up
			if !sleep(w.ctx, delay) {
				return
			}
			if delay < warpProbeEach {
				delay *= 2
			}
			continue
		}
		delay = time.Second
		select {
		case <-w.ctx.Done():
			return
		case <-t.C:
		}
	}
}

func sleep(ctx context.Context, d time.Duration) bool {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-t.C:
		return true
	}
}

// account loads the stored WARP account or registers a new one, then applies
// the configured license if it differs from the stored one.
func (w *warp) account() (config.Config, error) {
	var cfg config.Config
	b, err := os.ReadFile(w.path)
	switch {
	case err == nil:
		if err := json.Unmarshal(b, &cfg); err != nil {
			return cfg, fmt.Errorf("%s: %w", w.path, err)
		}
	case errors.Is(err, os.ErrNotExist):
		if cfg, err = w.register(); err != nil {
			return cfg, err
		}
		if err := w.save(cfg); err != nil {
			return cfg, err
		}
	default:
		return cfg, err
	}
	if w.license != "" && w.license != cfg.License {
		if err := setLicense(w.ctx, cfg, w.license); err != nil {
			// The free account still works; try the license again next start.
			w.log.Warn("warp license not applied, using the account as it is", "err", err)
		} else {
			cfg.License = w.license
			if err := w.save(cfg); err != nil {
				return cfg, err
			}
		}
	}
	return cfg, nil
}

func (w *warp) save(cfg config.Config) error {
	b, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(w.path), 0o700); err != nil {
		return err
	}
	tmp := w.path + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, w.path)
}

// register creates a free WARP account and enrolls a fresh MASQUE key. Using
// the exit means accepting Cloudflare's WARP terms of service.
func (w *warp) register() (config.Config, error) {
	w.log.Info("registering a WARP account; this accepts https://www.cloudflare.com/application/terms/")
	acc, err := api.Register("PC", "en_US", "", true)
	if err != nil {
		return config.Config{}, fmt.Errorf("register: %w", err)
	}
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return config.Config{}, err
	}
	privDER, err := x509.MarshalECPrivateKey(priv)
	if err != nil {
		return config.Config{}, err
	}
	pubDER, err := x509.MarshalPKIXPublicKey(&priv.PublicKey)
	if err != nil {
		return config.Config{}, err
	}
	up, apiErr, err := api.EnrollKey(acc, pubDER, "dotvpn-node")
	if err != nil {
		if apiErr != nil {
			return config.Config{}, fmt.Errorf("enroll: %w (%s)", err, apiErr.ErrorsAsString("; "))
		}
		return config.Config{}, fmt.Errorf("enroll: %w", err)
	}
	if len(up.Config.Peers) == 0 {
		return config.Config{}, errors.New("enroll: no peer in response")
	}
	p := up.Config.Peers[0]
	return config.Config{
		PrivateKey:     base64.StdEncoding.EncodeToString(privDER),
		EndpointV4:     hostOf(p.Endpoint.V4),
		EndpointV6:     hostOf(p.Endpoint.V6),
		EndpointPubKey: p.PublicKey,
		License:        up.Account.License,
		ID:             up.ID,
		AccessToken:    acc.Token,
		IPv4:           up.Config.Interface.Addresses.V4,
		IPv6:           up.Config.Interface.Addresses.V6,
	}, nil
}

// hostOf strips the ":0" Cloudflare appends to endpoint addresses.
func hostOf(hp string) string {
	h, _, err := net.SplitHostPort(hp)
	if err != nil {
		return hp
	}
	return h
}

// setLicense binds a WARP+ or Zero Trust license to the account.
func setLicense(ctx context.Context, cfg config.Config, license string) error {
	body, _ := json.Marshal(map[string]string{"license": license})
	req, err := http.NewRequestWithContext(ctx, http.MethodPut, warpAPI+"/reg/"+cfg.ID+"/account", bytes.NewReader(body))
	if err != nil {
		return err
	}
	for k, v := range warpHeaders {
		req.Header.Set(k, v)
	}
	req.Header.Set("Authorization", "Bearer "+cfg.AccessToken)
	cl := http.Client{Timeout: 20 * time.Second}
	resp, err := cl.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return fmt.Errorf("license update: %s: %s", resp.Status, b)
	}
	return nil
}

func (w *warp) tunnelParams(cfg config.Config) (*tls.Config, *net.UDPAddr, []netip.Addr, error) {
	kb, err := base64.StdEncoding.DecodeString(cfg.PrivateKey)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("private key: %w", err)
	}
	priv, err := x509.ParseECPrivateKey(kb)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("private key: %w", err)
	}
	blk, _ := pem.Decode([]byte(cfg.EndpointPubKey))
	if blk == nil {
		return nil, nil, nil, errors.New("endpoint public key: not PEM")
	}
	pk, err := x509.ParsePKIXPublicKey(blk.Bytes)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("endpoint public key: %w", err)
	}
	pub, ok := pk.(*ecdsa.PublicKey)
	if !ok {
		return nil, nil, nil, errors.New("endpoint public key: not ECDSA")
	}
	der, err := x509.CreateCertificate(rand.Reader, &x509.Certificate{
		SerialNumber: big.NewInt(0),
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(24 * time.Hour),
	}, &x509.Certificate{}, &priv.PublicKey, priv)
	if err != nil {
		return nil, nil, nil, err
	}
	tc, err := api.PrepareTlsConfig(priv, pub, [][]byte{der}, warpSNI)
	if err != nil {
		return nil, nil, nil, err
	}
	// ponytail: "auto" connects to the v4 endpoint, so a v6-only server must
	// set ip_family: v6. Add endpoint fallback if auto-detection is wanted.
	host := cfg.EndpointV4
	if w.family == "v6" {
		host = cfg.EndpointV6
	}
	ip, err := netip.ParseAddr(host)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("endpoint %q: %w", host, err)
	}
	var addrs []netip.Addr
	for _, s := range []string{cfg.IPv4, cfg.IPv6} {
		a, err := netip.ParseAddr(s)
		if err != nil {
			return nil, nil, nil, fmt.Errorf("tunnel address %q: %w", s, err)
		}
		addrs = append(addrs, a)
	}
	return tc, &net.UDPAddr{IP: ip.AsSlice(), Port: warpConnect}, addrs, nil
}
