package main

import (
	"context"
	"crypto/ed25519"
	"crypto/tls"
	"errors"
	"maps"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"

	"github.com/payam-foundation/dotvpn-core/internal/config"
	"github.com/payam-foundation/dotvpn-core/internal/control"
	"github.com/payam-foundation/dotvpn-core/internal/node"
	"github.com/payam-foundation/dotvpn-wire/auth"
	"github.com/payam-foundation/dotvpn-wire/transport"
	"github.com/payam-foundation/dotvpn-wire/transport/cdnws"
	"github.com/payam-foundation/dotvpn-wire/transport/h3connect"
	"github.com/payam-foundation/dotvpn-wire/transport/reverse"
	"github.com/payam-foundation/dotvpn-wire/transport/snowflake"
	"github.com/payam-foundation/dotvpn-wire/transport/webtunnel"
)

func init() {
	register("node", cmdNode)
}

func cmdNode(ctx context.Context, args []string) error {
	fs, cfgFlag, verbose := flagSet("node")
	if err := fs.Parse(args); err != nil {
		return err
	}
	log := setupLog(*verbose, stderr())
	c, path, err := loadConfig(*cfgFlag)
	if err != nil {
		return err
	}
	j := &c.Node.Join
	rs := &relaySet{}
	rs.setStatic(c.Node.Relays)
	if j.URL == "" {
		return runNode(ctx, c, nil, rs, nil)
	}

	// Joined node: register once, then heartbeat for usage and deny list.
	eps, err := nodeEndpoints(c)
	if err != nil {
		return err
	}
	if j.ID == "" {
		if j.Token == "" {
			return errors.New("node.join.token missing")
		}
		id, secret, keys, err := control.Join(ctx, nil, j.URL, j.Token, c.Node.Name, eps)
		if err != nil {
			return err
		}
		j.ID, j.Secret, j.Token = id, secret, ""
		c.Node.TrustedKeys = keys
		if err := config.Save(path, c); err != nil {
			return err
		}
		log.Info("joined control plane", "node_id", id)
	}
	return runNode(ctx, c, nil, rs, func(b *node.Backend) {
		a := &control.Agent{
			BaseURL: j.URL, NodeID: j.ID, Secret: j.Secret, Endpoints: eps, Log: log,
			Drain: func() []control.NodeUsage {
				var out []control.NodeUsage
				for _, u := range b.Drain() {
					out = append(out, control.NodeUsage{User: u.User, Up: u.Up, Down: u.Down})
				}
				return out
			},
			SetDenied: b.SetDenied,
			SetRelays: rs.set,
		}
		go a.Run(ctx)
	})
}

// nodeEndpoints are the endpoints this node advertises to the control plane.
func nodeEndpoints(c *config.Config) ([]transport.Endpoint, error) {
	return endpointsFor(c, c.Node.Join.ID)
}

// endpointsFor lists what a node advertises. A hidden node advertises only a
// reverse template (its identity, no address); control expands it into one
// endpoint per relay, so the node's own address never reaches a client.
func endpointsFor(c *config.Config, nodeID string) ([]transport.Endpoint, error) {
	if c.Node.Hidden {
		pub, err := identityPublic(c)
		if err != nil {
			return nil, err
		}
		return []transport.Endpoint{control.ReverseTemplate(c.Node.Name, nodeID, pub)}, nil
	}
	ep, err := advertisedEndpoint(c)
	if err != nil {
		return nil, err
	}
	return append([]transport.Endpoint{ep}, extraEndpoints(c, ep)...), nil
}

func identityPublic(c *config.Config) (string, error) {
	if c.Node.IdentityKey == "" {
		return "", errors.New("node.identity_key missing: run `dotvpn-core init`")
	}
	priv, err := auth.DecodePrivateKey(c.Node.IdentityKey)
	if err != nil {
		return "", err
	}
	return auth.EncodeKey(priv.Public().(ed25519.PublicKey)), nil
}

// relaySet is the live relay list and pool token a node dials out with.
type relaySet struct {
	mu     sync.Mutex
	relays []reverse.Relay
	token  string
}

func (s *relaySet) setStatic(refs []config.RelayRef) {
	infos := make([]control.RelayInfo, 0, len(refs))
	for _, r := range refs {
		infos = append(infos, control.RelayInfo{ID: r.ID, Addr: r.Addr, SNI: r.SNI, Key: r.Key})
	}
	s.set(infos, "")
}

func (s *relaySet) set(infos []control.RelayInfo, token string) {
	var rs []reverse.Relay
	for _, i := range infos {
		k, err := auth.DecodePublicKey(i.Key)
		if err != nil {
			continue
		}
		rs = append(rs, reverse.Relay{ID: i.ID, Addr: i.Addr, SNI: i.SNI, Key: k})
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.relays = rs
	if token != "" {
		s.token = token
	}
}

func (s *relaySet) list() []reverse.Relay {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]reverse.Relay(nil), s.relays...)
}

func (s *relaySet) tok() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.token
}

// extraEndpoints are the other carriers served at the same address.
func extraEndpoints(c *config.Config, base transport.Endpoint) []transport.Endpoint {
	var out []transport.Endpoint
	t := c.Node.Transports
	if t.H3 {
		h3 := base
		h3.Kind = transport.KindH3
		out = append(out, h3)
	}
	if t.CDNWSPath != "" {
		w := base
		w.Kind, w.Path = transport.KindCDNWS, t.CDNWSPath
		if t.CDNHost != "" {
			w.Addr, w.Host, w.Pin = t.CDNHost+":443", t.CDNHost, ""
		}
		out = append(out, w)
	}
	if t.WebTunnelPath != "" {
		w := base
		w.Kind, w.Path = transport.KindWebTunnel, t.WebTunnelPath
		out = append(out, w)
	}
	if sf := t.Snowflake; sf.Listen != "" && sf.BrokerPath != "" {
		w := base
		w.Kind, w.Path, w.Pin = transport.KindSnowflake, "", ""
		w.Params = map[string]string{snowflake.ParamBroker: "https://" + base.ServerName() + "/" + strings.Trim(sf.BrokerPath, "/") + "/", transport.ParamUDP: base.Params[transport.ParamUDP]}
		out = append(out, w)
	}
	return out
}

// snowflakeRelayURL is where volunteer proxies dial the node's snowflake server.
func snowflakeRelayURL(c *config.Config) (string, error) {
	sf := c.Node.Transports.Snowflake
	if sf.RelayURL != "" {
		return sf.RelayURL, nil
	}
	_, port, err := net.SplitHostPort(sf.Listen)
	if err != nil {
		return "", err
	}
	host := c.Node.Domain
	if host == "" {
		return "", errors.New("node.transports.snowflake.relay_url or node.domain required")
	}
	return "wss://" + net.JoinHostPort(host, port) + "/", nil
}

// runNode builds and serves a node from config. mounts lets allinone add the
// control API to the same port; ready receives the backend before Serve.
func runNode(ctx context.Context, c *config.Config, mounts map[string]http.Handler, rs *relaySet, ready func(*node.Backend)) error {
	pubs, err := trustedKeys(c)
	if err != nil {
		return err
	}
	b := node.NewBackend(auth.NewVerifier(pubs...), node.Policy{
		AllowedPorts:    c.Node.AllowedPorts,
		AllowedUDPPorts: c.Node.AllowedUDPPorts,
		ConcPerUser:     c.Node.ConcPerUser,
		MbpsPerUser:     c.Node.MbpsPerUser,
		AllowPrivate:    allowPrivateEgress,
	})
	var extra []func(context.Context, string, *tls.Config, http.Handler) error
	if c.Node.Transports.H3 {
		extra = append(extra, h3connect.Serve)
	}
	t := c.Node.Transports
	if t.CDNWSPath != "" || t.WebTunnelPath != "" || t.Snowflake.BrokerPath != "" {
		decoy, err := node.NewDecoy(c.Node.Decoy)
		if err != nil {
			return err
		}
		mounts = maps.Clone(mounts)
		if mounts == nil {
			mounts = map[string]http.Handler{}
		}
		if t.CDNWSPath != "" {
			mounts[t.CDNWSPath] = cdnws.Handler(b, decoy)
		}
		if t.WebTunnelPath != "" {
			mounts[t.WebTunnelPath] = webtunnel.Handler(b, decoy)
		}
		if t.Snowflake.Listen != "" && t.Snowflake.BrokerPath != "" {
			relay, err := snowflakeRelayURL(c)
			if err != nil {
				return err
			}
			if _, err := url.Parse(relay); err != nil {
				return err
			}
			br, err := snowflake.NewBroker(relay)
			if err != nil {
				return err
			}
			p := "/" + strings.Trim(t.Snowflake.BrokerPath, "/")
			mounts[p] = http.StripPrefix(p, br.Handler())
		}
	}
	if t.Snowflake.Listen != "" {
		listen := t.Snowflake.Listen
		extra = append(extra, func(ctx context.Context, _ string, cfg *tls.Config, _ http.Handler) error {
			return snowflake.Serve(ctx, listen, cfg, b)
		})
	}
	if c.Node.IdentityKey != "" {
		priv, err := auth.DecodePrivateKey(c.Node.IdentityKey)
		if err != nil {
			return err
		}
		pool := &reverse.Pool{Relays: rs.list, Identity: priv, Token: rs.tok}
		extra = append(extra, func(ctx context.Context, _ string, _ *tls.Config, _ http.Handler) error {
			return pool.Serve(ctx, b)
		})
	}
	n, err := node.New(node.Options{
		Extra:       extra,
		Name:        c.Node.Name,
		Listen:      c.Node.Listen,
		Domain:      c.Node.Domain,
		Email:       c.Node.ACMEEmail,
		DataDir:     c.DataDir,
		Decoy:       c.Node.Decoy,
		Backend:     b,
		Mounts:      mounts,
		AdminListen: c.Node.AdminListen,
	})
	if err != nil {
		return err
	}
	if ready != nil {
		ready(b)
	}
	return n.Serve(ctx)
}
