package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/payam-foundation/dotvpn-core/internal/config"
	"github.com/payam-foundation/dotvpn-core/internal/node"
	"github.com/payam-foundation/dotvpn-wire/auth"
	"github.com/payam-foundation/dotvpn-wire/invite"
	"github.com/payam-foundation/dotvpn-wire/transport"
)

func init() {
	register("init", cmdInit)
	register("invite", cmdInvite)
	register("token", cmdToken)
}

func cmdInit(_ context.Context, args []string) error {
	fs, cfgFlag, _ := flagSet("init")
	role := fs.String("role", "allinone", "allinone | node | control")
	domain := fs.String("domain", "", "public domain name (enables ACME certificates)")
	email := fs.String("email", "", "ACME contact email")
	advertise := fs.String("advertise", "", "host:port clients use to reach this node (default domain:443)")
	listen := fs.String("listen", "", "node listen address (default :443)")
	decoy := fs.String("decoy", "", `decoy site: "" built-in, "dir:/path", or an https:// URL`)
	controlURL := fs.String("control", "", "control plane URL (node role)")
	joinToken := fs.String("join-token", "", "one-time join token from the control plane (node role)")
	trusted := fs.String("trusted-key", "", "trusted public key (node role without control)")
	hidden := fs.Bool("hidden", false, "never advertise this node's address; clients reach it through relays")
	cdnPath := fs.String("cdnws-path", "", "enable the CDN WebSocket carrier on this path")
	cdnHost := fs.String("cdn-host", "", "CDN-proxied domain clients use for the cdnws carrier (with -cdnws-path)")
	wtPath := fs.String("webtunnel-path", "", "enable WebTunnel on this secret path")
	sfListen := fs.String("snowflake-listen", "", "enable the embedded snowflake server on this TLS address (e.g. :8443)")
	sfBroker := fs.String("snowflake-broker-path", "", "mount the snowflake broker on this URL path (default /sf with -snowflake-listen)")
	dataDir := fs.String("data-dir", "", "state directory (default /var/lib/dotvpn as root, else the user config dir)")
	force := fs.Bool("force", false, "overwrite an existing config")
	if err := fs.Parse(args); err != nil {
		return err
	}
	path := configPath(*cfgFlag)
	if _, err := os.Stat(path); err == nil && !*force {
		return fmt.Errorf("%s exists (use -force to overwrite; keys would be regenerated)", path)
	}
	c := &config.Config{DataDir: defaultDataDir()}
	if *dataDir != "" {
		c.DataDir = *dataDir
	}
	c.Defaults()
	n := &c.Node
	n.Domain, n.ACMEEmail, n.Decoy, n.Advertise = *domain, *email, *decoy, *advertise
	if *listen != "" {
		n.Listen = *listen
	}
	n.Transports.CDNWSPath, n.Transports.WebTunnelPath, n.Transports.CDNHost = *cdnPath, *wtPath, *cdnHost
	if *sfListen != "" {
		n.Transports.Snowflake.Listen = *sfListen
		n.Transports.Snowflake.BrokerPath = *sfBroker
		if *sfBroker == "" {
			n.Transports.Snowflake.BrokerPath = "/sf"
		}
	}
	if n.Advertise == "" && *domain != "" {
		n.Advertise = *domain + ":443"
	}
	n.Name = hostname()
	n.Hidden = *hidden
	if *role != "control" {
		_, idPriv, err := auth.GenerateKey()
		if err != nil {
			return err
		}
		n.IdentityKey = auth.EncodeKey(idPriv)
	}

	switch *role {
	case "allinone", "control":
		pub, priv, err := auth.GenerateKey()
		if err != nil {
			return err
		}
		c.Control.PrivateKey = auth.EncodeKey(priv)
		c.Control.AdminToken = randomSecret()
		c.Control.Domain = *domain
		n.TrustedKeys = []string{auth.EncodeKey(pub)}
		if *role == "allinone" {
			c.Control.Mount = "/dotvpn/api"
		}
	case "node":
		if *controlURL != "" {
			n.Join = config.JoinConfig{URL: *controlURL, Token: *joinToken}
		} else if *trusted != "" {
			n.TrustedKeys = []string{*trusted}
		} else {
			return errors.New("node role needs -control and -join-token, or -trusted-key")
		}
	default:
		return fmt.Errorf("unknown role %q", *role)
	}
	if err := config.Save(path, c); err != nil {
		return err
	}
	fmt.Println("wrote", path)
	return nil
}

func hostname() string {
	h, _ := os.Hostname()
	return strings.ToLower(h)
}

func cmdInvite(_ context.Context, args []string) error {
	fs, cfgFlag, _ := flagSet("invite")
	user := fs.String("user", "default", "account name the token is for (static deployments)")
	static := fs.Bool("static", false, "embed a long-lived bearer token instead of an account key")
	days := fs.Int("days", 30, "token lifetime in days (-static)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	c, _, err := loadConfig(*cfgFlag)
	if err != nil {
		return err
	}
	pubs, err := trustedKeys(c)
	if err != nil {
		return err
	}
	inv := invite.Invite{}
	for _, p := range pubs {
		inv.TrustedKey = append(inv.TrustedKey, auth.EncodeKey(p))
	}
	ep, err := advertisedEndpoint(c)
	if err != nil {
		return err
	}
	inv.Endpoints = append(inv.Endpoints, ep)
	inv.Endpoints = append(inv.Endpoints, extraEndpoints(c, ep)...)
	if *static {
		tok, err := mintStatic(c, *user, *days)
		if err != nil {
			return err
		}
		inv.Token = tok
	}
	fmt.Println(inv.Encode())
	return nil
}

// advertisedEndpoint is the h2 endpoint clients should use for this node.
func advertisedEndpoint(c *config.Config) (transport.Endpoint, error) {
	n := c.Node
	ep := transport.Endpoint{Kind: transport.KindH2, Name: n.Name, Addr: n.Advertise, Host: n.Domain,
		Params: map[string]string{transport.ParamUDP: "1"}} // the node serves UDP flows (ADR-018)
	if ep.Addr == "" {
		return ep, errors.New("set node.advertise (host:port) in the config first")
	}
	if n.Domain == "" {
		pin, err := node.SelfSignedPin(c.DataDir)
		if err != nil {
			return ep, err
		}
		ep.Pin = pin
	}
	return ep, nil
}

func trustedKeys(c *config.Config) ([]ed25519.PublicKey, error) {
	var out []ed25519.PublicKey
	for _, s := range c.Node.TrustedKeys {
		k, err := auth.DecodePublicKey(s)
		if err != nil {
			return nil, err
		}
		out = append(out, k)
	}
	if len(out) == 0 {
		return nil, errors.New("no trusted keys configured")
	}
	return out, nil
}

func cmdToken(_ context.Context, args []string) error {
	fs, cfgFlag, _ := flagSet("token")
	user := fs.String("user", "default", "subject")
	days := fs.Int("days", 30, "lifetime in days")
	if err := fs.Parse(args); err != nil {
		return err
	}
	c, _, err := loadConfig(*cfgFlag)
	if err != nil {
		return err
	}
	tok, err := mintStatic(c, *user, *days)
	if err != nil {
		return err
	}
	fmt.Println(tok)
	return nil
}

func mintStatic(c *config.Config, user string, days int) (string, error) {
	if c.Control.PrivateKey == "" {
		return "", errors.New("config has no control.private_key; run on the machine that ran `dotvpn-core init -role allinone`")
	}
	priv, err := auth.DecodePrivateKey(c.Control.PrivateKey)
	if err != nil {
		return "", err
	}
	return auth.NewSigner(priv).Mint(auth.Claims{Sub: user}, time.Duration(days)*24*time.Hour)
}

func randomSecret() string {
	b := make([]byte, 24)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}
