package control

import (
	"context"
	"encoding/base64"
	"errors"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/payam-foundation/dotvpn-wire/auth"
	"github.com/payam-foundation/dotvpn-wire/transport"
	"github.com/payam-foundation/dotvpn-wire/transport/reverse"
)

// Relay enrollment replaces the old shared X-Relay-Key. An admin creates a
// pending relay and gets a one-time enrollment token (auth.AudEnroll, bound to
// the relay id). The relay generates its own Ed25519 identity, shows it to
// control with that token, and from then on is pinned by that key. A relay
// holds no secret that lets it impersonate control, nodes or clients.
const (
	enrollTokenTTL = time.Hour
	poolTokenTTL   = 10 * time.Minute
)

// RelayInfo is what a node learns about a relay.
type RelayInfo struct {
	ID      string `json:"id"`
	Addr    string `json:"addr"`
	SNI     string `json:"sni"`
	Key     string `json:"key"`
	DNSAddr string `json:"dns_addr,omitempty"`
	DNSZone string `json:"dns_zone,omitempty"`
}

func (s *Service) activeRelays(ctx context.Context) ([]RelayInfo, error) {
	rs, err := s.o.Store.ListRelays(ctx)
	if err != nil {
		return nil, err
	}
	var out []RelayInfo
	for _, r := range rs {
		if r.Revoked || r.Key == "" {
			continue
		}
		out = append(out, RelayInfo{ID: r.ID, Addr: r.Addr, SNI: r.SNI, Key: r.Key, DNSAddr: r.DNSAddr, DNSZone: r.DNSZone})
	}
	return out, nil
}

func (s *Service) adminCreateRelay(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Name    string `json:"name"`
		Addr    string `json:"addr"`
		SNI     string `json:"sni"`
		DNSAddr string `json:"dns_addr"`
		DNSZone string `json:"dns_zone"`
	}
	if !readJSON(w, r, &req) {
		return
	}
	if _, _, err := net.SplitHostPort(req.Addr); err != nil || strings.TrimSpace(req.Name) == "" || req.SNI == "" {
		fail(w, http.StatusBadRequest, "name, addr (host:port) and sni required")
		return
	}
	if (req.DNSAddr == "") != (req.DNSZone == "") {
		fail(w, http.StatusBadRequest, "dns_addr and dns_zone go together")
		return
	}
	rel := Relay{ID: id(), Name: req.Name, Addr: req.Addr, SNI: req.SNI, DNSAddr: req.DNSAddr, DNSZone: req.DNSZone, Created: s.o.Now().Unix()}
	if err := s.o.Store.CreateRelay(r.Context(), rel); err != nil {
		fail(w, http.StatusInternalServerError, "store error")
		return
	}
	tok, err := s.o.Signer.Mint(auth.Claims{Sub: rel.ID, Aud: auth.AudEnroll, Jti: id()}, enrollTokenTTL)
	if err != nil {
		fail(w, http.StatusInternalServerError, "mint failed")
		return
	}
	// The token is shown exactly once and is useless after the first enrollment.
	writeJSON(w, http.StatusCreated, map[string]any{"relay": rel, "enroll_token": tok})
}

func (s *Service) adminListRelays(w http.ResponseWriter, r *http.Request) {
	rs, err := s.o.Store.ListRelays(r.Context())
	if err != nil {
		fail(w, http.StatusInternalServerError, "store error")
		return
	}
	writeJSON(w, http.StatusOK, rs)
}

// adminRevokeRelay adds the relay to the revocation list: it leaves every node
// pool and server list on the next heartbeat, and can never enroll again.
func (s *Service) adminRevokeRelay(w http.ResponseWriter, r *http.Request) {
	switch err := s.o.Store.RevokeRelay(r.Context(), r.PathValue("id")); {
	case errors.Is(err, ErrNotFound):
		fail(w, http.StatusNotFound, "no such relay")
	case err != nil:
		fail(w, http.StatusInternalServerError, "store error")
	default:
		w.WriteHeader(http.StatusNoContent)
	}
}

type enrollResponse struct {
	RelayID string `json:"relay_id"`
	// TrustedKeys are the control signing keys; the relay verifies pool tokens with them.
	TrustedKeys []string `json:"trusted_keys"`
}

// relayEnroll is unauthenticated except for the enrollment token. Every
// failure looks the same so it cannot be used to probe relay ids.
func (s *Service) relayEnroll(w http.ResponseWriter, r *http.Request) {
	if !s.limiter.allow(clientIP(r)) {
		fail(w, http.StatusTooManyRequests, "slow down")
		return
	}
	deny := func() { fail(w, http.StatusUnauthorized, "invalid enrollment") }
	v := auth.NewVerifier(s.o.Signer.Public())
	c, err := v.VerifyAud(auth.Bearer(r.Header.Get("Authorization")), auth.AudEnroll)
	if err != nil || c.Sub == "" {
		deny()
		return
	}
	// Per-relay limit: a leaked token cannot be hammered.
	if !s.relayLimiter.allow(c.Sub) {
		fail(w, http.StatusTooManyRequests, "slow down")
		return
	}
	var req struct {
		PublicKey string `json:"public_key"`
	}
	if !readJSON(w, r, &req) {
		return
	}
	if _, err := auth.DecodePublicKey(req.PublicKey); err != nil {
		deny()
		return
	}
	ok, err := s.o.Store.EnrollRelay(r.Context(), c.Sub, req.PublicKey, s.o.Now().Unix())
	switch {
	case err != nil:
		fail(w, http.StatusInternalServerError, "store error")
	case !ok:
		deny()
	default:
		writeJSON(w, http.StatusOK, enrollResponse{RelayID: c.Sub, TrustedKeys: []string{auth.EncodeKey(s.o.Signer.Public())}})
	}
}

// PoolToken mints the token a node presents to relays.
func (s *Service) PoolToken(nodeID string) (string, error) {
	return s.o.Signer.Mint(auth.Claims{Sub: nodeID, Aud: auth.AudPool}, poolTokenTTL)
}

// ActiveRelays lists enrolled, unrevoked relays.
func (s *Service) ActiveRelays(ctx context.Context) ([]RelayInfo, error) { return s.activeRelays(ctx) }

// ReverseTemplate is the endpoint a hidden node registers instead of an
// address: it names the node identity, and control expands it into one
// endpoint per active relay when it builds the signed list.
func ReverseTemplate(name, nodeID, identityPub string) transport.Endpoint {
	return transport.Endpoint{Kind: reverse.KindReverse, Name: name,
		Params: map[string]string{reverse.ParamNode: nodeID, reverse.ParamID: identityPub, transport.ParamUDP: "1"}}
}

// ExpandReverse replaces every address-less reverse template in eps with one
// TCP endpoint (and one DNS endpoint when the relay offers it) per active
// relay. Other endpoints pass through. The core address never appears.
func ExpandReverse(eps []transport.Endpoint, relays []Relay) []transport.Endpoint {
	var out []transport.Endpoint
	for _, ep := range eps {
		if ep.Kind != reverse.KindReverse || ep.Addr != "" {
			out = append(out, ep)
			continue
		}
		for _, r := range relays {
			if r.Revoked || r.Key == "" {
				continue
			}
			pub, err := auth.DecodePublicKey(r.Key)
			if err != nil {
				continue
			}
			node := ep.Params[reverse.ParamNode]
			p := map[string]string{
				reverse.ParamID:    ep.Params[reverse.ParamID],
				reverse.ParamNode:  node,
				reverse.ParamKnock: base64.StdEncoding.EncodeToString(reverse.ClientKnockKey(pub, node)),
			}
			if ep.Params[transport.ParamUDP] == "1" {
				p[transport.ParamUDP] = "1"
			}
			out = append(out, transport.Endpoint{Kind: reverse.KindReverse, Name: r.Name, Addr: r.Addr, Host: r.SNI, Params: p})
			if r.DNSAddr != "" {
				dp := map[string]string{reverse.ParamID: p[reverse.ParamID], reverse.ParamNode: node, reverse.ParamZone: r.DNSZone}
				out = append(out, transport.Endpoint{Kind: reverse.KindDNS, Name: r.Name + "-dns", Addr: r.DNSAddr, Params: dp})
			}
		}
	}
	return out
}
