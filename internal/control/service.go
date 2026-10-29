// Package control is the management plane: accounts, short-lived tokens,
// quota, node registry and the signed server list.
//
// Interface: New(Options) *Service; Service.Handler() http.Handler. The HTTP
// API is the only way in; the Store seam hides SQLite/Postgres.
package control

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"log/slog"
	"maps"
	"net/http"
	"strings"
	"time"

	"github.com/payam-foundation/dotvpn-wire/auth"
	"github.com/payam-foundation/dotvpn-wire/discovery"
	"github.com/payam-foundation/dotvpn-wire/transport"
	"github.com/payam-foundation/dotvpn-wire/transport/reverse"
)

// Options configure a Service.
type Options struct {
	Store      Store
	Signer     *auth.Signer
	AdminToken string
	TokenTTL   time.Duration
	// DefaultQuotaGB applies to new accounts; 0 is unlimited.
	DefaultQuotaGB int
	// StaticEndpoints are always included in the server list (e.g. relays, CDN
	// fronts that no node registers itself).
	StaticEndpoints []transport.Endpoint
	Log             *slog.Logger
	Now             func() time.Time
}

// Service is the control plane: accounts, tokens, server list, node and relay
// enrollment. Handlers are mounted by Handler.
type Service struct {
	o Options
	// limiter throttles unauthenticated token requests per remote address.
	limiter *ipLimiter
	// relayLimiter throttles enrollment attempts per relay id.
	relayLimiter *ipLimiter
}

// New applies defaults and returns a Service.
func New(o Options) *Service {
	if o.TokenTTL == 0 {
		o.TokenTTL = 15 * time.Minute
	}
	if o.Log == nil {
		o.Log = slog.Default()
	}
	if o.Now == nil {
		o.Now = time.Now
	}
	return &Service{o: o, limiter: newIPLimiter(30, time.Minute), relayLimiter: newIPLimiter(5, time.Minute)}
}

func hash(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}

func secret(prefix string) string {
	b := make([]byte, 32)
	_, _ = rand.Read(b)
	return prefix + hex.EncodeToString(b)
}

func id() string {
	b := make([]byte, 8)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

// Period is the billing month as YYYYMM.
func Period(t time.Time) int64 { return int64(t.UTC().Year()*100 + int(t.UTC().Month())) }

// Handler is the public API: tokens, server list, node and relay planes. It
// holds no admin route; those live on AdminHandler, which must be served on a
// loopback or unix listener only.
func (s *Service) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /v1/token", s.token)
	mux.HandleFunc("GET /v1/servers", s.servers)
	mux.HandleFunc("HEAD /v1/quota", s.quota)
	mux.HandleFunc("POST /v1/nodes/join", s.nodeJoin)
	mux.HandleFunc("POST /v1/nodes/heartbeat", s.nodeHeartbeat)
	mux.HandleFunc("POST /v1/relays/enroll", s.relayEnroll)
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte("ok")) })
	return mux
}

// AdminHandler is the management API. Every route needs the admin token, on
// top of the listener restriction enforced by the caller.
func (s *Service) AdminHandler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /v1/admin/accounts", s.admin(s.adminCreateAccount))
	mux.HandleFunc("GET /v1/admin/accounts", s.admin(s.adminListAccounts))
	mux.HandleFunc("PATCH /v1/admin/accounts/{id}", s.admin(s.adminPatchAccount))
	mux.HandleFunc("DELETE /v1/admin/accounts/{id}", s.admin(s.adminDeleteAccount))
	mux.HandleFunc("POST /v1/admin/join-tokens", s.admin(s.adminJoinToken))
	mux.HandleFunc("GET /v1/admin/nodes", s.admin(s.adminListNodes))
	mux.HandleFunc("DELETE /v1/admin/nodes/{id}", s.admin(s.adminDeleteNode))
	mux.HandleFunc("POST /v1/admin/relays", s.admin(s.adminCreateRelay))
	mux.HandleFunc("GET /v1/admin/relays", s.admin(s.adminListRelays))
	mux.HandleFunc("DELETE /v1/admin/relays/{id}", s.admin(s.adminRevokeRelay))
	return mux
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

func readJSON(w http.ResponseWriter, r *http.Request, v any) bool {
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
	if err := json.NewDecoder(r.Body).Decode(v); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "bad json"})
		return false
	}
	return true
}

func fail(w http.ResponseWriter, code int, msg string) {
	writeJSON(w, code, map[string]string{"error": msg})
}

// accountFromKey authenticates a client by account key.
func (s *Service) accountFromKey(ctx context.Context, key string) (Account, error) {
	if key == "" {
		return Account{}, ErrNotFound
	}
	return s.o.Store.AccountByKeyHash(ctx, hash(key))
}

func (s *Service) overQuota(a Account) bool {
	return a.Quota > 0 && a.Period == Period(s.o.Now()) && a.Used >= a.Quota
}

// serverList builds the signed list from registered nodes plus static entries.
func (s *Service) serverList(ctx context.Context) (discovery.Signed, error) {
	nodes, err := s.o.Store.ListNodes(ctx)
	if err != nil {
		return discovery.Signed{}, err
	}
	l := discovery.List{Issued: s.o.Now().Unix()}
	stale := s.o.Now().Add(-5 * time.Minute).Unix()
	for _, n := range nodes {
		if n.LastSeen < stale {
			continue // dead nodes drop out of the list
		}
		var eps []transport.Endpoint
		if json.Unmarshal([]byte(n.Endpoints), &eps) == nil {
			for i := range eps {
				// A hidden node cannot know its id before it joins.
				if eps[i].Kind == reverse.KindReverse && eps[i].Params[reverse.ParamNode] == "" {
					eps[i].Params = maps.Clone(eps[i].Params)
					eps[i].Params[reverse.ParamNode] = n.ID
				}
			}
			l.Endpoints = append(l.Endpoints, eps...)
		}
	}
	l.Endpoints = append(l.Endpoints, s.o.StaticEndpoints...)
	relays, err := s.o.Store.ListRelays(ctx)
	if err != nil {
		return discovery.Signed{}, err
	}
	l.Endpoints = ExpandReverse(l.Endpoints, relays)
	return discovery.Sign(s.o.Signer, l)
}

func (s *Service) token(w http.ResponseWriter, r *http.Request) {
	if !s.limiter.allow(clientIP(r)) {
		fail(w, http.StatusTooManyRequests, "slow down")
		return
	}
	var req struct {
		AccountKey string `json:"account_key"`
	}
	if !readJSON(w, r, &req) {
		return
	}
	a, err := s.accountFromKey(r.Context(), req.AccountKey)
	if err != nil || a.Disabled {
		fail(w, http.StatusUnauthorized, "invalid account")
		return
	}
	setQuotaHeaders(w, a, s.o.Now())
	if s.overQuota(a) {
		fail(w, http.StatusPaymentRequired, "quota exhausted")
		return
	}
	tok, err := s.o.Signer.Mint(auth.Claims{Sub: a.ID, Conc: a.Conc, Mbps: a.Mbps}, s.o.TokenTTL)
	if err != nil {
		fail(w, http.StatusInternalServerError, "mint failed")
		return
	}
	list, err := s.serverList(r.Context())
	if err != nil {
		fail(w, http.StatusInternalServerError, "server list failed")
		return
	}
	now := s.o.Now()
	writeJSON(w, http.StatusOK, discovery.TokenResponse{
		Token: tok, Expires: now.Add(s.o.TokenTTL).Unix(), Now: now.Unix(), Servers: list,
	})
}

func (s *Service) servers(w http.ResponseWriter, r *http.Request) {
	list, err := s.serverList(r.Context())
	if err != nil {
		fail(w, http.StatusInternalServerError, "server list failed")
		return
	}
	writeJSON(w, http.StatusOK, list)
}

// quota answers HEAD with X-Quota-* headers, like the Firefox VPN.
func (s *Service) quota(w http.ResponseWriter, r *http.Request) {
	a, err := s.accountFromKey(r.Context(), auth.Bearer(r.Header.Get("Authorization")))
	if err != nil {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	setQuotaHeaders(w, a, s.o.Now())
	w.WriteHeader(http.StatusOK)
}

func setQuotaHeaders(w http.ResponseWriter, a Account, now time.Time) {
	used := a.Used
	if a.Period != Period(now) {
		used = 0
	}
	w.Header().Set("X-Quota-Limit", itoa(a.Quota))
	w.Header().Set("X-Quota-Remaining", itoa(max(a.Quota-used, 0)))
	next := time.Date(now.UTC().Year(), now.UTC().Month()+1, 1, 0, 0, 0, 0, time.UTC)
	w.Header().Set("X-Quota-Reset", next.Format(time.RFC3339))
}

// --- node plane ---

type joinRequest struct {
	JoinToken string               `json:"join_token"`
	Name      string               `json:"name"`
	Endpoints []transport.Endpoint `json:"endpoints"`
}

type joinResponse struct {
	NodeID      string   `json:"node_id"`
	NodeSecret  string   `json:"node_secret"`
	TrustedKeys []string `json:"trusted_keys"`
}

func (s *Service) nodeJoin(w http.ResponseWriter, r *http.Request) {
	if !s.limiter.allow(clientIP(r)) {
		fail(w, http.StatusTooManyRequests, "slow down")
		return
	}
	var req joinRequest
	if !readJSON(w, r, &req) {
		return
	}
	ok, err := s.o.Store.ConsumeJoinToken(r.Context(), hash(req.JoinToken), s.o.Now().Unix())
	if err != nil {
		fail(w, http.StatusInternalServerError, "store error")
		return
	}
	if !ok {
		fail(w, http.StatusUnauthorized, "invalid join token")
		return
	}
	eps, _ := json.Marshal(req.Endpoints)
	n := Node{ID: id(), Name: req.Name, Endpoints: string(eps), LastSeen: s.o.Now().Unix(), Created: s.o.Now().Unix()}
	sec := secret("ns_")
	n.SecretHash = hash(sec)
	if err := s.o.Store.UpsertNode(r.Context(), n); err != nil {
		fail(w, http.StatusInternalServerError, "store error")
		return
	}
	writeJSON(w, http.StatusOK, joinResponse{
		NodeID: n.ID, NodeSecret: sec, TrustedKeys: []string{auth.EncodeKey(s.o.Signer.Public())},
	})
}

// UsageReport is what a node sends every heartbeat.
type UsageReport struct {
	Endpoints []transport.Endpoint `json:"endpoints,omitempty"`
	Usage     []struct {
		User string `json:"user"`
		Up   int64  `json:"up"`
		Down int64  `json:"down"`
	} `json:"usage"`
}

// HeartbeatResponse carries the deny list back to the node.
type HeartbeatResponse struct {
	Denied []string `json:"denied"`
	Now    int64    `json:"now"`
	// Relays are the active, unrevoked relays the node keeps tunnels to.
	Relays []RelayInfo `json:"relays,omitempty"`
	// PoolToken proves the node to those relays (auth.AudPool, short lived).
	PoolToken string `json:"pool_token,omitempty"`
}

func (s *Service) nodeAuth(r *http.Request) (Node, bool) {
	id := r.Header.Get("X-Node-ID")
	n, err := s.o.Store.NodeByID(r.Context(), id)
	if err != nil {
		return Node{}, false
	}
	got := hash(auth.Bearer(r.Header.Get("Authorization")))
	if subtle.ConstantTimeCompare([]byte(got), []byte(n.SecretHash)) != 1 {
		return Node{}, false
	}
	return n, true
}

func (s *Service) nodeHeartbeat(w http.ResponseWriter, r *http.Request) {
	n, ok := s.nodeAuth(r)
	if !ok {
		fail(w, http.StatusUnauthorized, "invalid node credentials")
		return
	}
	var rep UsageReport
	if !readJSON(w, r, &rep) {
		return
	}
	ctx := r.Context()
	p := Period(s.o.Now())
	for _, u := range rep.Usage {
		if err := s.o.Store.AddUsage(ctx, u.User, u.Up+u.Down, p); err != nil {
			s.o.Log.Warn("usage ingest failed", "err", err)
		}
	}
	eps := ""
	if len(rep.Endpoints) > 0 {
		b, _ := json.Marshal(rep.Endpoints)
		eps = string(b)
	}
	if err := s.o.Store.TouchNode(ctx, n.ID, s.o.Now().Unix(), eps); err != nil {
		fail(w, http.StatusInternalServerError, "store error")
		return
	}
	denied, err := s.o.Store.Blocked(ctx, p)
	if err != nil {
		fail(w, http.StatusInternalServerError, "store error")
		return
	}
	resp := HeartbeatResponse{Denied: denied, Now: s.o.Now().Unix()}
	if resp.Relays, err = s.activeRelays(ctx); err != nil {
		fail(w, http.StatusInternalServerError, "store error")
		return
	}
	if len(resp.Relays) > 0 {
		if resp.PoolToken, err = s.PoolToken(n.ID); err != nil {
			fail(w, http.StatusInternalServerError, "mint failed")
			return
		}
	}
	writeJSON(w, http.StatusOK, resp)
}

// --- admin ---

func (s *Service) admin(h http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		got := auth.Bearer(r.Header.Get("Authorization"))
		if s.o.AdminToken == "" || subtle.ConstantTimeCompare([]byte(got), []byte(s.o.AdminToken)) != 1 {
			fail(w, http.StatusUnauthorized, "admin token required")
			return
		}
		h(w, r)
	}
}

func (s *Service) adminCreateAccount(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Name    string `json:"name"`
		QuotaGB *int   `json:"quota_gb"`
		Conc    int    `json:"conc"`
		Mbps    int    `json:"mbps"`
	}
	if !readJSON(w, r, &req) {
		return
	}
	if strings.TrimSpace(req.Name) == "" {
		fail(w, http.StatusBadRequest, "name required")
		return
	}
	gb := s.o.DefaultQuotaGB
	if req.QuotaGB != nil {
		gb = *req.QuotaGB
	}
	key := secret("ak_")
	a := Account{ID: id(), Name: req.Name, KeyHash: hash(key), Quota: int64(gb) << 30,
		Conc: req.Conc, Mbps: req.Mbps, Created: s.o.Now().Unix()}
	if err := s.o.Store.CreateAccount(r.Context(), a); err != nil {
		fail(w, http.StatusInternalServerError, "store error")
		return
	}
	// The key is shown exactly once.
	writeJSON(w, http.StatusCreated, map[string]any{"account": a, "account_key": key})
}

func (s *Service) adminListAccounts(w http.ResponseWriter, r *http.Request) {
	as, err := s.o.Store.ListAccounts(r.Context())
	if err != nil {
		fail(w, http.StatusInternalServerError, "store error")
		return
	}
	writeJSON(w, http.StatusOK, as)
}

func (s *Service) adminPatchAccount(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Disabled *bool  `json:"disabled"`
		QuotaGB  *int64 `json:"quota_gb"`
	}
	if !readJSON(w, r, &req) {
		return
	}
	var q *int64
	if req.QuotaGB != nil {
		v := *req.QuotaGB << 30
		q = &v
	}
	switch err := s.o.Store.UpdateAccount(r.Context(), r.PathValue("id"), req.Disabled, q); {
	case errors.Is(err, ErrNotFound):
		fail(w, http.StatusNotFound, "no such account")
	case err != nil:
		fail(w, http.StatusInternalServerError, "store error")
	default:
		w.WriteHeader(http.StatusNoContent)
	}
}

func (s *Service) adminDeleteAccount(w http.ResponseWriter, r *http.Request) {
	switch err := s.o.Store.DeleteAccount(r.Context(), r.PathValue("id")); {
	case errors.Is(err, ErrNotFound):
		fail(w, http.StatusNotFound, "no such account")
	case err != nil:
		fail(w, http.StatusInternalServerError, "store error")
	default:
		w.WriteHeader(http.StatusNoContent)
	}
}

func (s *Service) adminJoinToken(w http.ResponseWriter, r *http.Request) {
	tok := secret("jt_")
	exp := s.o.Now().Add(24 * time.Hour).Unix()
	if err := s.o.Store.CreateJoinToken(r.Context(), hash(tok), exp); err != nil {
		fail(w, http.StatusInternalServerError, "store error")
		return
	}
	writeJSON(w, http.StatusCreated, map[string]any{"join_token": tok, "expires": exp})
}

func (s *Service) adminListNodes(w http.ResponseWriter, r *http.Request) {
	ns, err := s.o.Store.ListNodes(r.Context())
	if err != nil {
		fail(w, http.StatusInternalServerError, "store error")
		return
	}
	writeJSON(w, http.StatusOK, ns)
}

func (s *Service) adminDeleteNode(w http.ResponseWriter, r *http.Request) {
	switch err := s.o.Store.DeleteNode(r.Context(), r.PathValue("id")); {
	case errors.Is(err, ErrNotFound):
		fail(w, http.StatusNotFound, "no such node")
	case err != nil:
		fail(w, http.StatusInternalServerError, "store error")
	default:
		w.WriteHeader(http.StatusNoContent)
	}
}
