package control

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"github.com/payam-foundation/dotvpn-wire/auth"
	"github.com/payam-foundation/dotvpn-wire/discovery"
	"github.com/payam-foundation/dotvpn-wire/transport"
)

type env struct {
	srv *httptest.Server
	svc *Service
	v   *auth.Verifier
}

func newEnv(t *testing.T) *env {
	t.Helper()
	st, err := OpenStore(context.Background(), filepath.Join(t.TempDir(), "c.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	pub, priv, _ := auth.GenerateKey()
	svc := New(Options{Store: st, Signer: auth.NewSigner(priv), AdminToken: "adm", DefaultQuotaGB: 0})
	mux := http.NewServeMux()
	mux.Handle("/v1/admin/", svc.AdminHandler())
	mux.Handle("/", svc.Handler())
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return &env{srv: srv, svc: svc, v: auth.NewVerifier(pub)}
}

func (e *env) do(t *testing.T, method, path, bearer string, hdr map[string]string, in, out any) int {
	t.Helper()
	var body bytes.Buffer
	if in != nil {
		_ = json.NewEncoder(&body).Encode(in)
	}
	req, _ := http.NewRequest(method, e.srv.URL+path, &body)
	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	}
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if out != nil {
		_ = json.NewDecoder(resp.Body).Decode(out)
	}
	return resp.StatusCode
}

func TestAccountTokenQuotaFlow(t *testing.T) {
	e := newEnv(t)

	if c := e.do(t, "POST", "/v1/admin/accounts", "wrong", nil, map[string]any{"name": "a"}, nil); c != 401 {
		t.Fatalf("admin without token: %d", c)
	}
	var created struct {
		Account    Account `json:"account"`
		AccountKey string  `json:"account_key"`
	}
	if c := e.do(t, "POST", "/v1/admin/accounts", "adm", nil, map[string]any{"name": "alice", "quota_gb": 1}, &created); c != 201 {
		t.Fatalf("create: %d", c)
	}

	// Token issuance carries a verifiable token and signed (empty) list.
	var tr discovery.TokenResponse
	if c := e.do(t, "POST", "/v1/token", "", nil, map[string]string{"account_key": created.AccountKey}, &tr); c != 200 {
		t.Fatalf("token: %d", c)
	}
	claims, err := e.v.Verify(tr.Token)
	if err != nil || claims.Sub != created.Account.ID {
		t.Fatalf("token claims: %v %+v", err, claims)
	}
	if _, err := discovery.Open(e.v, tr.Servers, time.Minute); err != nil {
		t.Fatal(err)
	}
	if c := e.do(t, "POST", "/v1/token", "", nil, map[string]string{"account_key": "nope"}, nil); c != 401 {
		t.Fatalf("bad key: %d", c)
	}

	// Node joins with a one-time token; second use fails.
	var jt struct {
		JoinToken string `json:"join_token"`
	}
	e.do(t, "POST", "/v1/admin/join-tokens", "adm", nil, nil, &jt)
	eps := []transport.Endpoint{{Kind: transport.KindH2, Addr: "1.2.3.4:443", Host: "n1.example.com"}}
	var jr joinResponse
	if c := e.do(t, "POST", "/v1/nodes/join", "", nil, joinRequest{JoinToken: jt.JoinToken, Name: "n1", Endpoints: eps}, &jr); c != 200 {
		t.Fatalf("join: %d", c)
	}
	if c := e.do(t, "POST", "/v1/nodes/join", "", nil, joinRequest{JoinToken: jt.JoinToken, Name: "n2"}, nil); c != 401 {
		t.Fatalf("join token reuse: %d", c)
	}
	if len(jr.TrustedKeys) != 1 || jr.TrustedKeys[0] != auth.EncodeKey(e.svc.o.Signer.Public()) {
		t.Fatal("join did not hand out the signing key")
	}

	// Registered node appears in the signed list.
	e.do(t, "POST", "/v1/token", "", nil, map[string]string{"account_key": created.AccountKey}, &tr)
	l, _ := discovery.Open(e.v, tr.Servers, time.Minute)
	if len(l.Endpoints) != 1 || l.Endpoints[0].Addr != "1.2.3.4:443" {
		t.Fatalf("list: %+v", l)
	}

	// Heartbeat: usage over quota denies the user and the token endpoint.
	hb := map[string]string{"X-Node-ID": jr.NodeID}
	use := map[string]any{"usage": []map[string]any{{"user": created.Account.ID, "up": 1 << 29, "down": 1 << 29}}}
	var hr HeartbeatResponse
	if c := e.do(t, "POST", "/v1/nodes/heartbeat", jr.NodeSecret, hb, use, &hr); c != 200 {
		t.Fatalf("heartbeat: %d", c)
	}
	if len(hr.Denied) != 1 || hr.Denied[0] != created.Account.ID {
		t.Fatalf("denied: %+v", hr.Denied)
	}
	if c := e.do(t, "POST", "/v1/token", "", nil, map[string]string{"account_key": created.AccountKey}, nil); c != 402 {
		t.Fatalf("over quota token: %d", c)
	}
	if c := e.do(t, "POST", "/v1/nodes/heartbeat", "bad", hb, use, nil); c != 401 {
		t.Fatalf("heartbeat bad secret: %d", c)
	}

	// Raising the quota unblocks.
	if c := e.do(t, "PATCH", "/v1/admin/accounts/"+created.Account.ID, "adm", nil, map[string]any{"quota_gb": 0}, nil); c != 204 {
		t.Fatalf("patch: %d", c)
	}
	if c := e.do(t, "POST", "/v1/token", "", nil, map[string]string{"account_key": created.AccountKey}, nil); c != 200 {
		t.Fatalf("token after unblock: %d", c)
	}
}

func TestDiscoveryFallbackAndCache(t *testing.T) {
	e := newEnv(t)
	var created struct {
		AccountKey string `json:"account_key"`
	}
	e.do(t, "POST", "/v1/admin/accounts", "adm", nil, map[string]any{"name": "bob"}, &created)

	cache := filepath.Join(t.TempDir(), "list")
	c := &discovery.Client{
		Channels:   []discovery.ControlChannel{{URL: "http://127.0.0.1:1"}, {URL: e.srv.URL}},
		Verifier:   e.v,
		AccountKey: created.AccountKey,
		CachePath:  cache,
	}
	r, err := c.Refresh(context.Background())
	if err != nil || r.Token == "" || r.Source != "control" {
		t.Fatalf("refresh via second channel: %v %+v", err, r)
	}

	// All channels blocked: cache still yields endpoints, error explains.
	c.Channels = []discovery.ControlChannel{{URL: "http://127.0.0.1:1"}}
	r, err = c.Refresh(context.Background())
	if err == nil || r.Source != "cache" || r.Token != "" {
		t.Fatalf("offline refresh: %v %+v", err, r)
	}
}

func TestListRejectsForgery(t *testing.T) {
	_, priv, _ := auth.GenerateKey()
	other, _, _ := auth.GenerateKey()
	s, _ := discovery.Sign(auth.NewSigner(priv), discovery.List{Issued: time.Now().Unix()})
	if _, err := discovery.Open(auth.NewVerifier(other), s, 0); err == nil {
		t.Fatal("list signed by unknown key accepted")
	}
	old, _ := discovery.Sign(auth.NewSigner(priv), discovery.List{Issued: time.Now().Add(-48 * time.Hour).Unix()})
	pub := auth.NewSigner(priv).Public()
	if _, err := discovery.Open(auth.NewVerifier(pub), old, time.Hour); err == nil {
		t.Fatal("stale list accepted")
	}
}

func TestPublicHandlerHasNoAdminRoutes(t *testing.T) {
	e := newEnv(t)
	for _, p := range []string{"/v1/admin/accounts", "/v1/admin/relays", "/v1/admin/nodes"} {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest("GET", p, nil)
		req.Header.Set("Authorization", "Bearer adm")
		e.svc.Handler().ServeHTTP(rec, req)
		if rec.Code != http.StatusNotFound {
			t.Errorf("%s on public handler: %d", p, rec.Code)
		}
	}
}
