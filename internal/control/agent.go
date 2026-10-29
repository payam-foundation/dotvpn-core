package control

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"time"

	"github.com/payam-foundation/dotvpn-wire/transport"
)

// Join registers a node with a control plane using a one-time join token.
func Join(ctx context.Context, hc *http.Client, baseURL, joinToken, name string, eps []transport.Endpoint) (nodeID, nodeSecret string, trusted []string, err error) {
	var resp joinResponse
	err = postJSON(ctx, hc, baseURL+"/v1/nodes/join", nil, joinRequest{JoinToken: joinToken, Name: name, Endpoints: eps}, &resp)
	return resp.NodeID, resp.NodeSecret, resp.TrustedKeys, err
}

// NodeUsage is traffic for one user since the last drain.
type NodeUsage struct {
	User string
	Up   int64
	Down int64
}

// Agent heartbeats to the control plane: it pushes batched usage and pulls the
// deny list. If the control plane is down the node keeps serving with its last
// deny list, and unsent usage is carried over to the next attempt.
type Agent struct {
	HTTP    *http.Client
	BaseURL string
	NodeID  string
	Secret  string
	// Drain returns usage since the last call; SetDenied installs the deny list.
	Drain     func() []NodeUsage
	SetDenied func(ids []string)
	// SetRelays receives the active relay list and a fresh pool token on
	// every heartbeat; nil ignores them.
	SetRelays func(relays []RelayInfo, poolToken string)
	Endpoints []transport.Endpoint
	Interval  time.Duration
	Log       *slog.Logger

	pending map[string]*NodeUsage
}

// Run heartbeats to control every Interval, pushing usage and applying the
// returned deny list and relays, until ctx ends.
func (a *Agent) Run(ctx context.Context) {
	if a.Interval == 0 {
		a.Interval = 30 * time.Second
	}
	if a.Log == nil {
		a.Log = slog.Default()
	}
	if a.HTTP == nil {
		a.HTTP = &http.Client{Timeout: 15 * time.Second}
	}
	a.pending = map[string]*NodeUsage{}
	t := time.NewTicker(a.Interval)
	defer t.Stop()
	a.beat(ctx)
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			a.beat(ctx)
		}
	}
}

func (a *Agent) beat(ctx context.Context) {
	for _, u := range a.Drain() {
		p := a.pending[u.User]
		if p == nil {
			p = &NodeUsage{User: u.User}
			a.pending[u.User] = p
		}
		p.Up += u.Up
		p.Down += u.Down
	}
	var rep UsageReport
	rep.Endpoints = a.Endpoints
	for _, p := range a.pending {
		rep.Usage = append(rep.Usage, struct {
			User string `json:"user"`
			Up   int64  `json:"up"`
			Down int64  `json:"down"`
		}{p.User, p.Up, p.Down})
	}
	var resp HeartbeatResponse
	h := http.Header{}
	h.Set("X-Node-ID", a.NodeID)
	h.Set("Authorization", "Bearer "+a.Secret)
	if err := postJSON(ctx, a.HTTP, a.BaseURL+"/v1/nodes/heartbeat", h, rep, &resp); err != nil {
		a.Log.Warn("heartbeat failed", "err", err)
		return
	}
	clear(a.pending)
	a.SetDenied(resp.Denied)
	if a.SetRelays != nil {
		a.SetRelays(resp.Relays, resp.PoolToken)
	}
}

func postJSON(ctx context.Context, hc *http.Client, url string, hdr http.Header, in, out any) error {
	if hc == nil {
		hc = &http.Client{Timeout: 15 * time.Second}
	}
	body, err := json.Marshal(in)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	for k, v := range hdr {
		req.Header[k] = v
	}
	resp, err := hc.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("%s: %d %s", url, resp.StatusCode, bytes.TrimSpace(raw))
	}
	return json.Unmarshal(raw, out)
}
