package control

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strconv"
	"strings"

	_ "github.com/jackc/pgx/v5/stdlib" // postgres driver
	_ "modernc.org/sqlite"             // pure-Go sqlite driver
)

// ErrNotFound is returned when an account, node or relay does not exist.
var ErrNotFound = errors.New("control: not found")

// Account is a VPN user. The account key itself is never stored, only its hash.
type Account struct {
	ID       string `json:"id"`
	Name     string `json:"name"`
	KeyHash  string `json:"-"`
	Quota    int64  `json:"quota_bytes"` // per month, 0 = unlimited
	Used     int64  `json:"used_bytes"`
	Period   int64  `json:"period"` // YYYYMM the Used counter belongs to
	Disabled bool   `json:"disabled"`
	Conc     int    `json:"conc"`
	Mbps     int    `json:"mbps"`
	Created  int64  `json:"created"`
}

// Node is a registered edge proxy.
type Node struct {
	ID         string `json:"id"`
	Name       string `json:"name"`
	SecretHash string `json:"-"`
	Endpoints  string `json:"endpoints"` // JSON []transport.Endpoint
	LastSeen   int64  `json:"last_seen"`
	Created    int64  `json:"created"`
}

// Relay is an in-country forwarder. It is created pending by an admin, and
// becomes active when it enrolls its identity key with a one-time token.
type Relay struct {
	ID       string `json:"id"`
	Name     string `json:"name"`
	Key      string `json:"key"` // base64url Ed25519 public key; empty until enrolled
	Addr     string `json:"addr"`
	SNI      string `json:"sni"`
	DNSAddr  string `json:"dns_addr,omitempty"` // optional DNS-shaped UDP carrier
	DNSZone  string `json:"dns_zone,omitempty"`
	Revoked  bool   `json:"revoked"`
	Created  int64  `json:"created"`
	LastSeen int64  `json:"last_seen"`
}

// Store is the persistence seam. Adapters: SQLite (default) and Postgres.
// Every method is atomic on its own; the service needs no wider transaction.
type Store interface {
	CreateAccount(ctx context.Context, a Account) error
	AccountByKeyHash(ctx context.Context, hash string) (Account, error)
	AccountByID(ctx context.Context, id string) (Account, error)
	ListAccounts(ctx context.Context) ([]Account, error)
	UpdateAccount(ctx context.Context, id string, disabled *bool, quota *int64) error
	DeleteAccount(ctx context.Context, id string) error
	// AddUsage adds bytes to the account's counter for period, resetting the
	// counter first if it belongs to an older period. Unknown ids are ignored.
	AddUsage(ctx context.Context, id string, bytes, period int64) error
	// Blocked lists accounts that must not pass: disabled or over quota in period.
	Blocked(ctx context.Context, period int64) ([]string, error)

	UpsertNode(ctx context.Context, n Node) error
	NodeByID(ctx context.Context, id string) (Node, error)
	ListNodes(ctx context.Context) ([]Node, error)
	TouchNode(ctx context.Context, id string, seen int64, endpoints string) error
	DeleteNode(ctx context.Context, id string) error

	CreateRelay(ctx context.Context, r Relay) error
	RelayByID(ctx context.Context, id string) (Relay, error)
	ListRelays(ctx context.Context) ([]Relay, error)
	// EnrollRelay sets the identity key of a pending, unrevoked relay. It
	// reports false when the relay is unknown, revoked or already enrolled,
	// which makes an enrollment token single use.
	EnrollRelay(ctx context.Context, id, key string, now int64) (bool, error)
	RevokeRelay(ctx context.Context, id string) error

	CreateJoinToken(ctx context.Context, hash string, expires int64) error
	// ConsumeJoinToken marks a token used. It reports false for unknown,
	// used or expired tokens.
	ConsumeJoinToken(ctx context.Context, hash string, now int64) (bool, error)
	Close() error
}

const schema = `
CREATE TABLE IF NOT EXISTS accounts (
  id TEXT PRIMARY KEY, name TEXT NOT NULL, key_hash TEXT NOT NULL UNIQUE,
  quota BIGINT NOT NULL DEFAULT 0, used BIGINT NOT NULL DEFAULT 0, period BIGINT NOT NULL DEFAULT 0,
  disabled BIGINT NOT NULL DEFAULT 0, conc BIGINT NOT NULL DEFAULT 0, mbps BIGINT NOT NULL DEFAULT 0,
  created BIGINT NOT NULL);
CREATE TABLE IF NOT EXISTS nodes (
  id TEXT PRIMARY KEY, name TEXT NOT NULL, secret_hash TEXT NOT NULL,
  endpoints TEXT NOT NULL DEFAULT '[]', last_seen BIGINT NOT NULL DEFAULT 0, created BIGINT NOT NULL);
CREATE TABLE IF NOT EXISTS relays (
  id TEXT PRIMARY KEY, name TEXT NOT NULL, key TEXT NOT NULL DEFAULT '', addr TEXT NOT NULL,
  sni TEXT NOT NULL, dns_addr TEXT NOT NULL DEFAULT '', dns_zone TEXT NOT NULL DEFAULT '',
  revoked BIGINT NOT NULL DEFAULT 0, created BIGINT NOT NULL, last_seen BIGINT NOT NULL DEFAULT 0);
CREATE TABLE IF NOT EXISTS join_tokens (
  hash TEXT PRIMARY KEY, expires BIGINT NOT NULL, used BIGINT NOT NULL DEFAULT 0);
`

// OpenStore opens SQLite for a file path, or Postgres for a postgres:// URL.
func OpenStore(ctx context.Context, dsn string) (Store, error) {
	var db *sql.DB
	var err error
	pg := strings.HasPrefix(dsn, "postgres://") || strings.HasPrefix(dsn, "postgresql://")
	if pg {
		db, err = sql.Open("pgx", dsn)
	} else {
		db, err = sql.Open("sqlite", "file:"+dsn+"?_pragma=busy_timeout(5000)&_pragma=journal_mode(WAL)&_pragma=foreign_keys(1)")
		if err == nil {
			db.SetMaxOpenConns(1) // one writer; the control plane is not a hot path
		}
	}
	if err != nil {
		return nil, err
	}
	if err := db.PingContext(ctx); err != nil {
		_ = db.Close()
		return nil, err
	}
	for _, stmt := range strings.Split(schema, ";") {
		if strings.TrimSpace(stmt) == "" {
			continue
		}
		if _, err := db.ExecContext(ctx, stmt); err != nil {
			_ = db.Close()
			return nil, fmt.Errorf("control: migrate: %w", err)
		}
	}
	return &sqlStore{db: db, pg: pg}, nil
}

type sqlStore struct {
	db *sql.DB
	pg bool
}

// q rewrites ? placeholders to $n for Postgres.
func (s *sqlStore) q(query string) string {
	if !s.pg {
		return query
	}
	var b strings.Builder
	n := 0
	for _, r := range query {
		if r == '?' {
			n++
			b.WriteString("$" + strconv.Itoa(n))
			continue
		}
		b.WriteRune(r)
	}
	return b.String()
}

func b2i(b bool) int64 {
	if b {
		return 1
	}
	return 0
}

func (s *sqlStore) Close() error { return s.db.Close() }

const accountCols = "id, name, key_hash, quota, used, period, disabled, conc, mbps, created"

func scanAccount(r interface{ Scan(...any) error }) (Account, error) {
	var a Account
	var dis int64
	err := r.Scan(&a.ID, &a.Name, &a.KeyHash, &a.Quota, &a.Used, &a.Period, &dis, &a.Conc, &a.Mbps, &a.Created)
	a.Disabled = dis != 0
	if errors.Is(err, sql.ErrNoRows) {
		err = ErrNotFound
	}
	return a, err
}

func (s *sqlStore) CreateAccount(ctx context.Context, a Account) error {
	_, err := s.db.ExecContext(ctx, s.q("INSERT INTO accounts ("+accountCols+") VALUES (?,?,?,?,?,?,?,?,?,?)"),
		a.ID, a.Name, a.KeyHash, a.Quota, a.Used, a.Period, b2i(a.Disabled), a.Conc, a.Mbps, a.Created)
	return err
}

func (s *sqlStore) AccountByKeyHash(ctx context.Context, h string) (Account, error) {
	return scanAccount(s.db.QueryRowContext(ctx, s.q("SELECT "+accountCols+" FROM accounts WHERE key_hash=?"), h))
}

func (s *sqlStore) AccountByID(ctx context.Context, id string) (Account, error) {
	return scanAccount(s.db.QueryRowContext(ctx, s.q("SELECT "+accountCols+" FROM accounts WHERE id=?"), id))
}

func (s *sqlStore) ListAccounts(ctx context.Context) ([]Account, error) {
	rows, err := s.db.QueryContext(ctx, "SELECT "+accountCols+" FROM accounts ORDER BY created")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Account
	for rows.Next() {
		a, err := scanAccount(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, a)
	}
	return out, rows.Err()
}

func (s *sqlStore) UpdateAccount(ctx context.Context, id string, disabled *bool, quota *int64) error {
	res, err := s.db.ExecContext(ctx, s.q(`UPDATE accounts SET
	  disabled = CASE WHEN ? >= 0 THEN ? ELSE disabled END,
	  quota = CASE WHEN ? >= 0 THEN ? ELSE quota END WHERE id=?`),
		flag(disabled), flag(disabled), opt(quota), opt(quota), id)
	return affected(res, err)
}

func flag(b *bool) int64 {
	if b == nil {
		return -1
	}
	return b2i(*b)
}

func opt(v *int64) int64 {
	if v == nil {
		return -1
	}
	return *v
}

func affected(res sql.Result, err error) error {
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return nil
}

func (s *sqlStore) DeleteAccount(ctx context.Context, id string) error {
	res, err := s.db.ExecContext(ctx, s.q("DELETE FROM accounts WHERE id=?"), id)
	return affected(res, err)
}

func (s *sqlStore) AddUsage(ctx context.Context, id string, bytes, period int64) error {
	_, err := s.db.ExecContext(ctx, s.q(`UPDATE accounts SET
	  used = CASE WHEN period = ? THEN used + ? ELSE ? END, period = ? WHERE id = ?`),
		period, bytes, bytes, period, id)
	return err
}

func (s *sqlStore) Blocked(ctx context.Context, period int64) ([]string, error) {
	rows, err := s.db.QueryContext(ctx, s.q(`SELECT id FROM accounts
	  WHERE disabled <> 0 OR (quota > 0 AND period = ? AND used >= quota)`), period)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		out = append(out, id)
	}
	return out, rows.Err()
}

func (s *sqlStore) UpsertNode(ctx context.Context, n Node) error {
	_, err := s.db.ExecContext(ctx, s.q(`INSERT INTO nodes (id, name, secret_hash, endpoints, last_seen, created)
	  VALUES (?,?,?,?,?,?)
	  ON CONFLICT (id) DO UPDATE SET name = excluded.name, secret_hash = excluded.secret_hash,
	    endpoints = excluded.endpoints, last_seen = excluded.last_seen`),
		n.ID, n.Name, n.SecretHash, n.Endpoints, n.LastSeen, n.Created)
	return err
}

func (s *sqlStore) NodeByID(ctx context.Context, id string) (Node, error) {
	var n Node
	err := s.db.QueryRowContext(ctx, s.q("SELECT id, name, secret_hash, endpoints, last_seen, created FROM nodes WHERE id=?"), id).
		Scan(&n.ID, &n.Name, &n.SecretHash, &n.Endpoints, &n.LastSeen, &n.Created)
	if errors.Is(err, sql.ErrNoRows) {
		err = ErrNotFound
	}
	return n, err
}

func (s *sqlStore) ListNodes(ctx context.Context) ([]Node, error) {
	rows, err := s.db.QueryContext(ctx, "SELECT id, name, secret_hash, endpoints, last_seen, created FROM nodes ORDER BY created")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Node
	for rows.Next() {
		var n Node
		if err := rows.Scan(&n.ID, &n.Name, &n.SecretHash, &n.Endpoints, &n.LastSeen, &n.Created); err != nil {
			return nil, err
		}
		out = append(out, n)
	}
	return out, rows.Err()
}

func (s *sqlStore) TouchNode(ctx context.Context, id string, seen int64, endpoints string) error {
	res, err := s.db.ExecContext(ctx, s.q(`UPDATE nodes SET last_seen = ?,
	  endpoints = CASE WHEN ? <> '' THEN ? ELSE endpoints END WHERE id = ?`), seen, endpoints, endpoints, id)
	return affected(res, err)
}

func (s *sqlStore) DeleteNode(ctx context.Context, id string) error {
	res, err := s.db.ExecContext(ctx, s.q("DELETE FROM nodes WHERE id=?"), id)
	return affected(res, err)
}

func (s *sqlStore) CreateJoinToken(ctx context.Context, hash string, expires int64) error {
	_, err := s.db.ExecContext(ctx, s.q("INSERT INTO join_tokens (hash, expires, used) VALUES (?,?,0)"), hash, expires)
	return err
}

func (s *sqlStore) ConsumeJoinToken(ctx context.Context, hash string, now int64) (bool, error) {
	res, err := s.db.ExecContext(ctx, s.q("UPDATE join_tokens SET used = 1 WHERE hash = ? AND used = 0 AND expires > ?"), hash, now)
	if err != nil {
		return false, err
	}
	n, _ := res.RowsAffected()
	return n == 1, nil
}

const relayCols = "id, name, key, addr, sni, dns_addr, dns_zone, revoked, created, last_seen"

func scanRelay(r interface{ Scan(...any) error }) (Relay, error) {
	var x Relay
	var rev int64
	err := r.Scan(&x.ID, &x.Name, &x.Key, &x.Addr, &x.SNI, &x.DNSAddr, &x.DNSZone, &rev, &x.Created, &x.LastSeen)
	x.Revoked = rev != 0
	if errors.Is(err, sql.ErrNoRows) {
		err = ErrNotFound
	}
	return x, err
}

func (s *sqlStore) CreateRelay(ctx context.Context, r Relay) error {
	_, err := s.db.ExecContext(ctx, s.q("INSERT INTO relays ("+relayCols+") VALUES (?,?,?,?,?,?,?,?,?,?)"),
		r.ID, r.Name, r.Key, r.Addr, r.SNI, r.DNSAddr, r.DNSZone, b2i(r.Revoked), r.Created, r.LastSeen)
	return err
}

func (s *sqlStore) RelayByID(ctx context.Context, id string) (Relay, error) {
	return scanRelay(s.db.QueryRowContext(ctx, s.q("SELECT "+relayCols+" FROM relays WHERE id=?"), id))
}

func (s *sqlStore) ListRelays(ctx context.Context) ([]Relay, error) {
	rows, err := s.db.QueryContext(ctx, "SELECT "+relayCols+" FROM relays ORDER BY created")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Relay
	for rows.Next() {
		r, err := scanRelay(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

func (s *sqlStore) EnrollRelay(ctx context.Context, id, key string, now int64) (bool, error) {
	res, err := s.db.ExecContext(ctx, s.q("UPDATE relays SET key = ?, last_seen = ? WHERE id = ? AND key = '' AND revoked = 0"), key, now, id)
	if err != nil {
		return false, err
	}
	n, _ := res.RowsAffected()
	return n == 1, nil
}

func (s *sqlStore) RevokeRelay(ctx context.Context, id string) error {
	res, err := s.db.ExecContext(ctx, s.q("UPDATE relays SET revoked = 1 WHERE id = ?"), id)
	return affected(res, err)
}
