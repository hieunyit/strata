// Package store is the control plane's PostgreSQL access (schema in
// control-plane/db). Write operations that the admin API exposes take an
// audit entry and record it in the same transaction.
package store

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

var (
	ErrNotFound = errors.New("store: not found")
	ErrExists   = errors.New("store: already exists")
	// ErrTokenInvalid covers unknown, used and expired enrollment tokens
	// alike, so a caller learns nothing about which.
	ErrTokenInvalid = errors.New("store: enrollment token is not valid")
)

// Store wraps a pool.
type Store struct {
	pool *pgxpool.Pool
	// BundleLockWait bounds how long a deploy waits for another one to
	// finish (CP-A03); ErrBundleBusy after it. 0: DefaultBundleLockWait.
	BundleLockWait time.Duration
}

// DefaultBundleLockWait: a deploy compiles, signs and uploads while it
// holds the bundle lock (10–40 s with the whole signature package).
const DefaultBundleLockWait = 2 * time.Minute

// New returns a store on pool.
func New(pool *pgxpool.Pool) *Store { return &Store{pool: pool} }

// Audit is one audit_log row.
type Audit struct {
	// ReplayOperation is populated by the admin service, never from user JSON.
	ReplayOperation string `json:"-"`
	// RuleContext is populated from a looked-up event by the API, never JSON.
	RuleContext *EventRuleContext `json:"-"`

	At    time.Time `json:"at"`
	Actor string    `json:"actor"`
	// Subject: the caller's token subject (sub), which the user cannot
	// change, unlike the name in Actor; the four-eyes rule compares it.
	Subject   string `json:"subject,omitempty"`
	Channel   string `json:"channel"`  // ui, api, gitops, system
	Action    string `json:"action"`   // full method name, e.g. /strata.admin.v1.FleetAdminService/RevokeNode
	Resource  string `json:"resource"` // e.g. nodes/node-abc
	RequestID string `json:"request_id,omitempty"`
	Before    any    `json:"before,omitempty"` // marshalled to JSON; nil for none
	After     any    `json:"after,omitempty"`
}

func writeAudit(ctx context.Context, tx pgx.Tx, a Audit) error {
	if a.Channel == "" {
		a.Channel = "api"
	}
	enc := func(v any) ([]byte, error) {
		if v == nil {
			return nil, nil
		}
		return json.Marshal(v)
	}
	before, err := enc(a.Before)
	if err != nil {
		return err
	}
	after, err := enc(a.After)
	if err != nil {
		return err
	}
	_, err = tx.Exec(ctx, `INSERT INTO audit_log (actor, subject, channel, action, resource, request_id, before, after)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`, a.Actor, a.Subject, a.Channel, a.Action, a.Resource, a.RequestID, before, after)
	return err
}

func (s *Store) inTx(ctx context.Context, f func(pgx.Tx) error) error {
	tx, err := s.pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return fmt.Errorf("store: %w", err)
	}
	defer func() { _ = tx.Rollback(context.Background()) }()
	if err := f(tx); err != nil {
		return err
	}
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("store: commit: %w", err)
	}
	return nil
}

func isUniqueViolation(err error) bool {
	var pg *pgconn.PgError
	return errors.As(err, &pg) && pg.Code == "23505"
}

// Group is a connector group.
type Group struct {
	ID        string    `json:"id"`
	Name      string    `json:"name"`
	CreatedAt time.Time `json:"created_at"`
}

// CreateGroup adds a group.
func (s *Store) CreateGroup(ctx context.Context, g Group, a Audit) (Group, error) {
	err := s.inTx(ctx, func(tx pgx.Tx) error {
		err := tx.QueryRow(ctx, `INSERT INTO connector_groups (id, name) VALUES ($1, $2) RETURNING created_at`,
			g.ID, g.Name).Scan(&g.CreatedAt)
		if isUniqueViolation(err) {
			return ErrExists
		}
		if err != nil {
			return fmt.Errorf("store: create group: %w", err)
		}
		a.After = g
		return writeAudit(ctx, tx, a)
	})
	return g, err
}

// ListGroups returns every group by name.
func (s *Store) ListGroups(ctx context.Context) ([]Group, error) {
	rows, err := s.pool.Query(ctx, `SELECT id, name, created_at FROM connector_groups ORDER BY name`)
	if err != nil {
		return nil, fmt.Errorf("store: list groups: %w", err)
	}
	return pgx.CollectRows(rows, func(r pgx.CollectableRow) (Group, error) {
		var g Group
		err := r.Scan(&g.ID, &g.Name, &g.CreatedAt)
		return g, err
	})
}

// TokenHash is how enrollment tokens are kept: only their SHA-256.
func TokenHash(token string) []byte {
	h := sha256.Sum256([]byte(token))
	return h[:]
}

// CreateEnrollmentToken stores a token's hash for group, valid until
// expires.
func (s *Store) CreateEnrollmentToken(ctx context.Context, id, groupID string, token string, expires time.Time, a Audit) error {
	return s.inTx(ctx, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `INSERT INTO enrollment_tokens (id, group_id, token_sha256, expires_at, created_by)
			VALUES ($1, $2, $3, $4, $5)`, id, groupID, TokenHash(token), expires, a.Actor)
		var pg *pgconn.PgError
		if errors.As(err, &pg) && pg.Code == "23503" { // foreign key: no such group
			return ErrNotFound
		}
		if err != nil {
			return fmt.Errorf("store: create token: %w", err)
		}
		// The token itself never reaches the audit log.
		a.After = map[string]any{"id": id, "group_id": groupID, "expires_at": expires}
		return writeAudit(ctx, tx, a)
	})
}

// Node is a row of nodes.
type Node struct {
	Inventory            Inventory  `json:"inventory"`
	InventoryAt          *time.Time `json:"inventory_at,omitempty"`
	DesiredBundleVersion *int64     `json:"desired_bundle_version,omitempty"`
	ID                   string     `json:"id"`
	GroupID              string     `json:"group_id"`
	Hostname             string     `json:"hostname"`
	ProxyVersion         string     `json:"proxy_version"`
	ModuleVersion        string     `json:"module_version"`
	BundleVersion        *int64     `json:"bundle_version,omitempty"`
	BundleState          string     `json:"bundle_state"`
	CertSerial           string     `json:"cert_serial"`
	CertNotAfter         *time.Time `json:"cert_not_after,omitempty"`
	LastSeenAt           *time.Time `json:"last_seen_at,omitempty"`
	Connected            bool       `json:"connected"`
	RevokedAt            *time.Time `json:"revoked_at,omitempty"`
	CreatedAt            time.Time  `json:"created_at"`
}

const nodeCols = `id, group_id, hostname, proxy_version, module_version, bundle_version, bundle_state,
	cert_serial, cert_not_after, last_seen_at, connected, revoked_at, created_at, inventory, inventory_at, desired_bundle_version`

func scanNode(r pgx.Row) (Node, error) {
	var n Node
	var raw []byte
	err := r.Scan(&n.ID, &n.GroupID, &n.Hostname, &n.ProxyVersion, &n.ModuleVersion, &n.BundleVersion, &n.BundleState,
		&n.CertSerial, &n.CertNotAfter, &n.LastSeenAt, &n.Connected, &n.RevokedAt, &n.CreatedAt, &raw, &n.InventoryAt, &n.DesiredBundleVersion)
	if err == nil {
		err = json.Unmarshal(raw, &n.Inventory)
	}
	return n, err
}

// Issued is the certificate the CA made for a new node.
type Issued struct {
	Serial   string
	NotAfter time.Time
	CertPEM  []byte
}

// Enroll consumes a valid token and creates node n in the token's group,
// all in one transaction: the token row is locked, so it is used once even
// under concurrent requests. issue makes the certificate once the node's
// group is known.
func (s *Store) Enroll(ctx context.Context, token string, n Node, now time.Time, issue func(groupID string) (Issued, error)) (Node, Issued, error) {
	var iss Issued
	err := s.inTx(ctx, func(tx pgx.Tx) error {
		var tokenID, groupID string
		err := tx.QueryRow(ctx, `SELECT id, group_id FROM enrollment_tokens
			WHERE token_sha256 = $1 AND used_at IS NULL AND expires_at > $2 FOR UPDATE`, TokenHash(token), now).Scan(&tokenID, &groupID)
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrTokenInvalid
		}
		if err != nil {
			return fmt.Errorf("store: token: %w", err)
		}
		n.GroupID = groupID
		if iss, err = issue(groupID); err != nil {
			return err
		}
		n.CertSerial, n.CertNotAfter = iss.Serial, &iss.NotAfter
		// A new node runs what the fleet runs: the bundle of the latest
		// rollout that finished (W10-N-01). Without it a node enrolled
		// after a deploy had no bundle until the next one. A rollout still
		// running, paused, failed or aborted is not given out.
		row := tx.QueryRow(ctx, `INSERT INTO nodes (id, group_id, hostname, proxy_version, module_version, cert_serial, cert_not_after,
				desired_bundle_version)
			VALUES ($1, $2, $3, $4, $5, $6, $7,
				(SELECT bundle_version FROM rollouts WHERE state = 'DONE' ORDER BY id DESC LIMIT 1)) RETURNING `+nodeCols,
			n.ID, n.GroupID, n.Hostname, n.ProxyVersion, n.ModuleVersion, n.CertSerial, n.CertNotAfter)
		if n, err = scanNode(row); err != nil {
			return fmt.Errorf("store: create node: %w", err)
		}
		if _, err := tx.Exec(ctx, `UPDATE enrollment_tokens SET used_at = $2, used_by_node = $3 WHERE id = $1`, tokenID, now, n.ID); err != nil {
			return fmt.Errorf("store: use token: %w", err)
		}
		return writeAudit(ctx, tx, Audit{
			Actor: "node:" + n.ID, Channel: "system", Action: "/strata.fleet.v1.FleetService/Enroll",
			Resource: "nodes/" + n.ID, After: map[string]any{"group_id": groupID, "token_id": tokenID, "cert_serial": iss.Serial},
		})
	})
	return n, iss, err
}

// GetNode returns one node.
func (s *Store) GetNode(ctx context.Context, id string) (Node, error) {
	n, err := scanNode(s.pool.QueryRow(ctx, `SELECT `+nodeCols+` FROM nodes WHERE id = $1`, id))
	if errors.Is(err, pgx.ErrNoRows) {
		return Node{}, ErrNotFound
	}
	if err != nil {
		return Node{}, fmt.Errorf("store: get node: %w", err)
	}
	return n, nil
}

// ListNodes returns every node, newest first.
func (s *Store) ListNodes(ctx context.Context) ([]Node, error) {
	rows, err := s.pool.Query(ctx, `SELECT `+nodeCols+` FROM nodes ORDER BY created_at DESC, id`)
	if err != nil {
		return nil, fmt.Errorf("store: list nodes: %w", err)
	}
	return pgx.CollectRows(rows, func(r pgx.CollectableRow) (Node, error) { return scanNode(r) })
}

// NodeSeen records what a node reported in Hello or a heartbeat.
func (s *Store) NodeSeen(ctx context.Context, id string, at time.Time, hostname, proxyVersion, moduleVersion string, bundleVersion *int64) error {
	_, err := s.pool.Exec(ctx, `UPDATE nodes SET last_seen_at = $2, connected = true,
		hostname = coalesce(nullif($3, ''), hostname),
		proxy_version = coalesce(nullif($4, ''), proxy_version),
		module_version = coalesce(nullif($5, ''), module_version),
		bundle_version = coalesce($6, bundle_version)
		WHERE id = $1 AND revoked_at IS NULL`, id, at, hostname, proxyVersion, moduleVersion, bundleVersion)
	if err != nil {
		return fmt.Errorf("store: node seen: %w", err)
	}
	return nil
}

// NodeDisconnected records that the node's Connect stream ended.
func (s *Store) NodeDisconnected(ctx context.Context, id string, at time.Time) error {
	if _, err := s.pool.Exec(ctx, `UPDATE nodes SET connected = false, last_seen_at = $2 WHERE id = $1`, id, at); err != nil {
		return fmt.Errorf("store: node disconnected: %w", err)
	}
	return nil
}

// RenewCertificate replaces a node's current certificate.
func (s *Store) RenewCertificate(ctx context.Context, id, oldSerial string, iss Issued) error {
	tag, err := s.pool.Exec(ctx, `UPDATE nodes SET cert_serial = $3, cert_not_after = $4
		WHERE id = $1 AND cert_serial = $2 AND revoked_at IS NULL`, id, oldSerial, iss.Serial, iss.NotAfter)
	if err != nil {
		return fmt.Errorf("store: renew: %w", err)
	}
	if tag.RowsAffected() != 1 {
		return ErrNotFound
	}
	return nil
}

// RevokeNode marks a node revoked; its certificates stop working.
func (s *Store) RevokeNode(ctx context.Context, id string, at time.Time, a Audit) (Node, error) {
	var n Node
	err := s.inTx(ctx, func(tx pgx.Tx) error {
		before, err := scanNode(tx.QueryRow(ctx, `SELECT `+nodeCols+` FROM nodes WHERE id = $1 FOR UPDATE`, id))
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrNotFound
		}
		if err != nil {
			return fmt.Errorf("store: revoke: %w", err)
		}
		n, err = scanNode(tx.QueryRow(ctx, `UPDATE nodes SET revoked_at = coalesce(revoked_at, $2), connected = false WHERE id = $1 RETURNING `+nodeCols, id, at))
		if err != nil {
			return fmt.Errorf("store: revoke: %w", err)
		}
		a.Before, a.After = before, n
		return writeAudit(ctx, tx, a)
	})
	return n, err
}

// AuditEntries returns the newest audit rows (for tests and GET /v1/audit).
func (s *Store) AuditEntries(ctx context.Context, limit int) ([]Audit, error) {
	return s.SearchAudit(ctx, AuditFilter{Limit: limit})
}
