package store

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

// CanaryTrip is a row of canary_trips (W12-G2-01).
type CanaryTrip struct {
	ID        int64          `json:"id"`
	GroupID   string         `json:"group_id"`
	Reason    string         `json:"reason"`
	Detail    map[string]any `json:"detail,omitempty"`
	Policies  []string       `json:"policies"`
	TrippedAt time.Time      `json:"tripped_at"`
	RenewedAt time.Time      `json:"renewed_at"`
}

// ErrTripOpen: the group already has an open trip.
var ErrTripOpen = errors.New("store: the group already has an open canary trip")

const tripCols = `id, group_id, reason, detail, policies, tripped_at, renewed_at`

func scanTrip(r pgx.Row) (CanaryTrip, error) {
	var t CanaryTrip
	var detail []byte
	if err := r.Scan(&t.ID, &t.GroupID, &t.Reason, &detail, &t.Policies, &t.TrippedAt, &t.RenewedAt); err != nil {
		return CanaryTrip{}, err
	}
	_ = json.Unmarshal(detail, &t.Detail)
	return t, nil
}

func insertCommands(ctx context.Context, tx pgx.Tx, cmds []Command, actor string) ([]Command, error) {
	out := make([]Command, 0, len(cmds))
	for _, c := range cmds {
		ids := c.RuleIDs
		if ids == nil {
			ids = []int32{}
		}
		got, err := scanCommand(tx.QueryRow(ctx, `INSERT INTO node_commands (id, node_id, kind, policy_id, duration_seconds, rule_ids, created_by, expires_at)
			SELECT $1, id, $3, $4, $5, $6, $7, $8 FROM nodes WHERE id = $2 AND revoked_at IS NULL
			RETURNING `+commandCols, c.ID, c.NodeID, c.Kind, c.PolicyID, c.DurationSeconds, ids, actor, c.ExpiresAt))
		if errors.Is(err, pgx.ErrNoRows) {
			continue // revoked since
		}
		if err != nil {
			return nil, fmt.Errorf("store: create command: %w", err)
		}
		out = append(out, got)
	}
	return out, nil
}

// OpenCanaryTrip records a trip with its ForceShadow commands and an audit
// entry, in one transaction; ErrTripOpen when the group has one already
// (another control plane replica tripped first).
func (s *Store) OpenCanaryTrip(ctx context.Context, t CanaryTrip, cmds []Command, a Audit) (CanaryTrip, []Command, error) {
	var row CanaryTrip
	var out []Command
	err := s.inTx(ctx, func(tx pgx.Tx) error {
		detail, err := json.Marshal(t.Detail)
		if err != nil {
			return err
		}
		if t.Policies == nil {
			t.Policies = []string{}
		}
		row, err = scanTrip(tx.QueryRow(ctx, `INSERT INTO canary_trips (group_id, reason, detail, policies, tripped_at, renewed_at)
			VALUES ($1, $2, $3, $4, $5, $5) RETURNING `+tripCols, t.GroupID, t.Reason, detail, t.Policies, t.TrippedAt))
		var pe *pgconn.PgError
		if errors.As(err, &pe) && pe.Code == "23505" {
			return ErrTripOpen
		}
		if err != nil {
			return fmt.Errorf("store: open canary trip: %w", err)
		}
		if out, err = insertCommands(ctx, tx, cmds, a.Actor); err != nil {
			return err
		}
		a.After = map[string]any{"trip": row, "commands": len(out)}
		return writeAudit(ctx, tx, a)
	})
	return row, out, err
}

// OpenCanaryTrips: the trips not cleared, by group.
func (s *Store) OpenCanaryTrips(ctx context.Context) ([]CanaryTrip, error) {
	rows, err := s.pool.Query(ctx, `SELECT `+tripCols+` FROM canary_trips WHERE cleared_at IS NULL ORDER BY group_id`)
	if err != nil {
		return nil, fmt.Errorf("store: canary trips: %w", err)
	}
	return pgx.CollectRows(rows, func(r pgx.CollectableRow) (CanaryTrip, error) { return scanTrip(r) })
}

// RenewCanaryTrip stores the renewal's ForceShadow commands and its time.
func (s *Store) RenewCanaryTrip(ctx context.Context, id int64, cmds []Command, at time.Time) ([]Command, error) {
	var out []Command
	err := s.inTx(ctx, func(tx pgx.Tx) error {
		tag, err := tx.Exec(ctx, `UPDATE canary_trips SET renewed_at = $2 WHERE id = $1 AND cleared_at IS NULL`, id, at)
		if err != nil {
			return fmt.Errorf("store: renew canary trip: %w", err)
		}
		if tag.RowsAffected() == 0 {
			return ErrNotFound
		}
		out, err = insertCommands(ctx, tx, cmds, "canary-monitor")
		return err
	})
	return out, err
}

// ClearCanaryTrip removes policy (every policy with "") from the group's
// open trip, and clears the trip once no policy is left. Called with the
// clearForceShadow that lifts the shadow; the caller audits it.
func (s *Store) ClearCanaryTrip(ctx context.Context, group, policy, actor string, at time.Time) error {
	_, err := s.pool.Exec(ctx, `UPDATE canary_trips SET
			policies = CASE WHEN $2::text = '' THEN '{}' ELSE array_remove(policies, $2::text) END,
			cleared_at = CASE WHEN $2::text = '' OR cardinality(array_remove(policies, $2::text)) = 0 THEN $4::timestamptz END,
			cleared_by = CASE WHEN $2::text = '' OR cardinality(array_remove(policies, $2::text)) = 0 THEN $3::text END
		WHERE group_id = $1 AND cleared_at IS NULL`, group, policy, actor, at)
	if err != nil {
		return fmt.Errorf("store: clear canary trip: %w", err)
	}
	return nil
}

// CanaryPolicies: the names of the policies whose current version has an
// enforce canary.
func (s *Store) CanaryPolicies(ctx context.Context) ([]string, error) {
	rows, err := s.pool.Query(ctx, `SELECT p.name FROM policies p JOIN policy_versions v ON v.policy_id = p.id AND v.version = p.current_version
		WHERE coalesce((v.spec->>'canary_percent')::numeric, 0) > 0 ORDER BY p.name`)
	if err != nil {
		return nil, fmt.Errorf("store: canary policies: %w", err)
	}
	return pgx.CollectRows(rows, pgx.RowTo[string])
}
