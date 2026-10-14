package store

import (
	"context"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
)

// MaxDisabledRules a group can hold: what the control file of a node holds.
const MaxDisabledRules = 480

// DisabledRule is a row of disabled_rules.
type DisabledRule struct {
	GroupID   string    `json:"group_id"`
	RuleID    int32     `json:"rule_id"`
	Reason    string    `json:"reason"`
	CreatedBy string    `json:"created_by"`
	CreatedAt time.Time `json:"created_at"`
}

// ErrTooManyRules: the group already has MaxDisabledRules rules off.
var ErrTooManyRules = fmt.Errorf("store: at most %d disabled rules per group", MaxDisabledRules)

// SetRuleDisabled switches rule off (on) for group, creates cmds for the
// group's nodes and writes one audit entry, in one transaction. Disabling
// a rule already off updates its reason; enabling a rule that is on only
// sends the commands.
func (s *Store) SetRuleDisabled(ctx context.Context, group string, rule int32, off bool, reason string, cmds []Command, a Audit) (DisabledRule, []Command, error) {
	var row DisabledRule
	var out []Command
	err := s.inTx(ctx, func(tx pgx.Tx) error {
		if off {
			var n int
			if err := tx.QueryRow(ctx, `SELECT count(*) FROM disabled_rules WHERE group_id = $1 AND rule_id <> $2`, group, rule).Scan(&n); err != nil {
				return fmt.Errorf("store: count disabled rules: %w", err)
			}
			if n >= MaxDisabledRules {
				return ErrTooManyRules
			}
			err := tx.QueryRow(ctx, `INSERT INTO disabled_rules (group_id, rule_id, reason, created_by) VALUES ($1, $2, $3, $4)
				ON CONFLICT (group_id, rule_id) DO UPDATE SET reason = EXCLUDED.reason, created_by = EXCLUDED.created_by, created_at = now()
				RETURNING group_id, rule_id, reason, created_by, created_at`, group, rule, reason, a.Actor).
				Scan(&row.GroupID, &row.RuleID, &row.Reason, &row.CreatedBy, &row.CreatedAt)
			if err != nil {
				return fmt.Errorf("store: disable rule: %w", err)
			}
		} else {
			if _, err := tx.Exec(ctx, `DELETE FROM disabled_rules WHERE group_id = $1 AND rule_id = $2`, group, rule); err != nil {
				return fmt.Errorf("store: enable rule: %w", err)
			}
			row = DisabledRule{GroupID: group, RuleID: rule, Reason: reason, CreatedBy: a.Actor}
		}
		for _, c := range cmds {
			got, err := scanCommand(tx.QueryRow(ctx, `INSERT INTO node_commands (id, node_id, kind, policy_id, duration_seconds, rule_ids, created_by, expires_at)
				VALUES ($1, $2, $3, '', 0, $4, $5, $6) RETURNING `+commandCols, c.ID, c.NodeID, c.Kind, c.RuleIDs, a.Actor, c.ExpiresAt))
			if err != nil {
				return fmt.Errorf("store: create command: %w", err)
			}
			out = append(out, got)
		}
		a.After = map[string]any{"group_id": group, "rule_id": rule, "disabled": off, "reason": reason, "commands": len(out)}
		return writeAudit(ctx, tx, a)
	})
	return row, out, err
}

// DisabledRules of a group, or of every group with "", by rule id.
func (s *Store) DisabledRules(ctx context.Context, group string) ([]DisabledRule, error) {
	rows, err := s.pool.Query(ctx, `SELECT group_id, rule_id, reason, created_by, created_at FROM disabled_rules
		WHERE $1 = '' OR group_id = $1 ORDER BY group_id, rule_id`, group)
	if err != nil {
		return nil, fmt.Errorf("store: disabled rules: %w", err)
	}
	return pgx.CollectRows(rows, func(r pgx.CollectableRow) (DisabledRule, error) {
		var d DisabledRule
		err := r.Scan(&d.GroupID, &d.RuleID, &d.Reason, &d.CreatedBy, &d.CreatedAt)
		return d, err
	})
}

// NodeDisabledRules: the rules off for a node's group.
func (s *Store) NodeDisabledRules(ctx context.Context, node string) ([]int32, error) {
	rows, err := s.pool.Query(ctx, `SELECT d.rule_id FROM disabled_rules d JOIN nodes n ON n.group_id = d.group_id
		WHERE n.id = $1 ORDER BY d.rule_id`, node)
	if err != nil {
		return nil, fmt.Errorf("store: node disabled rules: %w", err)
	}
	return pgx.CollectRows(rows, pgx.RowTo[int32])
}
