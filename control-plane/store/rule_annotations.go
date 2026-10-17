package store

import (
	"context"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
)

// EventRuleContext binds a human FP annotation to the event snapshot. An FP
// event containing a rule is not proof that this individual rule caused the FP.
type EventRuleContext struct {
	PolicyID  string    `json:"policy_id"`
	EventTime time.Time `json:"event_time"`
	RuleIDs   []uint32  `json:"rule_ids"`
}

func writeRuleAnnotationContext(ctx context.Context, tx pgx.Tx, block string, c *EventRuleContext) error {
	if c.EventTime.IsZero() || len(c.PolicyID) > 55 || len(c.RuleIDs) > 64 {
		return fmt.Errorf("store: invalid rule annotation context")
	}
	ids := make([]int64, 0, len(c.RuleIDs))
	seen := make(map[uint32]bool, len(c.RuleIDs))
	for _, id := range c.RuleIDs {
		if id == 0 || seen[id] {
			continue
		}
		seen[id] = true
		ids = append(ids, int64(id))
	}
	_, err := tx.Exec(ctx, `INSERT INTO rule_annotation_context(block_id,policy_id,event_at,rule_ids)
 VALUES($1,$2,$3,$4) ON CONFLICT(block_id) DO UPDATE SET
 policy_id=excluded.policy_id,event_at=excluded.event_at,rule_ids=excluded.rule_ids`, block, c.PolicyID, c.EventTime, ids)
	if err != nil {
		return fmt.Errorf("store: save rule annotation context: %w", err)
	}
	return nil
}

// RuleFalsePositiveEvents counts distinct annotated events containing a rule,
// using decision time and a half-open window. It performs no writes or callbacks.
func (s *Store) RuleFalsePositiveEvents(ctx context.Context, rule uint32, policy string, from, to time.Time) (uint64, error) {
	if rule == 0 || from.IsZero() || !to.After(from) || to.Sub(from) > 24*time.Hour || len(policy) > 55 {
		return 0, fmt.Errorf("store: invalid rule annotation query")
	}
	q := `SELECT count(*) FROM rule_annotation_context c JOIN event_annotations a USING(block_id)
 WHERE c.rule_ids @> ARRAY[$1]::bigint[] AND c.event_at >= $2 AND c.event_at < $3`
	args := []any{int64(rule), from, to}
	if policy != "" {
		q += " AND c.policy_id = $4"
		args = append(args, policy)
	}
	var n uint64
	if err := s.pool.QueryRow(ctx, q, args...).Scan(&n); err != nil {
		return 0, fmt.Errorf("store: count rule FP events: %w", err)
	}
	return n, nil
}

// PruneRuleAnnotationContext deletes at most limit old snapshots per call.
// The annotation/audit/idempotency records are independent and stay intact.
func (s *Store) PruneRuleAnnotationContext(ctx context.Context, before time.Time, limit int) (int64, error) {
	if before.IsZero() || limit < 1 || limit > 1000 {
		return 0, fmt.Errorf("store: invalid rule context retention batch")
	}
	tag, err := s.pool.Exec(ctx, `WITH old AS (
 SELECT block_id FROM rule_annotation_context WHERE event_at < $1 ORDER BY event_at,block_id LIMIT $2 FOR UPDATE SKIP LOCKED
 ) DELETE FROM rule_annotation_context c USING old WHERE c.block_id=old.block_id`, before, limit)
	if err != nil {
		return 0, fmt.Errorf("store: prune rule annotation context: %w", err)
	}
	return tag.RowsAffected(), nil
}
