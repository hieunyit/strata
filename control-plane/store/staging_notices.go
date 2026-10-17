package store

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
)

// StagingNotice reports historical intent/publication, never current runtime
// protection. UInt64 counts/bundle versions are decimal strings for JS clients.
type StagingNotice struct {
	ID            string    `json:"id"`
	PolicyID      string    `json:"policy_id"`
	PolicyName    string    `json:"policy_name"`
	PolicyVersion int       `json:"policy_version"`
	RuleID        uint32    `json:"rule_id"`
	SourceBundle  string    `json:"source_bundle"`
	BundleVersion string    `json:"bundle_version"`
	Matches       string    `json:"matches"`
	Reports       string    `json:"reports"`
	WindowFrom    time.Time `json:"window_from"`
	WindowTo      time.Time `json:"window_to"`
	CreatedAt     time.Time `json:"created_at"`
	RolloutID     string    `json:"rollout_id"`
	RolloutState  string    `json:"rollout_state"`
}

// StagingNotices pages the durable action ledger, regardless of other audit
// traffic or a process restart. Read-only; no expiry, acknowledgments or reset.
func (s *Store) StagingNotices(ctx context.Context, before *time.Time, id string, limit int) ([]StagingNotice, error) {
	if limit < 1 || limit > 51 || len(id) > 128 || (before == nil) != (id == "") || before != nil && before.IsZero() {
		return nil, errors.New("store: invalid staging notice page")
	}
	bounded, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	rows, err := s.pool.Query(bounded, `SELECT a.id,a.policy_id,p.name,a.policy_version,a.rule_id,a.source_bundle::text,a.bundle_version::text,
  a.matches::text,a.reports::text,a.window_from,a.window_to,a.created_at,coalesce(r.id::text,''),coalesce(r.state,'PENDING')
  FROM rule_staging_actions a JOIN policies p ON p.id=a.policy_id LEFT JOIN rollouts r ON r.id=a.rollout_id
  WHERE ($1::timestamptz IS NULL OR (a.created_at,a.id)<($1,$2::text))
  ORDER BY a.created_at DESC,a.id DESC LIMIT $3`, before, id, limit)
	if err != nil {
		return nil, fmt.Errorf("store: staging notices: %w", err)
	}
	out, err := pgx.CollectRows(rows, func(r pgx.CollectableRow) (StagingNotice, error) {
		var n StagingNotice
		err := r.Scan(&n.ID, &n.PolicyID, &n.PolicyName, &n.PolicyVersion, &n.RuleID, &n.SourceBundle, &n.BundleVersion, &n.Matches, &n.Reports, &n.WindowFrom, &n.WindowTo, &n.CreatedAt, &n.RolloutID, &n.RolloutState)
		return n, err
	})
	if err != nil {
		return nil, fmt.Errorf("store: staging notice rows: %w", err)
	}
	return out, nil
}
