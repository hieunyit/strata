package store

import (
	"context"
	"fmt"
)

// KeptBundles returns the bundle versions whose artifacts must stay
// (CP-A07): the newest `newest` bundles (for rollback and the replay
// baseline), the version every node runs and should run, the bundles of
// running or paused rollouts, and the source and target of staging actions
// not yet rolled out. newestRecorded is the highest recorded version: an
// artifact above it is an upload not recorded yet, never removed.
func (s *Store) KeptBundles(ctx context.Context, newest int) (keep map[uint64]bool, newestRecorded uint64, err error) {
	if newest < 1 {
		return nil, 0, fmt.Errorf("store: keep at least the newest bundle")
	}
	// first: a bundle recorded after this read is above it, so kept
	var top int64
	if err := s.pool.QueryRow(ctx, "SELECT coalesce(max(version), 0) FROM bundles").Scan(&top); err != nil {
		return nil, 0, fmt.Errorf("store: newest bundle: %w", err)
	}
	rows, err := s.pool.Query(ctx, `
		SELECT version FROM (SELECT version FROM bundles ORDER BY version DESC LIMIT $1) n
		UNION SELECT bundle_version FROM nodes WHERE bundle_version IS NOT NULL
		UNION SELECT desired_bundle_version FROM nodes WHERE desired_bundle_version IS NOT NULL
		UNION SELECT bundle_version FROM rollouts WHERE state IN ('RUNNING', 'PAUSED')
		UNION SELECT source_bundle FROM rule_staging_actions WHERE rollout_id IS NULL
		UNION SELECT bundle_version FROM rule_staging_actions WHERE rollout_id IS NULL`, newest)
	if err != nil {
		return nil, 0, fmt.Errorf("store: kept bundles: %w", err)
	}
	defer rows.Close()
	keep = map[uint64]bool{}
	for rows.Next() {
		var v int64
		if err := rows.Scan(&v); err != nil {
			return nil, 0, fmt.Errorf("store: kept bundles: %w", err)
		}
		if v > 0 {
			keep[uint64(v)] = true
		}
	}
	if err := rows.Err(); err != nil {
		return nil, 0, fmt.Errorf("store: kept bundles: %w", err)
	}
	return keep, uint64(top), nil
}
