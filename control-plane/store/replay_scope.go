package store

import (
	"context"
	"fmt"
)

// ReplaySampleScope authorizes samples from a non-revoked enrolled node,
// with sampling enabled, only for policies in its active or desired bundle.
// This deliberately excludes the HMAC key itself.
func (s *Store) ReplaySampleScope(ctx context.Context, node string) (string, map[string]bool, error) {
	rows, err := s.pool.Query(ctx, `SELECT r.key_id, p.name FROM nodes n
		JOIN replay_sampling r ON r.group_id = n.group_id AND r.rate_bp > 0
		JOIN bundles b ON b.version IN (n.bundle_version, n.desired_bundle_version)
		JOIN policies p ON b.contents ? p.id
		WHERE n.id = $1 AND n.revoked_at IS NULL`, node)
	if err != nil {
		return "", nil, fmt.Errorf("store: replay sample scope: %w", err)
	}
	defer rows.Close()
	key := ""
	policies := map[string]bool{}
	for rows.Next() {
		var name string
		if err := rows.Scan(&key, &name); err != nil {
			return "", nil, fmt.Errorf("store: replay sample scope: %w", err)
		}
		policies[name] = true
	}
	if err := rows.Err(); err != nil {
		return "", nil, fmt.Errorf("store: replay sample scope: %w", err)
	}
	return key, policies, nil
}
