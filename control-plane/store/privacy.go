package store

import (
	"context"
	"encoding/json"
	"fmt"
)

// BundlePolicySpec uses the immutable bundle contents; event policy_version is
// the bundle version, not the policy revision. Never substitute the latest draft.
func (s *Store) BundlePolicySpec(ctx context.Context, bundle uint64, name string) (json.RawMessage, error) {
	var raw []byte
	err := s.pool.QueryRow(ctx, `SELECT v.spec FROM bundles b JOIN policies p ON p.name=$2 JOIN policy_versions v ON v.policy_id=p.id AND v.version=(b.contents->>p.id)::integer WHERE b.version=$1`, int64(bundle), name).Scan(&raw)
	if err != nil {
		return nil, fmt.Errorf("store: bundle policy privacy: %w", err)
	}
	return raw, nil
}
