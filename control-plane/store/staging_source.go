package store

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math"

	"github.com/jackc/pgx/v5"
)

func (s *Store) GetBundle(ctx context.Context, version uint64) (Bundle, error) {
	if version == 0 || version > math.MaxInt64 {
		return Bundle{}, ErrNotFound
	}
	return scanSourceBundle(s.pool.QueryRow(ctx, `SELECT version,sha256,object_key,size_bytes,contents,created_by,created_at,input_digest,rules_digest,required_capabilities FROM bundles WHERE version=$1`, int64(version)))
}

func scanSourceBundle(row pgx.Row) (Bundle, error) {
	var b Bundle
	var version int64
	var contents []byte
	err := row.Scan(&version, &b.SHA256, &b.ObjectKey, &b.SizeBytes, &contents, &b.CreatedBy, &b.CreatedAt, &b.InputDigest, &b.RulesDigest, &b.RequiredCapabilities)
	if errors.Is(err, pgx.ErrNoRows) {
		return Bundle{}, ErrNotFound
	}
	if err != nil {
		return Bundle{}, fmt.Errorf("store: source bundle: %w", err)
	}
	b.Version = uint64(version)
	if err = json.Unmarshal(contents, &b.Contents); err != nil {
		return Bundle{}, fmt.Errorf("store: source contents: %w", err)
	}
	return b, nil
}

// StagingRoot follows only recorded, immutable additive derivations. Policy
// versions and compiler input authority originate at the ordinary deployed root.
// At most 4096 stage entries fit the signed codec, bounding ancestry too.
func (s *Store) StagingRoot(ctx context.Context, version uint64) (Bundle, error) {
	if version == 0 || version > math.MaxInt64 {
		return Bundle{}, ErrNotFound
	}
	var root int64
	var depth int
	var more bool
	err := s.pool.QueryRow(ctx, `WITH RECURSIVE chain(version,depth) AS (
  SELECT $1::bigint,0 UNION ALL
  SELECT a.source_bundle,c.depth+1 FROM chain c JOIN rule_staging_actions a ON a.bundle_version=c.version WHERE c.depth<4096)
  SELECT c.version,c.depth,EXISTS(SELECT 1 FROM rule_staging_actions a WHERE a.bundle_version=c.version)
  FROM chain c ORDER BY c.depth DESC LIMIT 1`, int64(version)).Scan(&root, &depth, &more)
	if err != nil {
		return Bundle{}, fmt.Errorf("store: staging ancestry: %w", err)
	}
	if more {
		return Bundle{}, errors.New("store: staging ancestry exceeds codec limit")
	}
	return s.GetBundle(ctx, uint64(root))
}

// BundlePolicies selects the recorded versions, never the newest approved/draft
// versions. Missing historical resources fail closed rather than disappear.
func (s *Store) BundlePolicies(ctx context.Context, version uint64) ([]Policy, error) {
	b, err := s.GetBundle(ctx, version)
	if err != nil {
		return nil, err
	}
	if len(b.Contents) < 1 || len(b.Contents) > 4096 {
		return nil, errors.New("store: invalid bundle policy count")
	}
	rows, err := s.pool.Query(ctx, `SELECT p.id,p.name,v.version,v.spec FROM bundles b
  CROSS JOIN LATERAL jsonb_each_text(b.contents) c
  JOIN policies p ON p.id=c.key JOIN policy_versions v ON v.policy_id=p.id AND v.version=c.value::integer
  WHERE b.version=$1 ORDER BY p.name LIMIT 4097`, int64(version))
	if err != nil {
		return nil, fmt.Errorf("store: bundle policies: %w", err)
	}
	out, err := pgx.CollectRows(rows, func(r pgx.CollectableRow) (Policy, error) {
		var p Policy
		err := r.Scan(&p.ID, &p.Name, &p.CurrentVersion, &p.Spec)
		return p, err
	})
	if err != nil {
		return nil, fmt.Errorf("store: bundle policy rows: %w", err)
	}
	if len(out) != len(b.Contents) {
		return nil, errors.New("store: incomplete bundle policy history")
	}
	return out, nil
}

// StagingSourceReady requires a completed real rollout, at least one enrolled
// node and ACTIVE ACKs/desired state for the exact latest bundle. An empty DONE
// rollout or a mere recorded/uploaded artifact cannot authorize automation.
func (s *Store) StagingSourceReady(ctx context.Context, version uint64) (bool, error) {
	if version == 0 || version > math.MaxInt64 {
		return false, nil
	}
	var ready bool
	err := s.pool.QueryRow(ctx, `SELECT
  $1=(SELECT max(version) FROM bundles)
  AND EXISTS(SELECT 1 FROM rollouts WHERE id=(SELECT max(id) FROM rollouts) AND bundle_version=$1 AND state='DONE')
  AND NOT EXISTS(SELECT 1 FROM rollouts WHERE state IN ('RUNNING','PAUSED','FAILED'))
  AND EXISTS(SELECT 1 FROM nodes WHERE revoked_at IS NULL)
  AND NOT EXISTS(SELECT 1 FROM nodes WHERE revoked_at IS NULL AND
   (bundle_version IS DISTINCT FROM $1 OR desired_bundle_version IS DISTINCT FROM $1 OR bundle_state<>'ACTIVE'))`, int64(version)).Scan(&ready)
	if err != nil {
		return false, fmt.Errorf("store: staging source activation: %w", err)
	}
	return ready, nil
}
