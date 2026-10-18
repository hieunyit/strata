package store

import (
	"context"
	"errors"
	"fmt"
	"math"
	"time"

	"github.com/jackc/pgx/v5"
)

// LatestStagingAction finds recoverable intent only for the latest recorded
// bundle. Superseded actions remain historical; they cannot overwrite a newer
// human deployment. Linked RUNNING actions are returned to retry lost notices.
func (s *Store) LatestStagingAction(ctx context.Context) (StagingAction, error) {
	a, err := scanStaging(s.pool.QueryRow(ctx, `SELECT `+stagingCols+` FROM rule_staging_actions
  WHERE bundle_version=(SELECT max(version) FROM bundles)`))
	if errors.Is(err, pgx.ErrNoRows) {
		return StagingAction{}, ErrNotFound
	}
	if err != nil {
		return StagingAction{}, fmt.Errorf("store: latest staging action: %w", err)
	}
	return a, nil
}

// StartStagingRollout atomically links the durable action to exactly one
// rollout and desired node versions. Retries return that same rollout; they
// never unpause/retry failures, abort another rollout, or recreate an abort.
// The returned nodes may be notified again: they have not ACKed ACTIVE and
// agents deduplicate offers of their pending/active version.
func (s *Store) StartStagingRollout(ctx context.Context, id string, nodes []string, plan []float64, soak time.Duration, audit Audit) (Rollout, []string, error) {
	if len(id) < 1 || len(id) > 128 || len(nodes) < 1 || len(nodes) > 10000 || len(plan) < 1 || len(plan) > 16 || soak < 0 || soak > 24*time.Hour {
		return Rollout{}, nil, errors.New("store: invalid staging rollout")
	}
	seen := map[string]bool{}
	for _, node := range nodes {
		if node == "" || seen[node] {
			return Rollout{}, nil, errors.New("store: invalid staging nodes")
		}
		seen[node] = true
	}
	last := -1.0
	for _, wave := range plan {
		if math.IsNaN(wave) || wave < 0 || wave > 1 || wave <= last {
			return Rollout{}, nil, errors.New("store: invalid staging waves")
		}
		last = wave
	}
	var rolloutID int64
	err := s.inTx(ctx, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock($1)`, int64(lockBundleRecords)); err != nil {
			return fmt.Errorf("store: staging rollout lock: %w", err)
		}
		a, err := scanStaging(tx.QueryRow(ctx, `SELECT `+stagingCols+` FROM rule_staging_actions WHERE id=$1 FOR UPDATE`, id))
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrNotFound
		}
		if err != nil {
			return fmt.Errorf("store: staging intent: %w", err)
		}
		var latest int64
		if err := tx.QueryRow(ctx, `SELECT max(version) FROM bundles`).Scan(&latest); err != nil {
			return err
		}
		if uint64(latest) != a.BundleVersion {
			return ErrStagingConflict
		}
		if a.RolloutID != nil {
			rolloutID = *a.RolloutID
			return nil
		}
		var blocked bool
		if err := tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM rollouts WHERE state IN ('RUNNING','PAUSED','FAILED'))`).Scan(&blocked); err != nil {
			return err
		}
		if blocked {
			return ErrRolloutState
		}
		// Validate selected nodes are still enrolled, before changing desired state.
		var enrolled int
		if err := tx.QueryRow(ctx, `SELECT count(*) FROM nodes WHERE id=ANY($1) AND revoked_at IS NULL`, nodes).Scan(&enrolled); err != nil {
			return err
		}
		if enrolled != len(nodes) {
			return ErrStagingConflict
		}
		audit.Action = "rule-staging:start-rollout"
		r, _, err := createRolloutTx(ctx, tx, a.BundleVersion, nodes, plan, soak, audit)
		if err != nil {
			return err
		}
		rolloutID = r.ID
		_, err = tx.Exec(ctx, `UPDATE rule_staging_actions SET rollout_id=$2 WHERE id=$1`, id, rolloutID)
		if err != nil {
			return fmt.Errorf("store: link staging rollout: %w", err)
		}
		return nil
	})
	if err != nil {
		return Rollout{}, nil, err
	}
	r, err := s.GetRollout(ctx, rolloutID)
	if err != nil {
		return Rollout{}, nil, err
	}
	var notify []string
	if r.State == RolloutRunning {
		for _, n := range r.Nodes {
			if n.Wave == r.CurrentWave && (n.State == "NOTIFIED" || n.State == "VERIFIED") {
				notify = append(notify, n.NodeID)
			}
		}
	}
	return r, notify, nil
}
