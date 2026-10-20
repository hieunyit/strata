package store

import (
	"context"
	"fmt"

	"github.com/jackc/pgx/v5"
)

// RestoreState is what the database a restore replaces knows and the
// backup may not (CP-A09).
type RestoreState struct {
	// HighestBundle: the highest bundle version recorded or reported by a
	// node; bundles after the restore are numbered above it.
	HighestBundle uint64
	// Nodes enrolled now; those missing from the backup enroll again.
	Nodes []string
}

// ReadRestoreState reads a database about to be replaced. An empty
// database (no schema yet) is a zero state.
func (s *Store) ReadRestoreState(ctx context.Context) (RestoreState, error) {
	var st RestoreState
	var exists bool
	if err := s.pool.QueryRow(ctx, "SELECT to_regclass('public.nodes') IS NOT NULL AND to_regclass('public.bundles') IS NOT NULL").Scan(&exists); err != nil {
		return st, fmt.Errorf("store: restore state: %w", err)
	}
	if !exists {
		return st, nil
	}
	var floor bool
	if err := s.pool.QueryRow(ctx, "SELECT to_regclass('public.bundle_version_floor') IS NOT NULL").Scan(&floor); err != nil {
		return st, fmt.Errorf("store: restore state: %w", err)
	}
	q := `SELECT greatest((SELECT coalesce(max(version), 0) FROM bundles), (SELECT coalesce(max(bundle_version), 0) FROM nodes))`
	if floor {
		q = `SELECT greatest((SELECT coalesce(max(version), 0) FROM bundles), (SELECT coalesce(max(bundle_version), 0) FROM nodes),
			(SELECT coalesce(max(version), 0) FROM bundle_version_floor))`
	}
	var high int64
	if err := s.pool.QueryRow(ctx, q).Scan(&high); err != nil {
		return st, fmt.Errorf("store: restore state: %w", err)
	}
	st.HighestBundle = uint64(high)
	rows, err := s.pool.Query(ctx, "SELECT id FROM nodes WHERE revoked_at IS NULL ORDER BY id")
	if err != nil {
		return st, fmt.Errorf("store: restore state: %w", err)
	}
	st.Nodes, err = pgx.CollectRows(rows, pgx.RowTo[string])
	if err != nil {
		return st, fmt.Errorf("store: restore state: %w", err)
	}
	return st, nil
}

// RestoreResult is what FinishRestore changed.
type RestoreResult struct {
	Floor            uint64
	AbortedRollouts  int64
	FailedOperations int64
	ClearedDesired   int64
	NodesToReenroll  []string
}

// FinishRestore makes a restored database safe to serve, in one
// transaction: the bundle version floor above before.HighestBundle; no
// node is told to move to the bundle it should have run at backup time (a
// rollback to an older version); rollouts under way then are aborted,
// replays running then failed; the lease of the process that made the
// backup is dropped. Returns the nodes enrolled before the restore that
// the backup does not know.
func (s *Store) FinishRestore(ctx context.Context, before RestoreState) (RestoreResult, error) {
	var res RestoreResult
	err := s.inTx(ctx, func(tx pgx.Tx) error {
		var high int64
		if err := tx.QueryRow(ctx, `SELECT greatest($1::bigint, (SELECT coalesce(max(version), 0) FROM bundles),
			(SELECT coalesce(max(bundle_version), 0) FROM nodes), (SELECT coalesce(max(version), 0) FROM bundle_version_floor))`,
			int64(before.HighestBundle)).Scan(&high); err != nil {
			return err
		}
		res.Floor = uint64(high)
		if _, err := tx.Exec(ctx, `INSERT INTO bundle_version_floor (id, version) VALUES (1, $1)
			ON CONFLICT (id) DO UPDATE SET version = greatest(bundle_version_floor.version, EXCLUDED.version), set_at = now()`, high); err != nil {
			return err
		}
		tag, err := tx.Exec(ctx, `UPDATE rollouts SET state = 'ABORTED', reason = 'restored from a backup', updated_at = now()
			WHERE state IN ('RUNNING', 'PAUSED')`)
		if err != nil {
			return err
		}
		res.AbortedRollouts = tag.RowsAffected()
		tag, err = tx.Exec(ctx, `UPDATE operations SET state = 'FAILED', error = 'interrupted: restored from a backup', finished_at = now()
			WHERE state = 'RUNNING'`)
		if err != nil {
			return err
		}
		res.FailedOperations = tag.RowsAffected()
		tag, err = tx.Exec(ctx, `UPDATE nodes SET desired_bundle_version = NULL WHERE desired_bundle_version IS NOT NULL`)
		if err != nil {
			return err
		}
		res.ClearedDesired = tag.RowsAffected()
		if _, err := tx.Exec(ctx, `DELETE FROM control_plane_lease`); err != nil {
			return err
		}
		rows, err := tx.Query(ctx, `SELECT x FROM unnest($1::text[]) AS x WHERE x NOT IN (SELECT id FROM nodes) ORDER BY x`, before.Nodes)
		if err != nil {
			return err
		}
		res.NodesToReenroll, err = pgx.CollectRows(rows, pgx.RowTo[string])
		return err
	})
	if err != nil {
		return res, fmt.Errorf("store: finishing the restore: %w", err)
	}
	return res, nil
}
