package store

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
)

// Rollout states.
const (
	RolloutRunning = "RUNNING"
	RolloutPaused  = "PAUSED"
	RolloutFailed  = "FAILED"
	RolloutDone    = "DONE"
	RolloutAborted = "ABORTED"
)

// ErrRolloutState: the rollout cannot do that in its state.
var ErrRolloutState = errors.New("store: not possible in the rollout's state")

// Rollout is a row of rollouts with its nodes.
type Rollout struct {
	ID            int64         `json:"id"`
	BundleVersion uint64        `json:"bundle_version"`
	State         string        `json:"state"`
	Waves         []int         `json:"waves"`
	CurrentWave   int           `json:"current_wave"`
	SoakSeconds   int           `json:"soak_seconds"`
	WaveDoneAt    *time.Time    `json:"wave_done_at,omitempty"`
	Reason        string        `json:"reason"`
	CreatedBy     string        `json:"created_by"`
	CreatedAt     time.Time     `json:"created_at"`
	UpdatedAt     time.Time     `json:"updated_at"`
	Nodes         []RolloutNode `json:"nodes"`
}

// RolloutNode is one node of a rollout.
type RolloutNode struct {
	NodeID    string    `json:"node_id"`
	Wave      int       `json:"wave"`
	State     string    `json:"state"`
	Error     string    `json:"error"`
	UpdatedAt time.Time `json:"updated_at"`
}

// WavePlan splits n nodes into waves by the cumulative fractions (0..1] of
// plan, the first wave being at least one node and every wave adding at
// least one: 1 node, 10%, 100% gives [1, 2, 3] for three nodes.
func WavePlan(n int, plan []float64) []int {
	var waves []int
	last := 0
	for i, f := range plan {
		c := int(f*float64(n) + 0.999999)
		if i == 0 && f <= 0 {
			c = 1
		}
		if c <= last {
			c = last + 1
		}
		if c > n {
			c = n
		}
		if c > last {
			waves = append(waves, c)
			last = c
		}
	}
	if last < n {
		waves = append(waves, n)
	}
	return waves
}

// revertDesired gives the nodes of an aborted rollout that do not run its
// bundle their running version back as desired, so they stop fetching it.
func revertDesired(ctx context.Context, tx pgx.Tx, where string, args ...any) error {
	_, err := tx.Exec(ctx, `UPDATE nodes n SET desired_bundle_version = n.bundle_version
		FROM rollout_nodes rn JOIN rollouts r ON r.id = rn.rollout_id
		WHERE rn.node_id = n.id AND rn.state <> 'ACTIVE' AND n.desired_bundle_version = r.bundle_version AND `+where, args...)
	if err != nil {
		return fmt.Errorf("store: revert desired versions: %w", err)
	}
	return nil
}

// CreateRollout starts a rollout of version over nodes (in wave order) and
// aborts the rollouts still running or paused. The nodes of the first wave
// get the version as desired; their ids are returned for notification.
func (s *Store) CreateRollout(ctx context.Context, version uint64, nodes []string, plan []float64, soak time.Duration, a Audit) (Rollout, []string, error) {
	waves := WavePlan(len(nodes), plan)
	raw, _ := json.Marshal(waves)
	var r Rollout
	var first []string
	err := s.inTx(ctx, func(tx pgx.Tx) error {
		if err := revertDesired(ctx, tx, `r.state IN ('RUNNING', 'PAUSED', 'FAILED')`); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `UPDATE rollouts SET state = 'ABORTED', reason = $1, updated_at = now()
			WHERE state IN ('RUNNING', 'PAUSED', 'FAILED')`, fmt.Sprintf("superseded by bundle %d", version)); err != nil {
			return fmt.Errorf("store: supersede: %w", err)
		}
		state := RolloutRunning
		if len(nodes) == 0 {
			state = RolloutDone
		}
		if err := tx.QueryRow(ctx, `INSERT INTO rollouts (bundle_version, state, waves, soak_seconds, created_by)
			VALUES ($1, $2, $3, $4, $5) RETURNING id`, int64(version), state, raw, int(soak.Seconds()), a.Actor).Scan(&r.ID); err != nil {
			return fmt.Errorf("store: create rollout: %w", err)
		}
		for i, n := range nodes {
			w := 0
			for w < len(waves) && i >= waves[w] {
				w++
			}
			st := "PENDING"
			if w == 0 {
				st = "NOTIFIED"
				first = append(first, n)
			}
			if _, err := tx.Exec(ctx, `INSERT INTO rollout_nodes (rollout_id, node_id, wave, state) VALUES ($1, $2, $3, $4)`, r.ID, n, w, st); err != nil {
				return fmt.Errorf("store: rollout node: %w", err)
			}
		}
		if len(first) > 0 {
			if _, err := tx.Exec(ctx, `UPDATE nodes SET desired_bundle_version = $1 WHERE id = ANY($2)`, int64(version), first); err != nil {
				return fmt.Errorf("store: desired version: %w", err)
			}
		}
		a.Resource = fmt.Sprintf("rollouts/%d", r.ID)
		a.After = map[string]any{"bundle_version": version, "waves": waves, "nodes": nodes}
		return writeAudit(ctx, tx, a)
	})
	if err != nil {
		return Rollout{}, nil, err
	}
	r, err = s.GetRollout(ctx, r.ID)
	return r, first, err
}

// GetRollout returns a rollout and its nodes.
func (s *Store) GetRollout(ctx context.Context, id int64) (Rollout, error) {
	var r Rollout
	var waves []byte
	var v int64
	err := s.pool.QueryRow(ctx, `SELECT id, bundle_version, state, waves, current_wave, soak_seconds, wave_done_at, reason,
		created_by, created_at, updated_at FROM rollouts WHERE id = $1`, id).
		Scan(&r.ID, &v, &r.State, &waves, &r.CurrentWave, &r.SoakSeconds, &r.WaveDoneAt, &r.Reason, &r.CreatedBy, &r.CreatedAt, &r.UpdatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return Rollout{}, ErrNotFound
	}
	if err != nil {
		return Rollout{}, fmt.Errorf("store: rollout: %w", err)
	}
	r.BundleVersion = uint64(v)
	_ = json.Unmarshal(waves, &r.Waves)
	rows, err := s.pool.Query(ctx, `SELECT node_id, wave, state, error, updated_at FROM rollout_nodes
		WHERE rollout_id = $1 ORDER BY wave, node_id`, id)
	if err != nil {
		return Rollout{}, fmt.Errorf("store: rollout nodes: %w", err)
	}
	r.Nodes, err = pgx.CollectRows(rows, func(row pgx.CollectableRow) (RolloutNode, error) {
		var n RolloutNode
		err := row.Scan(&n.NodeID, &n.Wave, &n.State, &n.Error, &n.UpdatedAt)
		return n, err
	})
	return r, err
}

// ListRollouts returns the newest rollouts first.
func (s *Store) ListRollouts(ctx context.Context, limit int) ([]Rollout, error) {
	rows, err := s.pool.Query(ctx, `SELECT id FROM rollouts ORDER BY id DESC LIMIT $1`, limit)
	if err != nil {
		return nil, fmt.Errorf("store: list rollouts: %w", err)
	}
	ids, err := pgx.CollectRows(rows, pgx.RowTo[int64])
	if err != nil {
		return nil, err
	}
	out := make([]Rollout, 0, len(ids))
	for _, id := range ids {
		r, err := s.GetRollout(ctx, id)
		if err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, nil
}

// ActiveRollouts returns the rollouts in RUNNING state.
func (s *Store) ActiveRollouts(ctx context.Context) ([]Rollout, error) {
	rows, err := s.pool.Query(ctx, `SELECT id FROM rollouts WHERE state = 'RUNNING' ORDER BY id`)
	if err != nil {
		return nil, fmt.Errorf("store: running rollouts: %w", err)
	}
	ids, err := pgx.CollectRows(rows, pgx.RowTo[int64])
	if err != nil {
		return nil, err
	}
	var out []Rollout
	for _, id := range ids {
		r, err := s.GetRollout(ctx, id)
		if err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, nil
}

// ReportBundleStatus records a node's state for a bundle version: in the
// newest rollout of that version that includes the node, and as the node's
// bundle state.
func (s *Store) ReportBundleStatus(ctx context.Context, node string, version uint64, state, msg string) error {
	return s.inTx(ctx, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `UPDATE rollout_nodes rn SET state = $3, error = $4, updated_at = now()
			FROM rollouts r WHERE rn.rollout_id = r.id AND rn.node_id = $1 AND r.bundle_version = $2
			AND r.id = (SELECT max(r2.id) FROM rollouts r2 JOIN rollout_nodes n2 ON n2.rollout_id = r2.id
			            WHERE n2.node_id = $1 AND r2.bundle_version = $2)`, node, int64(version), state, msg); err != nil {
			return fmt.Errorf("store: rollout status: %w", err)
		}
		var err error
		switch state {
		case "ACTIVE":
			_, err = tx.Exec(ctx, `UPDATE nodes SET bundle_state = $2, bundle_version = $3 WHERE id = $1`, node, state, int64(version))
		case "VERIFIED", "FAILED":
			_, err = tx.Exec(ctx, `UPDATE nodes SET bundle_state = $2 WHERE id = $1`, node, state)
		}
		if err != nil {
			return fmt.Errorf("store: node bundle state: %w", err)
		}
		return nil
	})
}

// AdvanceRollout moves a running rollout to its next wave (its nodes get
// the version as desired; their ids are returned) or to DONE after the
// last one.
func (s *Store) AdvanceRollout(ctx context.Context, id int64) ([]string, error) {
	var next []string
	err := s.inTx(ctx, func(tx pgx.Tx) error {
		var cur, n int
		var v int64
		var waves []byte
		var state string
		if err := tx.QueryRow(ctx, `SELECT current_wave, bundle_version, waves, state FROM rollouts WHERE id = $1 FOR UPDATE`, id).
			Scan(&cur, &v, &waves, &state); err != nil {
			return fmt.Errorf("store: advance: %w", err)
		}
		if state != RolloutRunning {
			return ErrRolloutState
		}
		var w []int
		_ = json.Unmarshal(waves, &w)
		n = cur + 1
		if n >= len(w) {
			_, err := tx.Exec(ctx, `UPDATE rollouts SET state = 'DONE', wave_done_at = NULL, updated_at = now() WHERE id = $1`, id)
			return err
		}
		rows, err := tx.Query(ctx, `UPDATE rollout_nodes SET state = 'NOTIFIED', updated_at = now()
			WHERE rollout_id = $1 AND wave = $2 RETURNING node_id`, id, n)
		if err != nil {
			return fmt.Errorf("store: advance: %w", err)
		}
		if next, err = pgx.CollectRows(rows, pgx.RowTo[string]); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `UPDATE nodes SET desired_bundle_version = $1 WHERE id = ANY($2)`, v, next); err != nil {
			return err
		}
		_, err = tx.Exec(ctx, `UPDATE rollouts SET current_wave = $2, wave_done_at = NULL, updated_at = now() WHERE id = $1`, id, n)
		return err
	})
	return next, err
}

// MarkWaveDone records when the current wave became all ACTIVE (for the
// soak time); it keeps the first time.
func (s *Store) MarkWaveDone(ctx context.Context, id int64, at time.Time) error {
	_, err := s.pool.Exec(ctx, `UPDATE rollouts SET wave_done_at = coalesce(wave_done_at, $2) WHERE id = $1`, id, at)
	return err
}

// SetRolloutState pauses, resumes, fails or aborts a rollout. from lists
// the states the change is allowed from.
func (s *Store) SetRolloutState(ctx context.Context, id int64, to, reason string, from []string, a Audit) (Rollout, error) {
	err := s.inTx(ctx, func(tx pgx.Tx) error {
		var state string
		err := tx.QueryRow(ctx, `SELECT state FROM rollouts WHERE id = $1 FOR UPDATE`, id).Scan(&state)
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrNotFound
		}
		if err != nil {
			return err
		}
		ok := false
		for _, f := range from {
			ok = ok || f == state
		}
		if !ok {
			return ErrRolloutState
		}
		if to == RolloutAborted {
			if err := revertDesired(ctx, tx, `r.id = $1`, id); err != nil {
				return err
			}
		}
		if _, err := tx.Exec(ctx, `UPDATE rollouts SET state = $2, reason = $3, updated_at = now() WHERE id = $1`, id, to, reason); err != nil {
			return err
		}
		if a.Actor == "" {
			return nil // the controller, not a person: no audit entry
		}
		a.Resource = fmt.Sprintf("rollouts/%d", id)
		a.Before, a.After = map[string]string{"state": state}, map[string]string{"state": to, "reason": reason}
		return writeAudit(ctx, tx, a)
	})
	if err != nil {
		return Rollout{}, err
	}
	return s.GetRollout(ctx, id)
}

// EnrolledNodes returns the ids of the nodes that are not revoked, in a
// stable order.
func (s *Store) EnrolledNodes(ctx context.Context) ([]string, error) {
	rows, err := s.pool.Query(ctx, `SELECT id FROM nodes WHERE revoked_at IS NULL ORDER BY created_at, id`)
	if err != nil {
		return nil, fmt.Errorf("store: nodes: %w", err)
	}
	return pgx.CollectRows(rows, pgx.RowTo[string])
}

// DesiredBundle returns the bundle a node should run, or ErrNotFound.
func (s *Store) DesiredBundle(ctx context.Context, node string) (Bundle, error) {
	var b Bundle
	var v int64
	err := s.pool.QueryRow(ctx, `SELECT b.version, b.sha256, b.object_key, b.size_bytes FROM nodes n
		JOIN bundles b ON b.version = n.desired_bundle_version WHERE n.id = $1 AND n.revoked_at IS NULL`, node).
		Scan(&v, &b.SHA256, &b.ObjectKey, &b.SizeBytes)
	if errors.Is(err, pgx.ErrNoRows) {
		return Bundle{}, ErrNotFound
	}
	if err != nil {
		return Bundle{}, fmt.Errorf("store: desired bundle: %w", err)
	}
	b.Version = uint64(v)
	return b, nil
}
