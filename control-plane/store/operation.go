package store

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
)

// Operation states (migration 0013).
const (
	OpPending = "PENDING"
	OpRunning = "RUNNING"
	OpDone    = "DONE"
	OpFailed  = "FAILED"
)

// OpReplay replays a policy version against the traffic samples
// (W13-G2-01).
const OpReplay = "REPLAY"

// Operation is a long-running operation of the admin API.
type Operation struct {
	ID         string          `json:"id"`
	Kind       string          `json:"kind"`
	PolicyID   string          `json:"policy_id"`
	Version    int             `json:"version"`
	State      string          `json:"state"`
	Error      string          `json:"error,omitempty"`
	Result     json.RawMessage `json:"result,omitempty"`
	CreatedBy  string          `json:"created_by"`
	CreatedAt  time.Time       `json:"created_at"`
	StartedAt  *time.Time      `json:"started_at,omitempty"`
	FinishedAt *time.Time      `json:"finished_at,omitempty"`
}

// Done reports whether the operation finished, with a result or an error.
func (o Operation) Done() bool { return o.State == OpDone || o.State == OpFailed }

const opCols = `id, kind, policy_id, version, state, error, result, created_by, created_at, started_at, finished_at`

func scanOp(r pgx.Row) (Operation, error) {
	var o Operation
	var result []byte
	err := r.Scan(&o.ID, &o.Kind, &o.PolicyID, &o.Version, &o.State, &o.Error, &result, &o.CreatedBy,
		&o.CreatedAt, &o.StartedAt, &o.FinishedAt)
	if len(result) > 0 {
		o.Result = result
	}
	return o, err
}

func newOpID() (string, error) {
	b := make([]byte, 12)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return "op-" + hex.EncodeToString(b), nil
}

// CreateReplayOperation queues the replay of a policy version; ErrNotFound
// when the version does not exist.
func (s *Store) CreateReplayOperation(ctx context.Context, policyID string, version int, a Audit) (Operation, error) {
	var o Operation
	err := s.inTx(ctx, func(tx pgx.Tx) error {
		var err error
		o, err = createReplayOperationTx(ctx, tx, policyID, version, a)
		return err
	})
	return o, err
}

func createReplayOperationTx(ctx context.Context, tx pgx.Tx, policyID string, version int, a Audit) (Operation, error) {
	id, err := newOpID()
	if err != nil {
		return Operation{}, err
	}
	// Serialize new replays with decisions on this version. A replay queued
	// after approval cannot replace the proof saved by that approval.
	var lockedVersion int
	if err := tx.QueryRow(ctx, `SELECT version FROM policy_versions WHERE policy_id=$1 AND version=$2 FOR UPDATE`, policyID, version).Scan(&lockedVersion); errors.Is(err, pgx.ErrNoRows) {
		return Operation{}, ErrNotFound
	} else if err != nil {
		return Operation{}, fmt.Errorf("store: replay operation lock: %w", err)
	}
	o, err := scanOp(tx.QueryRow(ctx, `INSERT INTO operations (id,kind,policy_id,version,created_by,created_at)
 VALUES ($1,$2,$3,$4,$5,clock_timestamp()) RETURNING `+opCols, id, OpReplay, policyID, version, a.Actor))
	if err != nil {
		return Operation{}, fmt.Errorf("store: replay operation: %w", err)
	}
	a.After = o
	if err := writeAudit(ctx, tx, a); err != nil {
		return Operation{}, err
	}
	return o, nil
}

// GetOperation returns one operation.
func (s *Store) GetOperation(ctx context.Context, id string) (Operation, error) {
	o, err := scanOp(s.pool.QueryRow(ctx, `SELECT `+opCols+` FROM operations WHERE id = $1`, id))
	if errors.Is(err, pgx.ErrNoRows) {
		return Operation{}, ErrNotFound
	}
	if err != nil {
		return Operation{}, fmt.Errorf("store: get operation: %w", err)
	}
	return o, nil
}

// LatestReplay returns the newest replay operation of a policy version,
// finished or not; ErrNotFound when there is none.
func (s *Store) LatestReplay(ctx context.Context, policyID string, version int) (Operation, error) {
	o, err := scanOp(s.pool.QueryRow(ctx, `SELECT `+opCols+` FROM operations
		WHERE kind = $1 AND policy_id = $2 AND version = $3 ORDER BY created_at DESC, id LIMIT 1`, OpReplay, policyID, version))
	if errors.Is(err, pgx.ErrNoRows) {
		return Operation{}, ErrNotFound
	}
	if err != nil {
		return Operation{}, fmt.Errorf("store: latest replay: %w", err)
	}
	return o, nil
}

// ClaimOperation fails the RUNNING operations started before staleBefore
// (their control plane stopped, or they ran past the timeout), then takes
// the oldest PENDING one and marks it RUNNING. ok is false when none is
// pending. Several control planes may claim at once: each gets another one.
func (s *Store) ClaimOperation(ctx context.Context, staleBefore time.Time) (o Operation, ok bool, err error) {
	err = s.inTx(ctx, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `UPDATE operations SET state = $1, finished_at = now(),
			error = 'the control plane running it stopped, or it ran past the timeout'
			WHERE state = $2 AND started_at < $3`, OpFailed, OpRunning, staleBefore); err != nil {
			return fmt.Errorf("store: stale operations: %w", err)
		}
		o, err = scanOp(tx.QueryRow(ctx, `UPDATE operations SET state = $1, started_at = now()
			WHERE id = (SELECT id FROM operations WHERE state = $2 ORDER BY created_at, id LIMIT 1 FOR UPDATE SKIP LOCKED)
			RETURNING `+opCols, OpRunning, OpPending))
		if errors.Is(err, pgx.ErrNoRows) {
			return nil
		}
		if err != nil {
			return fmt.Errorf("store: claim operation: %w", err)
		}
		ok = true
		return nil
	})
	return o, ok, err
}

// FinishOperation records the result of a RUNNING operation, or its error
// when errMsg is not empty. An operation no longer RUNNING (failed as
// stale meanwhile) is left as it is.
func (s *Store) FinishOperation(ctx context.Context, id string, result json.RawMessage, errMsg string) error {
	state, res := OpDone, []byte(result)
	if errMsg != "" {
		state, res = OpFailed, nil
	}
	if _, err := s.pool.Exec(ctx, `UPDATE operations SET state = $2, result = $3, error = $4, finished_at = now()
		WHERE id = $1 AND state = $5`, id, state, res, errMsg, OpRunning); err != nil {
		return fmt.Errorf("store: finish operation: %w", err)
	}
	return nil
}
