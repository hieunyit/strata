package store

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
)

// CommandReplaySync: send the node its group's replay sampling (W12-N-01).
// It carries nothing; the dispatcher reads the group's row when it sends.
const CommandReplaySync = "REPLAY_SYNC"

// ReplaySampling is a row of replay_sampling. Key is never written to the
// audit log or returned by the API.
type ReplaySampling struct {
	GroupID   string    `json:"group_id"`
	RateBp    int       `json:"rate_bp"`
	KeyID     string    `json:"key_id"`
	Key       []byte    `json:"-"`
	UpdatedAt time.Time `json:"updated_at"`
	UpdatedBy string    `json:"updated_by"`
}

func newReplayKey() (id string, key []byte, err error) {
	b := make([]byte, 6+32)
	if _, err := rand.Read(b); err != nil {
		return "", nil, err
	}
	return "k" + hex.EncodeToString(b[:6]), b[6:], nil
}

// SetReplaySampling sets a group's rate; a new key when the group has none
// or rotate is set. Creates cmds (REPLAY_SYNC) and an audit entry (without
// the key), in one transaction.
func (s *Store) SetReplaySampling(ctx context.Context, group string, rateBp int, rotate bool, cmds []Command, a Audit) (ReplaySampling, []Command, error) {
	var row ReplaySampling
	var out []Command
	err := s.inTx(ctx, func(tx pgx.Tx) error {
		cur, err := scanReplay(tx.QueryRow(ctx, `SELECT `+replayCols+` FROM replay_sampling WHERE group_id = $1 FOR UPDATE`, group))
		if err != nil && !errors.Is(err, pgx.ErrNoRows) {
			return fmt.Errorf("store: replay sampling: %w", err)
		}
		keyID, key := cur.KeyID, cur.Key
		if errors.Is(err, pgx.ErrNoRows) || rotate {
			if keyID, key, err = newReplayKey(); err != nil {
				return err
			}
		}
		row, err = scanReplay(tx.QueryRow(ctx, `INSERT INTO replay_sampling (group_id, rate_bp, key_id, key, updated_by)
			VALUES ($1, $2, $3, $4, $5)
			ON CONFLICT (group_id) DO UPDATE SET rate_bp = EXCLUDED.rate_bp, key_id = EXCLUDED.key_id, key = EXCLUDED.key,
				updated_by = EXCLUDED.updated_by, updated_at = now()
			RETURNING `+replayCols, group, rateBp, keyID, key, a.Actor))
		if err != nil {
			return fmt.Errorf("store: set replay sampling: %w", err)
		}
		if out, err = insertCommands(ctx, tx, cmds, a.Actor); err != nil {
			return err
		}
		a.After = map[string]any{"group_id": group, "rate_bp": rateBp, "key_id": row.KeyID, "rotated": rotate || keyID != cur.KeyID,
			"commands": len(out)}
		return writeAudit(ctx, tx, a)
	})
	return row, out, err
}

const replayCols = `group_id, rate_bp, key_id, key, updated_at, updated_by`

func scanReplay(r pgx.Row) (ReplaySampling, error) {
	var x ReplaySampling
	err := r.Scan(&x.GroupID, &x.RateBp, &x.KeyID, &x.Key, &x.UpdatedAt, &x.UpdatedBy)
	return x, err
}

// GetReplaySampling of a group; ErrNotFound when it never had one.
func (s *Store) GetReplaySampling(ctx context.Context, group string) (ReplaySampling, error) {
	x, err := scanReplay(s.pool.QueryRow(ctx, `SELECT `+replayCols+` FROM replay_sampling WHERE group_id = $1`, group))
	if errors.Is(err, pgx.ErrNoRows) {
		return ReplaySampling{}, ErrNotFound
	}
	return x, err
}

// NodeReplaySampling: the replay sampling of a node's group; a zero rate
// (off) when the group has none.
func (s *Store) NodeReplaySampling(ctx context.Context, node string) (ReplaySampling, error) {
	x, err := scanReplay(s.pool.QueryRow(ctx, `SELECT r.group_id, r.rate_bp, r.key_id, r.key, r.updated_at, r.updated_by
		FROM replay_sampling r JOIN nodes n ON n.group_id = r.group_id WHERE n.id = $1`, node))
	if errors.Is(err, pgx.ErrNoRows) {
		return ReplaySampling{}, nil
	}
	return x, err
}
