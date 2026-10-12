package store

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
)

// Command kinds and states (node_commands).
const (
	CommandForceShadow = "FORCE_SHADOW"
	CommandDiagnostics = "DIAGNOSTICS"

	CommandPending = "PENDING"
	CommandSent    = "SENT"
	CommandDone    = "DONE"
	CommandFailed  = "FAILED"
	CommandExpired = "EXPIRED"
)

// Command is a row of node_commands.
type Command struct {
	ID              string    `json:"id"`
	NodeID          string    `json:"node_id"`
	Kind            string    `json:"kind"`
	PolicyID        string    `json:"policy_id"`
	DurationSeconds int       `json:"duration_seconds"`
	State           string    `json:"state"`
	Error           string    `json:"error"`
	Output          string    `json:"-"` // not in the audit log
	CreatedBy       string    `json:"created_by"`
	CreatedAt       time.Time `json:"created_at"`
	ExpiresAt       time.Time `json:"expires_at"`
	UpdatedAt       time.Time `json:"updated_at"`
}

const commandCols = `id, node_id, kind, policy_id, duration_seconds, state, error, output, created_by, created_at, expires_at, updated_at`

func scanCommand(r pgx.Row) (Command, error) {
	var c Command
	err := r.Scan(&c.ID, &c.NodeID, &c.Kind, &c.PolicyID, &c.DurationSeconds, &c.State, &c.Error, &c.Output,
		&c.CreatedBy, &c.CreatedAt, &c.ExpiresAt, &c.UpdatedAt)
	return c, err
}

// CreateCommands adds commands (ID, NodeID, Kind, PolicyID,
// DurationSeconds, ExpiresAt set by the caller) and one audit entry for
// them, in one transaction. Nodes that do not exist or are revoked fail it
// with ErrNotFound.
func (s *Store) CreateCommands(ctx context.Context, cmds []Command, a Audit) ([]Command, error) {
	var out []Command
	err := s.inTx(ctx, func(tx pgx.Tx) error {
		for _, c := range cmds {
			row := tx.QueryRow(ctx, `INSERT INTO node_commands (id, node_id, kind, policy_id, duration_seconds, created_by, expires_at)
				SELECT $1, id, $3, $4, $5, $6, $7 FROM nodes WHERE id = $2 AND revoked_at IS NULL
				RETURNING `+commandCols, c.ID, c.NodeID, c.Kind, c.PolicyID, c.DurationSeconds, a.Actor, c.ExpiresAt)
			got, err := scanCommand(row)
			if errors.Is(err, pgx.ErrNoRows) {
				return ErrNotFound
			}
			if err != nil {
				return fmt.Errorf("store: create command: %w", err)
			}
			out = append(out, got)
		}
		a.After = out
		return writeAudit(ctx, tx, a)
	})
	return out, err
}

// GroupNodes returns the ids of the group's nodes that are not revoked.
func (s *Store) GroupNodes(ctx context.Context, group string) ([]string, error) {
	rows, err := s.pool.Query(ctx, `SELECT id FROM nodes WHERE group_id = $1 AND revoked_at IS NULL ORDER BY id`, group)
	if err != nil {
		return nil, fmt.Errorf("store: group nodes: %w", err)
	}
	return pgx.CollectRows(rows, pgx.RowTo[string])
}

// GetCommand returns one command.
func (s *Store) GetCommand(ctx context.Context, id string) (Command, error) {
	c, err := scanCommand(s.pool.QueryRow(ctx, `SELECT `+commandCols+` FROM node_commands WHERE id = $1`, id))
	if errors.Is(err, pgx.ErrNoRows) {
		return Command{}, ErrNotFound
	}
	if err != nil {
		return Command{}, fmt.Errorf("store: get command: %w", err)
	}
	return c, nil
}

// ListCommands returns the newest commands, of one node or of all.
func (s *Store) ListCommands(ctx context.Context, node string, limit int) ([]Command, error) {
	rows, err := s.pool.Query(ctx, `SELECT `+commandCols+` FROM node_commands
		WHERE $1 = '' OR node_id = $1 ORDER BY created_at DESC, id LIMIT $2`, node, limit)
	if err != nil {
		return nil, fmt.Errorf("store: list commands: %w", err)
	}
	return pgx.CollectRows(rows, func(r pgx.CollectableRow) (Command, error) { return scanCommand(r) })
}

// PendingCommands returns the unsent, unexpired commands of nodes, oldest
// first, and expires the open ones past their deadline.
func (s *Store) PendingCommands(ctx context.Context, nodes []string, now time.Time) ([]Command, error) {
	if _, err := s.pool.Exec(ctx, `UPDATE node_commands SET state = 'EXPIRED', updated_at = $1
		WHERE state IN ('PENDING', 'SENT') AND expires_at <= $1`, now); err != nil {
		return nil, fmt.Errorf("store: expire commands: %w", err)
	}
	if len(nodes) == 0 {
		return nil, nil
	}
	rows, err := s.pool.Query(ctx, `SELECT `+commandCols+` FROM node_commands
		WHERE node_id = ANY($1) AND state = 'PENDING' ORDER BY created_at, id`, nodes)
	if err != nil {
		return nil, fmt.Errorf("store: pending commands: %w", err)
	}
	return pgx.CollectRows(rows, func(r pgx.CollectableRow) (Command, error) { return scanCommand(r) })
}

// MarkCommandSent moves a PENDING command to SENT.
func (s *Store) MarkCommandSent(ctx context.Context, id string, now time.Time) error {
	_, err := s.pool.Exec(ctx, `UPDATE node_commands SET state = 'SENT', updated_at = $2 WHERE id = $1 AND state = 'PENDING'`, id, now)
	if err != nil {
		return fmt.Errorf("store: command sent: %w", err)
	}
	return nil
}

// CompleteCommand records the node's answer to one of its open commands;
// ErrNotFound when node has no such open command (another node's id, a
// command already answered or expired).
func (s *Store) CompleteCommand(ctx context.Context, node, id string, ok bool, msg, output string, now time.Time) error {
	state := CommandDone
	if !ok {
		state = CommandFailed
	}
	tag, err := s.pool.Exec(ctx, `UPDATE node_commands SET state = $3, error = $4, output = $5, updated_at = $6
		WHERE id = $1 AND node_id = $2 AND state IN ('PENDING', 'SENT')`, id, node, state, msg, output, now)
	if err != nil {
		return fmt.Errorf("store: complete command: %w", err)
	}
	if tag.RowsAffected() != 1 {
		return ErrNotFound
	}
	return nil
}
