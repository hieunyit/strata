package store

import (
	"context"
	"fmt"
	"math"

	"github.com/jackc/pgx/v5"
)

// WithIngestBatch holds a durable per-node lock while write persists the events.
// ClickHouse and PostgreSQL cannot commit atomically: a crash between commits
// can leave physical duplicates, which event reads collapse with FINAL.
func (s *Store) WithIngestBatch(ctx context.Context, node string, seq uint64, write func(context.Context) error) (bool, error) {
	if node == "" || seq == 0 || seq > math.MaxInt64 {
		return false, fmt.Errorf("store: invalid ingest node or sequence")
	}
	duplicate := false
	err := s.inTx(ctx, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `INSERT INTO ingest_sequences(node_id) VALUES ($1) ON CONFLICT DO NOTHING`, node); err != nil {
			return fmt.Errorf("store: initialize ingest sequence: %w", err)
		}
		var last int64
		if err := tx.QueryRow(ctx, `SELECT last_seq FROM ingest_sequences WHERE node_id=$1 FOR UPDATE`, node).Scan(&last); err != nil {
			return fmt.Errorf("store: lock ingest sequence: %w", err)
		}
		if seq <= uint64(last) {
			duplicate = true
			return nil
		}
		if err := write(ctx); err != nil {
			return fmt.Errorf("store: ingest write: %w", err)
		}
		if _, err := tx.Exec(ctx, `UPDATE ingest_sequences SET last_seq=$2 WHERE node_id=$1`, node, int64(seq)); err != nil {
			return fmt.Errorf("store: commit ingest sequence: %w", err)
		}
		return nil
	})
	return duplicate, err
}
