package localauth

import (
	"context"

	"github.com/jackc/pgx/v5"
)

// ResetMFA is reserved for the host recovery command, never registered as an
// HTTP endpoint. Host access to the database credential is the recovery authority.
func (s *Store) ResetMFA(ctx context.Context, name, actor string) error {
	return s.inTx(ctx, func(tx pgx.Tx) error {
		var found string
		if err := tx.QueryRow(ctx, `SELECT username FROM local_users WHERE username=$1 FOR UPDATE`, name).Scan(&found); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `DELETE FROM local_mfa WHERE username=$1`, name); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `DELETE FROM local_sessions WHERE username=$1`, name); err != nil {
			return err
		}
		return audit(ctx, tx, actor, "local_users.mfa_host_reset", name, nil, map[string]any{"enabled": false})
	})
}
