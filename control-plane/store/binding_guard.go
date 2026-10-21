package store

import (
	"context"
	"github.com/jackc/pgx/v5"
	"github.com/strata/strata/control-plane/auth"
)

// Binding writers serialize and recheck the authenticated actor inside their
// transaction. Two requests authenticated earlier cannot demote each other.
func lockBindingChanges(ctx context.Context, tx pgx.Tx) error {
	if _, err := tx.Exec(ctx, "SELECT pg_advisory_xact_lock(6004516533000002)"); err != nil {
		return err
	}
	return bindingAuthority(ctx, tx)
}
func bindingAuthority(ctx context.Context, tx pgx.Tx) error {
	p := auth.FromContext(ctx)
	if p == nil {
		return nil
	} // trusted internal/bootstrap writer, not an HTTP request
	if p.Access != nil || !p.Can(auth.PermRoleBindingsWrite) {
		return auth.ErrScopeDenied
	}
	var marked, global bool
	err := tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM application_subjects WHERE subject=$1),EXISTS(SELECT 1 FROM application_role_bindings WHERE subject=$1 AND application_id IS NULL AND role='admin')`, p.Subject).Scan(&marked, &global)
	if err != nil {
		return err
	}
	if marked && !global {
		return auth.ErrScopeDenied
	}
	return nil
}
