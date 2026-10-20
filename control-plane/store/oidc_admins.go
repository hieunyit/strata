package store

import (
	"context"
	"fmt"
	"strings"
)

// RecordOIDCAdmin notes that an OIDC account with the admin role signed
// in (CP-A06).
func (s *Store) RecordOIDCAdmin(ctx context.Context, subject, name string) error {
	if !strings.HasPrefix(subject, "oidc:") {
		return fmt.Errorf("store: %q is not an OIDC subject", subject)
	}
	if len(name) > 256 {
		name = name[:256]
	}
	if _, err := s.pool.Exec(ctx, `INSERT INTO oidc_admin_sign_ins (subject, name) VALUES ($1, $2)
		ON CONFLICT (subject) DO UPDATE SET name = EXCLUDED.name, last_at = now()`, subject, name); err != nil {
		return fmt.Errorf("store: OIDC admin sign-in: %w", err)
	}
	return nil
}

// OIDCAdminSignedIn reports whether any OIDC account with the admin role
// ever signed in.
func (s *Store) OIDCAdminSignedIn(ctx context.Context) (bool, error) {
	var ok bool
	if err := s.pool.QueryRow(ctx, "SELECT EXISTS (SELECT 1 FROM oidc_admin_sign_ins)").Scan(&ok); err != nil {
		return false, fmt.Errorf("store: OIDC admin sign-ins: %w", err)
	}
	return ok, nil
}
