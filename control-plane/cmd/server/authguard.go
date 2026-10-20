package main

import (
	"context"
	"errors"
)

// errLocalOffUnsafe: local accounts would be turned off before any admin
// proved they can sign in through the IdP.
var errLocalOffUnsafe = errors.New("refusing to turn local accounts off: no OIDC account with the admin role has signed in yet. " +
	"With local accounts on, sign in once through SSO as an admin (this is recorded), then turn them off")

// checkLocalOff (CP-A06): turning local accounts off (with OIDC on) is
// allowed when no local account exists (nothing to lose) or an OIDC admin
// has signed in at least once; otherwise a wrong role mapping at the IdP
// would lock every admin out.
func checkLocalOff(ctx context.Context, localUsers func(context.Context) (int, error), oidcAdminSeen func(context.Context) (bool, error)) error {
	n, err := localUsers(ctx)
	if err != nil {
		return err
	}
	if n == 0 {
		return nil
	}
	seen, err := oidcAdminSeen(ctx)
	if err != nil {
		return err
	}
	if !seen {
		return errLocalOffUnsafe
	}
	return nil
}
