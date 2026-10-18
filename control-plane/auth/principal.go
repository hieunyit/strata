// Package auth authenticates admin API callers with OIDC access tokens and
// authorizes them by role. Agents never use this API: they call
// FleetService with their node certificate.
package auth

import (
	"context"
	"strings"
)

// Principal is an authenticated caller.
type Principal struct {
	Subject string // the token's sub
	Name    string // preferred_username, for audit
	Roles   []Role
	Scopes  []Permission // explicit scopes (e.g. service account token scopes)
}

// Can reports whether any of the caller's roles or explicit scopes grants p.
func (p *Principal) Can(perm Permission) bool {
	if p == nil {
		return false
	}
	// For service accounts (sa:), scopes are mandatory. If a service account principal has no scopes,
	// deny all permissions to prevent scope bypass.
	if strings.HasPrefix(p.Subject, "sa:") && len(p.Scopes) == 0 {
		return false
	}
	// If the principal has explicit scopes (e.g. a bounded service account token),
	// the scopes act as a strict boundary: the permission MUST be granted by scopes.
	if len(p.Scopes) > 0 {
		hasScope := false
		for _, s := range p.Scopes {
			if s == perm || s == "*" {
				hasScope = true
				break
			}
		}
		if !hasScope {
			return false
		}
		// If roles are also defined, the role must also permit it (least privilege).
		if len(p.Roles) > 0 {
			for _, r := range p.Roles {
				if r.Allows(perm) {
					return true
				}
			}
			return false
		}
		return true
	}

	for _, r := range p.Roles {
		if r.Allows(perm) {
			return true
		}
	}
	return false
}

type ctxKey struct{}

// WithPrincipal returns ctx carrying p.
func WithPrincipal(ctx context.Context, p *Principal) context.Context {
	return context.WithValue(ctx, ctxKey{}, p)
}

// FromContext returns the caller set by the HTTP middleware or the gRPC
// interceptors, or nil.
func FromContext(ctx context.Context) *Principal {
	p, _ := ctx.Value(ctxKey{}).(*Principal)
	return p
}
