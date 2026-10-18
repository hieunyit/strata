// Package auth authenticates admin API callers with OIDC access tokens and
// authorizes them by role. Agents never use this API: they call
// FleetService with their node certificate.
package auth

import "context"

// Principal is an authenticated caller.
type Principal struct {
	Subject string // the token's sub
	Name    string // preferred_username, for audit
	Roles   []Role
	Scopes  []Permission // explicit scopes (e.g. service account token scopes)
}

// Can intersects an explicit scope ceiling with the caller's role privileges.
// Nil scopes retain ordinary session RBAC; a nonnil empty ceiling grants none.
func (p *Principal) Can(perm Permission) bool {
	if p == nil {
		return false
	}
	if p.Scopes != nil {
		permitted := false
		for _, scope := range p.Scopes {
			if scope == perm {
				permitted = true
				break
			}
		}
		if !permitted {
			return false
		}
	}
	for _, role := range p.Roles {
		if role.Allows(perm) {
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
