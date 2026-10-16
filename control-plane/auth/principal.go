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

// Can reports whether any of the caller's roles or explicit scopes grants p.
func (p *Principal) Can(perm Permission) bool {
	if p == nil {
		return false
	}
	for _, s := range p.Scopes {
		if s == perm || s == "*" {
			return true
		}
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
