package auth

import (
	"context"
	"errors"
)

var ErrScopeDenied = errors.New("resource outside assigned scope")

// Access is a server-resolved authorization snapshot, never accepted from JSON.
// nil retains global session RBAC for installations without scoped bindings.
type Access struct {
	Lookup       func(string, Permission) bool
	Applications map[string]bool
	Environments map[string]bool
	Resources    map[string]map[Permission]bool
	Events       []EventScope
}

type EventScope struct {
	Policy    string
	Host      string
	Prefix    string
	Sensitive bool
	Nodes     []string
}

func (p *Principal) CanResource(resource string, permission Permission) bool {
	if !p.Can(permission) {
		return false
	}
	if p.Access == nil {
		return true
	}
	if p.Access.Resources[resource][permission] {
		return true
	}
	return p.Access.Lookup != nil && p.Access.Lookup(resource, permission)
}

// ResolveAccess refreshes bindings on every authentication, including gRPC calls.
type ResolveAccess struct {
	Authenticator
	Resolve func(context.Context, *Principal) (*Principal, error)
}

func (r ResolveAccess) Authenticate(ctx context.Context, raw string) (*Principal, error) {
	p, err := r.Authenticator.Authenticate(ctx, raw)
	if err != nil || p == nil {
		return p, err
	}
	clone := *p
	return r.Resolve(ctx, &clone)
}
