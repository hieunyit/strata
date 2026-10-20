package auth

import (
	"context"
	"log"
	"strings"
	"sync"
	"time"
)

// RecordAdmins wraps the OIDC authenticator: a token of an account with the
// admin role is noted with Record (at most once an hour per account, in
// the background), so that turning local accounts off can check that an
// admin can sign in through the IdP (CP-A06).
type RecordAdmins struct {
	Authenticator
	Record func(ctx context.Context, subject, name string) error

	mu   sync.Mutex
	seen map[string]time.Time
}

func (r *RecordAdmins) Authenticate(ctx context.Context, raw string) (*Principal, error) {
	p, err := r.Authenticator.Authenticate(ctx, raw)
	if err != nil || p == nil || !isAdmin(p) {
		return p, err
	}
	r.mu.Lock()
	if r.seen == nil {
		r.seen = map[string]time.Time{}
	}
	due := time.Since(r.seen[p.Subject]) > time.Hour
	if due {
		r.seen[p.Subject] = time.Now()
	}
	r.mu.Unlock()
	if due {
		subject, name := p.Subject, p.Name
		go func() {
			rctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			if err := r.Record(rctx, subject, name); err != nil {
				log.Printf("[WARN] auth: noting the OIDC admin sign-in of %s: %v", subject, err)
				r.mu.Lock()
				delete(r.seen, subject) // try again next time
				r.mu.Unlock()
			}
		}()
	}
	return p, nil
}

func isAdmin(p *Principal) bool {
	if p.Access != nil || !strings.HasPrefix(p.Subject, OIDCSubjectPrefix) {
		return false
	}
	for _, r := range p.Roles {
		if r == RoleAdmin {
			return true
		}
	}
	return false
}
