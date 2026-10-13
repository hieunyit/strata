package localauth

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"log"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/strata/strata/control-plane/auth"
)

// TokenPrefix marks a local session token, so the API knows which
// authenticator checks a bearer token without trying both.
const TokenPrefix = "stl_"

// Login throttling: an account is locked for LockFor after MaxFailures
// wrong passwords in a row, and one client IP may try IPAttempts times per
// IPWindow whatever the accounts.
const (
	MaxFailures = 5
	LockFor     = 15 * time.Minute
	IPAttempts  = 20
	IPWindow    = 5 * time.Minute
)

var (
	// ErrBadCredentials covers an unknown user, a wrong password, a
	// disabled or a locked account alike: the answer tells nothing about
	// which accounts exist.
	ErrBadCredentials = errors.New("invalid username or password, or the account is locked")
	ErrThrottled      = errors.New("too many sign-in attempts from this address; try again in a few minutes")
	ErrBadUsername    = errors.New("a username is 2 to 63 characters: lowercase letters, digits, dot, dash or underscore, starting with a letter or digit")
	ErrBadRoles       = errors.New("roles must be among viewer, operator, approver, admin")
)

var usernameRE = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{1,62}$`)

// NormalizeUsername lowercases and checks a username.
func NormalizeUsername(u string) (string, error) {
	u = strings.ToLower(strings.TrimSpace(u))
	if !usernameRE.MatchString(u) {
		return "", ErrBadUsername
	}
	return u, nil
}

// CheckRoles keeps known role names, refusing unknown ones.
func CheckRoles(names []string) ([]string, error) {
	roles := auth.ParseRoles(names)
	if len(roles) != len(dedupe(names)) {
		return nil, ErrBadRoles
	}
	out := make([]string, len(roles))
	for i, r := range roles {
		out[i] = string(r)
	}
	return out, nil
}

func dedupe(list []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, v := range list {
		if !seen[v] {
			seen[v] = true
			out = append(out, v)
		}
	}
	return out
}

// Session is what a login returns.
type Session struct {
	Token     string    `json:"token"`
	ExpiresAt time.Time `json:"expires_at"`
	Username  string    `json:"username"`
	Roles     []string  `json:"roles"`
}

// Service signs local users in and authenticates their session tokens.
type Service struct {
	store *Store
	ttl   time.Duration
	ip    *ipLimiter
	// dummy is verified when the user does not exist, so a login takes as
	// long for an unknown user as for a wrong password.
	dummy string
}

// NewService: sessions last ttl (no sliding renewal: signing in again is
// cheap, and a stolen token stays useful for at most ttl).
func NewService(store *Store, ttl time.Duration) (*Service, error) {
	if ttl <= 0 {
		ttl = 8 * time.Hour
	}
	dummy, err := HashPassword("not a password of any account")
	if err != nil {
		return nil, err
	}
	return &Service{store: store, ttl: ttl, ip: newIPLimiter(IPAttempts, IPWindow), dummy: dummy}, nil
}

func hashToken(t string) []byte {
	h := sha256.Sum256([]byte(t))
	return h[:]
}

// Login checks the password and opens a session.
func (s *Service) Login(ctx context.Context, username, password, clientIP, userAgent string) (*Session, error) {
	if !s.ip.allow(clientIP, time.Now()) {
		return nil, ErrThrottled
	}
	name, err := NormalizeUsername(username)
	if err != nil || len(password) > MaxPasswordLen {
		_, _ = VerifyPassword(s.dummy, password[:min(len(password), MaxPasswordLen)])
		return nil, ErrBadCredentials
	}
	c, err := s.store.credentials(ctx, name)
	if errors.Is(err, ErrNotFound) {
		_, _ = VerifyPassword(s.dummy, password)
		return nil, ErrBadCredentials
	}
	if err != nil {
		return nil, err
	}
	ok, err := VerifyPassword(c.hash, password)
	if err != nil {
		return nil, err
	}
	locked := c.lockedUntil != nil && c.lockedUntil.After(time.Now())
	if !ok {
		if !locked {
			if err := s.store.recordFailure(ctx, name, MaxFailures, LockFor); err != nil {
				return nil, err
			}
		}
		return nil, ErrBadCredentials
	}
	if c.disabled || locked {
		return nil, ErrBadCredentials
	}
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return nil, err
	}
	token := TokenPrefix + base64.RawURLEncoding.EncodeToString(raw)
	expires := time.Now().Add(s.ttl).UTC().Truncate(time.Second)
	if err := s.store.startSession(ctx, name, hashToken(token), expires, clientIP, userAgent); err != nil {
		return nil, err
	}
	roles := c.roles
	if roles == nil {
		roles = []string{}
	}
	return &Session{Token: token, ExpiresAt: expires, Username: name, Roles: roles}, nil
}

// Logout ends the session of token.
func (s *Service) Logout(ctx context.Context, token string) error {
	return s.store.endSession(ctx, hashToken(token))
}

// Authenticate implements auth.Authenticator for local session tokens.
func (s *Service) Authenticate(ctx context.Context, raw string) (*auth.Principal, error) {
	if !strings.HasPrefix(raw, TokenPrefix) || len(raw) > 128 {
		return nil, auth.ErrUnauthenticated
	}
	name, roles, err := s.store.sessionUser(ctx, hashToken(raw))
	if errors.Is(err, ErrNotFound) {
		return nil, auth.ErrUnauthenticated
	}
	if err != nil {
		return nil, fmt.Errorf("local session: %w", err)
	}
	return &auth.Principal{Subject: SubjectPrefix + name, Name: name, Roles: auth.ParseRoles(roles)}, nil
}

// SubjectPrefix marks the principals of local accounts.
const SubjectPrefix = "local:"

// LocalUsername returns the account of a local principal, "" for others.
func LocalUsername(p *auth.Principal) string {
	if p == nil {
		return ""
	}
	if name, ok := strings.CutPrefix(p.Subject, SubjectPrefix); ok {
		return name
	}
	return ""
}

// ChangeOwnPassword checks the current password, sets the new one and
// ends the user's other sessions (keep is the session making the change).
func (s *Service) ChangeOwnPassword(ctx context.Context, username, current, next, keepToken string) error {
	if err := CheckPassword(next); err != nil {
		return err
	}
	c, err := s.store.credentials(ctx, username)
	if err != nil {
		return err
	}
	ok, err := VerifyPassword(c.hash, current)
	if err != nil {
		return err
	}
	if !ok {
		return ErrBadCredentials
	}
	h, err := HashPassword(next)
	if err != nil {
		return err
	}
	return s.store.inTxSetPasswordKeeping(ctx, username, h, hashToken(keepToken))
}

// Bootstrap creates the first admin when there is no account at all, so a
// fresh installation can be signed into. It does nothing once any account
// exists: the password in the environment is only ever used once.
func (s *Service) Bootstrap(ctx context.Context, username, password string) (bool, error) {
	n, err := s.store.CountUsers(ctx)
	if err != nil || n > 0 {
		return false, err
	}
	name, err := NormalizeUsername(username)
	if err != nil {
		return false, err
	}
	if err := CheckPassword(password); err != nil {
		return false, fmt.Errorf("bootstrap admin: %w", err)
	}
	h, err := HashPassword(password)
	if err != nil {
		return false, err
	}
	if _, err := s.store.CreateUser(ctx, name, h, []string{"admin"}, "system:bootstrap"); err != nil {
		if errors.Is(err, ErrExists) {
			return false, nil // another control plane did it first
		}
		return false, err
	}
	return true, nil
}

// CleanExpired removes expired sessions every interval until ctx ends.
func (s *Service) CleanExpired(ctx context.Context, every time.Duration) {
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			if n, err := s.store.DeleteExpired(ctx); err != nil {
				log.Printf("[WARN] local sessions cleanup: %v", err)
			} else if n > 0 {
				log.Printf("[INFO] local sessions: %d expired removed", n)
			}
		}
	}
}

// ipLimiter allows n attempts per window per client IP (fixed windows,
// in memory: a control plane restart forgets them, the account lock does
// not).
type ipLimiter struct {
	mu     sync.Mutex
	n      int
	window time.Duration
	seen   map[string]*ipWindow
}

type ipWindow struct {
	start time.Time
	count int
}

func newIPLimiter(n int, window time.Duration) *ipLimiter {
	return &ipLimiter{n: n, window: window, seen: map[string]*ipWindow{}}
}

func (l *ipLimiter) allow(ip string, now time.Time) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	if len(l.seen) > 10000 { // forget old windows rather than grow without bound
		for k, w := range l.seen {
			if now.Sub(w.start) >= l.window {
				delete(l.seen, k)
			}
		}
	}
	w := l.seen[ip]
	if w == nil || now.Sub(w.start) >= l.window {
		l.seen[ip] = &ipWindow{start: now, count: 1}
		return true
	}
	w.count++
	return w.count <= l.n
}
