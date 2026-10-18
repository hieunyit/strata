package auth

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"
)

// ServiceAccountTokenPrefix distinguishes service account tokens from OIDC and local sessions.
const ServiceAccountTokenPrefix = "stsa_"

var (
	ErrServiceAccountNotFound = errors.New("service account not found")
	ErrTokenExpired           = errors.New("service account token expired")
	ErrInvalidToken           = errors.New("invalid service account token")
)

// ServiceAccount represents a machine identity for automation, CI/CD, or GitOps.
type ServiceAccount struct {
	ID          string    `json:"id"`
	Etag        string    `json:"etag"`
	Name        string    `json:"name"`
	Description string    `json:"description,omitempty"`
	Roles       []Role    `json:"roles"`
	CreatedAt   time.Time `json:"created_at"`
	CreatedBy   string    `json:"created_by"`
	TokenCount  int       `json:"token_count,omitempty"`
}

// ServiceAccountToken is a scoped, bounded-lifetime credential issued to a ServiceAccount.
type ServiceAccountToken struct {
	ID               string       `json:"id"`
	Etag             string       `json:"etag"`
	ServiceAccountID string       `json:"service_account_id"`
	TokenPrefix      string       `json:"token_prefix"` // e.g. "stsa_a1b2c3d4"
	TokenHash        string       `json:"-"`            // SHA-256 hash of secret
	Scopes           []Permission `json:"scopes"`       // explicit permissions allowed
	ExpiresAt        time.Time    `json:"expires_at"`
	CreatedAt        time.Time    `json:"created_at"`
	LastUsedAt       *time.Time   `json:"last_used_at,omitempty"`
	Revoked          bool         `json:"revoked"`
	RevokedAt        *time.Time   `json:"revoked_at,omitempty"`
}

// ServiceAccountStore reads credential metadata and records bounded usage.
// Management writes use the API/store atomic mutation interface.
type ServiceAccountStore interface {
	GetServiceAccount(ctx context.Context, id string) (*ServiceAccount, error)
	ListServiceAccounts(ctx context.Context) ([]ServiceAccount, error)
	FindTokenByHash(ctx context.Context, hash string) (*ServiceAccountToken, *ServiceAccount, error)
	ListTokens(ctx context.Context, saID string) ([]ServiceAccountToken, error)
	TouchTokenUsage(ctx context.Context, tokenID string, t time.Time) error
}

// ServiceAccountAuthenticator verifies incoming bearer tokens starting with "stsa_".
type ServiceAccountAuthenticator struct {
	store ServiceAccountStore
}

// NewServiceAccountAuthenticator returns an authenticator backed by store.
func NewServiceAccountAuthenticator(store ServiceAccountStore) *ServiceAccountAuthenticator {
	return &ServiceAccountAuthenticator{store: store}
}

// Authenticate verifies the raw token string and resolves the caller Principal.
func (a *ServiceAccountAuthenticator) Authenticate(ctx context.Context, raw string) (*Principal, error) {
	ctx, cancelLookup := context.WithTimeout(ctx, 2*time.Second)
	defer cancelLookup()
	if !strings.HasPrefix(raw, ServiceAccountTokenPrefix) {
		return nil, ErrUnauthenticated
	}

	h := HashToken(raw)
	tok, sa, err := a.store.FindTokenByHash(ctx, h)
	if err != nil {
		if errors.Is(err, ErrServiceAccountNotFound) {
			return nil, ErrUnauthenticated
		}
		return nil, err
	}

	if tok == nil || sa == nil || tok.Revoked || !time.Now().Before(tok.ExpiresAt) ||
		len(sa.Roles) == 0 || !validTokenScopes(tok.Scopes) {
		return nil, ErrUnauthenticated
	}

	// Keep I/O in the request context. A detached goroutine can outlive the
	// request and race store shutdown; a failed usage update must be visible.
	if tok.LastUsedAt == nil || time.Since(*tok.LastUsedAt) > 5*time.Minute {
		touchCtx, cancel := context.WithTimeout(ctx, time.Second)
		defer cancel()
		if err := a.store.TouchTokenUsage(touchCtx, tok.ID, time.Now().UTC()); err != nil {
			return nil, fmt.Errorf("record service account token usage: %w", err)
		}
	}

	return &Principal{
		Subject: "sa:" + sa.ID,
		Name:    sa.Name,
		Roles:   slices.Clone(sa.Roles),
		Scopes:  slices.Clone(tok.Scopes),
	}, nil
}

// HashToken calculates the SHA-256 hash of raw token string.
func HashToken(raw string) string {
	sum := sha256.Sum256([]byte(raw))
	return hex.EncodeToString(sum[:])
}

// GenerateToken creates a cryptographically secure token for saID with scopes and TTL.
func GenerateToken(saID string, scopes []Permission, ttl time.Duration) (raw string, tok ServiceAccountToken, err error) {
	if ttl <= 0 || ttl > 365*24*time.Hour {
		return "", tok, errors.New("service account token TTL must be positive and at most 365 days")
	}
	if !validTokenScopes(scopes) {
		return "", tok, errors.New("service account token requires explicit known scopes")
	}

	rawBytes := make([]byte, 24)
	if _, err := rand.Read(rawBytes); err != nil {
		return "", tok, fmt.Errorf("reading random bytes: %w", err)
	}

	tokenIDBytes := make([]byte, 12)
	if _, err := rand.Read(tokenIDBytes); err != nil {
		return "", tok, fmt.Errorf("reading random bytes for token ID: %w", err)
	}

	tokenID := "tok_" + hex.EncodeToString(tokenIDBytes)
	secret := hex.EncodeToString(rawBytes)
	raw = ServiceAccountTokenPrefix + secret
	prefix := raw
	if len(prefix) > 12 {
		prefix = prefix[:12] + "..."
	}

	now := time.Now()
	tok = ServiceAccountToken{
		ID:               tokenID,
		ServiceAccountID: saID,
		TokenPrefix:      prefix,
		TokenHash:        HashToken(raw),
		Scopes:           slices.Clone(scopes),
		ExpiresAt:        now.Add(ttl),
		CreatedAt:        now,
	}

	return raw, tok, nil
}

// Neither an empty scope list nor a wildcard is a machine credential ceiling.
func validTokenScopes(scopes []Permission) bool {
	if len(scopes) == 0 || len(scopes) > 32 {
		return false
	}
	for _, scope := range scopes {
		if !RoleAdmin.Allows(scope) {
			return false
		}
	}
	return true
}
