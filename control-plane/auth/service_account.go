package auth

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"sync"
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

// ServiceAccountStore persists service accounts and tokens.
type ServiceAccountStore interface {
	CreateServiceAccount(ctx context.Context, sa ServiceAccount) error
	GetServiceAccount(ctx context.Context, id string) (*ServiceAccount, error)
	ListServiceAccounts(ctx context.Context) ([]ServiceAccount, error)
	DeleteServiceAccount(ctx context.Context, id string) error
	CreateToken(ctx context.Context, tok ServiceAccountToken) error
	FindTokenByHash(ctx context.Context, hash string) (*ServiceAccountToken, *ServiceAccount, error)
	ListTokens(ctx context.Context, saID string) ([]ServiceAccountToken, error)
	RevokeToken(ctx context.Context, tokenID string) error
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

	if tok.Revoked || time.Now().After(tok.ExpiresAt) {
		return nil, ErrUnauthenticated
	}

	// Update last used time asynchronously if not touched recently (throttle to once per 5m)
	if tok.LastUsedAt == nil || time.Since(*tok.LastUsedAt) > 5*time.Minute {
		go func() {
			_ = a.store.TouchTokenUsage(context.Background(), tok.ID, time.Now())
		}()
	}

	return &Principal{
		Subject: "sa:" + sa.ID,
		Name:    sa.Name,
		Roles:   sa.Roles,
		Scopes:  tok.Scopes,
	}, nil
}

// HashToken calculates the SHA-256 hash of raw token string.
func HashToken(raw string) string {
	sum := sha256.Sum256([]byte(raw))
	return hex.EncodeToString(sum[:])
}

// GenerateToken creates a cryptographically secure token for saID with scopes and TTL.
func GenerateToken(saID string, scopes []Permission, ttl time.Duration) (raw string, tok ServiceAccountToken, err error) {
	if ttl <= 0 {
		return "", tok, errors.New("service account token requires a positive TTL")
	}
	if len(scopes) == 0 {
		return "", tok, errors.New("service account token requires at least one scope")
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
		Scopes:           scopes,
		ExpiresAt:        now.Add(ttl),
		CreatedAt:        now,
	}

	return raw, tok, nil
}

// MemoryServiceAccountStore provides an in-memory implementation for testing and lightweight setups.
type MemoryServiceAccountStore struct {
	mu       sync.RWMutex
	accounts map[string]ServiceAccount
	tokens   map[string]ServiceAccountToken // tokenID -> token
	byHash   map[string]string              // hash -> tokenID
}

// NewMemoryServiceAccountStore creates a new in-memory store.
func NewMemoryServiceAccountStore() *MemoryServiceAccountStore {
	return &MemoryServiceAccountStore{
		accounts: make(map[string]ServiceAccount),
		tokens:   make(map[string]ServiceAccountToken),
		byHash:   make(map[string]string),
	}
}

func (m *MemoryServiceAccountStore) CreateServiceAccount(_ context.Context, sa ServiceAccount) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, exists := m.accounts[sa.ID]; exists {
		return errors.New("service account already exists")
	}
	m.accounts[sa.ID] = sa
	return nil
}

func (m *MemoryServiceAccountStore) GetServiceAccount(_ context.Context, id string) (*ServiceAccount, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	sa, ok := m.accounts[id]
	if !ok {
		return nil, ErrServiceAccountNotFound
	}
	now := time.Now()
	count := 0
	for _, tok := range m.tokens {
		if tok.ServiceAccountID == id && !tok.Revoked && now.Before(tok.ExpiresAt) {
			count++
		}
	}
	sa.TokenCount = count
	return &sa, nil
}

func (m *MemoryServiceAccountStore) ListServiceAccounts(_ context.Context) ([]ServiceAccount, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	counts := make(map[string]int)
	now := time.Now()
	for _, tok := range m.tokens {
		if !tok.Revoked && now.Before(tok.ExpiresAt) {
			counts[tok.ServiceAccountID]++
		}
	}
	res := make([]ServiceAccount, 0, len(m.accounts))
	for _, sa := range m.accounts {
		sa.TokenCount = counts[sa.ID]
		res = append(res, sa)
	}
	return res, nil
}

func (m *MemoryServiceAccountStore) DeleteServiceAccount(_ context.Context, id string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.accounts, id)
	for tid, tok := range m.tokens {
		if tok.ServiceAccountID == id {
			delete(m.byHash, tok.TokenHash)
			delete(m.tokens, tid)
		}
	}
	return nil
}

func (m *MemoryServiceAccountStore) CreateToken(_ context.Context, tok ServiceAccountToken) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, exists := m.accounts[tok.ServiceAccountID]; !exists {
		return ErrServiceAccountNotFound
	}
	m.tokens[tok.ID] = tok
	m.byHash[tok.TokenHash] = tok.ID
	return nil
}

func (m *MemoryServiceAccountStore) FindTokenByHash(_ context.Context, hash string) (*ServiceAccountToken, *ServiceAccount, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	tid, ok := m.byHash[hash]
	if !ok {
		return nil, nil, ErrServiceAccountNotFound
	}
	tok := m.tokens[tid]
	if tok.Revoked {
		return nil, nil, ErrServiceAccountNotFound
	}
	sa, ok := m.accounts[tok.ServiceAccountID]
	if !ok {
		return nil, nil, ErrServiceAccountNotFound
	}
	return &tok, &sa, nil
}

func (m *MemoryServiceAccountStore) ListTokens(_ context.Context, saID string) ([]ServiceAccountToken, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	var res []ServiceAccountToken
	for _, tok := range m.tokens {
		if tok.ServiceAccountID == saID {
			res = append(res, tok)
		}
	}
	return res, nil
}

func (m *MemoryServiceAccountStore) RevokeToken(_ context.Context, tokenID string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	tok, ok := m.tokens[tokenID]
	if !ok {
		return errors.New("token not found")
	}
	delete(m.byHash, tok.TokenHash)
	tok.Revoked = true
	now := time.Now().UTC()
	tok.RevokedAt = &now
	m.tokens[tokenID] = tok
	return nil
}

func (m *MemoryServiceAccountStore) TouchTokenUsage(_ context.Context, tokenID string, t time.Time) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if tok, ok := m.tokens[tokenID]; ok {
		tok.LastUsedAt = &t
		m.tokens[tokenID] = tok
	}
	return nil
}
