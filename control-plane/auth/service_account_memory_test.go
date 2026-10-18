package auth

import (
	"context"
	"slices"
	"time"
)

// One credential pair per test; production has no memory credential store.
type testCredentialStore struct {
	account ServiceAccount
	token   ServiceAccountToken
}

func newTestCredentialStore() *testCredentialStore { return &testCredentialStore{} }
func (s *testCredentialStore) CreateServiceAccount(_ context.Context, sa ServiceAccount) error {
	sa.Roles = slices.Clone(sa.Roles)
	s.account = sa
	return nil
}
func (s *testCredentialStore) CreateToken(_ context.Context, tok ServiceAccountToken) error {
	tok.Scopes = slices.Clone(tok.Scopes)
	s.token = tok
	return nil
}
func (s *testCredentialStore) GetServiceAccount(_ context.Context, id string) (*ServiceAccount, error) {
	if id != s.account.ID {
		return nil, ErrServiceAccountNotFound
	}
	sa := s.account
	sa.Roles = slices.Clone(sa.Roles)
	return &sa, nil
}
func (s *testCredentialStore) ListServiceAccounts(ctx context.Context) ([]ServiceAccount, error) {
	sa, err := s.GetServiceAccount(ctx, s.account.ID)
	if err != nil {
		return nil, err
	}
	return []ServiceAccount{*sa}, nil
}
func (s *testCredentialStore) FindTokenByHash(ctx context.Context, hash string) (*ServiceAccountToken, *ServiceAccount, error) {
	if hash != s.token.TokenHash {
		return nil, nil, ErrServiceAccountNotFound
	}
	sa, err := s.GetServiceAccount(ctx, s.token.ServiceAccountID)
	if err != nil {
		return nil, nil, err
	}
	tok := s.token
	tok.Scopes = slices.Clone(tok.Scopes)
	return &tok, sa, nil
}
func (s *testCredentialStore) ListTokens(_ context.Context, id string) ([]ServiceAccountToken, error) {
	if id != s.token.ServiceAccountID {
		return []ServiceAccountToken{}, nil
	}
	tok := s.token
	tok.Scopes = slices.Clone(tok.Scopes)
	return []ServiceAccountToken{tok}, nil
}
func (s *testCredentialStore) TouchTokenUsage(_ context.Context, id string, at time.Time) error {
	if id != s.token.ID {
		return ErrServiceAccountNotFound
	}
	s.token.LastUsedAt = &at
	return nil
}
