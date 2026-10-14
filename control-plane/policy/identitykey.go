package policy

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"

	"github.com/jackc/pgx/v5/pgxpool"
)

// IdentityKeyLen is the length of the identity key (libstrata privacy.rs).
const IdentityKeyLen = 32

// IdentityKeys gives the installation's identity key, for policies with
// `privacy: { identity: hmac }` (P-01 §1). Env (64 hex digits, from
// STRATA_IDENTITY_HMAC_KEY: a secret manager) wins; otherwise the key kept
// in PostgreSQL, generated the first time a bundle needs it. The same key
// in every bundle keeps pseudonymized identities comparable across
// deploys; replacing it changes every value.
type IdentityKeys struct {
	Env  string
	Pool *pgxpool.Pool
}

// ParseIdentityKey reads 64 hex digits.
func ParseIdentityKey(s string) ([]byte, error) {
	k, err := hex.DecodeString(strings.TrimSpace(s))
	if err != nil || len(k) != IdentityKeyLen {
		return nil, errors.New("identity key: 64 hex digits")
	}
	zero := true
	for _, b := range k {
		zero = zero && b == 0
	}
	if zero {
		return nil, errors.New("identity key: all zeros")
	}
	return k, nil
}

// Key returns the key.
func (k IdentityKeys) Key(ctx context.Context) ([]byte, error) {
	if k.Env != "" {
		return ParseIdentityKey(k.Env)
	}
	if k.Pool == nil {
		return nil, errors.New("identity: hmac needs STRATA_IDENTITY_HMAC_KEY or PostgreSQL to keep the key")
	}
	fresh := make([]byte, IdentityKeyLen)
	if _, err := rand.Read(fresh); err != nil {
		return nil, err
	}
	// two control planes racing keep the first key
	if _, err := k.Pool.Exec(ctx, `INSERT INTO secrets (name, value) VALUES ('identity_hmac_key', $1) ON CONFLICT (name) DO NOTHING`, fresh); err != nil {
		return nil, fmt.Errorf("identity key: %w", err)
	}
	var key []byte
	if err := k.Pool.QueryRow(ctx, `SELECT value FROM secrets WHERE name = 'identity_hmac_key'`).Scan(&key); err != nil {
		return nil, fmt.Errorf("identity key: %w", err)
	}
	if len(key) != IdentityKeyLen {
		return nil, errors.New("identity key: stored key is not 32 bytes")
	}
	return key, nil
}
