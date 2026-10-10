package store

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
)

// ErrEtagMismatch: the policy changed since the caller read it.
var ErrEtagMismatch = errors.New("store: etag does not match")

// Policy with the spec of its current version.
type Policy struct {
	ID             string          `json:"id"`
	Name           string          `json:"name"`
	CurrentVersion int             `json:"current_version"`
	Etag           string          `json:"etag"`
	Spec           json.RawMessage `json:"spec"`
	CreatedBy      string          `json:"created_by"`
	CreatedAt      time.Time       `json:"created_at"`
	UpdatedAt      time.Time       `json:"updated_at"`
}

// PolicyVersion is one saved edit.
type PolicyVersion struct {
	PolicyID  string          `json:"policy_id"`
	Version   int             `json:"version"`
	Spec      json.RawMessage `json:"spec"`
	State     string          `json:"state"`
	CreatedBy string          `json:"created_by"`
	CreatedAt time.Time       `json:"created_at"`
}

func newEtag() (string, error) {
	b := make([]byte, 12)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

const policyCols = `p.id, p.name, p.current_version, p.etag, v.spec, p.created_by, p.created_at, p.updated_at`
const policyFrom = ` FROM policies p JOIN policy_versions v ON v.policy_id = p.id AND v.version = p.current_version`

func scanPolicy(r pgx.Row) (Policy, error) {
	var p Policy
	err := r.Scan(&p.ID, &p.Name, &p.CurrentVersion, &p.Etag, &p.Spec, &p.CreatedBy, &p.CreatedAt, &p.UpdatedAt)
	return p, err
}

// CreatePolicy stores a policy and its version 1.
func (s *Store) CreatePolicy(ctx context.Context, p Policy, a Audit) (Policy, error) {
	etag, err := newEtag()
	if err != nil {
		return Policy{}, err
	}
	err = s.inTx(ctx, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `INSERT INTO policies (id, name, current_version, etag, created_by) VALUES ($1, $2, 1, $3, $4)`,
			p.ID, p.Name, etag, a.Actor)
		if isUniqueViolation(err) {
			return ErrExists
		}
		if err != nil {
			return fmt.Errorf("store: create policy: %w", err)
		}
		if _, err := tx.Exec(ctx, `INSERT INTO policy_versions (policy_id, version, spec, created_by) VALUES ($1, 1, $2, $3)`,
			p.ID, []byte(p.Spec), a.Actor); err != nil {
			return fmt.Errorf("store: create policy version: %w", err)
		}
		if p, err = scanPolicy(tx.QueryRow(ctx, `SELECT `+policyCols+policyFrom+` WHERE p.id = $1`, p.ID)); err != nil {
			return fmt.Errorf("store: read policy: %w", err)
		}
		a.After = p
		return writeAudit(ctx, tx, a)
	})
	return p, err
}

// GetPolicy returns a policy with its current spec.
func (s *Store) GetPolicy(ctx context.Context, id string) (Policy, error) {
	p, err := scanPolicy(s.pool.QueryRow(ctx, `SELECT `+policyCols+policyFrom+` WHERE p.id = $1`, id))
	if errors.Is(err, pgx.ErrNoRows) {
		return Policy{}, ErrNotFound
	}
	if err != nil {
		return Policy{}, fmt.Errorf("store: get policy: %w", err)
	}
	return p, nil
}

// ListPolicies returns every policy by name.
func (s *Store) ListPolicies(ctx context.Context) ([]Policy, error) {
	rows, err := s.pool.Query(ctx, `SELECT `+policyCols+policyFrom+` ORDER BY p.name`)
	if err != nil {
		return nil, fmt.Errorf("store: list policies: %w", err)
	}
	return pgx.CollectRows(rows, func(r pgx.CollectableRow) (Policy, error) { return scanPolicy(r) })
}

// UpdatePolicy saves spec as a new version when etag is the current one;
// otherwise ErrEtagMismatch and nothing changes.
func (s *Store) UpdatePolicy(ctx context.Context, id, etag string, spec json.RawMessage, a Audit) (Policy, error) {
	next, err := newEtag()
	if err != nil {
		return Policy{}, err
	}
	var p Policy
	err = s.inTx(ctx, func(tx pgx.Tx) error {
		before, err := scanPolicy(tx.QueryRow(ctx, `SELECT `+policyCols+policyFrom+` WHERE p.id = $1 FOR UPDATE OF p`, id))
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrNotFound
		}
		if err != nil {
			return fmt.Errorf("store: update policy: %w", err)
		}
		if before.Etag != etag {
			return ErrEtagMismatch
		}
		v := before.CurrentVersion + 1
		if _, err := tx.Exec(ctx, `INSERT INTO policy_versions (policy_id, version, spec, created_by) VALUES ($1, $2, $3, $4)`,
			id, v, []byte(spec), a.Actor); err != nil {
			return fmt.Errorf("store: policy version: %w", err)
		}
		if _, err := tx.Exec(ctx, `UPDATE policies SET current_version = $2, etag = $3, updated_at = now() WHERE id = $1`, id, v, next); err != nil {
			return fmt.Errorf("store: update policy: %w", err)
		}
		if p, err = scanPolicy(tx.QueryRow(ctx, `SELECT `+policyCols+policyFrom+` WHERE p.id = $1`, id)); err != nil {
			return fmt.Errorf("store: read policy: %w", err)
		}
		a.Before, a.After = before, p
		return writeAudit(ctx, tx, a)
	})
	return p, err
}

// ListPolicyVersions returns a policy's versions, newest first.
func (s *Store) ListPolicyVersions(ctx context.Context, id string) ([]PolicyVersion, error) {
	rows, err := s.pool.Query(ctx, `SELECT policy_id, version, spec, state, created_by, created_at
		FROM policy_versions WHERE policy_id = $1 ORDER BY version DESC`, id)
	if err != nil {
		return nil, fmt.Errorf("store: list versions: %w", err)
	}
	vs, err := pgx.CollectRows(rows, func(r pgx.CollectableRow) (PolicyVersion, error) {
		var v PolicyVersion
		err := r.Scan(&v.PolicyID, &v.Version, &v.Spec, &v.State, &v.CreatedBy, &v.CreatedAt)
		return v, err
	})
	if err == nil && len(vs) == 0 {
		if _, err := s.GetPolicy(ctx, id); err != nil {
			return nil, err
		}
	}
	return vs, err
}

// GetPolicyVersion returns one version.
func (s *Store) GetPolicyVersion(ctx context.Context, id string, version int) (PolicyVersion, error) {
	var v PolicyVersion
	err := s.pool.QueryRow(ctx, `SELECT policy_id, version, spec, state, created_by, created_at
		FROM policy_versions WHERE policy_id = $1 AND version = $2`, id, version).
		Scan(&v.PolicyID, &v.Version, &v.Spec, &v.State, &v.CreatedBy, &v.CreatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return PolicyVersion{}, ErrNotFound
	}
	if err != nil {
		return PolicyVersion{}, fmt.Errorf("store: get version: %w", err)
	}
	return v, nil
}

// Bundle is a row of bundles.
type Bundle struct {
	Version   uint64         `json:"version"`
	SHA256    []byte         `json:"sha256"`
	ObjectKey string         `json:"object_key"`
	SizeBytes int64          `json:"size_bytes"`
	Contents  map[string]int `json:"contents"` // policy id -> version
	CreatedBy string         `json:"created_by"`
	CreatedAt time.Time      `json:"created_at"`
}

// lockBundles serializes bundle builds across control planes.
const lockBundles = 0x5354524154410002

// WithBundleLock runs build with the next bundle version while holding a
// database-wide lock, so versions increase strictly even with several
// control planes deploying at once.
func (s *Store) WithBundleLock(ctx context.Context, build func(next uint64) error) error {
	conn, err := s.pool.Acquire(ctx)
	if err != nil {
		return fmt.Errorf("store: %w", err)
	}
	defer conn.Release()
	if _, err := conn.Exec(ctx, "SELECT pg_advisory_lock($1)", int64(lockBundles)); err != nil {
		return fmt.Errorf("store: bundle lock: %w", err)
	}
	defer func() { _, _ = conn.Exec(context.Background(), "SELECT pg_advisory_unlock($1)", int64(lockBundles)) }()
	var last int64
	if err := conn.QueryRow(ctx, "SELECT coalesce(max(version), 0) FROM bundles").Scan(&last); err != nil {
		return fmt.Errorf("store: bundle version: %w", err)
	}
	return build(uint64(last) + 1)
}

// RecordBundle stores a built and uploaded bundle.
func (s *Store) RecordBundle(ctx context.Context, b Bundle, a Audit) (Bundle, error) {
	contents, err := json.Marshal(b.Contents)
	if err != nil {
		return Bundle{}, err
	}
	err = s.inTx(ctx, func(tx pgx.Tx) error {
		if err := tx.QueryRow(ctx, `INSERT INTO bundles (version, sha256, object_key, size_bytes, created_by, contents)
			VALUES ($1, $2, $3, $4, $5, $6) RETURNING created_at`,
			int64(b.Version), b.SHA256, b.ObjectKey, b.SizeBytes, a.Actor, contents).Scan(&b.CreatedAt); err != nil {
			return fmt.Errorf("store: record bundle: %w", err)
		}
		b.CreatedBy = a.Actor
		a.After = b
		return writeAudit(ctx, tx, a)
	})
	return b, err
}

// LatestBundle returns the newest bundle.
func (s *Store) LatestBundle(ctx context.Context) (Bundle, error) {
	var b Bundle
	var contents []byte
	var v int64
	err := s.pool.QueryRow(ctx, `SELECT version, sha256, object_key, size_bytes, contents, created_by, created_at
		FROM bundles ORDER BY version DESC LIMIT 1`).Scan(&v, &b.SHA256, &b.ObjectKey, &b.SizeBytes, &contents, &b.CreatedBy, &b.CreatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return Bundle{}, ErrNotFound
	}
	if err != nil {
		return Bundle{}, fmt.Errorf("store: latest bundle: %w", err)
	}
	b.Version = uint64(v)
	_ = json.Unmarshal(contents, &b.Contents)
	return b, nil
}
