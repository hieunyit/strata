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

// ErrFourEyes: whoever drafted or submitted a version cannot approve it.
var ErrFourEyes = errors.New("store: whoever drafted or submitted a version cannot approve it")

// StateError: a version is not in a state the step takes.
type StateError struct{ Msg string }

func (e *StateError) Error() string { return e.Msg }

// Policy version states (four eyes, W13-G2-02).
const (
	VersionDraft     = "DRAFT"
	VersionSubmitted = "SUBMITTED"
	VersionApproved  = "APPROVED"
	VersionRejected  = "REJECTED"
	VersionDeployed  = "DEPLOYED"
)

// Policy with the spec of its current (newest) version.
type Policy struct {
	ID             string `json:"id"`
	Name           string `json:"name"`
	CurrentVersion int    `json:"current_version"`
	// newest version approved (or deployed), and newest deployed; 0: none
	ApprovedVersion int             `json:"approved_version"`
	DeployedVersion int             `json:"deployed_version"`
	Etag            string          `json:"etag"`
	Spec            json.RawMessage `json:"spec"`
	CreatedBy       string          `json:"created_by"`
	CreatedAt       time.Time       `json:"created_at"`
	UpdatedAt       time.Time       `json:"updated_at"`
}

// PolicyVersion is one saved edit.
type PolicyVersion struct {
	ApprovedReplayID string `json:"approved_replay_id,omitempty"`

	PolicyID  string          `json:"policy_id"`
	Version   int             `json:"version"`
	Spec      json.RawMessage `json:"spec"`
	State     string          `json:"state"`
	CreatedBy string          `json:"created_by"`
	CreatedAt time.Time       `json:"created_at"`
	// four eyes (W13-G2-02)
	SubmittedBy     string     `json:"submitted_by,omitempty"`
	SubmittedAt     *time.Time `json:"submitted_at,omitempty"`
	DecidedBy       string     `json:"decided_by,omitempty"` // approved or rejected by
	DecidedAt       *time.Time `json:"decided_at,omitempty"`
	DecisionComment string     `json:"decision_comment,omitempty"`
}

const versionCols = `policy_id, version, spec, state, created_by, created_at,
	coalesce(submitted_by, ''), submitted_at, coalesce(decided_by, ''), decided_at, decision_comment, coalesce(approved_replay_id, '')`

func scanVersion(r pgx.Row) (PolicyVersion, error) {
	var v PolicyVersion
	err := r.Scan(&v.PolicyID, &v.Version, &v.Spec, &v.State, &v.CreatedBy, &v.CreatedAt,
		&v.SubmittedBy, &v.SubmittedAt, &v.DecidedBy, &v.DecidedAt, &v.DecisionComment, &v.ApprovedReplayID)
	return v, err
}

func newEtag() (string, error) {
	b := make([]byte, 12)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

const policyCols = `p.id, p.name, p.current_version, p.etag, v.spec, p.created_by, p.created_at, p.updated_at,
	coalesce((SELECT max(x.version) FROM policy_versions x WHERE x.policy_id = p.id AND x.state IN ('APPROVED', 'DEPLOYED')), 0),
	coalesce((SELECT max(x.version) FROM policy_versions x WHERE x.policy_id = p.id AND x.state = 'DEPLOYED'), 0)`
const policyFrom = ` FROM policies p JOIN policy_versions v ON v.policy_id = p.id AND v.version = p.current_version`

func scanPolicy(r pgx.Row) (Policy, error) {
	var p Policy
	err := r.Scan(&p.ID, &p.Name, &p.CurrentVersion, &p.Etag, &p.Spec, &p.CreatedBy, &p.CreatedAt, &p.UpdatedAt,
		&p.ApprovedVersion, &p.DeployedVersion)
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
		if _, err := tx.Exec(ctx, `INSERT INTO policy_versions (policy_id, version, spec, created_by, created_subject) VALUES ($1, 1, $2, $3, $4)`,
			p.ID, []byte(p.Spec), a.Actor, a.Subject); err != nil {
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

// GetPolicyByName resolves the unique bundle policy name recorded in events.
// Event PolicyID is this name, which may differ from the database resource ID.
func (s *Store) GetPolicyByName(ctx context.Context, name string) (Policy, error) {
	p, err := scanPolicy(s.pool.QueryRow(ctx, `SELECT `+policyCols+policyFrom+` WHERE p.name=$1`, name))
	if errors.Is(err, pgx.ErrNoRows) {
		return Policy{}, ErrNotFound
	}
	if err != nil {
		return Policy{}, fmt.Errorf("store: get policy by name: %w", err)
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
		var err error
		p, err = updatePolicyTx(ctx, tx, id, etag, spec, next, a)
		return err
	})
	return p, err
}

// updatePolicyTx saves an immutable draft version and audit under the policy lock.
func updatePolicyTx(ctx context.Context, tx pgx.Tx, id, etag string, spec json.RawMessage, next string, a Audit) (Policy, error) {
	before, err := scanPolicy(tx.QueryRow(ctx, `SELECT `+policyCols+policyFrom+` WHERE p.id = $1 FOR UPDATE OF p`, id))
	if errors.Is(err, pgx.ErrNoRows) {
		return Policy{}, ErrNotFound
	}
	if err != nil {
		return Policy{}, fmt.Errorf("store: update policy: %w", err)
	}
	if before.Etag != etag {
		return Policy{}, ErrEtagMismatch
	}
	v := before.CurrentVersion + 1
	if _, err := tx.Exec(ctx, `INSERT INTO policy_versions (policy_id, version, spec, created_by, created_subject) VALUES ($1, $2, $3, $4, $5)`,
		id, v, []byte(spec), a.Actor, a.Subject); err != nil {
		return Policy{}, fmt.Errorf("store: policy version: %w", err)
	}
	if _, err := tx.Exec(ctx, `UPDATE policies SET current_version = $2, etag = $3, updated_at = now() WHERE id = $1`, id, v, next); err != nil {
		return Policy{}, fmt.Errorf("store: update policy: %w", err)
	}
	p, err := scanPolicy(tx.QueryRow(ctx, `SELECT `+policyCols+policyFrom+` WHERE p.id = $1`, id))
	if err != nil {
		return Policy{}, fmt.Errorf("store: read policy: %w", err)
	}
	a.Before, a.After = before, p
	if err := writeAudit(ctx, tx, a); err != nil {
		return Policy{}, err
	}
	return p, nil
}

// ListPolicyVersions returns a policy's versions, newest first.
func (s *Store) ListPolicyVersions(ctx context.Context, id string) ([]PolicyVersion, error) {
	rows, err := s.pool.Query(ctx, `SELECT `+versionCols+` FROM policy_versions WHERE policy_id = $1 ORDER BY version DESC`, id)
	if err != nil {
		return nil, fmt.Errorf("store: list versions: %w", err)
	}
	vs, err := pgx.CollectRows(rows, func(r pgx.CollectableRow) (PolicyVersion, error) { return scanVersion(r) })
	if err == nil && len(vs) == 0 {
		if _, err := s.GetPolicy(ctx, id); err != nil {
			return nil, err
		}
	}
	return vs, err
}

// ListVersionsByState returns the versions of every policy in state, the
// oldest submitted first (the review queue).
func (s *Store) ListVersionsByState(ctx context.Context, state string) ([]PolicyVersion, error) {
	rows, err := s.pool.Query(ctx, `SELECT `+versionCols+` FROM policy_versions WHERE state = $1
		ORDER BY submitted_at NULLS LAST, created_at, policy_id, version`, state)
	if err != nil {
		return nil, fmt.Errorf("store: list versions: %w", err)
	}
	return pgx.CollectRows(rows, func(r pgx.CollectableRow) (PolicyVersion, error) { return scanVersion(r) })
}

// GetPolicyVersion returns one version.
func (s *Store) GetPolicyVersion(ctx context.Context, id string, version int) (PolicyVersion, error) {
	v, err := scanVersion(s.pool.QueryRow(ctx, `SELECT `+versionCols+` FROM policy_versions WHERE policy_id = $1 AND version = $2`, id, version))
	if errors.Is(err, pgx.ErrNoRows) {
		return PolicyVersion{}, ErrNotFound
	}
	if err != nil {
		return PolicyVersion{}, fmt.Errorf("store: get version: %w", err)
	}
	return v, nil
}

// lockVersion reads a version FOR UPDATE, with the subjects that drafted
// and submitted it, and the policy's newest approved (or deployed) version.
func lockVersion(ctx context.Context, tx pgx.Tx, id string, version int) (v PolicyVersion, created, submitted string, approved int, err error) {
	err = tx.QueryRow(ctx, `SELECT `+versionCols+`, created_subject, coalesce(submitted_subject, ''),
		coalesce((SELECT max(x.version) FROM policy_versions x WHERE x.policy_id = $1 AND x.state IN ('APPROVED', 'DEPLOYED')), 0)
		FROM policy_versions WHERE policy_id = $1 AND version = $2 FOR UPDATE`, id, version).
		Scan(&v.PolicyID, &v.Version, &v.Spec, &v.State, &v.CreatedBy, &v.CreatedAt,
			&v.SubmittedBy, &v.SubmittedAt, &v.DecidedBy, &v.DecidedAt, &v.DecisionComment, &v.ApprovedReplayID, &created, &submitted, &approved)
	if errors.Is(err, pgx.ErrNoRows) {
		err = ErrNotFound
	} else if err != nil {
		err = fmt.Errorf("store: version: %w", err)
	}
	return
}

// SubmitPolicyVersion puts a DRAFT (or REJECTED) version up for review.
func (s *Store) SubmitPolicyVersion(ctx context.Context, id string, version int, a Audit) (PolicyVersion, error) {
	var out PolicyVersion
	err := s.inTx(ctx, func(tx pgx.Tx) error {
		v, _, _, approved, err := lockVersion(ctx, tx, id, version)
		if err != nil {
			return err
		}
		if v.State != VersionDraft && v.State != VersionRejected {
			return &StateError{fmt.Sprintf("version %d is %s; only a DRAFT or REJECTED version can be submitted", version, v.State)}
		}
		if version < approved {
			return &StateError{fmt.Sprintf("version %d is older than version %d, already approved", version, approved)}
		}
		if out, err = scanVersion(tx.QueryRow(ctx, `UPDATE policy_versions SET state = $3, submitted_by = $4, submitted_subject = $5,
			submitted_at = now(), decided_by = NULL, decided_subject = NULL, decided_at = NULL, decision_comment = '', approved_replay_id = NULL
			WHERE policy_id = $1 AND version = $2 RETURNING `+versionCols, id, version, VersionSubmitted, a.Actor, a.Subject)); err != nil {
			return fmt.Errorf("store: submit: %w", err)
		}
		a.Before, a.After = v, out
		return writeAudit(ctx, tx, a)
	})
	return out, err
}

// DecidePolicyVersion approves or rejects a SUBMITTED version. Approval
// takes someone other than whoever drafted or submitted it (ErrFourEyes),
// identified by subject; a version older than the newest approved one
// cannot be approved.
func (s *Store) DecidePolicyVersion(ctx context.Context, id string, version int, approve bool, comment string, a Audit) (PolicyVersion, error) {
	var out PolicyVersion
	err := s.inTx(ctx, func(tx pgx.Tx) error {
		v, created, submitted, approved, err := lockVersion(ctx, tx, id, version)
		if err != nil {
			return err
		}
		if v.State != VersionSubmitted {
			return &StateError{fmt.Sprintf("version %d is %s; only a SUBMITTED version can be approved or rejected", version, v.State)}
		}
		state, approvedBy := VersionRejected, any(nil)
		if approve {
			if a.Subject == "" || a.Subject == created || a.Subject == submitted {
				return ErrFourEyes
			}
			if version < approved {
				return &StateError{fmt.Sprintf("version %d is older than version %d, already approved", version, approved)}
			}
			if a.ReplayOperation != "" {
				var valid bool
				if err := tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM operations WHERE id=$1 AND kind='REPLAY' AND policy_id=$2 AND version=$3 AND state='DONE')`, a.ReplayOperation, id, version).Scan(&valid); err != nil {
					return err
				}
				if !valid {
					return &StateError{Msg: "approved replay must be a DONE operation of this policy version"}
				}
			}
			state, approvedBy = VersionApproved, a.Actor
		}
		if out, err = scanVersion(tx.QueryRow(ctx, `UPDATE policy_versions SET state = $3, decided_by = $4, decided_subject = $5,
			decided_at = now(), decision_comment = $6, approved_by = $7, approved_replay_id = nullif($8, '')
			WHERE policy_id = $1 AND version = $2 RETURNING `+versionCols, id, version, state, a.Actor, a.Subject, comment, approvedBy, a.ReplayOperation)); err != nil {
			return fmt.Errorf("store: decide: %w", err)
		}
		a.Before, a.After = v, out
		return writeAudit(ctx, tx, a)
	})
	return out, err
}

// DeployablePolicies returns the policies a deploy builds: each at its
// newest APPROVED or DEPLOYED version (CurrentVersion and Spec are that
// version's); a policy without one is left out.
func (s *Store) DeployablePolicies(ctx context.Context) ([]Policy, error) {
	rows, err := s.pool.Query(ctx, `SELECT p.id, p.name, v.version, p.etag, v.spec, p.created_by, p.created_at, p.updated_at, v.version,
		coalesce((SELECT max(x.version) FROM policy_versions x WHERE x.policy_id = p.id AND x.state = 'DEPLOYED'), 0)
		FROM policies p JOIN LATERAL (SELECT version, spec FROM policy_versions
			WHERE policy_id = p.id AND state IN ('APPROVED', 'DEPLOYED') ORDER BY version DESC LIMIT 1) v ON true
		ORDER BY p.name`)
	if err != nil {
		return nil, fmt.Errorf("store: deployable policies: %w", err)
	}
	return pgx.CollectRows(rows, func(r pgx.CollectableRow) (Policy, error) { return scanPolicy(r) })
}

// Bundle is a row of bundles.
type Bundle struct {
	InputDigest string `json:"input_digest,omitempty"`

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
		if _, err := tx.Exec(ctx, "SELECT pg_advisory_xact_lock($1)", int64(lockBundleRecords)); err != nil {
			return fmt.Errorf("store: bundle record lock: %w", err)
		}
		var e error
		b, e = recordBundleJSON(ctx, tx, b, a, contents, true)
		return e
	})
	return b, err
}

// recordBundle shares the transaction with an automatic staging action.
func recordBundle(ctx context.Context, tx pgx.Tx, b Bundle, a Audit, ordinary bool) (Bundle, error) {
	contents, err := json.Marshal(b.Contents)
	if err != nil {
		return Bundle{}, err
	}
	return recordBundleJSON(ctx, tx, b, a, contents, ordinary)
}

func recordBundleJSON(ctx context.Context, tx pgx.Tx, b Bundle, a Audit, contents []byte, ordinary bool) (Bundle, error) {
	if err := tx.QueryRow(ctx, `INSERT INTO bundles (version, sha256, object_key, size_bytes, created_by, contents, input_digest)
			VALUES ($1, $2, $3, $4, $5, $6, $7) RETURNING created_at`,
		int64(b.Version), b.SHA256, b.ObjectKey, b.SizeBytes, a.Actor, contents, b.InputDigest).Scan(&b.CreatedAt); err != nil {
		return Bundle{}, fmt.Errorf("store: record bundle: %w", err)
	}
	b.CreatedBy = a.Actor
	// the approved versions the bundle took are deployed now
	for id, v := range b.Contents {
		if _, err := tx.Exec(ctx, `UPDATE policy_versions SET state = $3 WHERE policy_id = $1 AND version = $2 AND state = $4`,
			id, v, VersionDeployed, VersionApproved); err != nil {
			return Bundle{}, fmt.Errorf("store: deployed versions: %w", err)
		}
	}
	if ordinary {
		a.After = b
	}
	return b, writeAudit(ctx, tx, a)
}

// LatestBundle returns the newest bundle.
func (s *Store) LatestBundle(ctx context.Context) (Bundle, error) {
	var b Bundle
	var contents []byte
	var v int64
	err := s.pool.QueryRow(ctx, `SELECT version, sha256, object_key, size_bytes, contents, created_by, created_at, input_digest
		FROM bundles ORDER BY version DESC LIMIT 1`).Scan(&v, &b.SHA256, &b.ObjectKey, &b.SizeBytes, &contents, &b.CreatedBy, &b.CreatedAt, &b.InputDigest)
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

// ListBundles returns the newest bundles first.
func (s *Store) ListBundles(ctx context.Context, limit int) ([]Bundle, error) {
	rows, err := s.pool.Query(ctx, `SELECT version, sha256, object_key, size_bytes, contents, created_by, created_at, input_digest
		FROM bundles ORDER BY version DESC LIMIT $1`, limit)
	if err != nil {
		return nil, fmt.Errorf("store: list bundles: %w", err)
	}
	return pgx.CollectRows(rows, func(r pgx.CollectableRow) (Bundle, error) {
		var b Bundle
		var v int64
		var contents []byte
		err := r.Scan(&v, &b.SHA256, &b.ObjectKey, &b.SizeBytes, &contents, &b.CreatedBy, &b.CreatedAt, &b.InputDigest)
		b.Version = uint64(v)
		_ = json.Unmarshal(contents, &b.Contents)
		return b, err
	})
}
