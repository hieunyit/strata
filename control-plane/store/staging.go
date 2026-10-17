package store

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"math"
	"strconv"
	"time"

	"github.com/jackc/pgx/v5"
)

// ErrStagingConflict means the source moved, a rule is already staged, or an
// idempotency key was reused for different inputs. Re-evaluate the source.
var ErrStagingConflict = errors.New("store: staging source or request conflict")

// Serializes recording (not compilation) with ordinary RecordBundle. Separate
// from lockBundles: its holder records on a different pooled connection.
const lockBundleRecords = 0x5354524154410003

// StagingAction is durable effective state and rollout intent. RolloutID nil
// means publication is pending, never that a node activated the derived bundle.
type StagingAction struct {
	ID            string    `json:"id"`
	PolicyID      string    `json:"policy_id"`
	PolicyVersion int       `json:"policy_version"`
	RuleID        uint32    `json:"rule_id"`
	SourceBundle  uint64    `json:"source_bundle"`
	BundleVersion uint64    `json:"bundle_version"`
	Matches       uint64    `json:"matches"`
	Reports       uint64    `json:"reports"`
	WindowFrom    time.Time `json:"window_from"`
	WindowTo      time.Time `json:"window_to"`
	RolloutID     *int64    `json:"rollout_id,omitempty"`
	CreatedAt     time.Time `json:"created_at"`
}

const stagingCols = `id, policy_id, policy_version, rule_id, source_bundle, bundle_version,
 matches::text, reports::text, window_from, window_to, rollout_id, created_at`

func scanStaging(r pgx.Row) (StagingAction, error) {
	var a StagingAction
	var source, version int64
	var matches, reports string
	err := r.Scan(&a.ID, &a.PolicyID, &a.PolicyVersion, &a.RuleID, &source, &version,
		&matches, &reports, &a.WindowFrom, &a.WindowTo, &a.RolloutID, &a.CreatedAt)
	if err != nil {
		return a, err
	}
	a.SourceBundle, a.BundleVersion = uint64(source), uint64(version)
	if a.Matches, err = strconv.ParseUint(matches, 10, 64); err != nil {
		return a, err
	}
	a.Reports, err = strconv.ParseUint(reports, 10, 64)
	return a, err
}

// RecordStagingBundle atomically records a verified/uploaded derivation, its
// effective staging state, audit and pending publication. Caller must authorize
// the opt-in, bind captured inputs to source.InputDigest, and verify the signed
// artifact. This storage primitive does not authorize compilation/publication.
func (s *Store) RecordStagingBundle(ctx context.Context, source, b Bundle, action StagingAction, audit Audit) (StagingAction, error) {
	validDigest := func(v string) bool { x, err := hex.DecodeString(v); return err == nil && len(x) == 32 }
	if len(action.ID) < 1 || len(action.ID) > 128 || action.PolicyID == "" || action.PolicyVersion < 1 || action.RuleID == 0 ||
		source.Version == 0 || source.Version >= math.MaxInt64 || b.Version != source.Version+1 ||
		!validDigest(source.InputDigest) || !validDigest(b.InputDigest) || source.InputDigest == b.InputDigest ||
		len(source.SHA256) != 32 || len(b.SHA256) != 32 || b.SizeBytes < 1 || b.ObjectKey == "" ||
		len(source.Contents) < 1 || len(source.Contents) > 4096 || !maps.Equal(source.Contents, b.Contents) ||
		source.Contents[action.PolicyID] != action.PolicyVersion || action.Matches == 0 || action.Reports == 0 || action.Reports > action.Matches ||
		action.WindowFrom.IsZero() || action.WindowTo.IsZero() || !action.WindowTo.After(action.WindowFrom) || action.WindowTo.Sub(action.WindowFrom) > 24*time.Hour {
		return StagingAction{}, errors.New("store: invalid staging derivation")
	}
	action.SourceBundle, action.BundleVersion = source.Version, b.Version
	action.CreatedAt, action.RolloutID = time.Time{}, nil
	// PostgreSQL stores microseconds; canonicalize before hashing retries.
	action.WindowFrom = action.WindowFrom.UTC().Truncate(time.Microsecond)
	action.WindowTo = action.WindowTo.UTC().Truncate(time.Microsecond)
	if !action.WindowTo.After(action.WindowFrom) {
		return StagingAction{}, errors.New("store: empty staging window")
	}
	raw, err := json.Marshal(struct {
		SourceVersion uint64
		SourceDigest  string
		SourceSHA     []byte
		DerivedDigest string
		DerivedSHA    []byte
		ObjectKey     string
		Size          int64
		Contents      map[string]int
		Action        StagingAction
	}{source.Version, source.InputDigest, source.SHA256, b.InputDigest, b.SHA256, b.ObjectKey, b.SizeBytes, b.Contents, action})
	if err != nil {
		return StagingAction{}, fmt.Errorf("store: staging fingerprint: %w", err)
	}
	fingerprint := sha256.Sum256(raw)
	var out StagingAction
	err = s.inTx(ctx, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock($1)`, int64(lockBundleRecords)); err != nil {
			return fmt.Errorf("store: staging record lock: %w", err)
		}
		var prior []byte
		err := tx.QueryRow(ctx, `SELECT request_digest FROM rule_staging_actions WHERE id=$1`, action.ID).Scan(&prior)
		if err == nil {
			if !bytes.Equal(prior, fingerprint[:]) {
				return ErrStagingConflict
			}
			out, err = scanStaging(tx.QueryRow(ctx, `SELECT `+stagingCols+` FROM rule_staging_actions WHERE id=$1`, action.ID))
			return err
		}
		if !errors.Is(err, pgx.ErrNoRows) {
			return fmt.Errorf("store: staging retry: %w", err)
		}
		var current int64
		var digest string
		var sum, contents []byte
		if err := tx.QueryRow(ctx, `SELECT version, input_digest, sha256, contents FROM bundles ORDER BY version DESC LIMIT 1`).Scan(&current, &digest, &sum, &contents); err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				return ErrStagingConflict
			}
			return fmt.Errorf("store: staging source: %w", err)
		}
		var currentContents map[string]int
		if err := json.Unmarshal(contents, &currentContents); err != nil {
			return fmt.Errorf("store: staging source contents: %w", err)
		}
		if uint64(current) != source.Version || digest != source.InputDigest || !bytes.Equal(sum, source.SHA256) || !maps.Equal(currentContents, source.Contents) {
			return ErrStagingConflict
		}
		var approved bool
		if err := tx.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM policy_versions WHERE policy_id=$1 AND version=$2
   AND state IN ('APPROVED','DEPLOYED') AND decided_subject IS NOT NULL AND decided_subject <> ''
   AND decided_subject <> created_subject AND decided_subject <> coalesce(submitted_subject, ''))`, action.PolicyID, action.PolicyVersion).Scan(&approved); err != nil {
			return fmt.Errorf("store: staging approval: %w", err)
		}
		if !approved {
			return ErrStagingConflict
		}
		var staged bool
		if err := tx.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM rule_staging_actions WHERE policy_id=$1 AND policy_version=$2 AND rule_id=$3)`, action.PolicyID, action.PolicyVersion, int64(action.RuleID)).Scan(&staged); err != nil {
			return fmt.Errorf("store: staging state: %w", err)
		}
		if staged {
			return ErrStagingConflict
		}
		// Same helper as ordinary deploy, but this audit includes the derivation's
		// provenance. A failed audit rolls back the bundle and the effective state.
		audit.Before = map[string]any{"source_bundle": source.Version, "source_digest": source.InputDigest}
		audit.After = map[string]any{"bundle": b, "staging": action}
		if _, err := recordBundle(ctx, tx, b, audit, false); err != nil {
			return err
		}
		_, err = tx.Exec(ctx, `INSERT INTO rule_staging_actions
   (id,policy_id,policy_version,rule_id,source_bundle,bundle_version,matches,reports,window_from,window_to,request_digest)
   VALUES ($1,$2,$3,$4,$5,$6,$7::numeric,$8::numeric,$9,$10,$11)`, action.ID, action.PolicyID, action.PolicyVersion, int64(action.RuleID),
			int64(source.Version), int64(b.Version), strconv.FormatUint(action.Matches, 10), strconv.FormatUint(action.Reports, 10), action.WindowFrom, action.WindowTo, fingerprint[:])
		if err != nil {
			return fmt.Errorf("store: record staging: %w", err)
		}
		out, err = scanStaging(tx.QueryRow(ctx, `SELECT `+stagingCols+` FROM rule_staging_actions WHERE id=$1`, action.ID))
		return err
	})
	if err != nil {
		return StagingAction{}, err
	}
	return out, nil
}

// StagedRules returns immutable effective state only for the exact requested
// policy versions. Pending publication remains effective input for recovery;
// it is not evidence of runtime activation. No expiry or automatic reset.
func (s *Store) StagedRules(ctx context.Context, versions map[string]int) (map[string][]uint32, error) {
	if len(versions) > 4096 {
		return nil, errors.New("store: too many staging policies")
	}
	if len(versions) == 0 {
		return nil, nil
	}
	for id, v := range versions {
		if id == "" || v < 1 {
			return nil, errors.New("store: invalid staging version")
		}
	}
	raw, err := json.Marshal(versions)
	if err != nil {
		return nil, err
	}
	rows, err := s.pool.Query(ctx, `SELECT s.policy_id,s.rule_id FROM rule_staging_actions s
  JOIN jsonb_each_text($1::jsonb) v ON v.key=s.policy_id AND v.value::integer=s.policy_version
  ORDER BY s.policy_id,s.rule_id LIMIT 4097`, raw)
	if err != nil {
		return nil, fmt.Errorf("store: staged rules: %w", err)
	}
	defer rows.Close()
	out := map[string][]uint32{}
	count := 0
	for rows.Next() {
		var id string
		var rule uint32
		if err := rows.Scan(&id, &rule); err != nil {
			return nil, err
		}
		count++
		if count > 4096 || len(out[id]) >= 16 {
			return nil, errors.New("store: staging codec limit exceeded")
		}
		out[id] = append(out[id], rule)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("store: staged rules: %w", err)
	}
	return out, nil
}
