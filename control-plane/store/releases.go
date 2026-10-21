package store

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"time"

	"github.com/jackc/pgx/v5"
)

var ErrReleaseState = errors.New("release: invalid state")
var ErrReleaseBaseline = errors.New("release: baseline changed or historical evidence; explicitly acknowledge the current baseline")

const releaseSelect = `SELECT id,etag,state,snapshot,snapshot_hash,coalesce(source_release,''),created_by,created_subject,approved_by,approved_subject,created_at,updated_at,coalesce(bundle_version,0),coalesce(rollout_id,0) FROM releases`

func scanRelease(row pgx.Row) (Release, error) {
	var r Release
	var raw []byte
	err := row.Scan(&r.ID, &r.Etag, &r.State, &raw, &r.SnapshotHash, &r.SourceRelease, &r.CreatedBy, &r.CreatedSubject, &r.ApprovedBy, &r.ApprovedSubject, &r.CreatedAt, &r.UpdatedAt, &r.BundleVersion, &r.RolloutID)
	if errors.Is(err, pgx.ErrNoRows) {
		return r, ErrNotFound
	}
	if err != nil {
		return r, err
	}
	err = json.Unmarshal(raw, &r.Snapshot)
	return r, err
}
func (s *Store) GetRelease(ctx context.Context, id string) (Release, error) {
	return scanRelease(s.pool.QueryRow(ctx, releaseSelect+" WHERE id=$1", id))
}
func (s *Store) ListReleases(ctx context.Context, after string) ([]Release, error) {
	rows, err := s.pool.Query(ctx, releaseSelect+" WHERE id>$1 ORDER BY id LIMIT 100", after)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, func(r pgx.CollectableRow) (Release, error) { return scanRelease(r) })
}

// A request receipt is protected before the expensive build. Retrying after a
// lost reply returns the same immutable snapshot, even if approvals changed.
func (s *Store) CreateRelease(ctx context.Context, id, requestID, source string, build func() (ReleaseSnapshot, error), a Audit) (Release, error) {
	var out Release
	if !appID.MatchString(id) || len(requestID) == 0 || len(requestID) > 128 {
		return out, errors.New("release: invalid id or request_id")
	}
	err := s.inTx(ctx, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, "SELECT pg_advisory_xact_lock(hashtextextended($1,34))", a.Subject+"/"+requestID); err != nil {
			return err
		}
		prior, err := scanRelease(tx.QueryRow(ctx, releaseSelect+" WHERE created_subject=$1 AND request_id=$2", a.Subject, requestID))
		if err == nil {
			if prior.SourceRelease != source {
				return ErrApplicationConflict
			}
			out = prior
			return nil
		}
		if !errors.Is(err, ErrNotFound) {
			return err
		}
		if _, err := tx.Exec(ctx, "SELECT pg_advisory_xact_lock(6004516533000001)"); err != nil {
			return err
		}
		var n int
		if err := tx.QueryRow(ctx, "SELECT count(*) FROM releases").Scan(&n); err != nil {
			return err
		}
		if n >= 1000 {
			return errors.New("release: retention limit reached (1000 releases)")
		}
		snapshot, err := build()
		if err != nil {
			return err
		}
		raw, err := json.Marshal(snapshot)
		if err != nil {
			return err
		}
		hash := hex.EncodeToString(snapshot.Bundle.SHA256)
		if len(hash) != 64 {
			return errors.New("release: invalid snapshot hash")
		}
		tag, err := newEtag()
		if err != nil {
			return err
		}
		_, err = tx.Exec(ctx, `INSERT INTO releases(id,etag,state,snapshot,snapshot_hash,source_release,created_by,created_subject,request_id) VALUES($1,$2,'DRAFT',$3,$4,nullif($5,''),$6,$7,$8)`, id, tag, raw, hash, source, a.Actor, a.Subject, requestID)
		if err != nil {
			return err
		}
		out, err = scanRelease(tx.QueryRow(ctx, releaseSelect+" WHERE id=$1", id))
		if err != nil {
			return err
		}
		a.Resource = "releases/" + id
		a.After = out
		return writeAudit(ctx, tx, a)
	})
	return out, err
}
func (s *Store) ReviewRelease(ctx context.Context, id, etag, hash string, replayIDs map[string]string, approve bool, a Audit) (Release, error) {
	var out Release
	err := s.inTx(ctx, func(tx pgx.Tx) error {
		r, err := scanRelease(tx.QueryRow(ctx, releaseSelect+" WHERE id=$1 FOR UPDATE", id))
		if err != nil {
			return err
		}
		if etag == "" || r.Etag != etag {
			return ErrEtagMismatch
		}
		if r.State != "DRAFT" {
			return ErrReleaseState
		}
		if approve && (r.CreatedSubject == a.Subject || a.Subject == "") {
			return ErrFourEyes
		}
		if hash != r.SnapshotHash || !reflect.DeepEqual(replayIDs, r.Snapshot.ReplayIDs) {
			return ErrEtagMismatch
		}
		state := "REJECTED"
		if approve {
			state = "APPROVED"
		}
		tag, err := newEtag()
		if err != nil {
			return err
		}
		_, err = tx.Exec(ctx, "UPDATE releases SET state=$2,etag=$3,approved_by=$4,approved_subject=$5,updated_at=now() WHERE id=$1", id, state, tag, a.Actor, a.Subject)
		if err != nil {
			return err
		}
		out, err = scanRelease(tx.QueryRow(ctx, releaseSelect+" WHERE id=$1", id))
		if err != nil {
			return err
		}
		a.Resource = "releases/" + id
		a.Before = r
		a.After = out
		return writeAudit(ctx, tx, a)
	})
	return out, err
}

// CommitReleaseDeployment atomically records the new version, desired versions,
// rollout and receipt. A candidate never becomes a replay baseline prematurely.
func (s *Store) CommitReleaseDeployment(ctx context.Context, id, etag string, b Bundle, ack *uint64, plan []float64, soak time.Duration, a Audit) (Release, Rollout, []string, error) {
	var out Release
	var rollout Rollout
	var first []string
	err := s.inTx(ctx, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, "SELECT pg_advisory_xact_lock($1)", int64(lockBundleRecords)); err != nil {
			return err
		}
		r, err := scanRelease(tx.QueryRow(ctx, releaseSelect+" WHERE id=$1 FOR UPDATE", id))
		if err != nil {
			return err
		}
		if r.Etag != etag || etag == "" {
			return ErrEtagMismatch
		}
		if r.State != "APPROVED" || r.ApprovedSubject == "" || r.ApprovedSubject == r.CreatedSubject {
			return ErrReleaseState
		}
		var current uint64
		if err := tx.QueryRow(ctx, "SELECT coalesce(max(version),0) FROM bundles").Scan(&current); err != nil {
			return err
		}
		// Every historical snapshot/rollback gets an explicit warning. A changed
		// baseline cannot be silently accepted from an earlier screen's checkbox.
		if (r.Snapshot.Baseline != current || r.SourceRelease != "" || r.Snapshot.ReplayBaselineMismatch) && (ack == nil || *ack != current) {
			return ErrReleaseBaseline
		}
		if !reflect.DeepEqual(b.Contents, r.Snapshot.Bundle.Contents) || b.InputDigest != r.Snapshot.Bundle.InputDigest || b.RulesDigest != r.Snapshot.Bundle.RulesDigest {
			return ErrReleaseState
		}
		if _, err := recordBundle(ctx, tx, b, a, true); err != nil {
			return err
		}
		rows, err := tx.Query(ctx, "SELECT id FROM nodes WHERE revoked_at IS NULL ORDER BY created_at,id")
		if err != nil {
			return err
		}
		nodes, err := pgx.CollectRows(rows, pgx.RowTo[string])
		if err != nil {
			return err
		}
		rollout, first, err = createRolloutTx(ctx, tx, b.Version, nodes, plan, soak, a)
		if err != nil {
			return err
		}
		tag, err := newEtag()
		if err != nil {
			return err
		}
		_, err = tx.Exec(ctx, "UPDATE releases SET state='DEPLOYED',bundle_version=$2,rollout_id=$3,etag=$4,updated_at=now() WHERE id=$1", id, int64(b.Version), rollout.ID, tag)
		if err != nil {
			return err
		}
		out, err = scanRelease(tx.QueryRow(ctx, releaseSelect+" WHERE id=$1", id))
		if err != nil {
			return err
		}
		a.Resource = "releases/" + id
		a.Before = r
		a.After = out
		return writeAudit(ctx, tx, a)
	})
	if err != nil {
		return Release{}, Rollout{}, nil, fmt.Errorf("release deploy: %w", err)
	}
	rollout, err = s.GetRollout(ctx, rollout.ID)
	return out, rollout, first, err
}
