package store

import (
	"context"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
)

type ExceptionMaintenance struct {
	PolicyID      string    `json:"policy_id"`
	SourceVersion int       `json:"source_version"`
	SourceEtag    string    `json:"source_etag"`
	ExpiredIDs    []string  `json:"expired_ids"`
	State         string    `json:"state"`
	Etag          string    `json:"etag"`
	DraftVersion  int       `json:"draft_version"`
	CreatedAt     time.Time `json:"created_at"`
	UpdatedAt     time.Time `json:"updated_at"`
}

const maintenanceCols = `policy_id,source_version,source_etag,expired_ids,state,etag,coalesce(draft_version,0),created_at,updated_at`

func scanMaintenance(row pgx.Row) (ExceptionMaintenance, error) {
	var v ExceptionMaintenance
	err := row.Scan(&v.PolicyID, &v.SourceVersion, &v.SourceEtag, &v.ExpiredIDs, &v.State, &v.Etag, &v.DraftVersion, &v.CreatedAt, &v.UpdatedAt)
	return v, err
}
func (s *Store) QueueExceptionMaintenance(ctx context.Context, id string, version int, etag string, expired []string) (ExceptionMaintenance, error) {
	var out ExceptionMaintenance
	if id == "" || etag == "" || version < 1 || len(expired) < 1 || len(expired) > 128 {
		return out, fmt.Errorf("exceptions: invalid maintenance")
	}
	err := s.inTx(ctx, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(742002)`); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `UPDATE exception_maintenance SET state='superseded',updated_at=now(),etag=gen_random_uuid()::text WHERE policy_id=$1 AND source_version<$2 AND state='pending'`, id, version); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `DELETE FROM exception_maintenance WHERE state<>'pending' AND updated_at<now()-interval '30 days'`); err != nil {
			return err
		}
		var count int
		if err := tx.QueryRow(ctx, `SELECT count(*) FROM exception_maintenance`).Scan(&count); err != nil {
			return err
		}
		if count >= 10000 {
			var exists bool
			if err := tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM exception_maintenance WHERE policy_id=$1 AND source_version=$2)`, id, version).Scan(&exists); err != nil {
				return err
			}
			if !exists {
				tag, err := tx.Exec(ctx, `DELETE FROM exception_maintenance WHERE (policy_id,source_version) IN(SELECT policy_id,source_version FROM exception_maintenance WHERE state<>'pending' ORDER BY updated_at LIMIT 100)`)
				if err != nil {
					return err
				}
				if tag.RowsAffected() == 0 {
					return fmt.Errorf("exceptions: maintenance quota reached")
				}
			}
		}
		tag, err := tx.Exec(ctx, `INSERT INTO exception_maintenance(policy_id,source_version,source_etag,expired_ids) VALUES($1,$2,$3,$4) ON CONFLICT(policy_id,source_version) DO NOTHING`, id, version, etag, expired)
		if err != nil {
			return err
		}
		out, err = scanMaintenance(tx.QueryRow(ctx, `SELECT `+maintenanceCols+` FROM exception_maintenance WHERE policy_id=$1 AND source_version=$2`, id, version))
		if err != nil {
			return err
		}
		if tag.RowsAffected() > 0 {
			return writeAudit(ctx, tx, Audit{Actor: "system", Subject: "system:exception-maintenance", Channel: "system", Action: "exceptions.maintenanceQueued", Resource: "policies/" + id, After: map[string]any{"source_version": version, "expired_count": len(expired)}})
		}

		return err
	})
	return out, err
}
func (s *Store) ExceptionMaintenance(ctx context.Context, id string) ([]ExceptionMaintenance, error) {
	rows, err := s.pool.Query(ctx, `SELECT `+maintenanceCols+` FROM exception_maintenance WHERE policy_id=$1 ORDER BY source_version DESC LIMIT 20`, id)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, func(r pgx.CollectableRow) (ExceptionMaintenance, error) { return scanMaintenance(r) })
}
func (s *Store) CompleteExceptionMaintenance(ctx context.Context, v ExceptionMaintenance, draft int) error {
	return s.inTx(ctx, func(tx pgx.Tx) error {
		tag, err := tx.Exec(ctx, `UPDATE exception_maintenance SET state='drafted',draft_version=$1,updated_at=now(),etag=gen_random_uuid()::text WHERE policy_id=$2 AND source_version=$3 AND etag=$4 AND state='pending'`, draft, v.PolicyID, v.SourceVersion, v.Etag)
		if err != nil {
			return err
		}
		if tag.RowsAffected() != 1 {
			return ErrEtagMismatch
		}
		return writeAudit(ctx, tx, Audit{Actor: "system", Subject: "system:exception-maintenance", Channel: "system", Action: "exceptions.maintenanceDrafted", Resource: "policies/" + v.PolicyID, After: map[string]any{"source_version": v.SourceVersion, "draft_version": draft}})
	})
}

// ReconcileExceptionMaintenance also runs when no expired candidates remain.
func (s *Store) ReconcileExceptionMaintenance(ctx context.Context) error {
	return s.inTx(ctx, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(742002)`); err != nil {
			return err
		}
		updated, err := tx.Exec(ctx, `UPDATE exception_maintenance m SET state='superseded',updated_at=now(),etag=gen_random_uuid()::text WHERE m.state='pending' AND EXISTS(SELECT 1 FROM policy_versions v WHERE v.policy_id=m.policy_id AND v.version>m.source_version AND v.state IN('APPROVED','DEPLOYED'))`)
		if err != nil {
			return err
		}
		deleted, err := tx.Exec(ctx, `DELETE FROM exception_maintenance WHERE state<>'pending' AND updated_at<now()-interval '30 days'`)
		if err != nil {
			return err
		}
		if updated.RowsAffected()+deleted.RowsAffected() == 0 {
			return nil
		}
		return writeAudit(ctx, tx, Audit{Actor: "system", Subject: "system:exception-maintenance", Channel: "system", Action: "exceptions.maintenanceReconciled", Resource: "exceptions", After: map[string]any{"superseded": updated.RowsAffected(), "pruned": deleted.RowsAffected()}})
	})
}
