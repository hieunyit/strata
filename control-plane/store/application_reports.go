package store

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/jackc/pgx/v5"
	"time"
)

type ReportSchedule struct {
	ApplicationID string    `json:"application_id"`
	EnvironmentID string    `json:"environment_id"`
	ScopeEtag     string    `json:"-"`
	Enabled       bool      `json:"enabled"`
	EveryHours    int       `json:"every_hours"`
	Etag          string    `json:"etag"`
	Owner         string    `json:"owner"`
	NextRun       time.Time `json:"next_run"`
	Claim         string    `json:"-"`
}

const scheduleCols = `application_id,environment_id,scope_etag,enabled,every_hours,etag,owner_subject,next_run,coalesce(claim::text,'')`

func scanSchedule(row pgx.Row) (ReportSchedule, error) {
	var v ReportSchedule
	err := row.Scan(&v.ApplicationID, &v.EnvironmentID, &v.ScopeEtag, &v.Enabled, &v.EveryHours, &v.Etag, &v.Owner, &v.NextRun, &v.Claim)
	if errors.Is(err, pgx.ErrNoRows) {
		err = ErrNotFound
	}
	return v, err
}
func (s *Store) ReportSchedule(ctx context.Context, app, env string) (ReportSchedule, error) {
	return scanSchedule(s.pool.QueryRow(ctx, `SELECT `+scheduleCols+` FROM application_report_schedules WHERE application_id=$1 AND environment_id=$2`, app, env))
}
func (s *Store) SaveReportSchedule(ctx context.Context, v ReportSchedule, a Audit) (ReportSchedule, error) {
	var out ReportSchedule
	if v.EveryHours != 24 && v.EveryHours != 168 {
		return out, fmt.Errorf("operations: invalid frequency")
	}
	err := s.investigationOnce(ctx, v, a, func(tx pgx.Tx) (any, error) {
		if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(743002)`); err != nil {
			return nil, err
		}
		before, err := scanSchedule(tx.QueryRow(ctx, `SELECT `+scheduleCols+` FROM application_report_schedules WHERE application_id=$1 AND environment_id=$2 FOR UPDATE`, v.ApplicationID, v.EnvironmentID))
		if errors.Is(err, ErrNotFound) {
			if v.Etag != "" {
				return nil, ErrEtagMismatch
			}
			var n int
			if err = tx.QueryRow(ctx, `SELECT count(*) FROM application_report_schedules`).Scan(&n); err != nil {
				return nil, err
			}
			if n >= 1000 {
				return nil, fmt.Errorf("operations: schedule quota")
			}
			return scanSchedule(tx.QueryRow(ctx, `INSERT INTO application_report_schedules(application_id,environment_id,scope_etag,enabled,every_hours,owner_subject) VALUES($1,$2,$3,$4,$5,$6) RETURNING `+scheduleCols, v.ApplicationID, v.EnvironmentID, v.ScopeEtag, v.Enabled, v.EveryHours, a.Subject))
		}
		if err != nil {
			return nil, err
		}
		if before.Etag != v.Etag {
			return nil, ErrEtagMismatch
		}
		return scanSchedule(tx.QueryRow(ctx, `UPDATE application_report_schedules SET enabled=$3,every_hours=$4,scope_etag=$5,owner_subject=$6,etag=gen_random_uuid()::text,claim=NULL,lease_until=NULL,next_run=now() WHERE application_id=$1 AND environment_id=$2 RETURNING `+scheduleCols, v.ApplicationID, v.EnvironmentID, v.Enabled, v.EveryHours, v.ScopeEtag, a.Subject))
	}, &out)
	return out, err
}
func (s *Store) ClaimApplicationReport(ctx context.Context, now time.Time) (ReportSchedule, error) {
	return scanSchedule(s.pool.QueryRow(ctx, `UPDATE application_report_schedules SET claim=gen_random_uuid(),lease_until=$1+interval '2 minutes' WHERE (application_id,environment_id)=(SELECT application_id,environment_id FROM application_report_schedules WHERE enabled AND next_run<=$1 AND (lease_until IS NULL OR lease_until<$1) ORDER BY next_run LIMIT 1 FOR UPDATE SKIP LOCKED) RETURNING `+scheduleCols, now))
}

type ApplicationReport struct {
	ID            string          `json:"id"`
	ApplicationID string          `json:"application_id"`
	EnvironmentID string          `json:"environment_id"`
	ScopeEtag     string          `json:"-"`
	PeriodStart   time.Time       `json:"period_start"`
	PeriodEnd     time.Time       `json:"period_end"`
	Body          json.RawMessage `json:"body"`
	ExpiresAt     time.Time       `json:"expires_at"`
}

const reportCols = `id::text,application_id,environment_id,scope_etag,period_start,period_end,body,expires_at`

func scanReport(row pgx.Row) (ApplicationReport, error) {
	var v ApplicationReport
	err := row.Scan(&v.ID, &v.ApplicationID, &v.EnvironmentID, &v.ScopeEtag, &v.PeriodStart, &v.PeriodEnd, &v.Body, &v.ExpiresAt)
	if errors.Is(err, pgx.ErrNoRows) {
		err = ErrNotFound
	}
	return v, err
}
func (s *Store) FinishApplicationReport(ctx context.Context, v ReportSchedule, body json.RawMessage, now time.Time, outbound bool) error {
	if !json.Valid(body) || len(body) > 16384 {
		return fmt.Errorf("operations: invalid report")
	}
	return s.inTx(ctx, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(743002)`); err != nil {
			return err
		}
		var current bool
		if err := tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM application_report_schedules s JOIN applications a ON a.id=s.application_id WHERE s.application_id=$1 AND s.environment_id=$2 AND s.enabled AND s.claim::text=$3 AND s.lease_until>$4 AND a.etag=s.scope_etag AND s.scope_etag=$5)`, v.ApplicationID, v.EnvironmentID, v.Claim, now, v.ScopeEtag).Scan(&current); err != nil {
			return err
		}
		if !current {
			return ErrEtagMismatch
		}
		var total int
		if err := tx.QueryRow(ctx, `SELECT count(*) FROM application_reports`).Scan(&total); err != nil {
			return err
		}
		if total >= 10000 {
			return fmt.Errorf("operations: report quota")
		}
		report, err := scanReport(tx.QueryRow(ctx, `INSERT INTO application_reports(application_id,environment_id,scope_etag,period_start,period_end,body,expires_at) VALUES($1,$2,$3,$4,$5,$6,$7) ON CONFLICT(application_id,environment_id,period_end) DO UPDATE SET body=application_reports.body RETURNING `+reportCols, v.ApplicationID, v.EnvironmentID, v.ScopeEtag, v.NextRun.Add(-time.Duration(v.EveryHours)*time.Hour), v.NextRun, body, now.Add(30*24*time.Hour)))
		if err != nil {
			return err
		}
		if _, err = tx.Exec(ctx, `UPDATE application_report_schedules SET next_run=$4,claim=NULL,lease_until=NULL WHERE application_id=$1 AND environment_id=$2 AND claim::text=$3`, v.ApplicationID, v.EnvironmentID, v.Claim, now.Add(time.Duration(v.EveryHours)*time.Hour)); err != nil {
			return err
		}
		if err = writeAudit(ctx, tx, Audit{Actor: "system", Subject: "system:reports", Channel: "system", Action: "reports.created", Resource: "reports/" + report.ID}); err != nil {
			return err
		}
		if outbound {
			payload, _ := json.Marshal(map[string]any{"type": "report", "report_id": report.ID, "period_start": report.PeriodStart, "period_end": report.PeriodEnd, "summary": json.RawMessage(body)})
			var queued bool
			if err := tx.QueryRow(ctx, `SELECT enqueue_outbound('report',$1,NULL,$2)`, report.ID, payload).Scan(&queued); err != nil {
				return err
			}
			if !queued {
				return fmt.Errorf("operations: delivery queue full")
			}
			return nil
		}
		return nil
	})
}
func (s *Store) PauseChangedReportScope(ctx context.Context, v ReportSchedule) error {
	return s.inTx(ctx, func(tx pgx.Tx) error {
		tag, err := tx.Exec(ctx, `UPDATE application_report_schedules SET enabled=false,claim=NULL,lease_until=NULL,etag=gen_random_uuid()::text WHERE application_id=$1 AND environment_id=$2 AND claim::text=$3`, v.ApplicationID, v.EnvironmentID, v.Claim)
		if err != nil || tag.RowsAffected() == 0 {
			return err
		}
		return writeAudit(ctx, tx, Audit{Actor: "system", Subject: "system:reports", Channel: "system", Action: "reports.scopeChanged", Resource: "applications/" + v.ApplicationID})
	})
}
func (s *Store) ApplicationReports(ctx context.Context, app, env, scope string, now time.Time) ([]ApplicationReport, error) {
	rows, err := s.pool.Query(ctx, `SELECT `+reportCols+` FROM application_reports WHERE application_id=$1 AND environment_id=$2 AND scope_etag=$3 AND expires_at>$4 ORDER BY period_end DESC LIMIT 32`, app, env, scope, now)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, func(r pgx.CollectableRow) (ApplicationReport, error) { return scanReport(r) })
}
func (s *Store) RetainOperations(ctx context.Context, now time.Time) error {
	return s.inTx(ctx, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `DELETE FROM application_reports WHERE expires_at<=$1`, now); err != nil {
			return err
		}
		_, err := tx.Exec(ctx, `DELETE FROM operation_incidents WHERE observed_at<$1`, now.Add(-30*24*time.Hour))
		return err
	})
}
