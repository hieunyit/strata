package store

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/jackc/pgx/v5"
	"regexp"
	"time"
)

type Incident struct {
	ID            string     `json:"id"`
	ApplicationID string     `json:"application_id"`
	EnvironmentID string     `json:"environment_id"`
	ScopeEtag     string     `json:"-"`
	Kind          string     `json:"kind"`
	State         string     `json:"state"`
	SignalState   string     `json:"signal_state"`
	Affected      int        `json:"affected"`
	Etag          string     `json:"etag"`
	OpenedAt      time.Time  `json:"opened_at"`
	ObservedAt    time.Time  `json:"observed_at"`
	NotifiedAt    *time.Time `json:"notified_at"`
	AckSubject    string     `json:"ack_subject"`
}

const incidentCols = `id::text,application_id,environment_id,scope_etag,kind,state,signal_state,affected,etag,opened_at,observed_at,notified_at,ack_subject`

func scanIncident(row pgx.Row) (Incident, error) {
	var v Incident
	err := row.Scan(&v.ID, &v.ApplicationID, &v.EnvironmentID, &v.ScopeEtag, &v.Kind, &v.State, &v.SignalState, &v.Affected, &v.Etag, &v.OpenedAt, &v.ObservedAt, &v.NotifiedAt, &v.AckSubject)
	if errors.Is(err, pgx.ErrNoRows) {
		err = ErrNotFound
	}
	return v, err
}

var incidentKind = regexp.MustCompile(`^[a-z_]{1,48}$`)

// ObserveIncident groups all affected nodes by cause. Only known healthy resolves;
// stale/unknown data cannot declare an incident recovered.
func (s *Store) ObserveIncident(ctx context.Context, v Incident, outbound bool) error {
	if !incidentKind.MatchString(v.Kind) || v.Affected < 0 || v.Affected > 1000000 {
		return fmt.Errorf("operations: invalid signal")
	}
	switch v.SignalState {
	case "healthy", "degraded", "unavailable", "stale", "unknown":
	default:
		return fmt.Errorf("operations: invalid state")
	}
	return s.inTx(ctx, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(743001)`); err != nil {
			return err
		}
		before, err := scanIncident(tx.QueryRow(ctx, `SELECT `+incidentCols+` FROM operation_incidents WHERE application_id=$1 AND environment_id=$2 AND scope_etag=$3 AND kind=$4 FOR UPDATE`, v.ApplicationID, v.EnvironmentID, v.ScopeEtag, v.Kind))
		created := errors.Is(err, ErrNotFound)
		bad := v.SignalState == "degraded" || v.SignalState == "unavailable"
		if errors.Is(err, ErrNotFound) {
			if !bad {
				return nil
			}
			var total int
			if err = tx.QueryRow(ctx, `SELECT count(*) FROM operation_incidents`).Scan(&total); err != nil {
				return err
			}
			if total >= 10000 {
				return fmt.Errorf("operations: incident quota")
			}
			before, err = scanIncident(tx.QueryRow(ctx, `INSERT INTO operation_incidents(application_id,environment_id,scope_etag,kind,state,signal_state,affected,opened_at,observed_at) VALUES($1,$2,$3,$4,'open',$5,$6,$7,$7) RETURNING `+incidentCols, v.ApplicationID, v.EnvironmentID, v.ScopeEtag, v.Kind, v.SignalState, v.Affected, v.ObservedAt))
		}
		if err != nil {
			return err
		}
		if v.ObservedAt.Before(before.ObservedAt) {
			return nil
		}
		state := before.State
		reopened := bad && state == "resolved"
		if reopened {
			state = "open"
		}
		if v.SignalState == "healthy" {
			state = "resolved"
		}
		changed := state != before.State || v.SignalState != before.SignalState || v.Affected != before.Affected
		if _, err = tx.Exec(ctx, `UPDATE operation_incidents SET state=$2,signal_state=$3,affected=$4,observed_at=$5,etag=CASE WHEN $6 THEN gen_random_uuid()::text ELSE etag END,opened_at=CASE WHEN $7 THEN $5 ELSE opened_at END,ack_subject=CASE WHEN $7 THEN '' ELSE ack_subject END WHERE id=$1::uuid`, before.ID, state, v.SignalState, v.Affected, v.ObservedAt, changed, reopened); err != nil {
			return err
		}
		due := bad && state == "open" && (before.NotifiedAt == nil || v.ObservedAt.Sub(*before.NotifiedAt) >= time.Hour)
		recovered := state == "resolved" && before.State != "resolved"
		if changed || created {
			if err = writeAudit(ctx, tx, Audit{Actor: "system", Subject: "system:operations", Channel: "system", Action: "operations.incidentObserved", Resource: "incidents/" + before.ID, After: map[string]any{"state": state, "kind": v.Kind}}); err != nil {
				return err
			}
		}
		if outbound && (due || recovered) {
			// Opaque incident ID and fixed cause/state only: never app names, nodes, URI,
			// client addresses, samples, error text, subjects or before/after documents.
			payload, _ := json.Marshal(map[string]any{"type": "alert", "incident_id": before.ID, "kind": v.Kind, "state": state, "affected": v.Affected, "at": v.ObservedAt})
			var queued bool
			if err = tx.QueryRow(ctx, `SELECT enqueue_outbound('alert',$1,NULL,$2)`, before.ID+"/"+state+"/"+fmt.Sprint(v.ObservedAt.Unix()/3600), payload).Scan(&queued); err != nil {
				return err
			}
			if queued {
				_, err = tx.Exec(ctx, `UPDATE operation_incidents SET notified_at=$2 WHERE id=$1::uuid`, before.ID, v.ObservedAt)
				return err
			}
		}
		return nil
	})
}
func (s *Store) Incidents(ctx context.Context, app, env, scope string) ([]Incident, error) {
	rows, err := s.pool.Query(ctx, `SELECT `+incidentCols+` FROM operation_incidents WHERE application_id=$1 AND environment_id=$2 AND scope_etag=$3 ORDER BY observed_at DESC,id LIMIT 200`, app, env, scope)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, func(r pgx.CollectableRow) (Incident, error) { return scanIncident(r) })
}
func (s *Store) AcknowledgeIncident(ctx context.Context, id, etag, app, env, scope string, a Audit) (Incident, error) {
	var out Incident
	err := s.inTx(ctx, func(tx pgx.Tx) error {
		var err error
		out, err = scanIncident(tx.QueryRow(ctx, `UPDATE operation_incidents SET state='acknowledged',ack_subject=$7,etag=gen_random_uuid()::text WHERE id::text=$1 AND etag=$2 AND application_id=$3 AND environment_id=$4 AND scope_etag=$5 AND state='open' AND $6<>'' RETURNING `+incidentCols, id, etag, app, env, scope, a.RequestID, a.Subject))
		if errors.Is(err, ErrNotFound) {
			return ErrEtagMismatch
		}
		if err != nil {
			return err
		}
		return writeAudit(ctx, tx, a)
	})
	return out, err
}
func (s *Store) RecordBackupObservation(ctx context.Context, ok bool) error {
	return s.inTx(ctx, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `INSERT INTO backup_observation(id,succeeded) VALUES(1,$1) ON CONFLICT(id) DO UPDATE SET succeeded=$1,at=now()`, ok); err != nil {
			return err
		}
		return writeAudit(ctx, tx, Audit{Actor: "system", Subject: "system:backup", Channel: "system", Action: "backup.completed", Resource: "backup", After: map[string]any{"succeeded": ok}})
	})
}
func (s *Store) BackupObservation(ctx context.Context) (bool, time.Time, error) {
	var ok bool
	var at time.Time
	err := s.pool.QueryRow(ctx, `SELECT succeeded,at FROM backup_observation WHERE id=1`).Scan(&ok, &at)
	if errors.Is(err, pgx.ErrNoRows) {
		err = ErrNotFound
	}
	return ok, at, err
}
