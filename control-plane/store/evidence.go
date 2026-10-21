package store

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/strata/strata/control-plane/auth"
)

type EvidenceExport struct {
	ID            string          `json:"id"`
	Owner         string          `json:"owner"`
	ApplicationID string          `json:"application_id"`
	EnvironmentID string          `json:"environment_id"`
	Sensitive     bool            `json:"sensitive"`
	State         string          `json:"state"`
	Etag          string          `json:"etag"`
	RowCount      int             `json:"row_count"`
	Truncated     bool            `json:"truncated"`
	SHA256        string          `json:"sha256"`
	CreatedAt     time.Time       `json:"created_at"`
	ExpiresAt     time.Time       `json:"expires_at"`
	Filter        json.RawMessage `json:"-"`
	Principal     json.RawMessage `json:"-"`
	ArtifactKey   string          `json:"-"`
	Attempts      int             `json:"-"`
}

const evidenceCols = `id::text,owner_subject,application_id,environment_id,sensitive,state,etag,row_count,truncated,sha256,created_at,expires_at,filter,principal,artifact_key,attempts`

func scanEvidence(row pgx.Row) (EvidenceExport, error) {
	var v EvidenceExport
	err := row.Scan(&v.ID, &v.Owner, &v.ApplicationID, &v.EnvironmentID, &v.Sensitive, &v.State, &v.Etag, &v.RowCount, &v.Truncated, &v.SHA256, &v.CreatedAt, &v.ExpiresAt, &v.Filter, &v.Principal, &v.ArtifactKey, &v.Attempts)
	if errors.Is(err, pgx.ErrNoRows) {
		err = ErrNotFound
	}
	return v, err
}
func (s *Store) CreateEvidenceExport(ctx context.Context, v EvidenceExport, a Audit) (EvidenceExport, error) {
	var out EvidenceExport
	if !appID.MatchString(v.ApplicationID) || !appID.MatchString(v.EnvironmentID) || !json.Valid(v.Filter) || len(v.Filter) > 8192 || !json.Valid(v.Principal) || len(v.Principal) > 1<<20 {
		return out, fmt.Errorf("investigation: invalid evidence request")
	}
	err := s.investigationOnce(ctx, struct {
		Application, Environment string
		Sensitive                bool
		Filter                   json.RawMessage
	}{v.ApplicationID, v.EnvironmentID, v.Sensitive, v.Filter}, a, func(tx pgx.Tx) (any, error) {
		if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(741004)`); err != nil {
			return nil, err
		}
		var total, own int
		if err := tx.QueryRow(ctx, `SELECT count(*),count(*) FILTER(WHERE owner_subject=$1) FROM evidence_exports`, a.Subject).Scan(&total, &own); err != nil {
			return nil, err
		}
		if total >= 1000 || own >= 20 {
			return nil, fmt.Errorf("investigation: evidence quota reached")
		}
		return scanEvidence(tx.QueryRow(ctx, `INSERT INTO evidence_exports(owner_subject,application_id,environment_id,filter,principal,sensitive) VALUES($1,$2,$3,$4,$5,$6) RETURNING `+evidenceCols, a.Subject, v.ApplicationID, v.EnvironmentID, v.Filter, v.Principal, v.Sensitive))
	}, &out)
	return out, err
}
func (s *Store) EvidenceExport(ctx context.Context, id string) (EvidenceExport, error) {
	return scanEvidence(s.pool.QueryRow(ctx, `SELECT `+evidenceCols+` FROM evidence_exports WHERE id::text=$1 AND expires_at>now()`, id))
}
func (s *Store) ClaimEvidence(ctx context.Context) (EvidenceExport, error) {
	// Expired leases can retry after a crash. Three failures become terminal.
	if _, err := s.pool.Exec(ctx, `UPDATE evidence_exports SET state='failed',etag=gen_random_uuid()::text WHERE attempts=3 AND state='running' AND lease_until<now()`); err != nil {
		return EvidenceExport{}, err
	}
	return scanEvidence(s.pool.QueryRow(ctx, `UPDATE evidence_exports SET state='running',attempts=attempts+1,lease_until=now()+interval '6 minutes',etag=gen_random_uuid()::text WHERE id=(SELECT id FROM evidence_exports WHERE expires_at>now() AND attempts<3 AND (state='pending' OR state='running' AND lease_until<now()) ORDER BY created_at FOR UPDATE SKIP LOCKED LIMIT 1) RETURNING `+evidenceCols))
}
func (s *Store) FinishEvidence(ctx context.Context, v EvidenceExport, success bool) error {
	state := "failed"
	if success {
		state = "done"
	}
	return s.inTx(ctx, func(tx pgx.Tx) error {
		tag, err := tx.Exec(ctx, `UPDATE evidence_exports SET state=$1,artifact_key=$2,sha256=$3,row_count=$4,truncated=$5,lease_until=NULL,etag=gen_random_uuid()::text WHERE id::text=$6 AND etag=$7 AND state='running' AND expires_at>now()`, state, v.ArtifactKey, v.SHA256, v.RowCount, v.Truncated, v.ID, v.Etag)
		if err != nil {
			return err
		}
		if tag.RowsAffected() != 1 {
			return ErrEtagMismatch
		}
		return writeAudit(ctx, tx, Audit{Subject: "system:evidence", Actor: "system", Channel: "system", Action: "evidence." + state, Resource: "evidence/" + v.ID})
	})
}
func (s *Store) ExpiredEvidence(ctx context.Context) ([]EvidenceExport, error) {
	rows, err := s.pool.Query(ctx, `SELECT `+evidenceCols+` FROM evidence_exports WHERE expires_at<=now() AND (state<>'running' OR lease_until<now()) ORDER BY expires_at LIMIT 50`)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, func(r pgx.CollectableRow) (EvidenceExport, error) { return scanEvidence(r) })
}
func (s *Store) DeleteExpiredEvidence(ctx context.Context, id string) error {
	_, err := s.pool.Exec(ctx, `DELETE FROM evidence_exports WHERE id::text=$1 AND expires_at<=now()`, id)
	return err
}

// Recheck local account state and current app bindings. Roles captured when the
// job was created are a ceiling, so later promotions cannot widen an export.
func (s *Store) EvidencePrincipal(ctx context.Context, p auth.Principal) (*auth.Principal, error) {
	if strings.HasPrefix(p.Subject, "local:") {
		var roles []string
		var disabled bool
		err := s.pool.QueryRow(ctx, `SELECT roles,disabled FROM local_users WHERE username=$1`, strings.TrimPrefix(p.Subject, "local:")).Scan(&roles, &disabled)
		if errors.Is(err, pgx.ErrNoRows) || disabled {
			return nil, ErrNotFound
		}
		if err != nil {
			return nil, err
		}
		p.Roles = slices.DeleteFunc(p.Roles, func(r auth.Role) bool { return !slices.Contains(roles, string(r)) })
	}
	ceiling := append([]auth.Role(nil), p.Roles...)
	resolved, err := s.ResolveApplicationAccess(ctx, &p)
	if err != nil {
		return nil, err
	}
	resolved.Roles = slices.DeleteFunc(resolved.Roles, func(r auth.Role) bool { return !slices.Contains(ceiling, r) })
	return resolved, nil
}

func (s *Store) EvidenceExports(ctx context.Context, subject, app, environment string) ([]EvidenceExport, error) {
	rows, err := s.pool.Query(ctx, `SELECT `+evidenceCols+` FROM evidence_exports WHERE owner_subject=$1 AND application_id=$2 AND environment_id=$3 AND expires_at>now() ORDER BY created_at DESC LIMIT 20`, subject, app, environment)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, func(r pgx.CollectableRow) (EvidenceExport, error) { return scanEvidence(r) })
}
