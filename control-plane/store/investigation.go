package store

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
)

// Investigation writes commit their replayable result and audit together. The
// caller validates current application/event access before invoking these methods.
func (s *Store) investigationOnce(ctx context.Context, input any, a Audit, run func(pgx.Tx) (any, error), out any) error {
	if a.Subject == "" || a.RequestID == "" || len(a.RequestID) > 128 {
		return fmt.Errorf("investigation: request_id required")
	}
	raw, err := json.Marshal(struct {
		Action, Resource string
		Input            any
	}{a.Action, a.Resource, input})
	if err != nil {
		return err
	}
	digest := sha256.Sum256(raw)
	return s.inTx(ctx, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1,741))`, a.Subject+"/"+a.RequestID); err != nil {
			return err
		}
		var old, reply []byte
		err := tx.QueryRow(ctx, `SELECT fingerprint,response FROM investigation_requests WHERE subject=$1 AND request_id=$2`, a.Subject, a.RequestID).Scan(&old, &reply)
		if err == nil {
			if !bytes.Equal(old, digest[:]) {
				return ErrRequestReused
			}
			return json.Unmarshal(reply, out)
		}
		if !errors.Is(err, pgx.ErrNoRows) {
			return err
		}
		result, err := run(tx)
		if err != nil {
			return err
		}
		reply, err = json.Marshal(result)
		if err != nil {
			return err
		}
		// Filters and case notes may contain personal data: the audit records only
		// the operation/resource. The bounded retention tables own the content.
		a.Before, a.After = nil, nil
		if err := writeAudit(ctx, tx, a); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `INSERT INTO investigation_requests(subject,request_id,fingerprint,response) VALUES($1,$2,$3,$4)`, a.Subject, a.RequestID, digest[:], reply); err != nil {
			return err
		}
		return json.Unmarshal(reply, out)
	})
}

type SavedSearch struct {
	Editable      bool            `json:"editable"`
	ID            string          `json:"id"`
	ApplicationID string          `json:"application_id"`
	EnvironmentID string          `json:"environment_id"`
	Owner         string          `json:"owner"`
	Title         string          `json:"title"`
	Shared        bool            `json:"shared"`
	Sensitive     bool            `json:"sensitive"`
	Filter        json.RawMessage `json:"filter"`
	Etag          string          `json:"etag"`
	ExpiresAt     time.Time       `json:"expires_at"`
}

const savedSearchCols = `id::text,application_id,environment_id,owner_subject,title,shared,sensitive,filter,etag,expires_at`

func scanSavedSearch(row pgx.Row) (SavedSearch, error) {
	var v SavedSearch
	err := row.Scan(&v.ID, &v.ApplicationID, &v.EnvironmentID, &v.Owner, &v.Title, &v.Shared, &v.Sensitive, &v.Filter, &v.Etag, &v.ExpiresAt)
	if errors.Is(err, pgx.ErrNoRows) {
		err = ErrNotFound
	}
	return v, err
}
func (s *Store) SavedSearch(ctx context.Context, id string) (SavedSearch, error) {
	return scanSavedSearch(s.pool.QueryRow(ctx, `SELECT `+savedSearchCols+` FROM saved_searches WHERE id::text=$1 AND expires_at>now()`, id))
}
func (s *Store) SavedSearches(ctx context.Context, app, environment, subject, after string) ([]SavedSearch, error) {
	rows, err := s.pool.Query(ctx, `SELECT `+savedSearchCols+` FROM saved_searches WHERE application_id=$1 AND environment_id=$2 AND (owner_subject=$3 OR shared) AND expires_at>now() AND id::text>$4 ORDER BY id LIMIT 50`, app, environment, subject, after)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, func(r pgx.CollectableRow) (SavedSearch, error) { return scanSavedSearch(r) })
}
func (s *Store) SaveSearch(ctx context.Context, v SavedSearch, create bool, a Audit) (SavedSearch, error) {
	var out SavedSearch
	if !appID.MatchString(v.ApplicationID) || !appID.MatchString(v.EnvironmentID) || strings.TrimSpace(v.Title) == "" || len(v.Title) > 100 || !json.Valid(v.Filter) || len(v.Filter) > 8192 {
		return out, fmt.Errorf("investigation: invalid saved search")
	}
	err := s.investigationOnce(ctx, struct {
		Value  SavedSearch
		Create bool
	}{v, create}, a, func(tx pgx.Tx) (any, error) {
		next, err := newEtag()
		if err != nil {
			return nil, err
		}
		if create {
			var count int
			if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1,742))`, a.Subject); err != nil {
				return nil, err
			}
			if err := tx.QueryRow(ctx, `SELECT count(*) FROM saved_searches WHERE owner_subject=$1 AND expires_at>now()`, a.Subject).Scan(&count); err != nil {
				return nil, err
			}
			if count >= 100 {
				return nil, fmt.Errorf("investigation: saved search quota reached")
			}
			return scanSavedSearch(tx.QueryRow(ctx, `INSERT INTO saved_searches(id,application_id,environment_id,owner_subject,title,shared,sensitive,filter,etag) VALUES(gen_random_uuid(),$1,$2,$3,$4,$5,$6,$7,$8) RETURNING `+savedSearchCols, v.ApplicationID, v.EnvironmentID, a.Subject, v.Title, v.Shared, v.Sensitive, v.Filter, next))
		}
		result, err := scanSavedSearch(tx.QueryRow(ctx, `UPDATE saved_searches SET title=$1,shared=$2,sensitive=$3,filter=$4,etag=$5 WHERE id::text=$6 AND owner_subject=$7 AND application_id=$8 AND environment_id=$9 AND etag=$10 AND expires_at>now() RETURNING `+savedSearchCols, v.Title, v.Shared, v.Sensitive, v.Filter, next, v.ID, a.Subject, v.ApplicationID, v.EnvironmentID, v.Etag))
		if errors.Is(err, ErrNotFound) {
			err = ErrEtagMismatch
		}
		return result, err
	}, &out)
	return out, err
}

type EventCase struct {
	BlockID   string    `json:"block_id"`
	Assignee  string    `json:"assignee"`
	Status    string    `json:"status"`
	Note      string    `json:"note"`
	Etag      string    `json:"etag"`
	ExpiresAt time.Time `json:"expires_at"`
}

func (s *Store) EventCase(ctx context.Context, block string) (EventCase, error) {
	var v EventCase
	var raw []byte
	err := s.pool.QueryRow(ctx, `SELECT case_data,case_etag,case_expires_at FROM event_annotations WHERE block_id=$1 AND case_expires_at>now()`, block).Scan(&raw, &v.Etag, &v.ExpiresAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return v, ErrNotFound
	}
	if err != nil {
		return v, err
	}
	etag, expires := v.Etag, v.ExpiresAt
	err = json.Unmarshal(raw, &v)
	v.Etag, v.ExpiresAt = etag, expires
	return v, err
}
func (s *Store) SaveEventCase(ctx context.Context, v EventCase, a Audit) (EventCase, error) {
	var out EventCase
	if v.BlockID == "" || len(v.BlockID) > 128 || len(v.Assignee) > 256 || len(v.Note) > 1000 || (v.Status != "open" && v.Status != "investigating" && v.Status != "resolved") {
		return out, fmt.Errorf("investigation: invalid case")
	}
	err := s.investigationOnce(ctx, v, a, func(tx pgx.Tx) (any, error) {
		if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1,712))`, v.BlockID); err != nil {
			return nil, err
		}
		var old string
		err := tx.QueryRow(ctx, `SELECT coalesce(case_etag,'') FROM event_annotations WHERE block_id=$1 AND case_expires_at>now()`, v.BlockID).Scan(&old)
		if err != nil && !errors.Is(err, pgx.ErrNoRows) {
			return nil, err
		}
		if old != v.Etag {
			return nil, ErrEtagMismatch
		}
		next, err := newEtag()
		if err != nil {
			return nil, err
		}
		v.Etag = next
		raw, err := json.Marshal(v)
		if err != nil {
			return nil, err
		}
		err = tx.QueryRow(ctx, `INSERT INTO event_annotations(block_id,reason,marked_by,marked_subject,etag,case_only,case_data,case_etag,case_expires_at) VALUES($1,'-', $2,$3,$4,true,$5,$4,now()+interval '30 days') ON CONFLICT(block_id) DO UPDATE SET case_data=excluded.case_data,case_etag=excluded.case_etag,case_expires_at=excluded.case_expires_at RETURNING case_expires_at`, v.BlockID, a.Actor, a.Subject, next, raw).Scan(&v.ExpiresAt)
		return v, err
	}, &out)
	return out, err
}

// PurgeInvestigationContent removes notes, filters and idempotent copies under
// the same bounded retention policy. Audit contains no copy of this content.
func (s *Store) PurgeInvestigationContent(ctx context.Context) error {
	return s.inTx(ctx, func(tx pgx.Tx) error {
		for _, query := range []string{`DELETE FROM saved_searches WHERE expires_at<=now()`, `DELETE FROM event_annotations WHERE case_only AND case_expires_at<=now()`, `UPDATE event_annotations SET case_data=NULL,case_etag=NULL,case_expires_at=NULL WHERE case_expires_at<=now()`, `DELETE FROM investigation_requests WHERE created_at<=now()-interval '30 days'`} {
			if _, err := tx.Exec(ctx, query); err != nil {
				return err
			}
		}
		return nil
	})
}

// An explicit assignee must have a binding on an application/environment that
// owns this exact event route and node. Unknown subjects never become assignees.
func (s *Store) EventAssigneeAllowed(ctx context.Context, policy, host, path, node, subject string) (bool, error) {
	var allowed bool
	err := s.pool.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM application_role_bindings b JOIN application_routes r ON r.application_id=b.application_id AND (b.environment_id IS NULL OR b.environment_id=r.environment_id) JOIN application_environments e ON (e.application_id,e.id)=(r.application_id,r.environment_id) JOIN nodes n ON n.group_id=e.group_id JOIN policies p ON p.id=r.policy_id WHERE b.subject=$1 AND p.name=$2 AND r.host=lower($3) AND starts_with($4,r.path_prefix) AND n.id=$5 AND n.revoked_at IS NULL AND NOT EXISTS(SELECT 1 FROM local_users u WHERE 'local:'||u.username=b.subject AND u.disabled))`, subject, policy, host, path, node).Scan(&allowed)
	return allowed, err
}
