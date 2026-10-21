package store

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/jackc/pgx/v5"
	"github.com/strata/strata/control-plane/apidiscovery"
	"time"
)

type DiscoveryDocument struct {
	ApplicationID string                   `json:"application_id"`
	EnvironmentID string                   `json:"environment_id"`
	ScopeEtag     string                   `json:"-"`
	Etag          string                   `json:"etag"`
	Operations    []apidiscovery.Operation `json:"operations"`
	Digest        string                   `json:"digest"`
	UpdatedAt     time.Time                `json:"updated_at"`
	Owner         string                   `json:"owner"`
}

const discoveryDocCols = `application_id,environment_id,scope_etag,etag,operations,digest,updated_at,owner_subject`

func scanDiscoveryDocument(row pgx.Row) (DiscoveryDocument, error) {
	var v DiscoveryDocument
	var raw []byte
	err := row.Scan(&v.ApplicationID, &v.EnvironmentID, &v.ScopeEtag, &v.Etag, &raw, &v.Digest, &v.UpdatedAt, &v.Owner)
	if errors.Is(err, pgx.ErrNoRows) {
		err = ErrNotFound
	}
	if err == nil {
		err = json.Unmarshal(raw, &v.Operations)
	}
	return v, err
}
func (s *Store) DiscoveryDocument(ctx context.Context, app, env, scope string) (DiscoveryDocument, error) {
	return scanDiscoveryDocument(s.pool.QueryRow(ctx, `SELECT `+discoveryDocCols+` FROM discovery_documents WHERE application_id=$1 AND environment_id=$2 AND scope_etag=$3`, app, env, scope))
}
func (s *Store) SaveDiscoveryDocument(ctx context.Context, v DiscoveryDocument, a Audit) (DiscoveryDocument, error) {
	var out DiscoveryDocument
	if len(v.Operations) > 2000 || !appID.MatchString(v.ApplicationID) || !appID.MatchString(v.EnvironmentID) {
		return out, fmt.Errorf("discovery: invalid document")
	}
	err := s.investigationOnce(ctx, v, a, func(tx pgx.Tx) (any, error) {
		var current bool
		if err := tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM applications WHERE id=$1 AND etag=$2)`, v.ApplicationID, v.ScopeEtag).Scan(&current); err != nil {
			return nil, err
		}
		if !current {
			return nil, ErrEtagMismatch
		}
		if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(744002)`); err != nil {
			return nil, err
		}
		before, err := scanDiscoveryDocument(tx.QueryRow(ctx, `SELECT `+discoveryDocCols+` FROM discovery_documents WHERE application_id=$1 AND environment_id=$2 FOR UPDATE`, v.ApplicationID, v.EnvironmentID))
		raw, encodeErr := json.Marshal(v.Operations)
		if encodeErr != nil {
			return nil, encodeErr
		}
		if errors.Is(err, ErrNotFound) {
			if v.Etag != "" {
				return nil, ErrEtagMismatch
			}
			var count int
			if err = tx.QueryRow(ctx, `SELECT count(*) FROM discovery_documents`).Scan(&count); err != nil {
				return nil, err
			}
			if count >= 1000 {
				return nil, fmt.Errorf("discovery: document quota")
			}
			return scanDiscoveryDocument(tx.QueryRow(ctx, `INSERT INTO discovery_documents(application_id,environment_id,scope_etag,operations,digest,owner_subject) VALUES($1,$2,$3,$4,$5,$6) RETURNING `+discoveryDocCols, v.ApplicationID, v.EnvironmentID, v.ScopeEtag, raw, apidiscovery.Digest(v.Operations), a.Subject))
		}
		if err != nil {
			return nil, err
		}
		if before.Etag != v.Etag {
			return nil, ErrEtagMismatch
		}
		return scanDiscoveryDocument(tx.QueryRow(ctx, `UPDATE discovery_documents SET operations=$3,digest=$4,scope_etag=$5,owner_subject=$6,etag=gen_random_uuid()::text,updated_at=now() WHERE application_id=$1 AND environment_id=$2 RETURNING `+discoveryDocCols, v.ApplicationID, v.EnvironmentID, raw, apidiscovery.Digest(v.Operations), v.ScopeEtag, a.Subject))
	}, &out)
	return out, err
}

// The current etag remains accessible after a scope change so an authorized
// operator can explicitly replace the baseline instead of becoming stuck.
func (s *Store) DiscoveryDocumentEtag(ctx context.Context, app, env string) (string, error) {
	var etag string
	err := s.pool.QueryRow(ctx, `SELECT etag FROM discovery_documents WHERE application_id=$1 AND environment_id=$2`, app, env).Scan(&etag)
	if errors.Is(err, pgx.ErrNoRows) {
		err = ErrNotFound
	}
	return etag, err
}
