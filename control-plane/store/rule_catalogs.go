package store

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/strata/strata/control-plane/rulecat"
)

type CatalogSnapshot struct {
	Digest     string    `json:"digest"`
	CreatedAt  time.Time `json:"created_at"`
	LastSeenAt time.Time `json:"last_seen_at"`
	Current    bool      `json:"current"`
	Rules      int       `json:"rules"`
}

func (s *Store) RecordCatalog(ctx context.Context, entries []rulecat.Entry) (string, error) {
	if len(entries) > 100000 {
		return "", fmt.Errorf("catalog: too many rules")
	}
	raw, err := json.Marshal(entries)
	if err != nil {
		return "", err
	}
	if len(raw) > 32<<20 {
		return "", fmt.Errorf("catalog: metadata exceeds 32 MiB")
	}
	sum := sha256.Sum256(raw)
	digest := hex.EncodeToString(sum[:])
	err = s.inTx(ctx, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(742001)`); err != nil {
			return err
		}
		tag, err := tx.Exec(ctx, `INSERT INTO rule_catalogs(digest,entries) VALUES($1,$2) ON CONFLICT(digest) DO NOTHING`, digest, raw)
		if err != nil {
			return err
		}
		var old string
		err = tx.QueryRow(ctx, `SELECT current_digest FROM rule_catalog_settings WHERE id`).Scan(&old)
		if err != nil && !errors.Is(err, pgx.ErrNoRows) {
			return err
		}
		if old != digest {
			if _, err := tx.Exec(ctx, `INSERT INTO rule_catalog_settings(id,current_digest) VALUES(true,$1) ON CONFLICT(id) DO UPDATE SET current_digest=excluded.current_digest`, digest); err != nil {
				return err
			}
			if _, err := tx.Exec(ctx, `UPDATE rule_catalogs SET last_seen_at=now() WHERE digest=$1`, digest); err != nil {
				return err
			}
			if err := writeAudit(ctx, tx, Audit{Actor: "system", Subject: "system:rule-catalog", Channel: "system", Action: "catalog.changed", Resource: "catalogs/" + digest, After: map[string]any{"digest": digest, "rules": len(entries), "new": tag.RowsAffected() > 0}}); err != nil {
				return err
			}
		}
		_, err = tx.Exec(ctx, `DELETE FROM rule_catalogs WHERE digest<>$1 AND digest NOT IN(SELECT digest FROM rule_catalogs ORDER BY last_seen_at DESC,digest LIMIT 20)`, digest)
		return err
	})
	return digest, err
}
func (s *Store) CatalogHistory(ctx context.Context) ([]CatalogSnapshot, error) {
	rows, err := s.pool.Query(ctx, `SELECT digest,created_at,last_seen_at,digest=(SELECT current_digest FROM rule_catalog_settings WHERE id),jsonb_array_length(entries) FROM rule_catalogs ORDER BY last_seen_at DESC,digest LIMIT 20`)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, func(r pgx.CollectableRow) (CatalogSnapshot, error) {
		var v CatalogSnapshot
		err := r.Scan(&v.Digest, &v.CreatedAt, &v.LastSeenAt, &v.Current, &v.Rules)
		return v, err
	})
}
func (s *Store) CatalogEntries(ctx context.Context, digest string) ([]rulecat.Entry, error) {
	var raw []byte
	err := s.pool.QueryRow(ctx, `SELECT entries FROM rule_catalogs WHERE digest=$1`, digest).Scan(&raw)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	var out []rulecat.Entry
	err = json.Unmarshal(raw, &out)
	return out, err
}
