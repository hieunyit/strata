package store

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
)

var ErrRequestReused = errors.New("store: request_id reused with different content")

// EventAnnotation is independent of immutable ClickHouse event rows.
type EventAnnotation struct {
	CaseOnly      bool      `json:"case_only,omitempty"`
	BlockID       string    `json:"block_id"`
	Reason        string    `json:"reason"`
	MarkedBy      string    `json:"marked_by"`
	MarkedSubject string    `json:"marked_subject"`
	MarkedAt      time.Time `json:"marked_at"`
	Etag          string    `json:"etag"`
}

// MarkEventFalsePositive atomically saves the annotation and its audit entry.
// Creation takes an empty etag; every subsequent edit requires the current one.
func (s *Store) MarkEventFalsePositive(ctx context.Context, block, reason, etag string, a Audit) (EventAnnotation, error) {
	var result EventAnnotation
	if block == "" || len(block) > 128 || strings.TrimSpace(reason) == "" || len(reason) > 500 || a.Subject == "" || len(a.RequestID) > 128 {
		return result, fmt.Errorf("store: invalid event annotation")
	}
	err := s.inTx(ctx, func(tx pgx.Tx) error {
		// Lock request before block, so concurrent retries cannot both audit a write.
		if a.RequestID != "" {
			if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1, 711))`, a.Subject+"/"+a.RequestID); err != nil {
				return err
			}
			var raw []byte
			err := tx.QueryRow(ctx, `SELECT response FROM event_annotation_requests WHERE subject=$1 AND request_id=$2`, a.Subject, a.RequestID).Scan(&raw)
			if err == nil {
				if err := json.Unmarshal(raw, &result); err != nil {
					return err
				}
				if result.BlockID != block || result.Reason != reason {
					return ErrRequestReused
				}
				return nil
			}
			if !errors.Is(err, pgx.ErrNoRows) {
				return err
			}
		}
		if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1, 712))`, block); err != nil {
			return err
		}
		var before EventAnnotation
		err := tx.QueryRow(ctx, `SELECT block_id,reason,marked_by,marked_subject,marked_at,etag FROM event_annotations WHERE block_id=$1`, block).Scan(&before.BlockID, &before.Reason, &before.MarkedBy, &before.MarkedSubject, &before.MarkedAt, &before.Etag)
		if err != nil && !errors.Is(err, pgx.ErrNoRows) {
			return err
		}
		if before.Etag != etag {
			return ErrEtagMismatch
		}
		next, err := newEtag()
		if err != nil {
			return err
		}
		result = EventAnnotation{BlockID: block, Reason: reason, MarkedBy: a.Actor, MarkedSubject: a.Subject, Etag: next}
		err = tx.QueryRow(ctx, `INSERT INTO event_annotations(block_id,reason,marked_by,marked_subject,etag) VALUES($1,$2,$3,$4,$5)
   ON CONFLICT(block_id) DO UPDATE SET case_only=false,reason=excluded.reason,marked_by=excluded.marked_by,marked_subject=excluded.marked_subject,marked_at=now(),etag=excluded.etag RETURNING marked_at`, block, reason, a.Actor, a.Subject, next).Scan(&result.MarkedAt)
		if err != nil {
			return err
		}
		result.MarkedAt = result.MarkedAt.UTC()
		if a.RuleContext != nil {
			if err := writeRuleAnnotationContext(ctx, tx, block, a.RuleContext, before.Etag == "", result.MarkedAt); err != nil {
				return err
			}
		}
		if before.Etag != "" {
			a.Before = before
		}
		a.After = result
		if a.RuleContext != nil {
			a.After = map[string]any{"annotation": result, "event_context": a.RuleContext}
		}
		if err := writeAudit(ctx, tx, a); err != nil {
			return err
		}
		if a.RequestID != "" {
			raw, err := json.Marshal(result)
			if err != nil {
				return err
			}
			_, err = tx.Exec(ctx, `INSERT INTO event_annotation_requests(subject,request_id,response) VALUES($1,$2,$3)`, a.Subject, a.RequestID, raw)
			return err
		}
		return nil
	})
	if err != nil {
		return EventAnnotation{}, fmt.Errorf("store: annotate event: %w", err)
	}
	return result, nil
}

// EventAnnotations overlays one search page in a single database query.
func (s *Store) EventAnnotations(ctx context.Context, blocks []string) (map[string]EventAnnotation, error) {
	if len(blocks) > 200 {
		return nil, fmt.Errorf("store: annotation page exceeds 200")
	}
	result := map[string]EventAnnotation{}
	if len(blocks) == 0 {
		return result, nil
	}
	rows, err := s.pool.Query(ctx, `SELECT block_id,reason,marked_by,marked_subject,marked_at,etag,case_only FROM event_annotations WHERE block_id=ANY($1)`, blocks)
	if err != nil {
		return nil, fmt.Errorf("store: read annotations: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var a EventAnnotation
		if err := rows.Scan(&a.BlockID, &a.Reason, &a.MarkedBy, &a.MarkedSubject, &a.MarkedAt, &a.Etag, &a.CaseOnly); err != nil {
			return nil, err
		}
		a.MarkedAt = a.MarkedAt.UTC()
		result[a.BlockID] = a
	}
	return result, rows.Err()
}
