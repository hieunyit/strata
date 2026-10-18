package store

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
)

// AuditFilter is applied by PostgreSQL before limiting the newest matching rows.
// Time bounds are [From, To); Action and Resource are literal substrings.
type AuditFilter struct {
	Actor, Channel, Action, Resource string
	From, To                         time.Time
	Limit                            int
}

func (s *Store) SearchAudit(ctx context.Context, f AuditFilter) ([]Audit, error) {
	if f.Limit == 0 {
		f.Limit = 100
	}
	// The HTTP reader may request one extra row to report has_more.
	if f.Limit < 1 || f.Limit > 501 {
		return nil, fmt.Errorf("store: invalid audit limit")
	}
	if !f.From.IsZero() && !f.To.IsZero() && !f.From.Before(f.To) {
		return nil, fmt.Errorf("store: invalid audit time range")
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	where := []string{"true"}
	args := []any{}
	add := func(clause string, v any) {
		args = append(args, v)
		where = append(where, fmt.Sprintf(clause, len(args)))
	}
	if f.Actor != "" {
		add("actor = $%d", f.Actor)
	}
	if f.Channel != "" {
		add("channel = $%d", f.Channel)
	}
	if f.Action != "" {
		add("strpos(lower(action), lower($%d)) > 0", f.Action)
	}
	if f.Resource != "" {
		add("strpos(lower(resource), lower($%d)) > 0", f.Resource)
	}
	if !f.From.IsZero() {
		add("at >= $%d", f.From)
	}
	if !f.To.IsZero() {
		add("at < $%d", f.To)
	}
	args = append(args, f.Limit)
	query := fmt.Sprintf(`SELECT at,actor,subject,channel,action,resource,request_id,before,after
	 FROM audit_log WHERE %s ORDER BY at DESC,id DESC LIMIT $%d`, strings.Join(where, " AND "), len(args))
	rows, err := s.pool.Query(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("store: search audit: %w", err)
	}
	return pgx.CollectRows(rows, func(r pgx.CollectableRow) (Audit, error) {
		var a Audit
		var before, after []byte
		err := r.Scan(&a.At, &a.Actor, &a.Subject, &a.Channel, &a.Action, &a.Resource, &a.RequestID, &before, &after)
		if before != nil {
			a.Before = json.RawMessage(before)
		}
		if after != nil {
			a.After = json.RawMessage(after)
		}
		return a, err
	})
}
