package delivery

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"regexp"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

type Outbox struct {
	Pool   *pgxpool.Pool
	Sender *Sender
}

var safeAction = regexp.MustCompile(`^[A-Za-z0-9_.:-]{1,100}$`)

type job struct {
	id, kind string
	audit    *int64
	payload  []byte
	attempts int
}

// ConfigureAudit starts copying new audit rows only. Queue writes are triggered
// in the same transaction, so commit order cannot skip a cursor position.
func (o *Outbox) ConfigureAudit(ctx context.Context, enabled bool) error {
	tx, err := o.Pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if _, err := tx.Exec(ctx, `UPDATE outbound_settings SET audit_enabled=$1 WHERE id=1`, enabled); err != nil {
		return err
	}
	if !enabled {
		if _, err := tx.Exec(ctx, `UPDATE outbound_deliveries SET state='failed',finished_at=now(),lease_until=NULL WHERE kind='audit' AND state IN ('pending','running')`); err != nil {
			return err
		}
	}
	return tx.Commit(ctx)
}

func (o *Outbox) claim(ctx context.Context) (job, error) {
	var j job
	_, err := o.Pool.Exec(ctx, `UPDATE outbound_deliveries SET state='failed',finished_at=now() WHERE state='running' AND lease_until<now() AND attempts>=5`)
	if err != nil {
		return j, err
	}
	err = o.Pool.QueryRow(ctx, `UPDATE outbound_deliveries SET state='running',attempts=attempts+1,lease_until=now()+interval '60 seconds' WHERE id=(SELECT id FROM outbound_deliveries WHERE attempts<5 AND (kind<>'audit' OR (SELECT audit_enabled FROM outbound_settings WHERE id=1)) AND ((state='pending' AND next_attempt<=now()) OR (state='running' AND lease_until<now())) ORDER BY created_at LIMIT 1 FOR UPDATE SKIP LOCKED) RETURNING id::text,kind,audit_id,payload,attempts`).Scan(&j.id, &j.kind, &j.audit, &j.payload, &j.attempts)
	return j, err
}

func opaque(key []byte, value string) string {
	h := hmac.New(sha256.New, key)
	_, _ = h.Write([]byte("strata/outbound/v1/" + value))
	return hex.EncodeToString(h.Sum(nil)[:16])
}

func (o *Outbox) auditPayload(ctx context.Context, id int64) ([]byte, error) {
	var at time.Time
	var subject, action, resource, channel string
	err := o.Pool.QueryRow(ctx, `SELECT at,subject,action,resource,channel FROM audit_log WHERE id=$1`, id).Scan(&at, &subject, &action, &resource, &channel)
	if err != nil {
		return nil, err
	}
	// Actor names, raw subjects/resources, IPs and before/after documents never
	// enter an external copy. Stable keyed pseudonyms still allow correlation.
	actionParts := strings.Split(action, "/")
	action = actionParts[len(actionParts)-1]
	if !safeAction.MatchString(action) {
		action = "custom"
	}
	switch channel {
	case "api", "ui", "gitops", "system":
	default:
		channel = "other"
	}
	return json.Marshal(map[string]any{"type": "audit", "at": at.UTC(), "event_id": id, "subject": opaque(o.Sender.key, subject), "action": action, "resource": opaque(o.Sender.key, resource), "channel": channel})
}

// Step sends at most one job. A crash after receiver acceptance may resend the
// same delivery ID, so receivers should deduplicate X-Strata-Delivery.
func (o *Outbox) Step(ctx context.Context) (bool, error) {
	if o.Sender == nil {
		return false, nil
	}
	ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	j, err := o.claim(ctx)
	if errors.Is(err, pgx.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("outbound claim: %w", err)
	}
	payload := j.payload
	if j.kind == "audit" {
		if j.audit == nil {
			err = ErrPermanent
		} else {
			payload, err = o.auditPayload(ctx, *j.audit)
		}
	}
	if err == nil {
		err = o.Sender.Send(ctx, j.id, payload)
	}
	state := "delivered"
	if err != nil {
		state = "pending"
		if errors.Is(err, ErrPermanent) || j.attempts >= 5 {
			state = "failed"
		}
	}
	// Use a fresh bounded cleanup context if the send exhausted its deadline.
	finish, done := context.WithTimeout(context.WithoutCancel(ctx), 3*time.Second)
	defer done()
	_, saveErr := o.Pool.Exec(finish, `UPDATE outbound_deliveries SET state=$2,lease_until=NULL,next_attempt=now()+$3*interval '1 second',finished_at=CASE WHEN $2 IN ('delivered','failed') THEN now() ELSE NULL END WHERE id::text=$1 AND state='running' AND attempts=$4`, j.id, state, 30*(1<<uint(j.attempts-1)), j.attempts)
	if saveErr != nil {
		return true, fmt.Errorf("outbound receipt: %w", saveErr)
	}
	return true, nil
}

func (o *Outbox) Run(ctx context.Context) {
	timer := time.NewTicker(time.Second)
	defer timer.Stop()
	defer o.Sender.Close()
	for {
		select {
		case <-ctx.Done():
			return
		case <-timer.C:
			for range 10 {
				work, err := o.Step(ctx)
				if err != nil {
					log.Print("[WARN] outbound delivery queue unavailable")
					break
				}
				if !work || ctx.Err() != nil {
					break
				}
			}
		}
	}
}
