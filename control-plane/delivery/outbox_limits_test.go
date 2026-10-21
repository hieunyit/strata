package delivery

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"sync/atomic"
	"testing"

	"github.com/strata/strata/control-plane/localauth/localauthtest"
)

func TestOutboxBoundedRetriesAtomicEnqueueAndDisable(t *testing.T) {
	pool := localauthtest.Pool(t)
	ctx := context.Background()
	var calls atomic.Int32
	receiver := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { calls.Add(1); w.WriteHeader(503) }))
	defer receiver.Close()
	s, err := New(Config{URL: receiver.URL, Key: bytes.Repeat([]byte{4}, 32), Allow: []netip.Prefix{netip.MustParsePrefix("127.0.0.1/32")}, TLS: receiver.Client().Transport.(*http.Transport).TLSClientConfig})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	o := Outbox{Pool: pool, Sender: s}
	if err := o.ConfigureAudit(ctx, true); err != nil {
		t.Fatal(err)
	}
	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec(ctx, `INSERT INTO audit_log(actor,subject,channel,action,resource) VALUES('example-admin','local:example-admin','api','policies.update','policies/example-api')`); err != nil {
		t.Fatal(err)
	}
	if err := tx.Rollback(ctx); err != nil {
		t.Fatal(err)
	}
	var n int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM outbound_deliveries`).Scan(&n); err != nil || n != 0 {
		t.Fatal("rolled-back audit queued", n, err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO audit_log(actor,subject,channel,action,resource) VALUES('example-admin','local:example-admin','api','policies.update','policies/example-api')`); err != nil {
		t.Fatal(err)
	}
	for range 5 {
		if _, err := pool.Exec(ctx, `UPDATE outbound_deliveries SET next_attempt=now()`); err != nil {
			t.Fatal(err)
		}
		if work, err := o.Step(ctx); err != nil || !work {
			t.Fatal("retry", work, err)
		}
	}
	if work, err := o.Step(ctx); err != nil || work || calls.Load() != 5 {
		t.Fatal("retry budget exceeded", work, err, calls.Load())
	}
	if _, err := pool.Exec(ctx, `INSERT INTO audit_log(actor,subject,channel,action,resource) VALUES('example-admin','local:example-admin','api','policies.update','policies/example-api')`); err != nil {
		t.Fatal(err)
	}
	if err := o.ConfigureAudit(ctx, false); err != nil {
		t.Fatal(err)
	}
	if work, err := o.Step(ctx); err != nil || work {
		t.Fatal("disabled audit still sent", work, err)
	}
	// A full queue drops the external copy rather than failing the local audit.
	if _, err := pool.Exec(ctx, `DELETE FROM outbound_deliveries; INSERT INTO outbound_deliveries(kind,dedupe) SELECT 'alert',n::text FROM generate_series(1,10000) n`); err != nil {
		t.Fatal(err)
	}
	if err := o.ConfigureAudit(ctx, true); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO audit_log(actor,subject,channel,action,resource) VALUES('example-admin','local:example-admin','api','policies.update','policies/example-api')`); err != nil {
		t.Fatal("queue pressure failed audit", err)
	}
	var dropped int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM outbound_deliveries`).Scan(&n); err != nil || n != 10000 {
		t.Fatal("unbounded queue", n, err)
	}
	if err := pool.QueryRow(ctx, `SELECT dropped FROM outbound_settings`).Scan(&dropped); err != nil || dropped != 1 {
		t.Fatal("missing drop counter", dropped, err)
	}
}
