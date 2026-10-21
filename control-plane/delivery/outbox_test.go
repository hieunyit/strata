package delivery

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/strata/strata/control-plane/localauth/localauthtest"
)

func TestDurableAuditDeliveryRetriesAndAllowlist(t *testing.T) {
	pool := localauthtest.Pool(t)
	ctx := context.Background()
	type received struct{ payload, id string }
	messages := make(chan received, 4)
	var calls atomic.Int32
	receiver := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		data, _ := io.ReadAll(r.Body)
		messages <- received{string(data), r.Header.Get("X-Strata-Delivery")}
		if calls.Add(1) == 1 {
			w.WriteHeader(503)
		} else {
			w.WriteHeader(204)
		}
	}))
	defer receiver.Close()
	sender, err := New(Config{URL: receiver.URL, Key: bytes.Repeat([]byte{5}, 32), Allow: []netip.Prefix{netip.MustParsePrefix("127.0.0.1/32")}, TLS: receiver.Client().Transport.(*http.Transport).TLSClientConfig})
	if err != nil {
		t.Fatal(err)
	}
	defer sender.Close()
	o := Outbox{Pool: pool, Sender: sender}
	if _, err := pool.Exec(ctx, `INSERT INTO audit_log(actor,subject,channel,action,resource) VALUES('example-admin','local:example-admin','api','policies.update','policies/example-api')`); err != nil {
		t.Fatal(err)
	}
	var n int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM outbound_deliveries`).Scan(&n); err != nil || n != 0 {
		t.Fatal("export enabled by default", n, err)
	}
	if err := o.ConfigureAudit(ctx, true); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO audit_log(actor,subject,channel,action,resource,before,after) VALUES('email@example.test','local:email@example.test','api','local_users.update','local_users/email@example.test','{"token":"example-secret"}','{"client_ip":"192.0.2.123"}')`); err != nil {
		t.Fatal(err)
	}
	if work, err := o.Step(ctx); err != nil || !work {
		t.Fatal("first delivery", work, err)
	}
	var state string
	if err := pool.QueryRow(ctx, `SELECT state FROM outbound_deliveries`).Scan(&state); err != nil || state != "pending" {
		t.Fatal("retry not persisted", state, err)
	}
	if _, err := pool.Exec(ctx, `UPDATE outbound_deliveries SET next_attempt=now()`); err != nil {
		t.Fatal(err)
	}
	if work, err := o.Step(ctx); err != nil || !work {
		t.Fatal("retry", err)
	}
	if err := pool.QueryRow(ctx, `SELECT state FROM outbound_deliveries`).Scan(&state); err != nil || state != "delivered" {
		t.Fatal("receipt", err)
	}
	first, second := <-messages, <-messages
	if first.id != second.id {
		t.Fatal("retry changed delivery ID")
	}
	payload := second.payload
	for _, secret := range []string{"email@example.test", "example-secret", "192.0.2.123", "token_sha256", "before", "after"} {
		if strings.Contains(payload, secret) {
			t.Fatal("audit export leak", secret)
		}
	}
	if work, err := o.Step(ctx); err != nil || work || calls.Load() != 2 {
		t.Fatal("duplicate delivery", work, err, calls.Load())
	}
}
