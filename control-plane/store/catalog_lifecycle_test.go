package store_test

import (
	"encoding/json"
	"errors"
	"testing"

	"github.com/strata/strata/control-plane/db"
	"github.com/strata/strata/control-plane/localauth/localauthtest"
	"github.com/strata/strata/control-plane/rulecat"
	"github.com/strata/strata/control-plane/store"
)

func TestCatalogSnapshotsAndBroadExceptionGuard(t *testing.T) {
	pool := localauthtest.Pool(t)
	st := store.New(pool)
	ctx := t.Context()
	first := []rulecat.Entry{{ID: 700001, Rule: rulecat.Rule{Name: "Example", Pack: "core", Digest: "old"}}}
	digest, err := st.RecordCatalog(ctx, first)
	if err != nil {
		t.Fatal(err)
	}
	if again, err := st.RecordCatalog(ctx, first); err != nil || again != digest {
		t.Fatal("snapshot not stable", err)
	}
	first[0].Digest = "new"
	next, err := st.RecordCatalog(ctx, first)
	if err != nil || next == digest {
		t.Fatal("changed content not captured", err)
	}
	old, err := st.CatalogEntries(ctx, digest)
	if err != nil || old[0].Digest != "old" {
		t.Fatal("snapshot was mutable", err)
	}
	history, err := st.CatalogHistory(ctx)
	if err != nil || len(history) != 2 || !history[0].Current {
		t.Fatalf("history %+v %v", history, err)
	}
	broad := json.RawMessage(`{"mode":"enforce","exceptions":[{"id":"exc-0123456789abcdef0123456789abcdef","rule_id":700011,"method":"GET","host":"api.example.test","path":"/","field":"ARGS:q","expires_unix_ms":4000000000000,"reason":"example"}]}`)
	a := store.Audit{Actor: "operator", Subject: "oidc:operator", Action: "policy.create"}
	if _, err := st.CreatePolicy(ctx, store.Policy{ID: "blocked", Name: "blocked", Spec: broad}, a); !errors.Is(err, store.ErrBroadException) {
		t.Fatalf("broad grant accepted: %v", err)
	}
	// Upgrade from the previous schema with an existing reviewed root exception.
	if err := db.Migrate(ctx, pool, 41); err != nil {
		t.Fatal(err)
	}
	legacy, err := st.CreatePolicy(ctx, store.Policy{ID: "legacy-api", Name: "legacy-api", Spec: broad}, a)
	if err != nil {
		t.Fatal(err)
	}
	if err := db.Migrate(ctx, pool, 42); err != nil {
		t.Fatal(err)
	}
	same, err := st.UpdatePolicy(ctx, legacy.ID, legacy.Etag, broad, a)
	if err != nil {
		t.Fatalf("unchanged legacy entry rejected: %v", err)
	}
	var fields map[string]any
	if err := json.Unmarshal(broad, &fields); err != nil {
		t.Fatal(err)
	}
	fields["exceptions"].([]any)[0].(map[string]any)["expires_unix_ms"] = 4000000000001
	changed, err := json.Marshal(fields)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := st.UpdatePolicy(ctx, legacy.ID, same.Etag, changed, a); !errors.Is(err, store.ErrBroadException) {
		t.Fatalf("legacy grant widened: %v", err)
	}
}
