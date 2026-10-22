package store_test

import (
	"context"
	"errors"
	"os"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/strata/strata/control-plane/db"
	"github.com/strata/strata/control-plane/store"
)

// Against a real PostgreSQL (STRATA_TEST_POSTGRES_DSN): migration 0014 keeps
// the versions saved before it deployable, and the database itself refuses
// an approval by the subject that drafted or submitted the version
// (W13-G2-02).
func TestFourEyesInPostgres(t *testing.T) {
	dsn := os.Getenv("STRATA_TEST_POSTGRES_DSN")
	if dsn == "" {
		t.Skip("STRATA_TEST_POSTGRES_DSN not set")
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)
	if err := db.Migrate(ctx, pool, 13); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Migrate(context.Background(), pool, 0) })
	if _, err := pool.Exec(ctx, `INSERT INTO policies (id, name, current_version, etag, created_by) VALUES ('example-api', 'example-api', 2, 'e', 'alice');
		INSERT INTO policy_versions (policy_id, version, spec, created_by) VALUES ('example-api', 1, '{"mode":"shadow"}', 'alice'),
			('example-api', 2, '{"mode":"enforce"}', 'alice')`); err != nil {
		t.Fatal(err)
	}
	latest, _ := db.Latest()
	if err := db.Migrate(ctx, pool, latest); err != nil {
		t.Fatal(err)
	}
	s := store.New(pool)
	p, err := s.GetPolicy(ctx, "example-api")
	if err != nil || p.ApprovedVersion != 2 || p.DeployedVersion != 2 {
		t.Fatalf("after 0014: %+v %v", p, err)
	}
	ds, err := s.DeployablePolicies(ctx)
	if err != nil || len(ds) != 1 || ds[0].CurrentVersion != 2 {
		t.Fatalf("deployable: %+v %v", ds, err)
	}

	bob := store.Audit{Actor: "Bob (bob)", Subject: "bob", Action: "UpdatePolicy", Resource: "policies/example-api"}
	if _, err := s.UpdatePolicy(ctx, "example-api", p.Etag, []byte(`{"mode":"shadow"}`), bob); err != nil {
		t.Fatal(err)
	}
	if ds, _ := s.DeployablePolicies(ctx); ds[0].CurrentVersion != 2 {
		t.Fatalf("a draft is not deployable: %+v", ds)
	}
	if _, err := s.SubmitPolicyVersion(ctx, "example-api", 3, bob); err != nil {
		t.Fatal(err)
	}
	// the name changed, the subject did not: still bob
	renamed := store.Audit{Actor: "Robert (bob)", Subject: "bob"}
	if _, err := s.DecidePolicyVersion(ctx, "example-api", 3, true, "", renamed); !errors.Is(err, store.ErrFourEyes) {
		t.Fatalf("self approval: %v", err)
	}
	if _, err := s.DecidePolicyVersion(ctx, "example-api", 3, true, "", store.Audit{Actor: "anonymous"}); !errors.Is(err, store.ErrFourEyes) {
		t.Fatalf("approval without a subject: %v", err)
	}
	// and the database refuses it even past the store
	if _, err := pool.Exec(ctx, `UPDATE policy_versions SET state = 'APPROVED', decided_subject = 'bob'
		WHERE policy_id = 'example-api' AND version = 3`); err == nil {
		t.Fatal("the database took a self approval")
	}
	// audit 22/10/2026: nor through a service account bob created
	if _, err := pool.Exec(ctx, `INSERT INTO machine_accounts (id, metadata) VALUES ('bobs-bot', '{"created_by":"bob"}')`); err != nil {
		t.Fatal(err)
	}
	if _, err := s.DecidePolicyVersion(ctx, "example-api", 3, true, "", store.Audit{Actor: "bot", Subject: "sa:bobs-bot"}); !errors.Is(err, store.ErrFourEyes) {
		t.Fatalf("approval by the author's service account: %v", err)
	}
	v, err := s.DecidePolicyVersion(ctx, "example-api", 3, true, "ok", store.Audit{Actor: "Carol (carol)", Subject: "carol"})
	if err != nil || v.State != store.VersionApproved || v.DecidedBy != "Carol (carol)" {
		t.Fatalf("approval: %+v %v", v, err)
	}
	var se *store.StateError
	if _, err := s.DecidePolicyVersion(ctx, "example-api", 3, false, "late", store.Audit{Subject: "dave"}); !errors.As(err, &se) {
		t.Fatalf("decided twice: %v", err)
	}
	if ds, _ := s.DeployablePolicies(ctx); ds[0].CurrentVersion != 3 || string(ds[0].Spec) != `{"mode": "shadow"}` {
		t.Fatalf("deployable after approval: %+v", ds)
	}
	if _, err := s.RecordBundle(ctx, store.Bundle{Version: 1, SHA256: make([]byte, 32), ObjectKey: "k", SizeBytes: 1, Contents: map[string]int{"example-api": 3}},
		store.Audit{Actor: "carol"}); err != nil {
		t.Fatal(err)
	}
	if v, _ := s.GetPolicyVersion(ctx, "example-api", 3); v.State != store.VersionDeployed {
		t.Fatalf("after the bundle: %+v", v)
	}
	if err := db.Migrate(ctx, pool, 13); err != nil {
		t.Fatalf("down to 13: %v", err)
	}
}
