package store_test

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/strata/strata/control-plane/db"
)

// Against a real PostgreSQL (STRATA_TEST_POSTGRES_DSN): migration 0025
// (CP-SEC-01) moves the stored OIDC subjects into the "oidc:" namespace,
// leaves local accounts and service accounts as they are, keeps the
// four-eyes CHECK satisfied, and goes back down.
func TestOIDCSubjectNamespaceMigration(t *testing.T) {
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
	if err := db.Migrate(ctx, pool, 24); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Migrate(context.Background(), pool, 0) })
	if _, err := pool.Exec(ctx, `
		INSERT INTO policies (id, name, current_version, etag, created_by) VALUES ('example-api', 'example-api', 3, 'e', 'alice');
		INSERT INTO policy_versions (policy_id, version, spec, state, created_by, created_subject, submitted_by, submitted_subject, decided_by, decided_subject)
		VALUES ('example-api', 1, '{}', 'APPROVED', 'alice', 'alice-uuid', 'alice', 'alice-uuid', 'carol', 'local:carol'),
		       ('example-api', 2, '{}', 'APPROVED', 'ci', 'sa:ci', 'ci', 'sa:ci', 'bob', 'bob-uuid'),
		       ('example-api', 3, '{}', 'DRAFT', 'dave', 'dave-uuid', NULL, NULL, NULL, NULL);
		INSERT INTO event_annotations (block_id, reason, marked_by, marked_subject, etag) VALUES ('STR-A', 'fp', 'bob', 'bob-uuid', 'e'), ('STR-B', 'fp', 'carol', 'local:carol', 'e');
		INSERT INTO event_annotation_requests (subject, request_id, response) VALUES ('bob-uuid', 'r1', '{}');
		INSERT INTO policy_edit_requests (subject, request_id, fingerprint, response) VALUES ('bob-uuid', 'r1', decode(repeat('00', 32), 'hex'), '{}');
		INSERT INTO machine_requests (subject, request_id, digest, receipt) VALUES ('bob-uuid', 'r1', decode(repeat('00', 32), 'hex'), '{}'), ('local:carol', 'r2', decode(repeat('00', 32), 'hex'), '{}')`); err != nil {
		t.Fatal(err)
	}
	if err := db.Migrate(ctx, pool, 25); err != nil {
		t.Fatalf("up: %v", err)
	}
	read := func(q string) []string {
		t.Helper()
		rows, err := pool.Query(ctx, q)
		if err != nil {
			t.Fatal(err)
		}
		defer rows.Close()
		var out []string
		for rows.Next() {
			var s *string
			if err := rows.Scan(&s); err != nil {
				t.Fatal(err)
			}
			if s == nil {
				out = append(out, "<nil>")
			} else {
				out = append(out, *s)
			}
		}
		return out
	}
	eq := func(what string, got []string, want ...string) {
		t.Helper()
		if len(got) != len(want) {
			t.Fatalf("%s: %v, want %v", what, got, want)
		}
		for i := range want {
			if got[i] != want[i] {
				t.Fatalf("%s: %v, want %v", what, got, want)
			}
		}
	}
	eq("created", read(`SELECT created_subject FROM policy_versions ORDER BY version`), "oidc:alice-uuid", "sa:ci", "oidc:dave-uuid")
	eq("submitted", read(`SELECT submitted_subject FROM policy_versions ORDER BY version`), "oidc:alice-uuid", "sa:ci", "<nil>")
	eq("decided", read(`SELECT decided_subject FROM policy_versions ORDER BY version`), "local:carol", "oidc:bob-uuid", "<nil>")
	eq("annotations", read(`SELECT marked_subject FROM event_annotations ORDER BY block_id`), "oidc:bob-uuid", "local:carol")
	eq("annotation requests", read(`SELECT subject FROM event_annotation_requests`), "oidc:bob-uuid")
	eq("policy edit requests", read(`SELECT subject FROM policy_edit_requests`), "oidc:bob-uuid")
	eq("machine requests", read(`SELECT subject FROM machine_requests ORDER BY request_id`), "oidc:bob-uuid", "local:carol")

	// the CHECK still holds: an OIDC user cannot approve a version whose
	// drafter has the same sub
	if _, err := pool.Exec(ctx, `UPDATE policy_versions SET state = 'APPROVED', decided_subject = 'oidc:dave-uuid' WHERE version = 3`); err == nil {
		t.Fatal("self approval accepted after the migration")
	}

	if err := db.Migrate(ctx, pool, 24); err != nil {
		t.Fatalf("down: %v", err)
	}
	eq("created after down", read(`SELECT created_subject FROM policy_versions ORDER BY version`), "alice-uuid", "sa:ci", "dave-uuid")
	eq("machine requests after down", read(`SELECT subject FROM machine_requests ORDER BY request_id`), "bob-uuid", "local:carol")
	// up again in the same session (temporary functions are replaced)
	if err := db.Migrate(ctx, pool, 25); err != nil {
		t.Fatalf("up again: %v", err)
	}
}
