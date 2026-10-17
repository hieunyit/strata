package api

import (
	"github.com/jackc/pgx/v5/pgxpool"
	"testing"

	"github.com/strata/strata/control-plane/ingest"
	"github.com/strata/strata/control-plane/localauth/localauthtest"
	"github.com/strata/strata/control-plane/store"
)

func TestStagingNoticeAPIReadsDurableHistoryWithoutRounding(t *testing.T) {
	pool := localauthtest.Pool(t)
	ctx := t.Context()
	seedNoticeReadFixture(t, pool)
	var before int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM audit_log`).Scan(&before); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 2; i++ {
		server := NewServer(ServerConfig{Auth: tokenRoles{}, StagingNotices: store.New(pool)}, ingest.NewMockEventStore())
		code, body := do(t, server, "GET", "/v1/rules/staging-actions", "approver", nil)
		if code != 200 {
			t.Fatalf("read: %d %v", code, body)
		}
		notices := body["notices"].([]any)
		if len(notices) != 1 {
			t.Fatal(body)
		}
		n := notices[0].(map[string]any)
		if n["matches"] != "18446744073709551615" || n["reports"] != "5" || n["bundle_version"] != "2" || n["rollout_state"] != "PENDING" || n["policy_name"] != "example-api" {
			t.Fatal(n)
		}
		if _, exists := n["sha256"]; exists {
			t.Fatal("artifact internals leaked")
		}
	}
	var after int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM audit_log`).Scan(&after); err != nil || after != before {
		t.Fatal("GET changed audit")
	}
}

func seedNoticeReadFixture(t *testing.T, pool *pgxpool.Pool) {
	t.Helper()
	ctx := t.Context()
	pg := store.New(pool)
	if _, err := pg.CreatePolicy(ctx, store.Policy{ID: "example-api", Name: "example-api", Spec: []byte(`{"mode":"enforce"}`)}, store.Audit{Actor: "operator", Subject: "operator"}); err != nil {
		t.Fatal(err)
	}
	// Read fixture only: the writer/approval/real compiler path is tested in
	// policy. SQL seeds a historical intent, not a claim it was activated.
	if _, err := pool.Exec(ctx, `INSERT INTO bundles(version,sha256,object_key,size_bytes,created_by)
  VALUES(1,decode(repeat('aa',32),'hex'),'example/1',100,'fixture'),(2,decode(repeat('bb',32),'hex'),'example/2',100,'fixture');
  INSERT INTO rule_staging_actions(id,policy_id,policy_version,rule_id,source_bundle,bundle_version,matches,reports,window_from,window_to,request_digest)
  VALUES('example-notice','example-api',1,942100,1,2,18446744073709551615,5,now()-interval '5 minutes',now(),decode(repeat('cc',32),'hex'))`); err != nil {
		t.Fatal(err)
	}
}
