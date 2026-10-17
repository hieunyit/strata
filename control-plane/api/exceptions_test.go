package api

import (
	"encoding/json"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/strata/strata/control-plane/ingest"
	"github.com/strata/strata/control-plane/localauth/localauthtest"
	"github.com/strata/strata/control-plane/rulecat"
	"github.com/strata/strata/control-plane/store"
)

const exceptionBlock = "STR-0000-0000-0000-0001"

func exceptionServer(t *testing.T) (*Server, *store.Store, store.Policy) {
	t.Helper()
	return exceptionServerWithPool(t, localauthtest.Pool(t))
}

func exceptionServerWithPool(t *testing.T, pool *pgxpool.Pool) (*Server, *store.Store, store.Policy) {
	t.Helper()
	pg := store.New(pool)
	first, err := pg.CreatePolicy(t.Context(), store.Policy{ID: "resource-api", Name: "example-api", Spec: json.RawMessage(`{"mode":"enforce","max_args":200,"future_setting":{"keep":true}}`)}, store.Audit{Actor: "creator", Subject: "creator-sub", Action: "policies.create"})
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "rules.yaml")
	if err := os.WriteFile(path, []byte("rules:\n  - {id: 700011, name: example SQLi, layer: managed}\n"), 0600); err != nil {
		t.Fatal(err)
	}
	cat, err := rulecat.Load([]string{path})
	if err != nil {
		t.Fatal(err)
	}
	events := ingest.NewMockEventStore()
	if err := events.SaveEvents(t.Context(), []ingest.Event{{BlockID: exceptionBlock, Timestamp: time.Now(), PolicyID: "example-api", HTTPMethod: "GET", HTTPHost: "api.example.test", HTTPPath: "/search", Action: "block", Violations: []ingest.Violation{{RuleID: 700011, Field: "ARGS:Name"}, {RuleID: 700011, Field: "ARGS:other"}, {RuleID: 700011, Field: "ARGS:Name|base64"}}}}); err != nil {
		t.Fatal(err)
	}
	return NewServer(ServerConfig{Auth: tokenRoles{}, Exceptions: pg, ReplayKick: func() {}, Rules: cat}, events), pg, first
}
func exceptionRequest(etag string) ExceptionFromBlockRequest {
	return ExceptionFromBlockRequest{BlockID: exceptionBlock, RuleID: 700011, Field: "ARGS:Name", Reason: "legitimate application query", TTLSeconds: 3600, Etag: etag, RequestID: "create-exception"}
}
func TestExceptionDraftAPIInPostgres(t *testing.T) {
	s, pg, first := exceptionServer(t)
	req := exceptionRequest(first.Etag)
	for _, role := range []string{"", "viewer", "approver"} {
		code, _ := do(t, s, "POST", "/v1/exceptions:fromBlockId", role, req)
		want := 403
		if role == "" {
			want = 401
		}
		if code != want {
			t.Fatalf("%s code=%d", role, code)
		}
	}
	var wg sync.WaitGroup
	replies := make(chan map[string]any, 12)
	for range 12 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			code, reply := do(t, s, "POST", "/v1/exceptions:fromBlockId", "operator", req)
			if code != 200 {
				t.Errorf("create %d %v", code, reply)
				return
			}
			replies <- reply
		}()
	}
	wg.Wait()
	close(replies)
	var reply map[string]any
	n := 0
	for r := range replies {
		if n == 0 {
			reply = r
		}
		if !reflect.DeepEqual(reply, r) {
			t.Error("concurrent reply changed ID or expiry")
		}
		n++
	}
	if n != 12 || reply["policy_id"] != "resource-api" || reply["policy_version"] != 2.0 || reply["state"] != "DRAFT" {
		t.Fatalf("replies=%d %v", n, reply)
	}
	e := reply["exception"].(map[string]any)
	if e["method"] != "GET" || e["host"] != "api.example.test" || e["path"] != "/search" || e["field"] != "ARGS:Name" {
		t.Fatal("scope not derived from event", e)
	}
	delta := int64(e["expires_unix_ms"].(float64)) - time.Now().UnixMilli()
	if delta < 3590000 || delta > 3600000 {
		t.Fatal("unexpected TTL", delta)
	}
	current, err := pg.GetPolicy(t.Context(), first.ID)
	if err != nil || !strings.Contains(string(current.Spec), "future_setting") || !strings.Contains(string(current.Spec), "200") {
		t.Fatal("existing settings lost", err)
	}
	op, err := pg.LatestReplay(t.Context(), first.ID, 2)
	if err != nil || op.State != store.OpPending {
		t.Fatal("no durable replay", err)
	}
	vs, err := pg.ListPolicyVersions(t.Context(), first.ID)
	if err != nil || len(vs) != 2 || vs[0].State != store.VersionDraft {
		t.Fatal("not a draft", err)
	}
	audits, err := pg.AuditEntries(t.Context(), 20)
	if err != nil || len(audits) != 3 {
		t.Fatalf("audit count %d %v", len(audits), err)
	}
	// Simulate a restart after event retention and a newer policy edit.
	if _, err := pg.UpdatePolicy(t.Context(), first.ID, current.Etag, current.Spec, store.Audit{Actor: "other", Subject: "other-sub", Action: "policies.update"}); err != nil {
		t.Fatal(err)
	}
	restarted := NewServer(ServerConfig{Auth: tokenRoles{}, Exceptions: pg}, ingest.NewMockEventStore())
	code, retry := do(t, restarted, "POST", "/v1/exceptions:fromBlockId", "operator", req)
	if code != 200 || !reflect.DeepEqual(retry, reply) {
		t.Fatal("retention/restart retry lost original response", code, retry)
	}
	changed := req
	changed.TTLSeconds = 7200
	if code, _ := do(t, restarted, "POST", "/v1/exceptions:fromBlockId", "operator", changed); code != 409 {
		t.Fatal("request reuse accepted", code)
	}
}
func TestExceptionDraftValidationInPostgres(t *testing.T) {
	s, pg, first := exceptionServer(t)
	req := exceptionRequest(first.Etag)
	for _, edit := range []func(*ExceptionFromBlockRequest){func(r *ExceptionFromBlockRequest) { r.TTLSeconds = 0 }, func(r *ExceptionFromBlockRequest) { r.TTLSeconds = 2592001 }, func(r *ExceptionFromBlockRequest) { r.Reason = "" }, func(r *ExceptionFromBlockRequest) { r.Etag = "" }, func(r *ExceptionFromBlockRequest) { r.RequestID = "" }} {
		bad := req
		edit(&bad)
		if code, _ := do(t, s, "POST", "/v1/exceptions:fromBlockId", "operator", bad); code != 400 {
			t.Fatal("invalid request", code)
		}
	}
	for _, field := range []string{"ARGS:missing", "ARGS:*", "REQUEST_BODY", "ARGS:Name|base64"} {
		bad := req
		bad.Field = field
		if code, _ := do(t, s, "POST", "/v1/exceptions:fromBlockId", "operator", bad); code != 409 {
			t.Fatal("ambiguous/broad field", code)
		}
	}
	for _, raw := range []string{"", `{`, `null`, `{} {}`, `{"block_id":"` + exceptionBlock + `","host":"other.example.test"}`, strings.Repeat("x", 8193)} {
		r := httptest.NewRequest("POST", "/v1/exceptions:fromBlockId", strings.NewReader(raw))
		w := httptest.NewRecorder()
		serve(s, w, r)
		if w.Code != 400 {
			t.Fatal("malformed request", w.Code)
		}
	}
	if code, _ := do(t, s, "GET", "/v1/exceptions:fromBlockId", "operator", nil); code != 405 {
		t.Fatal("GET writes", code)
	}
	code, reply := do(t, s, "POST", "/v1/exceptions:fromBlockId", "admin", req)
	if code != 200 {
		t.Fatal("admin denied", code, reply)
	}
	duplicate := req
	duplicate.RequestID = "second"
	duplicate.Etag = reply["etag"].(string)
	if code, _ := do(t, s, "POST", "/v1/exceptions:fromBlockId", "operator", duplicate); code != 409 {
		t.Fatal("duplicate scope extended expiry", code)
	}
	vs, err := pg.ListPolicyVersions(t.Context(), first.ID)
	if err != nil || len(vs) != 2 {
		t.Fatal("invalid input wrote version", err)
	}
	no := NewServer(ServerConfig{Auth: tokenRoles{}}, ingest.NewMockEventStore())
	if code, _ := do(t, no, "POST", "/v1/exceptions:fromBlockId", "operator", req); code != 503 {
		t.Fatal("no PG accepted", code)
	}
	s.cfg.ReplayKick = nil
	req.RequestID = "no-runner"
	if code, _ := do(t, s, "POST", "/v1/exceptions:fromBlockId", "operator", req); code != 503 {
		t.Fatal("no replay accepted", code)
	}
}
