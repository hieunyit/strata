package api

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/strata/strata/control-plane/auth"
	"github.com/strata/strata/control-plane/ingest"
	"github.com/strata/strata/control-plane/localauth/localauthtest"
	"github.com/strata/strata/control-plane/store"
)

func machineRequest(h http.Handler, method, path string, input any, headers map[string]string) (int, []byte) {
	data, _ := json.Marshal(input)
	req := httptest.NewRequest(method, path, bytes.NewReader(data))
	req.Header.Set("Authorization", "Bearer admin")
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec.Code, rec.Body.Bytes()
}

func TestMachineCredentialsAtomicRetryAndRestart(t *testing.T) {
	pool := localauthtest.Pool(t)
	pg := store.New(pool)
	server := NewServer(ServerConfig{Auth: tokenRoles{}, ServiceAccounts: pg}, ingest.NewMockEventStore())
	create := CreateServiceAccountRequest{ID: "example-machine", Name: "Example automation", RequestID: "create-account", Roles: []auth.Role{auth.RoleAdmin}}
	code, data := machineRequest(server.Handler(), "POST", "/v1/service-accounts", create, nil)
	if code != 201 {
		t.Fatalf("create %d: %s", code, data)
	}
	var account auth.ServiceAccount
	if err := json.Unmarshal(data, &account); err != nil {
		t.Fatal(err)
	}
	code, again := machineRequest(server.Handler(), "POST", "/v1/service-accounts", create, nil)
	if code != 201 || !bytes.Equal(data, again) {
		t.Fatalf("account retry changed receipt: %d", code)
	}
	issue := CreateTokenRequest{RequestID: "issue-token", Etag: account.Etag, TTLSeconds: 3600, Scopes: []auth.Permission{auth.PermEventsRead}}
	code, data = machineRequest(server.Handler(), "POST", "/v1/service-accounts/example-machine/tokens", issue, nil)
	if code != 201 {
		t.Fatalf("issue %d: %s", code, data)
	}
	var first CreateTokenResponse
	if err := json.Unmarshal(data, &first); err != nil {
		t.Fatal(err)
	}
	if first.RawToken == "" || first.Token.Etag == "" {
		t.Fatal("missing one-time secret or token etag")
	}
	code, data = machineRequest(server.Handler(), "POST", "/v1/service-accounts/example-machine/tokens", issue, nil)
	var retry CreateTokenResponse
	if err := json.Unmarshal(data, &retry); err != nil {
		t.Fatal(err)
	}
	if code != 200 || !retry.Replayed || retry.RawToken != "" || retry.Token.ID != first.Token.ID {
		t.Fatal("retry issued or exposed another secret")
	}
	issue.TTLSeconds = 7200
	code, _ = machineRequest(server.Handler(), "POST", "/v1/service-accounts/example-machine/tokens", issue, nil)
	if code != 409 {
		t.Fatalf("changed retry status %d", code)
	}
	var tokens, audits, requests int
	if err := pool.QueryRow(t.Context(), `SELECT (SELECT count(*) FROM machine_tokens),(SELECT count(*) FROM audit_log),(SELECT count(*) FROM machine_requests)`).Scan(&tokens, &audits, &requests); err != nil {
		t.Fatal(err)
	}
	if tokens != 1 || audits != 2 || requests != 2 {
		t.Fatalf("duplicate mutation: tokens=%d audits=%d receipts=%d", tokens, audits, requests)
	}
	list, err := pg.ListServiceAccounts(t.Context())
	if err != nil || len(list) != 1 || list[0].TokenCount != 1 {
		t.Fatalf("active count %+v %v", list, err)
	}
	// Recreate store and server objects; no in-memory credential state is reused.
	restored := store.New(pool)
	second := NewServer(ServerConfig{Auth: auth.Dispatch{OIDC: tokenRoles{}, ServiceAccountPrefix: auth.ServiceAccountTokenPrefix, ServiceAccount: auth.NewServiceAccountAuthenticator(restored)}, ServiceAccounts: restored}, ingest.NewMockEventStore())
	code, _ = machineRequest(second.Handler(), "GET", "/v1/auth/me", nil, map[string]string{"Authorization": "Bearer " + first.RawToken})
	if code != 200 {
		t.Fatalf("credential did not survive new server objects: %d", code)
	}
	bearer := map[string]string{"Authorization": "Bearer " + first.RawToken}
	code, _ = machineRequest(second.Handler(), "POST", "/v1/events:search", map[string]any{"limit": 10}, bearer)
	if code != 200 {
		t.Fatalf("scoped read status %d", code)
	}
	code, _ = machineRequest(second.Handler(), "POST", "/v1/service-accounts", CreateServiceAccountRequest{ID: "example-forbidden", Name: "Forbidden", RequestID: "scope-boundary"}, bearer)
	if code != 403 {
		t.Fatalf("narrow token bypassed admin role ceiling: %d", code)
	}
	if _, err := pool.Exec(t.Context(), `UPDATE machine_tokens SET expires_at=now()-interval '1 second' WHERE id=$1`, first.Token.ID); err != nil {
		t.Fatal(err)
	}
	code, _ = machineRequest(second.Handler(), "GET", "/v1/auth/me", nil, bearer)
	if code != 401 {
		t.Fatalf("expired token status %d", code)
	}
	if _, err := pool.Exec(t.Context(), `UPDATE machine_tokens SET expires_at=$1 WHERE id=$2`, first.Token.ExpiresAt, first.Token.ID); err != nil {
		t.Fatal(err)
	}
	path := "/v1/service-accounts/example-machine/tokens/" + first.Token.ID
	code, _ = machineRequest(second.Handler(), "DELETE", path, nil, map[string]string{"Idempotency-Key": "revoke-token", "If-Match": "stale"})
	if code != 409 {
		t.Fatalf("stale revoke %d", code)
	}
	command := map[string]string{"Idempotency-Key": "revoke-token", "If-Match": first.Token.Etag}
	for i := 0; i < 2; i++ {
		code, _ = machineRequest(second.Handler(), "DELETE", path, nil, command)
		if code != 204 {
			t.Fatalf("revoke/retry %d", code)
		}
	}
	code, _ = machineRequest(second.Handler(), "GET", "/v1/auth/me", nil, map[string]string{"Authorization": "Bearer " + first.RawToken})
	if code != 401 {
		t.Fatalf("revoked credential status %d", code)
	}
	var leaked bool
	if err := pool.QueryRow(t.Context(), `SELECT EXISTS(SELECT 1 FROM machine_requests WHERE receipt::text LIKE $1) OR EXISTS(SELECT 1 FROM audit_log WHERE coalesce(before::text,'') LIKE $1 OR coalesce(after::text,'') LIKE $1) OR EXISTS(SELECT 1 FROM machine_tokens WHERE metadata::text LIKE $1)`, "%"+first.RawToken+"%").Scan(&leaked); err != nil {
		t.Fatal(err)
	}
	if leaked {
		t.Fatal("plaintext credential persisted in receipt/audit/metadata")
	}
	var before, after []byte
	if err := pool.QueryRow(t.Context(), `SELECT before,after FROM audit_log WHERE action='/v1/service-accounts/tokens:revoke'`).Scan(&before, &after); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(before), `"revoked": false`) || !strings.Contains(string(after), `"revoked": true`) {
		t.Fatal("missing revoke before/after audit")
	}
	code, _ = machineRequest(second.Handler(), "DELETE", "/v1/service-accounts/example-machine", nil, map[string]string{"Idempotency-Key": "delete-account", "If-Match": account.Etag})
	if code != 204 {
		t.Fatalf("account delete %d", code)
	}
	code, _ = machineRequest(second.Handler(), "GET", "/v1/service-accounts/example-machine", nil, nil)
	if code != 404 {
		t.Fatalf("deleted account %d", code)
	}
}

func TestMachineAuditFailureRollsBackCredentialAndReceipt(t *testing.T) {
	pool := localauthtest.Pool(t)
	pg := store.New(pool)
	if _, err := pool.Exec(t.Context(), `CREATE FUNCTION reject_machine_audit() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'synthetic audit failure'; END $$;
 CREATE TRIGGER fail_machine_audit BEFORE INSERT ON audit_log FOR EACH ROW EXECUTE FUNCTION reject_machine_audit()`); err != nil {
		t.Fatal(err)
	}
	h := NewServer(ServerConfig{Auth: tokenRoles{}, ServiceAccounts: pg}, ingest.NewMockEventStore()).Handler()
	command := CreateServiceAccountRequest{ID: "example-rollback", Name: "Example rollback", RequestID: "audit-failure"}
	code, _ := machineRequest(h, "POST", "/v1/service-accounts", command, nil)
	if code != 500 {
		t.Fatalf("audit failure %d", code)
	}
	var accounts, receipts int
	if err := pool.QueryRow(t.Context(), `SELECT (SELECT count(*) FROM machine_accounts),(SELECT count(*) FROM machine_requests)`).Scan(&accounts, &receipts); err != nil {
		t.Fatal(err)
	}
	if accounts != 0 || receipts != 0 {
		t.Fatalf("failed audit committed accounts=%d receipts=%d", accounts, receipts)
	}
	if _, err := pool.Exec(t.Context(), `DROP TRIGGER fail_machine_audit ON audit_log;DROP FUNCTION reject_machine_audit()`); err != nil {
		t.Fatal(err)
	}
	code, _ = machineRequest(h, "POST", "/v1/service-accounts", command, nil)
	if code != 201 {
		t.Fatalf("same command could not retry after rollback: %d", code)
	}
}

func TestMachineConcurrentTokenRetryCommitsOnce(t *testing.T) {
	pool := localauthtest.Pool(t)
	pg := store.New(pool)
	h := NewServer(ServerConfig{Auth: tokenRoles{}, ServiceAccounts: pg}, ingest.NewMockEventStore()).Handler()
	code, data := machineRequest(h, "POST", "/v1/service-accounts", CreateServiceAccountRequest{ID: "example-concurrent", Name: "Example concurrent", RequestID: "account"}, nil)
	if code != 201 {
		t.Fatalf("account %d", code)
	}
	var account auth.ServiceAccount
	if err := json.Unmarshal(data, &account); err != nil {
		t.Fatal(err)
	}
	issue := CreateTokenRequest{RequestID: "same-command", Etag: account.Etag, TTLSeconds: 3600, Scopes: []auth.Permission{auth.PermEventsRead}}
	type result struct {
		code int
		data []byte
	}
	done := make(chan result, 2)
	for i := 0; i < 2; i++ {
		go func() {
			status, receipt := machineRequest(h, "POST", "/v1/service-accounts/example-concurrent/tokens", issue, nil)
			done <- result{status, receipt}
		}()
	}
	var issuedID string
	secrets := 0
	replays := 0
	for i := 0; i < 2; i++ {
		got := <-done
		if got.code != 200 && got.code != 201 {
			t.Fatalf("concurrent command %d", got.code)
		}
		var receipt CreateTokenResponse
		if err := json.Unmarshal(got.data, &receipt); err != nil {
			t.Fatal(err)
		}
		if issuedID != "" && issuedID != receipt.Token.ID {
			t.Fatal("concurrent retry issued two credentials")
		}
		issuedID = receipt.Token.ID
		if receipt.RawToken != "" {
			secrets++
		}
		if receipt.Replayed {
			replays++
		}
	}
	if secrets != 1 || replays != 1 {
		t.Fatalf("secrets=%d replayed=%d", secrets, replays)
	}
	var count int
	if err := pool.QueryRow(t.Context(), `SELECT count(*) FROM machine_tokens`).Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 1 {
		t.Fatalf("stored %d tokens", count)
	}
}

func TestMachineManagementRejectsOtherRolesAndBoundsHeaders(t *testing.T) {
	pool := localauthtest.Pool(t)
	pg := store.New(pool)
	h := NewServer(ServerConfig{Auth: tokenRoles{}, ServiceAccounts: pg}, ingest.NewMockEventStore()).Handler()
	for _, role := range []string{"viewer", "operator", "approver"} {
		for _, method := range []string{"GET", "POST", "DELETE"} {
			path := "/v1/service-accounts"
			if method == "DELETE" {
				path += "/example-account"
			}
			code, _ := machineRequest(h, method, path, CreateServiceAccountRequest{ID: "example-account", Name: "Example", RequestID: "denied"}, map[string]string{"Authorization": "Bearer " + role, "Idempotency-Key": "denied", "If-Match": "example-etag"})
			if code != 403 {
				t.Fatalf("%s %s status %d", role, method, code)
			}
		}
	}
	for _, etag := range []string{strings.Repeat("x", 129), "invalid\x00etag", "\xff"} {
		code, _ := machineRequest(h, "DELETE", "/v1/service-accounts/example-account", nil, map[string]string{"Idempotency-Key": "invalid-header", "If-Match": etag})
		if code != 400 {
			t.Fatalf("unbounded or invalid header status %d", code)
		}
	}
	for _, id := range []string{"tok_%00", strings.Repeat("x", 129)} {
		code, _ := machineRequest(h, "DELETE", "/v1/service-accounts/example-account/tokens/"+id, nil, map[string]string{"Idempotency-Key": "invalid-path", "If-Match": "example-etag"})
		if code != 400 {
			t.Fatalf("invalid token path status %d", code)
		}
	}

}

func TestMachinePlaintextReceiptIsNotCacheable(t *testing.T) {
	pool := localauthtest.Pool(t)
	pg := store.New(pool)
	h := NewServer(ServerConfig{Auth: tokenRoles{}, ServiceAccounts: pg}, ingest.NewMockEventStore()).Handler()
	code, data := machineRequest(h, "POST", "/v1/service-accounts", CreateServiceAccountRequest{ID: "example-cache", Name: "Example", RequestID: "account"}, nil)
	if code != 201 {
		t.Fatalf("account %d", code)
	}
	var account auth.ServiceAccount
	if err := json.Unmarshal(data, &account); err != nil {
		t.Fatal(err)
	}
	body, err := json.Marshal(CreateTokenRequest{RequestID: "one-time-secret", Etag: account.Etag, Scopes: []auth.Permission{auth.PermEventsRead}, TTLSeconds: 3600})
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest("POST", "/v1/service-accounts/example-cache/tokens", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer admin")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != 201 || rec.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("secret response status=%d cache=%q", rec.Code, rec.Header().Get("Cache-Control"))
	}
}
