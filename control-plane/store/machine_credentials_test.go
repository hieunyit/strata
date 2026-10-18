package store_test

import (
	"context"
	"testing"
	"time"

	"github.com/strata/strata/control-plane/auth"
	"github.com/strata/strata/control-plane/localauth/localauthtest"
	"github.com/strata/strata/control-plane/store"
)

func machineActor(t *testing.T) context.Context {
	return auth.WithPrincipal(t.Context(), &auth.Principal{Subject: "example-admin", Name: "Example administrator", Roles: []auth.Role{auth.RoleAdmin}})
}

func TestMachineCredentialsPersistWithAuditedRetry(t *testing.T) {
	pool := localauthtest.Pool(t)
	pg := store.New(pool)
	ctx := machineActor(t)
	cmd := store.MachineCommand{RequestID: "create-account", Input: "example-account"}
	account, err := pg.CreateMachineAccount(ctx, auth.ServiceAccount{ID: "example-account", Name: "Example", Roles: []auth.Role{auth.RoleViewer}, CreatedBy: "example-admin", CreatedAt: time.Now().UTC()}, cmd)
	if err != nil {
		t.Fatal(err)
	}
	same, err := pg.CreateMachineAccount(ctx, account, cmd)
	if err != nil || same.Etag != account.Etag {
		t.Fatalf("account retry failed: %v", err)
	}
	raw, tok, err := auth.GenerateToken(account.ID, []auth.Permission{auth.PermEventsRead}, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	issue := store.MachineCommand{RequestID: "issue-token", Etag: account.Etag, Input: "events:read/1h"}
	tok, replayed, err := pg.IssueMachineToken(ctx, tok, issue)
	if err != nil || replayed {
		t.Fatalf("issue failed: %v", err)
	}
	again, replayed, err := pg.IssueMachineToken(ctx, tok, issue)
	if err != nil || !replayed || again.ID != tok.ID {
		t.Fatalf("token retry failed: %v", err)
	}
	invalid := tok
	invalid.Scopes = nil
	if _, _, err := pg.IssueMachineToken(ctx, invalid, store.MachineCommand{RequestID: "invalid-empty", Etag: account.Etag}); err == nil {
		t.Fatal("stored an unscoped credential")
	}
	invalid = tok
	invalid.ExpiresAt = time.Now().Add(-time.Second)
	if _, _, err := pg.IssueMachineToken(ctx, invalid, store.MachineCommand{RequestID: "invalid-expired", Etag: account.Etag}); err == nil {
		t.Fatal("stored an expired credential")
	}
	var audits, receipts, tokens int
	if err := pool.QueryRow(ctx, `SELECT (SELECT count(*) FROM audit_log),(SELECT count(*) FROM machine_requests),(SELECT count(*) FROM machine_tokens)`).Scan(&audits, &receipts, &tokens); err != nil {
		t.Fatal(err)
	}
	if audits != 2 || receipts != 2 || tokens != 1 {
		t.Fatalf("duplicate mutation %d/%d/%d", audits, receipts, tokens)
	}
	fresh := store.New(pool)
	if _, err := auth.NewServiceAccountAuthenticator(fresh).Authenticate(ctx, raw); err != nil {
		t.Fatalf("credential did not persist: %v", err)
	}
	list, err := fresh.ListServiceAccounts(ctx)
	if err != nil || len(list) != 1 || list[0].TokenCount != 1 {
		t.Fatalf("active token count is wrong: %v", err)
	}
	revoke := store.MachineCommand{RequestID: "revoke-token", Etag: tok.Etag}
	for i := 0; i < 2; i++ {
		if err := fresh.RevokeMachineToken(ctx, account.ID, tok.ID, revoke); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := auth.NewServiceAccountAuthenticator(fresh).Authenticate(ctx, raw); err == nil {
		t.Fatal("revoked token authenticated")
	}
	var subject string
	var leaked bool
	if err := pool.QueryRow(ctx, `SELECT after->>'actor_subject' FROM audit_log WHERE action='/v1/service-accounts/tokens:revoke'`).Scan(&subject); err != nil {
		t.Fatal(err)
	}
	if subject != "example-admin" {
		t.Fatal("audit lost immutable actor identity")
	}
	if err := pool.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM machine_requests WHERE receipt::text LIKE $1) OR EXISTS(SELECT 1 FROM audit_log WHERE after::text LIKE $1)`, "%"+raw+"%").Scan(&leaked); err != nil {
		t.Fatal(err)
	}
	if leaked {
		t.Fatal("plaintext persisted in audit or retry receipt")
	}
}

func TestMachineCredentialAuditRollback(t *testing.T) {
	pool := localauthtest.Pool(t)
	pg := store.New(pool)
	ctx := machineActor(t)
	if _, err := pool.Exec(ctx, `CREATE FUNCTION reject_machine_audit() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'synthetic failure'; END $$;
 CREATE TRIGGER reject_machine BEFORE INSERT ON audit_log FOR EACH ROW EXECUTE FUNCTION reject_machine_audit()`); err != nil {
		t.Fatal(err)
	}
	cmd := store.MachineCommand{RequestID: "retry-after-rollback"}
	account := auth.ServiceAccount{ID: "example-rollback", Name: "Example", Roles: []auth.Role{auth.RoleViewer}}
	if _, err := pg.CreateMachineAccount(ctx, account, cmd); err == nil {
		t.Fatal("accepted failed audit")
	}
	var rows int
	if err := pool.QueryRow(ctx, `SELECT (SELECT count(*) FROM machine_accounts)+(SELECT count(*) FROM machine_requests)`).Scan(&rows); err != nil {
		t.Fatal(err)
	}
	if rows != 0 {
		t.Fatal("audit failure committed account or receipt")
	}
	if _, err := pool.Exec(ctx, `DROP TRIGGER reject_machine ON audit_log;DROP FUNCTION reject_machine_audit()`); err != nil {
		t.Fatal(err)
	}
	if _, err := pg.CreateMachineAccount(ctx, account, cmd); err != nil {
		t.Fatalf("same command could not retry: %v", err)
	}
}
