package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/strata/strata/control-plane/auth"
	"github.com/strata/strata/control-plane/ingest"
	"github.com/strata/strata/control-plane/localauth"
	"github.com/strata/strata/control-plane/localauth/localauthtest"
	"github.com/strata/strata/control-plane/store"
)

func TestAuditSearchInPostgres(t *testing.T) {
	p := localauthtest.Pool(t)
	ctx := t.Context()
	pg := store.New(p)
	at := time.Date(2026, 10, 17, 10, 0, 0, 0, time.UTC)
	if _, err := p.Exec(ctx, `INSERT INTO audit_log(at,actor,subject,channel,action,resource,before,after)
	 VALUES($1,'example-admin','immutable-subject','ui','/UpdatePolicy','policies/100%_literal','{"v":1}','{"v":2}')`, at); err != nil {
		t.Fatal(err)
	}
	if _, err := p.Exec(ctx, `INSERT INTO audit_log(at,actor,channel,action,resource)
	 SELECT $1::timestamptz + n * interval '1 second','other-admin','api','/DeployPolicy','policies/example-api' FROM generate_series(1,600) n`, at); err != nil {
		t.Fatal(err)
	}
	h := NewServer(ServerConfig{Auth: tokenRoles{}, Audit: pg}, ingest.NewMockEventStore()).Handler()
	type response struct {
		Entries []store.Audit `json:"entries"`
		More    bool          `json:"has_more"`
		Limit   int           `json:"limit"`
	}
	get := func(q url.Values, role string) response {
		t.Helper()
		r := httptest.NewRequest(http.MethodGet, "/v1/audit?"+q.Encode(), nil)
		r.Header.Set("Authorization", "Bearer "+role)
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		if w.Code != 200 {
			t.Fatalf("audit status=%d body=%s", w.Code, w.Body.String())
		}
		if w.Header().Get("Cache-Control") != "no-store" {
			t.Fatal("audit response may be cached")
		}
		var v response
		if err := json.Unmarshal(w.Body.Bytes(), &v); err != nil {
			t.Fatal(err)
		}
		return v
	}
	base := get(url.Values{"limit": {"200"}}, "admin")
	if len(base.Entries) != 200 || !base.More {
		t.Fatal("recent results lost truncation marker")
	}
	old := get(url.Values{"actor": {"example-admin"}, "channel": {"ui"}, "action": {"update"}, "resource": {"100%_literal"}, "from": {at.Format(time.RFC3339)}, "to": {at.Add(time.Second).Format(time.RFC3339)}}, "admin")
	if len(old.Entries) != 1 || old.More || old.Entries[0].Subject != "immutable-subject" || old.Entries[0].Before == nil || old.Entries[0].After == nil {
		t.Fatalf("older matching audit omitted: %+v", old)
	}
	end := get(url.Values{"actor": {"example-admin"}, "to": {at.Format(time.RFC3339)}}, "admin")
	if len(end.Entries) != 0 {
		t.Fatal("exclusive to boundary was ignored")
	}
	for _, q := range []url.Values{{"actor": {"' OR 1=1 --"}}, {"resource": {"%_does_not_exist"}}} {
		if len(get(q, "admin").Entries) != 0 {
			t.Fatal("query was not treated as literal data")
		}
	}
	r := httptest.NewRequest(http.MethodGet, "/v1/audit?actor=example-admin", nil)
	r.Header.Set("Authorization", "Bearer viewer")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != 403 {
		t.Fatal("viewer read audit")
	}
	if _, err := pg.CreateGroup(ctx, store.Group{ID: "example-group", Name: "Example"}, store.Audit{Actor: "Display name", Subject: "stable-subject", Channel: "ui", Action: "/CreateGroup", Resource: "groups/example-group"}); err != nil {
		t.Fatal(err)
	}
	created, err := pg.SearchAudit(ctx, store.AuditFilter{Actor: "Display name"})
	if err != nil || len(created) != 1 || created[0].Subject != "stable-subject" {
		t.Fatalf("audit writer lost immutable identity: %v", err)
	}
	accounts := localauth.NewStore(p)
	adminContext := auth.WithPrincipal(ctx, &auth.Principal{Subject: "oidc-subject", Name: "Display name", Roles: []auth.Role{auth.RoleAdmin}})
	if _, err := accounts.CreateUser(adminContext, "example-viewer", "synthetic-unused-hash", []string{"viewer"}, "Display name"); err != nil {
		t.Fatal(err)
	}
	local, err := pg.SearchAudit(ctx, store.AuditFilter{Action: "local_users.create"})
	if err != nil || len(local) != 1 || local[0].Subject != "oidc-subject" {
		t.Fatalf("local admin writer lost subject: %v", err)
	}
}
