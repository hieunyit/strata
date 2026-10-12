package admin_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/strata/strata/control-plane/admin"
	"github.com/strata/strata/control-plane/api"
	"github.com/strata/strata/control-plane/auth"
	"github.com/strata/strata/control-plane/auth/authtest"
	"github.com/strata/strata/control-plane/ingest"
	"github.com/strata/strata/control-plane/store"
)

type fakeFleet struct{ admin.FleetStore }

type fakePresence struct{}

func (fakePresence) Online(string, bool, *time.Time, bool, time.Time) bool { return false }
func (fakePresence) Cut(string)                                            {}

type fakeCommands struct {
	mu      sync.Mutex
	created []store.Command
	audits  []store.Audit
	groups  map[string][]string
}

func (f *fakeCommands) CreateCommands(_ context.Context, cs []store.Command, a store.Audit) ([]store.Command, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	for i := range cs {
		if cs[i].NodeID == "node-revoked" {
			return nil, store.ErrNotFound
		}
		cs[i].State, cs[i].CreatedBy = store.CommandPending, a.Actor
	}
	f.created = append(f.created, cs...)
	f.audits = append(f.audits, a)
	return cs, nil
}

func (f *fakeCommands) GroupNodes(_ context.Context, g string) ([]string, error) {
	return f.groups[g], nil
}

func (f *fakeCommands) GetCommand(_ context.Context, id string) (store.Command, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, c := range f.created {
		if c.ID == id {
			return c, nil
		}
	}
	return store.Command{}, store.ErrNotFound
}

func (f *fakeCommands) ListCommands(context.Context, string, int) ([]store.Command, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]store.Command{}, f.created...), nil
}

type countKick struct{ n int }

func (k *countKick) Kick() { k.n++ }

func TestForceShadowAndDiagnostics_REST(t *testing.T) {
	ctx := context.Background()
	is := authtest.New(t)
	v, err := auth.NewVerifier(ctx, auth.Config{Issuer: is.URL, Audience: authtest.Audience})
	if err != nil {
		t.Fatal(err)
	}
	cs := &fakeCommands{groups: map[string][]string{"lab": {"node-a", "node-b"}}}
	kick := &countKick{}
	a, err := admin.New(ctx, v, admin.BuildInfo{}, admin.Deps{Fleet: fakeFleet{}, Presence: fakePresence{}, Commands: cs, CommandKicker: kick})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(a.Close)
	h := api.NewServer(api.ServerConfig{Auth: v, Admin: a.Gateway}, ingest.NewMockEventStore()).Handler()
	call := func(role, method, path, body string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(method, path, strings.NewReader(body))
		req.Header.Set("Authorization", "Bearer "+is.Token(t, authtest.Claims{Subject: "lab-" + role, Roles: []string{role}}))
		req.Header.Set("Content-Type", "application/json")
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		return rec
	}

	for _, c := range []struct {
		role, body string
		code       int
	}{
		{"viewer", `{"node_id":"node-a","duration_seconds":60}`, http.StatusForbidden},
		{"approver", `{"node_id":"node-a","duration_seconds":60}`, http.StatusForbidden},
		{"operator", `{"duration_seconds":60}`, http.StatusBadRequest},
		{"operator", `{"node_id":"node-a","group_id":"lab","duration_seconds":60}`, http.StatusBadRequest},
		{"operator", `{"node_id":"node-a"}`, http.StatusBadRequest},
		{"operator", `{"node_id":"node-a","duration_seconds":86401}`, http.StatusBadRequest},
		{"operator", `{"node_id":"node-a","policy_id":"Example API","duration_seconds":60}`, http.StatusBadRequest},
		{"operator", `{"node_id":"node-revoked","duration_seconds":60}`, http.StatusNotFound},
		{"operator", `{"group_id":"empty","duration_seconds":60}`, http.StatusNotFound},
	} {
		if rec := call(c.role, http.MethodPost, "/v1/nodes:forceShadow", c.body); rec.Code != c.code {
			t.Errorf("%s %s: %d %s, want %d", c.role, c.body, rec.Code, rec.Body.String(), c.code)
		}
	}
	if len(cs.created) != 0 || kick.n != 0 {
		t.Fatalf("refused requests created commands: %v", cs.created)
	}

	rec := call("operator", http.MethodPost, "/v1/nodes:forceShadow", `{"group_id":"lab","policy_id":"example-api","duration_seconds":300}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("force shadow: %d %s", rec.Code, rec.Body.String())
	}
	var fs struct {
		Commands []struct {
			ID, NodeID, Kind, PolicyID, State string
			Duration                          int `json:"duration_seconds"`
		} `json:"commands"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &fs)
	if len(fs.Commands) != 2 || kick.n != 1 {
		t.Fatalf("got %s, kicks %d", rec.Body.String(), kick.n)
	}
	c0 := cs.created[0]
	if c0.Kind != store.CommandForceShadow || c0.PolicyID != "example-api" || c0.DurationSeconds != 300 ||
		time.Until(c0.ExpiresAt) > 301*time.Second || !strings.HasPrefix(c0.ID, "cmd-") {
		t.Fatalf("stored %+v", c0)
	}
	if au := cs.audits[0]; !strings.Contains(au.Action, "ForceShadow") || au.Resource != "groups/lab:forceShadow" || au.Actor == "" {
		t.Fatalf("audit %+v", au)
	}

	// clear: same targeting and permission, no duration
	if rec := call("viewer", http.MethodPost, "/v1/nodes:clearForceShadow", `{"node_id":"node-a"}`); rec.Code != http.StatusForbidden {
		t.Fatalf("viewer clears: %d", rec.Code)
	}
	if rec := call("operator", http.MethodPost, "/v1/nodes:clearForceShadow", `{"node_id":"node-a","group_id":"lab"}`); rec.Code != http.StatusBadRequest {
		t.Fatalf("clear with node and group: %d", rec.Code)
	}
	n := len(cs.created)
	if rec := call("operator", http.MethodPost, "/v1/nodes:clearForceShadow", `{"group_id":"lab","policy_id":"example-api"}`); rec.Code != http.StatusOK {
		t.Fatalf("clear: %d %s", rec.Code, rec.Body.String())
	}
	if c := cs.created[n]; len(cs.created) != n+2 || c.Kind != store.CommandClearShadow || c.PolicyID != "example-api" || c.DurationSeconds != 0 ||
		time.Until(c.ExpiresAt) > admin.DiagnosticsTTL+time.Second {
		t.Fatalf("clear stored %+v", cs.created[n:])
	}
	if au := cs.audits[len(cs.audits)-1]; au.Resource != "groups/lab:clearForceShadow" {
		t.Fatalf("audit %+v", au)
	}

	if rec := call("operator", http.MethodPost, "/v1/nodes/node-a:collectDiagnostics", `{}`); rec.Code != http.StatusForbidden {
		t.Fatalf("operator diagnostics: %d", rec.Code)
	}
	rec = call("admin", http.MethodPost, "/v1/nodes/node-a:collectDiagnostics", `{}`)
	if rec.Code != http.StatusOK || cs.created[len(cs.created)-1].Kind != store.CommandDiagnostics {
		t.Fatalf("diagnostics: %d %s", rec.Code, rec.Body.String())
	}
	if rec := call("viewer", http.MethodGet, "/v1/commands/"+cs.created[len(cs.created)-1].ID, ""); rec.Code != http.StatusOK {
		t.Fatalf("get command: %d %s", rec.Code, rec.Body.String())
	}
	if rec := call("viewer", http.MethodGet, "/v1/commands/../x", ""); rec.Code == http.StatusOK {
		t.Fatal("bad command id accepted")
	}
	if rec := call("viewer", http.MethodGet, "/v1/commands?node_id=node-a", ""); rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), cs.created[0].ID) {
		t.Fatalf("list: %d %s", rec.Code, rec.Body.String())
	}
}
