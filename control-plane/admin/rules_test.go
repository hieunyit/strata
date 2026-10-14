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

type fakeRules struct {
	mu     sync.Mutex
	off    map[int32]store.DisabledRule
	audits []store.Audit
	cmds   []store.Command
}

func (f *fakeRules) SetRuleDisabled(_ context.Context, g string, r int32, off bool, reason string, cs []store.Command, a store.Audit) (store.DisabledRule, []store.Command, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	row := store.DisabledRule{GroupID: g, RuleID: r, Reason: reason, CreatedBy: a.Actor}
	if off {
		f.off[r] = row
	} else {
		delete(f.off, r)
	}
	f.audits = append(f.audits, a)
	f.cmds = append(f.cmds, cs...)
	return row, cs, nil
}

func (f *fakeRules) DisabledRules(context.Context, string) ([]store.DisabledRule, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []store.DisabledRule
	for _, r := range f.off {
		out = append(out, r)
	}
	return out, nil
}

// W12-G2-02: POST /v1/rules/{id}:emergencyDisable needs rules:disable and a
// reason, sends DISABLE_RULES to every node of the group and is audited.
func TestEmergencyDisableRule_REST(t *testing.T) {
	ctx := context.Background()
	is := authtest.New(t)
	v, err := auth.NewVerifier(ctx, auth.Config{Issuer: is.URL, Audience: authtest.Audience})
	if err != nil {
		t.Fatal(err)
	}
	cs := &fakeCommands{groups: map[string][]string{"lab": {"node-a", "node-b"}}}
	rs := &fakeRules{off: map[int32]store.DisabledRule{}}
	kick := &countKick{}
	a, err := admin.New(ctx, v, admin.BuildInfo{}, admin.Deps{Fleet: fakeFleet{}, Presence: fakePresence{}, Commands: cs, CommandKicker: kick, KillSwitch: rs})
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
		role, path, body string
		code             int
	}{
		{"viewer", "/v1/rules/942100:emergencyDisable", `{"group_id":"lab","reason":"FP on /search"}`, http.StatusForbidden},
		{"operator", "/v1/rules/942100:emergencyDisable", `{"group_id":"lab"}`, http.StatusBadRequest},
		{"operator", "/v1/rules/942100:emergencyDisable", `{"group_id":"lab","reason":"   "}`, http.StatusBadRequest},
		{"operator", "/v1/rules/942100:emergencyDisable", `{"group_id":"lab","reason":"` + strings.Repeat("x", 501) + `"}`, http.StatusBadRequest},
		{"operator", "/v1/rules/942100:emergencyDisable", `{"reason":"FP on /search"}`, http.StatusBadRequest},
		{"operator", "/v1/rules/0:emergencyDisable", `{"group_id":"lab","reason":"FP on /search"}`, http.StatusBadRequest},
		{"operator", "/v1/rules/1000000:emergencyDisable", `{"group_id":"lab","reason":"FP on /search"}`, http.StatusBadRequest},
		{"operator", "/v1/rules/942100:emergencyDisable", `{"group_id":"empty","reason":"FP on /search"}`, http.StatusNotFound},
		{"viewer", "/v1/rules/942100:enable", `{"group_id":"lab","reason":"fixed"}`, http.StatusForbidden},
	} {
		if rec := call(c.role, http.MethodPost, c.path, c.body); rec.Code != c.code {
			t.Errorf("%s %s %s: %d %s, want %d", c.role, c.path, c.body, rec.Code, rec.Body.String(), c.code)
		}
	}
	if len(rs.cmds) != 0 || len(rs.audits) != 0 || kick.n != 0 {
		t.Fatalf("refused requests changed state: %v %v", rs.cmds, rs.audits)
	}

	for _, role := range []string{"operator", "approver", "admin"} {
		rec := call(role, http.MethodPost, "/v1/rules/942100:emergencyDisable", `{"group_id":"lab","reason":" FP on /search "}`)
		if rec.Code != http.StatusOK {
			t.Fatalf("%s: %d %s", role, rec.Code, rec.Body.String())
		}
	}
	if len(rs.cmds) != 6 || kick.n != 3 {
		t.Fatalf("commands %d, kicks %d", len(rs.cmds), kick.n)
	}
	c0 := rs.cmds[0]
	if c0.Kind != store.CommandDisableRules || len(c0.RuleIDs) != 1 || c0.RuleIDs[0] != 942100 || c0.NodeID != "node-a" {
		t.Fatalf("command %+v", c0)
	}
	au := rs.audits[0]
	if !strings.Contains(au.Action, "EmergencyDisableRule") || au.Resource != "groups/lab/rules/942100" || au.Actor == "" {
		t.Fatalf("audit %+v", au)
	}
	if rs.off[942100].Reason != "FP on /search" {
		t.Fatalf("reason not trimmed: %+v", rs.off[942100])
	}

	rec := call("viewer", http.MethodGet, "/v1/rules:disabled?group_id=lab", "")
	var list struct {
		Rules []struct {
			GroupID string `json:"group_id"`
			RuleID  int    `json:"rule_id"`
			Reason  string `json:"reason"`
		} `json:"rules"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &list)
	if rec.Code != http.StatusOK || len(list.Rules) != 1 || list.Rules[0].RuleID != 942100 {
		t.Fatalf("list: %d %s", rec.Code, rec.Body.String())
	}

	rec = call("operator", http.MethodPost, "/v1/rules/942100:enable", `{"group_id":"lab","reason":"rule fixed in 0.0.2"}`)
	if rec.Code != http.StatusOK || len(rs.off) != 0 {
		t.Fatalf("enable: %d %s", rec.Code, rec.Body.String())
	}
	if last := rs.cmds[len(rs.cmds)-1]; last.Kind != store.CommandEnableRules {
		t.Fatalf("enable command %+v", last)
	}
}

type fakeTrips struct{ cleared []string }

func (f *fakeTrips) ClearCanaryTrip(_ context.Context, group, policy, actor string, _ time.Time) error {
	f.cleared = append(f.cleared, group+"/"+policy+"/"+actor)
	return nil
}

// W12-G2-01: clearForceShadow on a group also ends the canary fallback's
// hold there, so the control plane stops renewing it; on one node it does
// not.
func TestClearForceShadowEndsTheCanaryTrip(t *testing.T) {
	ctx := context.Background()
	is := authtest.New(t)
	v, err := auth.NewVerifier(ctx, auth.Config{Issuer: is.URL, Audience: authtest.Audience})
	if err != nil {
		t.Fatal(err)
	}
	cs := &fakeCommands{groups: map[string][]string{"lab": {"node-a"}}}
	trips := &fakeTrips{}
	a, err := admin.New(ctx, v, admin.BuildInfo{}, admin.Deps{Fleet: fakeFleet{}, Presence: fakePresence{}, Commands: cs,
		CommandKicker: &countKick{}, CanaryTrips: trips})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(a.Close)
	h := api.NewServer(api.ServerConfig{Auth: v, Admin: a.Gateway}, ingest.NewMockEventStore()).Handler()
	call := func(role, body string) int {
		req := httptest.NewRequest(http.MethodPost, "/v1/nodes:clearForceShadow", strings.NewReader(body))
		req.Header.Set("Authorization", "Bearer "+is.Token(t, authtest.Claims{Subject: "lab-" + role, Roles: []string{role}}))
		req.Header.Set("Content-Type", "application/json")
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		return rec.Code
	}
	if c := call("viewer", `{"group_id":"lab","policy_id":"example-canary"}`); c != http.StatusForbidden || len(trips.cleared) != 0 {
		t.Fatalf("viewer: %d %v", c, trips.cleared)
	}
	if c := call("operator", `{"node_id":"node-a","policy_id":"example-canary"}`); c != http.StatusOK || len(trips.cleared) != 0 {
		t.Fatalf("one node: %d %v", c, trips.cleared)
	}
	if c := call("operator", `{"group_id":"lab","policy_id":"example-canary"}`); c != http.StatusOK ||
		len(trips.cleared) != 1 || !strings.HasPrefix(trips.cleared[0], "lab/example-canary/lab-operator") {
		t.Fatalf("group: %d %v", c, trips.cleared)
	}
}
