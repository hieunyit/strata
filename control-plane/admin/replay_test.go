package admin_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/strata/strata/control-plane/admin"
	"github.com/strata/strata/control-plane/api"
	"github.com/strata/strata/control-plane/auth"
	"github.com/strata/strata/control-plane/auth/authtest"
	"github.com/strata/strata/control-plane/ingest"
	"github.com/strata/strata/control-plane/store"
)

type fakeReplay struct {
	row  *store.ReplaySampling
	cmds []store.Command
	sets int
}

func (f *fakeReplay) SetReplaySampling(_ context.Context, g string, bp int, rotate bool, cs []store.Command, a store.Audit) (store.ReplaySampling, []store.Command, error) {
	f.sets++
	if f.row == nil || rotate {
		f.row = &store.ReplaySampling{GroupID: g, KeyID: "kabc123", Key: []byte(strings.Repeat("K", 32))}
	}
	f.row.RateBp, f.row.UpdatedBy, f.row.UpdatedAt = bp, a.Actor, time.Now()
	f.cmds = append(f.cmds, cs...)
	return *f.row, cs, nil
}

func (f *fakeReplay) GetReplaySampling(context.Context, string) (store.ReplaySampling, error) {
	if f.row == nil {
		return store.ReplaySampling{}, store.ErrNotFound
	}
	return *f.row, nil
}

// W12-N-01: replay sampling of a group: admin only, above 0 only once the
// control plane runs with -replay-sampling-approved; the key never in a
// response.
func TestReplaySampling_REST(t *testing.T) {
	for _, approved := range []bool{false, true} {
		ctx := context.Background()
		is := authtest.New(t)
		v, err := auth.NewVerifier(ctx, auth.Config{Issuer: is.URL, Audience: authtest.Audience})
		if err != nil {
			t.Fatal(err)
		}
		cs := &fakeCommands{groups: map[string][]string{"lab": {"node-a", "node-b"}}}
		rs := &fakeReplay{}
		a, err := admin.New(ctx, v, admin.BuildInfo{}, admin.Deps{Fleet: fakeFleet{}, Presence: fakePresence{}, Commands: cs,
			CommandKicker: &countKick{}, Replay: rs, ReplayApproved: approved})
		if err != nil {
			t.Fatal(err)
		}
		h := api.NewServer(api.ServerConfig{Auth: v, Admin: a.Gateway}, ingest.NewMockEventStore()).Handler()
		call := func(role, method, path, body string) *httptest.ResponseRecorder {
			req := httptest.NewRequest(method, path, strings.NewReader(body))
			req.Header.Set("Authorization", "Bearer "+is.Token(t, authtest.Claims{Subject: "lab-" + role, Roles: []string{role}}))
			req.Header.Set("Content-Type", "application/json")
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, req)
			return rec
		}
		set := "/v1/groups/lab:setReplaySampling"
		for _, role := range []string{"viewer", "operator", "approver"} {
			if rec := call(role, http.MethodPost, set, `{"rate_percent":1}`); rec.Code != http.StatusForbidden {
				t.Fatalf("%s: %d", role, rec.Code)
			}
		}
		for _, body := range []string{`{"rate_percent":-1}`, `{"rate_percent":100.5}`, `{"rate_percent":0.001}`} {
			if rec := call("admin", http.MethodPost, set, body); rec.Code != http.StatusBadRequest {
				t.Fatalf("%s: %d %s", body, rec.Code, rec.Body.String())
			}
		}
		rec := call("admin", http.MethodPost, set, `{"rate_percent":1}`)
		if !approved {
			if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "legal review") || rs.sets != 0 {
				t.Fatalf("not approved: %d %s", rec.Code, rec.Body.String())
			}
			// off is always allowed
			if rec := call("admin", http.MethodPost, set, `{"rate_percent":0}`); rec.Code != http.StatusOK {
				t.Fatalf("off: %d %s", rec.Code, rec.Body.String())
			}
			a.Close()
			continue
		}
		if rec.Code != http.StatusOK || strings.Contains(rec.Body.String(), "KKKK") || !strings.Contains(rec.Body.String(), `"key_id":"kabc123"`) {
			t.Fatalf("approved: %d %s", rec.Code, rec.Body.String())
		}
		if len(rs.cmds) != 2 || rs.cmds[0].Kind != store.CommandReplaySync || rs.cmds[0].PolicyID != "" {
			t.Fatalf("commands %+v", rs.cmds)
		}
		get := call("viewer", http.MethodGet, "/v1/groups/lab/replaySampling", "")
		if get.Code != http.StatusOK || !strings.Contains(get.Body.String(), `"rate_percent":1`) || strings.Contains(get.Body.String(), "KKKK") {
			t.Fatalf("get: %d %s", get.Code, get.Body.String())
		}
		a.Close()
	}
}
