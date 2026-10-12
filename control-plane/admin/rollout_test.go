package admin_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"

	"github.com/strata/strata/control-plane/admin"
	"github.com/strata/strata/control-plane/api"
	"github.com/strata/strata/control-plane/auth"
	"github.com/strata/strata/control-plane/auth/authtest"
	"github.com/strata/strata/control-plane/ingest"
	"github.com/strata/strata/control-plane/store"
)

// memRollouts keeps one rollout and applies SetRolloutState like the store.
type memRollouts struct {
	admin.RolloutStore
	state string
}

func (m *memRollouts) SetRolloutState(_ context.Context, id int64, to, _ string, from []string, _ store.Audit) (store.Rollout, error) {
	if id != 1 {
		return store.Rollout{}, store.ErrNotFound
	}
	if !slices.Contains(from, m.state) {
		return store.Rollout{}, store.ErrRolloutState
	}
	m.state = to
	return store.Rollout{ID: 1, State: to}, nil
}

// W07-G2-01 (check of W05-G2-01): pause, resume, abort follow the state
// machine, need policies:deploy, and wake the rollout controller.
func TestRolloutPauseResumeAbort(t *testing.T) {
	ctx := context.Background()
	is := authtest.New(t)
	v, err := auth.NewVerifier(ctx, auth.Config{Issuer: is.URL, Audience: authtest.Audience})
	if err != nil {
		t.Fatal(err)
	}
	ro := &memRollouts{state: store.RolloutRunning}
	kick := &countKick{}
	a, err := admin.New(ctx, v, admin.BuildInfo{}, admin.Deps{Rollouts: ro, Kicker: kick})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(a.Close)
	h := api.NewServer(api.ServerConfig{Auth: v, Admin: a.Gateway}, ingest.NewMockEventStore()).Handler()
	call := func(role, path string) int {
		req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(`{}`))
		req.Header.Set("Authorization", "Bearer "+is.Token(t, authtest.Claims{Subject: "lab-" + role, Roles: []string{role}}))
		req.Header.Set("Content-Type", "application/json")
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		return rec.Code
	}
	for _, c := range []struct {
		role, path string
		code       int
		state      string
	}{
		{"viewer", "/v1/rollouts/1:pause", http.StatusForbidden, store.RolloutRunning},
		{"operator", "/v1/rollouts/1:resume", http.StatusBadRequest, store.RolloutRunning}, // FailedPrecondition
		{"operator", "/v1/rollouts/1:pause", http.StatusOK, store.RolloutPaused},
		{"operator", "/v1/rollouts/1:pause", http.StatusBadRequest, store.RolloutPaused},
		{"operator", "/v1/rollouts/1:resume", http.StatusOK, store.RolloutRunning},
		{"operator", "/v1/rollouts/2:abort", http.StatusNotFound, store.RolloutRunning},
		{"operator", "/v1/rollouts/1:abort", http.StatusOK, store.RolloutAborted},
		{"operator", "/v1/rollouts/1:resume", http.StatusBadRequest, store.RolloutAborted},
	} {
		if got := call(c.role, c.path); got != c.code || ro.state != c.state {
			t.Errorf("%s %s: %d (state %s), want %d (%s)", c.role, c.path, got, ro.state, c.code, c.state)
		}
	}
	if kick.n != 3 {
		t.Errorf("%d kicks, want 3", kick.n)
	}
}
