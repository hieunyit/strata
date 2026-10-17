package api

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/strata/strata/control-plane/ingest"
	"github.com/strata/strata/control-plane/rulehealth"
)

type healthReadFunc func(context.Context, uint32, string, time.Time, time.Time) (rulehealth.Health, error)

func (f healthReadFunc) Read(ctx context.Context, id uint32, p string, from, to time.Time) (rulehealth.Health, error) {
	return f(ctx, id, p, from, to)
}

func TestRuleHealthReadRolesAndExactRouting(t *testing.T) {
	calls := 0
	reader := healthReadFunc(func(_ context.Context, id uint32, p string, from, to time.Time) (rulehealth.Health, error) {
		calls++
		if id != 942100 || to.Sub(from) != 5*time.Minute {
			t.Errorf("wrong rule/window: %d %v", id, to.Sub(from))
		}
		return rulehealth.Health{RuleID: id, PolicyID: p, From: from, To: to, Status: "observing", CostSamples: "36893488147419103230"}, nil
	})
	forwarded := ""
	s := NewServer(ServerConfig{Auth: tokenRoles{}, Health: reader, Admin: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		forwarded = r.URL.Path
		w.WriteHeader(204)
	})}, ingest.NewMockEventStore())
	const path = "/v1/rules/942100/health"
	if code, _ := do(t, s, "GET", path, "", nil); code != 401 || calls != 0 {
		t.Fatal("unauthenticated health read reached store")
	}
	for _, role := range []string{"viewer", "operator", "approver", "admin"} {
		if code, body := do(t, s, "GET", path, role, nil); code != 200 || body["cost_samples"] != "36893488147419103230" {
			t.Fatalf("%s: %d %v", role, code, body)
		}
	}
	for _, path := range []string{"/v1/rules/942100:emergencyDisable", "/v1/rules/942100/health/extra"} {
		if code, _ := do(t, s, "POST", path, "operator", nil); code != 204 || forwarded != path || calls != 4 {
			t.Fatalf("non-health route was intercepted: %s %d", path, code)
		}
	}
}

func TestRuleHealthRejectsInvalidInputAndDoesNotLeakStoreErrors(t *testing.T) {
	calls := 0
	reader := healthReadFunc(func(context.Context, uint32, string, time.Time, time.Time) (rulehealth.Health, error) {
		calls++
		return rulehealth.Health{}, errors.New("fixture-private-db-details")
	})
	s := NewServer(ServerConfig{Auth: tokenRoles{}, Health: reader}, ingest.NewMockEventStore())
	for _, path := range []string{
		"/v1/rules/0/health", "/v1/rules/no/health", "/v1/rules/4294967296/health",
		"/v1/rules/942100/health?from=bad", "/v1/rules/942100/health?to=",
		"/v1/rules/942100/health?policy_id=a&policy_id=b", "/v1/rules/942100/health?policy_id=%ZZ",
		"/v1/rules/942100/health?from=2026-10-17T00:00:00Z&to=2026-10-19T00:00:00Z",
		"/v1/rules/942100/health?unknown=1", "/v1/rules/942100/health?policy_id=" + strings.Repeat("x", 56),
		"/v1/rules/942100/health?policy_id=" + strings.Repeat("x", 2049),
	} {
		if code, _ := do(t, s, "GET", path, "operator", nil); code != 400 || calls != 0 {
			t.Fatalf("invalid health query reached store: %s %d", path, code)
		}
	}
	const path = "/v1/rules/942100/health"
	if code, _ := do(t, s, "POST", path, "operator", nil); code != 405 || calls != 0 {
		t.Fatal("non-GET request reached health reader")
	}
	if code, body := do(t, s, "GET", path, "operator", nil); code != 503 || strings.Contains(body["error"].(string), "fixture-private") {
		t.Fatalf("store error leaked or became fake healthy data: %d %v", code, body)
	}
	busy := NewServer(ServerConfig{Auth: tokenRoles{}, Health: healthReadFunc(func(context.Context, uint32, string, time.Time, time.Time) (rulehealth.Health, error) {
		return rulehealth.Health{}, rulehealth.ErrBusy
	})}, ingest.NewMockEventStore())
	w := httptest.NewRecorder()
	serve(busy, w, httptest.NewRequest("GET", path, nil))
	if w.Code != 503 || w.Header().Get("Retry-After") != "1" || w.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("wrong busy response: %d %v", w.Code, w.Header())
	}
	without := NewServer(ServerConfig{Auth: tokenRoles{}}, ingest.NewMockEventStore())
	if code, _ := do(t, without, "GET", path, "operator", nil); code != 404 {
		t.Fatalf("health advertised without stores: %d", code)
	}
}
