package api_test

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/strata/strata/control-plane/api"
	"github.com/strata/strata/control-plane/auth"
	"github.com/strata/strata/control-plane/auth/authtest"
	"github.com/strata/strata/control-plane/ingest"
	"github.com/strata/strata/control-plane/store"
)

func TestRuleHealth_InsufficientTelemetry(t *testing.T) {
	ctx := context.Background()
	monitor := api.NewRuleHealthMonitor(api.QuarantineConfig{
		WindowDuration:   5 * time.Minute,
		MinMatches:       10,
		FPSurgeThreshold: 0.05,
		MinFPCount:       5,
	})

	now := time.Now()
	// Record only 3 events (< 10 MinMatches)
	for i := 0; i < 3; i++ {
		monitor.RecordEvent(942100, false, 50, now)
	}

	health, err := monitor.GetHealth(ctx, 942100, now)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if health.Status != api.StatusInsufficientTelemetry {
		t.Fatalf("expected status %s, got %s", api.StatusInsufficientTelemetry, health.Status)
	}
	if health.MatchesCount != 3 {
		t.Fatalf("expected 3 matches, got %d", health.MatchesCount)
	}
}

func TestRuleHealth_Healthy(t *testing.T) {
	ctx := context.Background()
	monitor := api.NewRuleHealthMonitor(api.QuarantineConfig{
		WindowDuration:   5 * time.Minute,
		MinMatches:       10,
		FPSurgeThreshold: 0.05,
		MinFPCount:       5,
	})

	now := time.Now()
	// Record 20 events with 0 FP
	for i := 0; i < 20; i++ {
		monitor.RecordEvent(942100, false, 40, now)
	}

	health, err := monitor.GetHealth(ctx, 942100, now)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if health.Status != api.StatusHealthy {
		t.Fatalf("expected status %s, got %s", api.StatusHealthy, health.Status)
	}
	if health.FalsePositiveRate != 0 {
		t.Fatalf("expected 0 FP rate, got %f", health.FalsePositiveRate)
	}
}

func TestRuleHealth_FPSurgeAutoQuarantine(t *testing.T) {
	ctx := context.Background()
	monitor := api.NewRuleHealthMonitor(api.QuarantineConfig{
		WindowDuration:   5 * time.Minute,
		MinMatches:       10,
		FPSurgeThreshold: 0.10, // 10% threshold
		MinFPCount:       5,
		CooldownDuration: 15 * time.Minute,
		AutoQuarantine:   true,
	})

	var alertReceived *api.RuleHealthAlert
	monitor.OnAlert(func(alert api.RuleHealthAlert) {
		alertReceived = &alert
	})

	var auditRecorded *store.Audit
	monitor.OnAudit(func(a store.Audit) {
		auditRecorded = &a
	})

	now := time.Now()
	// 20 total matches: 6 False Positives (30% FP rate > 10% threshold)
	for i := 0; i < 14; i++ {
		monitor.RecordEvent(942100, false, 50, now)
	}
	for i := 0; i < 6; i++ {
		monitor.RecordEvent(942100, true, 80, now)
	}

	health, err := monitor.GetHealth(ctx, 942100, now)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Rule must be auto-quarantined into staging (log-only mode)
	if health.Status != api.StatusQuarantinedStaging {
		t.Fatalf("expected status %s, got %s", api.StatusQuarantinedStaging, health.Status)
	}
	if health.FalsePositiveCount != 6 {
		t.Fatalf("expected 6 FPs, got %d", health.FalsePositiveCount)
	}
	if health.CooldownUntil == nil {
		t.Fatal("expected cooldown_until to be set")
	}

	// Verify Alert dispatched to approver
	if alertReceived == nil {
		t.Fatal("expected alert to be dispatched to approver")
	}
	if alertReceived.RuleID != 942100 || alertReceived.NewStatus != api.StatusQuarantinedStaging {
		t.Fatalf("unexpected alert payload: %+v", alertReceived)
	}

	// Verify Audit record generated
	if auditRecorded == nil {
		t.Fatal("expected audit record to be logged")
	}
	if auditRecorded.Action != "RuleAutoQuarantined" || auditRecorded.Resource != "rules/942100" {
		t.Fatalf("unexpected audit record: %+v", auditRecorded)
	}
}

func TestRuleHealth_AntiFlappingAndRecovery(t *testing.T) {
	ctx := context.Background()
	monitor := api.NewRuleHealthMonitor(api.QuarantineConfig{
		WindowDuration:   5 * time.Minute,
		MinMatches:       10,
		FPSurgeThreshold: 0.10,
		MinFPCount:       5,
		CooldownDuration: 15 * time.Minute,
		AutoQuarantine:   true,
	})

	now := time.Now()
	for i := 0; i < 10; i++ {
		monitor.RecordEvent(942100, true, 50, now)
	}

	// Trigger auto-quarantine
	health, _ := monitor.GetHealth(ctx, 942100, now)
	if health.Status != api.StatusQuarantinedStaging {
		t.Fatalf("expected quarantined_staging, got %s", health.Status)
	}

	// Attempt recovery during cooldown (5 minutes later < 15 minute cooldown)
	fiveMinLater := now.Add(5 * time.Minute)
	_, errEarly := monitor.Recover(ctx, 942100, "operator", fiveMinLater)
	if errEarly == nil || !errors.Is(errEarly, api.ErrAntiFlappingActive) {
		t.Fatalf("expected ErrAntiFlappingActive, got %v", errEarly)
	}

	// Attempt recovery after cooldown expires (16 minutes later > 15 minute cooldown)
	sixteenMinLater := now.Add(16 * time.Minute)
	recovered, errRecovered := monitor.Recover(ctx, 942100, "operator", sixteenMinLater)
	if errRecovered != nil {
		t.Fatalf("expected successful recovery after cooldown, got: %v", errRecovered)
	}
	if recovered.Status != api.StatusHealthy {
		t.Fatalf("expected status healthy after recovery, got %s", recovered.Status)
	}
}

func TestRuleHealth_HTTP_Endpoint(t *testing.T) {
	ctx := context.Background()
	is := authtest.New(t)
	verifier, err := auth.NewVerifier(ctx, auth.Config{Issuer: is.URL, Audience: authtest.Audience})
	if err != nil {
		t.Fatal(err)
	}

	monitor := api.NewRuleHealthMonitor(api.DefaultQuarantineConfig())
	now := time.Now()
	for i := 0; i < 15; i++ {
		monitor.RecordEvent(941100, false, 30, now)
	}

	srv := api.NewServer(api.ServerConfig{
		Auth:          verifier,
		HealthMonitor: monitor,
	}, ingest.NewMockEventStore())

	token := is.Token(t, authtest.Claims{Subject: "test-viewer", Roles: []string{"viewer"}})

	// 1. Success case: GET /v1/rules/941100/health
	req := httptest.NewRequest(http.MethodGet, "/v1/rules/941100/health", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 OK, got %d: %s", rec.Code, rec.Body.String())
	}

	var resp api.RuleHealth
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}
	if resp.RuleID != 941100 || resp.Status != api.StatusHealthy || resp.MatchesCount != 15 {
		t.Fatalf("unexpected rule health response: %+v", resp)
	}

	// 2. Bad request: invalid rule ID
	reqBad := httptest.NewRequest(http.MethodGet, "/v1/rules/abc/health", nil)
	reqBad.Header.Set("Authorization", "Bearer "+token)
	recBad := httptest.NewRecorder()
	srv.Handler().ServeHTTP(recBad, reqBad)
	if recBad.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 Bad Request, got %d", recBad.Code)
	}

	// 3. Not found: wrong suffix
	req404 := httptest.NewRequest(http.MethodGet, "/v1/rules/941100/details", nil)
	req404.Header.Set("Authorization", "Bearer "+token)
	rec404 := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec404, req404)
	if rec404.Code != http.StatusNotFound {
		t.Fatalf("expected 404 Not Found, got %d", rec404.Code)
	}

	// 4. Unauthorized: missing token
	reqUnauth := httptest.NewRequest(http.MethodGet, "/v1/rules/941100/health", nil)
	recUnauth := httptest.NewRecorder()
	srv.Handler().ServeHTTP(recUnauth, reqUnauth)
	if recUnauth.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 Unauthorized, got %d", recUnauth.Code)
	}
}
