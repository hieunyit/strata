package policy_test

import (
	"errors"
	"testing"
	"time"

	"github.com/strata/strata/control-plane/policy"
)

func TestResolveRuleAction_ExceptionOverridesOverride(t *testing.T) {
	now := time.Now()
	ctx := policy.RuleContext{
		PolicyID: "example-api",
		Path:     "/api/v1/auth/login",
		RuleID:   942100,
		Field:    "args.username",
		Now:      now,
	}

	overrides := []policy.Override{
		{
			ID:         "ovr-block-login",
			PolicyID:   "example-api",
			PathPrefix: "/api/v1/auth",
			RuleID:     942100,
			Action:     policy.ActionBlock,
		},
	}

	exceptions := []policy.Exception{
		{
			ID:        "exc-login-user",
			PolicyID:  "example-api",
			RuleID:    942100,
			Field:     "args.username",
			ExpiresAt: now.Add(24 * time.Hour),
			Status:    "APPROVED",
		},
	}

	action, reason := policy.ResolveRuleAction(ctx, policy.ActionLog, exceptions, overrides)

	if action != policy.ActionSkip {
		t.Fatalf("expected action ActionSkip, got %v", action)
	}
	if reason != "exception:exc-login-user" {
		t.Fatalf("expected reason exception:exc-login-user, got %v", reason)
	}
}

func TestResolveRuleAction_OverrideOverridesDefault(t *testing.T) {
	now := time.Now()
	ctx := policy.RuleContext{
		PolicyID: "example-api",
		Path:     "/upload",
		RuleID:   942100,
		Field:    "body.file",
		Now:      now,
	}

	overrides := []policy.Override{
		{
			ID:         "ovr-skip-upload",
			PolicyID:   "example-api",
			PathPrefix: "/upload",
			RuleID:     942100,
			Action:     policy.ActionSkip,
		},
	}

	action, reason := policy.ResolveRuleAction(ctx, policy.ActionBlock, nil, overrides)

	if action != policy.ActionSkip {
		t.Fatalf("expected action ActionSkip, got %v", action)
	}
	if reason != "override:ovr-skip-upload" {
		t.Fatalf("expected reason override:ovr-skip-upload, got %v", reason)
	}
}

func TestResolveRuleAction_ExpiredExceptionIsIgnored(t *testing.T) {
	now := time.Now()
	ctx := policy.RuleContext{
		PolicyID: "example-api",
		Path:     "/api/v1/auth/login",
		RuleID:   942100,
		Field:    "args.username",
		Now:      now,
	}

	overrides := []policy.Override{
		{
			ID:         "ovr-count-login",
			PolicyID:   "example-api",
			PathPrefix: "/api/v1/auth",
			RuleID:     942100,
			Action:     policy.ActionCount,
		},
	}

	exceptions := []policy.Exception{
		{
			ID:        "exc-expired",
			PolicyID:  "example-api",
			RuleID:    942100,
			Field:     "args.username",
			ExpiresAt: now.Add(-1 * time.Hour), // Expired 1 hour ago
			Status:    "APPROVED",
		},
	}

	action, reason := policy.ResolveRuleAction(ctx, policy.ActionBlock, exceptions, overrides)

	// Expired exception ignored -> Override applies!
	if action != policy.ActionCount {
		t.Fatalf("expected action ActionCount, got %v", action)
	}
	if reason != "override:ovr-count-login" {
		t.Fatalf("expected reason override:ovr-count-login, got %v", reason)
	}
}

func TestResolveRuleAction_UnapprovedExceptionIsIgnored(t *testing.T) {
	now := time.Now()
	ctx := policy.RuleContext{
		PolicyID: "example-api",
		Path:     "/search",
		RuleID:   941100,
		Field:    "query.q",
		Now:      now,
	}

	exceptions := []policy.Exception{
		{
			ID:        "exc-pending",
			PolicyID:  "example-api",
			RuleID:    941100,
			Field:     "query.q",
			ExpiresAt: now.Add(24 * time.Hour),
			Status:    "PENDING_REVIEW", // Not approved
		},
	}

	action, reason := policy.ResolveRuleAction(ctx, policy.ActionBlock, exceptions, nil)

	if action != policy.ActionBlock {
		t.Fatalf("expected default action ActionBlock, got %v", action)
	}
	if reason != "default" {
		t.Fatalf("expected reason default, got %v", reason)
	}
}

func TestFilterActiveExceptions(t *testing.T) {
	now := time.Now()
	exceptions := []policy.Exception{
		{
			ID:        "active-1",
			RuleID:    1,
			ExpiresAt: now.Add(10 * time.Minute),
			Status:    "APPROVED",
		},
		{
			ID:        "expired-1",
			RuleID:    2,
			ExpiresAt: now.Add(-1 * time.Minute),
			Status:    "APPROVED",
		},
		{
			ID:        "pending-1",
			RuleID:    3,
			ExpiresAt: now.Add(10 * time.Minute),
			Status:    "PENDING_REVIEW",
		},
	}

	active := policy.FilterActiveExceptions(exceptions, now)
	if len(active) != 1 || active[0].ID != "active-1" {
		t.Fatalf("unexpected active exceptions: %+v", active)
	}
}

func TestValidateOverrides_ConflictDetection(t *testing.T) {
	valid := []policy.Override{
		{ID: "o1", PolicyID: "p1", PathPrefix: "/a", RuleID: 10, Action: policy.ActionCount},
		{ID: "o2", PolicyID: "p1", PathPrefix: "/b", RuleID: 10, Action: policy.ActionSkip},
	}
	if err := policy.ValidateOverrides(valid); err != nil {
		t.Fatalf("unexpected error for valid overrides: %v", err)
	}

	conflicting := []policy.Override{
		{ID: "c1", PolicyID: "p1", PathPrefix: "/a", RuleID: 10, Action: policy.ActionCount},
		{ID: "c2", PolicyID: "p1", PathPrefix: "/a", RuleID: 10, Action: policy.ActionBlock},
	}
	err := policy.ValidateOverrides(conflicting)
	if err == nil || !errors.Is(err, policy.ErrRuleConflict) {
		t.Fatalf("expected ErrRuleConflict, got %v", err)
	}
}
