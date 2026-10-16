package policy

import (
	"errors"
	"fmt"
	"strings"
	"time"
)

// Action represents the verdict action for a rule evaluation.
type Action string

const (
	ActionBlock Action = "block"
	ActionLog   Action = "log"
	ActionCount Action = "count"
	ActionSkip  Action = "skip"
)

// Exception represents an active exception on a rule and field (W14-R-01).
// Exceptions have highest priority and bypass rule checks when valid.
type Exception struct {
	ID        string    `json:"id"`
	PolicyID  string    `json:"policy_id"`
	RuleID    uint32    `json:"rule_id"`
	Field     string    `json:"field"`
	Reason    string    `json:"reason"`
	CreatedBy string    `json:"created_by"`
	CreatedAt time.Time `json:"created_at"`
	ExpiresAt time.Time `json:"expires_at"`
	Status    string    `json:"status"` // APPROVED, PENDING_REVIEW, REJECTED
}

// Override represents a conditional configuration override (e.g. path prefix).
type Override struct {
	ID         string `json:"id"`
	PolicyID   string `json:"policy_id"`
	PathPrefix string `json:"path_prefix"`
	RuleID     uint32 `json:"rule_id,omitempty"` // 0 indicates all rules on path
	Action     Action `json:"action"`
}

// RuleContext provides the execution context for resolving rule decisions.
type RuleContext struct {
	PolicyID string
	Path     string
	RuleID   uint32
	Field    string
	Now      time.Time
}

// ErrRuleConflict indicates conflicting override configurations.
var ErrRuleConflict = errors.New("rule conflict: duplicate override with conflicting action")

// ResolveRuleAction resolves the effective action for a rule violation.
// Priority order:
// 1. Exception (if approved, matching policy, rule, field, and unexpired) -> ActionSkip
// 2. Override (if matching policy, path prefix, and rule) -> ovr.Action
// 3. Default action -> defaultAction
func ResolveRuleAction(ctx RuleContext, defaultAction Action, exceptions []Exception, overrides []Override) (Action, string) {
	// 1. Exceptions evaluation first (highest priority)
	for _, exc := range exceptions {
		if exc.Status != "APPROVED" {
			continue
		}
		if exc.PolicyID != "" && exc.PolicyID != ctx.PolicyID {
			continue
		}
		if exc.RuleID != ctx.RuleID {
			continue
		}
		if exc.Field != "" && exc.Field != "*" && exc.Field != ctx.Field {
			continue
		}
		if !exc.ExpiresAt.IsZero() && ctx.Now.After(exc.ExpiresAt) {
			// Expired exception, ignore!
			continue
		}
		return ActionSkip, fmt.Sprintf("exception:%s", exc.ID)
	}

	// 2. Overrides evaluation second
	for _, ovr := range overrides {
		if ovr.PolicyID != "" && ovr.PolicyID != ctx.PolicyID {
			continue
		}
		if ovr.PathPrefix != "" && !strings.HasPrefix(ctx.Path, ovr.PathPrefix) {
			continue
		}
		if ovr.RuleID != 0 && ovr.RuleID != ctx.RuleID {
			continue
		}
		return ovr.Action, fmt.Sprintf("override:%s", ovr.ID)
	}

	// 3. Default action
	return defaultAction, "default"
}

// FilterActiveExceptions discards expired or non-approved exceptions.
func FilterActiveExceptions(exceptions []Exception, now time.Time) []Exception {
	var active []Exception
	for _, exc := range exceptions {
		if exc.Status != "APPROVED" {
			continue
		}
		if !exc.ExpiresAt.IsZero() && now.After(exc.ExpiresAt) {
			continue
		}
		active = append(active, exc)
	}
	return active
}

// ValidateOverrides verifies that no two overrides have conflicting actions for the same path and rule.
func ValidateOverrides(overrides []Override) error {
	for i := 0; i < len(overrides); i++ {
		for j := i + 1; j < len(overrides); j++ {
			o1, o2 := overrides[i], overrides[j]
			if o1.PolicyID == o2.PolicyID &&
				o1.PathPrefix == o2.PathPrefix &&
				o1.RuleID == o2.RuleID &&
				o1.Action != o2.Action {
				return fmt.Errorf("%w: override %s (%s) vs %s (%s) on rule %d path %q",
					ErrRuleConflict, o1.ID, o1.Action, o2.ID, o2.Action, o1.RuleID, o1.PathPrefix)
			}
		}
	}
	return nil
}
