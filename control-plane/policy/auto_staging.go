package policy

import "fmt"

// AutoStaging is control-plane delegation metadata in an approved policy.
// Omitted or enabled=false never authorizes staging. No threshold is implicit.
// The event share is over stored matched security events, not all requests.
// Effective staged IDs are internal deployment state, never supplied here.
type AutoStaging struct {
	Enabled        bool     `json:"enabled"`
	RuleIDs        []uint32 `json:"rule_ids,omitempty"`
	WindowSeconds  uint32   `json:"window_seconds,omitempty"`
	MinMatches     uint32   `json:"min_matches,omitempty"`
	MinReports     uint32   `json:"min_reports,omitempty"`
	FPThresholdBPS uint32   `json:"fp_threshold_bps,omitempty"`
}

func (a *AutoStaging) Validate() error {
	if a == nil {
		return nil
	}
	if !a.Enabled && len(a.RuleIDs) == 0 && a.WindowSeconds == 0 && a.MinMatches == 0 && a.MinReports == 0 && a.FPThresholdBPS == 0 {
		return nil
	}
	if len(a.RuleIDs) < 1 || len(a.RuleIDs) > 16 {
		return fmt.Errorf("auto_staging: 1 to 16 explicit rule_ids required")
	}
	seen := make(map[uint32]bool, len(a.RuleIDs))
	for _, id := range a.RuleIDs {
		if id == 0 || seen[id] {
			return fmt.Errorf("auto_staging: nonzero distinct rule_ids required")
		}
		seen[id] = true
	}
	if a.WindowSeconds < 60 || a.WindowSeconds > 86400 {
		return fmt.Errorf("auto_staging: window_seconds must be 60 to 86400")
	}
	if a.MinMatches < 1 || a.MinMatches > 1000000000 || a.MinReports < 1 || a.MinReports > a.MinMatches {
		return fmt.Errorf("auto_staging: 1 <= min_reports <= min_matches <= 1000000000 required")
	}
	if a.FPThresholdBPS < 1 || a.FPThresholdBPS > 10000 {
		return fmt.Errorf("auto_staging: fp_threshold_bps must be 1 to 10000")
	}
	return nil
}
