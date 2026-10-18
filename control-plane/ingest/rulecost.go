package ingest

// MaxEventRuleCosts is event.proto's per-event limit, not the cumulative
// worker counters' limit. Event samples contain only the eight costliest rules.
const MaxEventRuleCosts = 8

// RuleCost measures sampled evaluations in nanoseconds. RuleID zero denotes
// shared prefilter work; it must not be attributed to an individual rule.
type RuleCost struct {
	RuleID  uint32
	Samples uint64
	TotalNS uint64
	MaxNS   uint64
}

// validRuleCosts discards malformed optional telemetry without losing the
// security event. Check the length before iterating over untrusted samples.
func validRuleCosts(costs []RuleCost) []RuleCost {
	if len(costs) > MaxEventRuleCosts {
		return nil
	}
	for i, c := range costs {
		if c.Samples == 0 || c.MaxNS > c.TotalNS {
			return nil
		}
		// ceil(total/samples) must not exceed the largest sample. Subtract
		// before dividing so even UInt64 maxima cannot overflow.
		if c.TotalNS > 0 && (c.TotalNS-1)/c.Samples >= c.MaxNS {
			return nil
		}
		for _, prior := range costs[:i] {
			if prior.RuleID == c.RuleID {
				return nil
			}
		}
	}
	return costs
}
