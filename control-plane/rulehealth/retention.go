// Package rulehealth holds the background work for durable rule telemetry.
package rulehealth

import (
	"context"
	"log"
	"time"

	"github.com/strata/strata/control-plane/ingest"
)

type ContextPruner interface {
	PruneRuleAnnotationContext(context.Context, time.Time, int) (int64, error)
}

// ContextRetention keeps FP context for at most 90 days. Main can select a
// shorter configured event retention window.
// It deletes at most 1000 rows per minute and never runs on an HTTP read path.
// Backlogs drain incrementally; this is not an immediate hard disk-size cap.
type ContextRetention struct {
	Store    ContextPruner
	Interval time.Duration // <=0: one minute
	MaxAge   time.Duration // <=0 or >90 days: the 90-day event age limit
}

func (r ContextRetention) Run(ctx context.Context) {
	interval := r.Interval
	if interval <= 0 {
		interval = time.Minute
	}
	maxAge := r.MaxAge
	if maxAge <= 0 || maxAge > ingest.MaxEventAge {
		maxAge = ingest.MaxEventAge
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		if ctx.Err() != nil {
			return
		}
		bounded, cancel := context.WithTimeout(ctx, 5*time.Second)
		_, err := r.Store.PruneRuleAnnotationContext(bounded, time.Now().UTC().Add(-maxAge), 1000)
		cancel()
		if err != nil && ctx.Err() == nil {
			log.Printf("[WARN] rule health: context retention: %v", err)
		}
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}
