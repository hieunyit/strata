package rulehealth

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/strata/strata/control-plane/ingest"
)

var (
	ErrBusy        = errors.New("rule health query capacity reached")
	ErrUnavailable = errors.New("rule health stores unavailable")
	ErrInvalid     = errors.New("invalid rule health query")
)

type EventReader interface {
	RuleTelemetry(context.Context, uint32, string, time.Time, time.Time) (ingest.RuleTelemetry, error)
}

type FPReader interface {
	RuleFalsePositiveEvents(context.Context, uint32, string, time.Time, time.Time) (uint64, error)
}

type Health struct {
	RuleID           uint32    `json:"rule_id"`
	PolicyID         string    `json:"policy_id,omitempty"`
	From             time.Time `json:"from"`
	To               time.Time `json:"to"`
	Status           string    `json:"status"`
	MatchedEvents    uint64    `json:"matched_events"`
	ReportedFPEvents uint64    `json:"reported_fp_events"`
	ReportedFPShare  *float64  `json:"reported_fp_share"`
	CostSource       string    `json:"cost_source"`
	CostSamples      string    `json:"cost_samples"`
	CostTotalNS      string    `json:"cost_total_ns"`
	CostMeanNS       *float64  `json:"cost_mean_ns"`
}

// Service reads durable telemetry and optional staging thresholds. It never
// approves, deploys or writes state. Four in-flight queries per replica bound this expensive path.
type Service struct {
	events      EventReader
	annotations FPReader
	slots       chan struct{}
}

func NewService(events EventReader, annotations FPReader) *Service {
	return &Service{events: events, annotations: annotations, slots: make(chan struct{}, 4)}
}

func (s *Service) Read(ctx context.Context, rule uint32, policy string, from, to time.Time) (Health, error) {
	out := Health{RuleID: rule, PolicyID: policy, From: from.UTC(), To: to.UTC(), CostSource: "sampled_security_events_top8"}
	if rule == 0 || from.IsZero() || !to.After(from) || to.Sub(from) > 24*time.Hour || len(policy) > 55 {
		return out, ErrInvalid
	}
	if s.events == nil || s.annotations == nil {
		return out, ErrUnavailable
	}
	if err := ctx.Err(); err != nil {
		return out, err
	}
	select {
	case s.slots <- struct{}{}:
		defer func() { <-s.slots }()
	default:
		return out, ErrBusy
	}
	bounded, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	tm, err := s.events.RuleTelemetry(bounded, rule, policy, out.From, out.To)
	if err != nil {
		return out, fmt.Errorf("rule health events: %w", err)
	}
	fp, err := s.annotations.RuleFalsePositiveEvents(bounded, rule, policy, out.From, out.To)
	if err != nil {
		return out, fmt.Errorf("rule health annotations: %w", err)
	}
	out.MatchedEvents, out.ReportedFPEvents = tm.MatchedEvents, fp
	out.CostSamples, out.CostTotalNS, out.CostMeanNS = tm.CostSamples, tm.CostTotalNS, tm.CostMeanNS
	out.Status = "observing"
	switch {
	case fp > tm.MatchedEvents:
		out.Status = "inconsistent_snapshot"
	case tm.MatchedEvents == 0:
		out.Status = "insufficient_telemetry"
	default:
		share := float64(fp) / float64(tm.MatchedEvents)
		out.ReportedFPShare = &share
	}
	return out, nil
}
