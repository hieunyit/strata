package api

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/strata/strata/control-plane/store"
)

// RuleHealthStatus defines the health status of a rule.
type RuleHealthStatus string

const (
	StatusHealthy               RuleHealthStatus = "healthy"
	StatusQuarantinedStaging    RuleHealthStatus = "quarantined_staging"
	StatusDisabled              RuleHealthStatus = "disabled"
	StatusInsufficientTelemetry RuleHealthStatus = "insufficient_telemetry"
)

// RuleHealth is the JSON response for GET /v1/rules/{rule_id}/health (W14-G2-02).
type RuleHealth struct {
	RuleID             uint32           `json:"rule_id"`
	Status             RuleHealthStatus `json:"status"`
	MatchesCount       uint64           `json:"matches_count"`
	FalsePositiveCount uint64           `json:"false_positive_count"`
	FalsePositiveRate  float64          `json:"false_positive_rate"`
	AvgLatencyUs       uint64           `json:"avg_latency_us"`
	LastEvaluatedAt    time.Time        `json:"last_evaluated_at"`
	QuarantineReason   string           `json:"quarantine_reason,omitempty"`
	QuarantinedAt      *time.Time       `json:"quarantined_at,omitempty"`
	CooldownUntil      *time.Time       `json:"cooldown_until,omitempty"`
}

// QuarantineConfig configures the auto-quarantine detection parameters.
type QuarantineConfig struct {
	WindowDuration   time.Duration // Sliding window for metrics (default 5m)
	MinMatches       uint64        // Minimum matches before judging surge (default 10)
	FPSurgeThreshold float64       // False positive rate surge threshold (e.g. 0.05 = 5%)
	MinFPCount       uint64        // Minimum absolute FPs to trigger surge (default 5)
	CooldownDuration time.Duration // Anti-flapping cooldown period (default 15m)
	AutoQuarantine   bool          // Whether to automatically transition to staging
}

// DefaultQuarantineConfig returns production-safe defaults.
func DefaultQuarantineConfig() QuarantineConfig {
	return QuarantineConfig{
		WindowDuration:   5 * time.Minute,
		MinMatches:       10,
		FPSurgeThreshold: 0.05,
		MinFPCount:       5,
		CooldownDuration: 15 * time.Minute,
		AutoQuarantine:   true,
	}
}

// RuleHealthAlert is sent to approvers upon auto-quarantine.
type RuleHealthAlert struct {
	RuleID    uint32           `json:"rule_id"`
	OldStatus RuleHealthStatus `json:"old_status"`
	NewStatus RuleHealthStatus `json:"new_status"`
	Reason    string           `json:"reason"`
	FPCount   uint64           `json:"fp_count"`
	FPRate    float64          `json:"fp_rate"`
	Timestamp time.Time        `json:"timestamp"`
}

// ErrAntiFlappingActive is returned when trying to recover a rule before its cooldown expires.
var ErrAntiFlappingActive = errors.New("rule cannot be recovered: anti-flapping cooldown is active")

type ruleEvent struct {
	timestamp time.Time
	isFP      bool
	latencyUs uint64
}

type ruleState struct {
	ruleID           uint32
	status           RuleHealthStatus
	events           []ruleEvent
	quarantinedAt    *time.Time
	cooldownUntil    *time.Time
	quarantineReason string
	lastEvaluatedAt  time.Time
}

// RuleHealthMonitor manages rule health evaluation and auto-quarantine.
type RuleHealthMonitor struct {
	mu         sync.RWMutex
	cfg        QuarantineConfig
	rules      map[uint32]*ruleState
	alertSinks []func(alert RuleHealthAlert)
	auditSinks []func(a store.Audit)
}

// NewRuleHealthMonitor creates a new monitor with the given config.
func NewRuleHealthMonitor(cfg QuarantineConfig) *RuleHealthMonitor {
	if cfg.WindowDuration <= 0 {
		cfg.WindowDuration = 5 * time.Minute
	}
	if cfg.MinMatches == 0 {
		cfg.MinMatches = 10
	}
	if cfg.FPSurgeThreshold <= 0 {
		cfg.FPSurgeThreshold = 0.05
	}
	if cfg.MinFPCount == 0 {
		cfg.MinFPCount = 5
	}
	if cfg.CooldownDuration <= 0 {
		cfg.CooldownDuration = 15 * time.Minute
	}

	return &RuleHealthMonitor{
		cfg:   cfg,
		rules: make(map[uint32]*ruleState),
	}
}

// OnAlert registers a callback to notify approvers.
func (m *RuleHealthMonitor) OnAlert(sink func(alert RuleHealthAlert)) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.alertSinks = append(m.alertSinks, sink)
}

// OnAudit registers a callback to record audit logs.
func (m *RuleHealthMonitor) OnAudit(sink func(a store.Audit)) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.auditSinks = append(m.auditSinks, sink)
}

// RecordEvent records an execution metric for a rule.
func (m *RuleHealthMonitor) RecordEvent(ruleID uint32, isFP bool, latencyUs uint64, t time.Time) {
	m.mu.Lock()
	defer m.mu.Unlock()

	st, ok := m.rules[ruleID]
	if !ok {
		st = &ruleState{
			ruleID: ruleID,
			status: StatusHealthy,
		}
		m.rules[ruleID] = st
	}

	st.events = append(st.events, ruleEvent{
		timestamp: t,
		isFP:      isFP,
		latencyUs: latencyUs,
	})
}

// GetHealth computes and returns the current health status of a rule.
func (m *RuleHealthMonitor) GetHealth(ctx context.Context, ruleID uint32, now time.Time) (RuleHealth, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	st, ok := m.rules[ruleID]
	if !ok {
		return RuleHealth{
			RuleID:          ruleID,
			Status:          StatusInsufficientTelemetry,
			LastEvaluatedAt: now,
		}, nil
	}

	// Purge events older than window
	windowStart := now.Add(-m.cfg.WindowDuration)
	validEvents := make([]ruleEvent, 0, len(st.events))
	var matchCount, fpCount, totalLatency uint64

	for _, e := range st.events {
		if e.timestamp.After(windowStart) {
			validEvents = append(validEvents, e)
			matchCount++
			if e.isFP {
				fpCount++
			}
			totalLatency += e.latencyUs
		}
	}
	st.events = validEvents
	st.lastEvaluatedAt = now

	var fpRate float64
	var avgLatency uint64
	if matchCount > 0 {
		fpRate = float64(fpCount) / float64(matchCount)
		avgLatency = totalLatency / matchCount
	}

	// Evaluate status
	if matchCount < m.cfg.MinMatches && st.status != StatusQuarantinedStaging && st.status != StatusDisabled {
		st.status = StatusInsufficientTelemetry
	} else if m.cfg.AutoQuarantine && st.status != StatusDisabled && st.status != StatusQuarantinedStaging {
		// Detect FP surge: minimum FP count met AND rate exceeds threshold
		if fpCount >= m.cfg.MinFPCount && fpRate >= m.cfg.FPSurgeThreshold {
			oldStatus := st.status
			st.status = StatusQuarantinedStaging
			qAt := now
			st.quarantinedAt = &qAt
			cdUntil := now.Add(m.cfg.CooldownDuration)
			st.cooldownUntil = &cdUntil
			st.quarantineReason = fmt.Sprintf("FP surge detected: %d FPs (%.1f%%) in %s (threshold: %.1f%%)",
				fpCount, fpRate*100, m.cfg.WindowDuration, m.cfg.FPSurgeThreshold*100)

			// Notify approvers
			alert := RuleHealthAlert{
				RuleID:    ruleID,
				OldStatus: oldStatus,
				NewStatus: st.status,
				Reason:    st.quarantineReason,
				FPCount:   fpCount,
				FPRate:    fpRate,
				Timestamp: now,
			}
			for _, sink := range m.alertSinks {
				sink(alert)
			}

			// Record audit log
			audit := store.Audit{
				Actor:    "system:rule_health_monitor",
				Channel:  "system",
				Action:   "RuleAutoQuarantined",
				Resource: fmt.Sprintf("rules/%d", ruleID),
			}
			for _, sink := range m.auditSinks {
				sink(audit)
			}
		} else {
			st.status = StatusHealthy
		}
	}

	return RuleHealth{
		RuleID:             ruleID,
		Status:             st.status,
		MatchesCount:       matchCount,
		FalsePositiveCount: fpCount,
		FalsePositiveRate:  fpRate,
		AvgLatencyUs:       avgLatency,
		LastEvaluatedAt:    now,
		QuarantineReason:   st.quarantineReason,
		QuarantinedAt:      st.quarantinedAt,
		CooldownUntil:      st.cooldownUntil,
	}, nil
}

// Recover manually or automatically restores a quarantined rule to healthy status.
func (m *RuleHealthMonitor) Recover(ctx context.Context, ruleID uint32, actor string, now time.Time) (RuleHealth, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	st, ok := m.rules[ruleID]
	if !ok {
		return RuleHealth{}, fmt.Errorf("rule %d not found", ruleID)
	}

	// Check anti-flapping guardrail
	if st.cooldownUntil != nil && now.Before(*st.cooldownUntil) {
		return RuleHealth{}, fmt.Errorf("%w: cooldown active until %s", ErrAntiFlappingActive, st.cooldownUntil.Format(time.RFC3339))
	}

	st.status = StatusHealthy
	st.quarantinedAt = nil
	st.cooldownUntil = nil
	st.quarantineReason = ""
	st.lastEvaluatedAt = now

	// Record audit
	audit := store.Audit{
		Actor:    actor,
		Channel:  "api",
		Action:   "RuleRecovered",
		Resource: fmt.Sprintf("rules/%d", ruleID),
	}
	for _, sink := range m.auditSinks {
		sink(audit)
	}

	return RuleHealth{
		RuleID:          ruleID,
		Status:          st.status,
		LastEvaluatedAt: now,
	}, nil
}

// HandleGetRuleHealth serves GET /v1/rules/{rule_id}/health.
func (s *Server) HandleGetRuleHealth(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed", "")
		return
	}

	// Path expected: /v1/rules/{rule_id}/health
	parts := strings.Split(strings.Trim(r.URL.Path, "/"), "/")
	if len(parts) != 4 || parts[0] != "v1" || parts[1] != "rules" || parts[3] != "health" {
		writeError(w, http.StatusNotFound, "route not found", "")
		return
	}

	ruleID64, err := strconv.ParseUint(parts[2], 10, 32)
	if err != nil || ruleID64 == 0 {
		writeError(w, http.StatusBadRequest, "invalid rule_id: must be positive integer", "")
		return
	}
	ruleID := uint32(ruleID64)

	if s.healthMonitor == nil {
		s.healthMonitor = NewRuleHealthMonitor(DefaultQuarantineConfig())
	}

	health, err := s.healthMonitor.GetHealth(r.Context(), ruleID, time.Now())
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to evaluate rule health", err.Error())
		return
	}

	writeJSON(w, http.StatusOK, health)
}
