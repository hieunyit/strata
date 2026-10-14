package ingest

import (
	"time"
)

// Violation represents an individual rule match or inspection violation.
type Violation struct {
	RuleID  uint32 `json:"rule_id" ch:"rule_id"`
	Layer   string `json:"layer" ch:"layer"`
	Field   string `json:"field" ch:"field"`
	Snippet string `json:"snippet" ch:"snippet"`
}

// Header is a request header of an event's context (RV-G2-01), masked by
// the engine: sensitive values are [MASKED].
type Header struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

// Event represents a security event produced by proxy connectors and agent.
type Event struct {
	BlockID       string      `json:"block_id" ch:"block_id"`
	Timestamp     time.Time   `json:"timestamp" ch:"timestamp"`
	NodeID        string      `json:"node_id" ch:"node_id"`
	ConnectorType string      `json:"connector_type" ch:"connector_type"`
	PolicyID      string      `json:"policy_id" ch:"policy_id"`
	PolicyVersion uint64      `json:"policy_version" ch:"policy_version"`
	ClientIP      string      `json:"client_ip" ch:"client_ip"`
	Identity      string      `json:"identity" ch:"identity"`
	RequestID     string      `json:"request_id" ch:"request_id"`
	HTTPMethod    string      `json:"http_method" ch:"http_method"`
	HTTPHost      string      `json:"http_host" ch:"http_host"`
	HTTPPath      string      `json:"http_path" ch:"http_path"`
	StatusCode    uint16      `json:"status_code" ch:"status_code"`
	Action        string      `json:"action" ch:"action"`
	ScoreProtocol int32       `json:"score_protocol" ch:"score_protocol"`
	ScoreSQLi     int32       `json:"score_sqli" ch:"score_sqli"`
	ScoreXSS      int32       `json:"score_xss" ch:"score_xss"`
	ScoreAnomaly  int32       `json:"score_anomaly" ch:"score_anomaly"`
	MatchedRules  []uint32    `json:"matched_rules" ch:"matched_rules"`
	Violations    []Violation `json:"violations" ch:"violations"`
	ReceivedAt    time.Time   `json:"received_at" ch:"received_at"`
	// RV-G2-01: the request's context, masked by the engine; read by the
	// event lookup (GetEvent), not by searches.
	UserAgent string   `json:"user_agent,omitempty" ch:"user_agent"`
	Referer   string   `json:"referer,omitempty" ch:"referer"`
	Headers   []Header `json:"headers,omitempty" ch:"headers"`
	// RV-N-01: full, partial (CPU budget ran out), body_skipped; empty for
	// modules from before the field.
	Inspection string `json:"inspection,omitempty" ch:"inspection"`
}

// EventBatch models a batch of events sent by an agent with a monotonic sequence number.
type EventBatch struct {
	NodeID string  `json:"node_id"`
	Seq    uint64  `json:"seq"`
	Events []Event `json:"events"`
}

// EventAck confirms the persistence or processing of an EventBatch up to acked_seq.
type EventAck struct {
	NodeID   string `json:"node_id"`
	AckedSeq uint64 `json:"acked_seq"`
	Success  bool   `json:"success"`
	Error    string `json:"error,omitempty"`
	// Duplicate: the batch was received before (a resend); what it
	// carries besides events (replay samples) must not be taken again.
	Duplicate bool `json:"duplicate,omitempty"`
}
