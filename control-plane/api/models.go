package api

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"github.com/strata/strata/control-plane/rulecat"
	"time"

	"github.com/strata/strata/control-plane/ingest"
)

// ErrorResponse represents a standardized JSON error payload.
type ErrorResponse struct {
	Error   string `json:"error"`
	BlockID string `json:"block_id,omitempty"`
	Code    int    `json:"code,omitempty"`
}

// GetEventResponse represents the detailed decision trace returned for a single Block ID.
type GetEventResponse struct {
	Event ingest.Event `json:"event"`
	// Rules: what the rule catalog knows about the rules of the event
	// (name, source, author...), keyed by Rule ID (W09-F-01).
	Rules map[string]rulecat.Rule `json:"rules,omitempty"`
}

// MarkFalsePositiveRequest is the payload for POST /v1/events/{block_id}:markFalsePositive.
type MarkFalsePositiveRequest struct {
	Reason string `json:"reason"`
}

// MarkFalsePositiveResponse is the result of POST /v1/events/{block_id}:markFalsePositive.
type MarkFalsePositiveResponse struct {
	BlockID       string    `json:"block_id"`
	FalsePositive bool      `json:"false_positive"`
	Reason        string    `json:"reason"`
	MarkedBy      string    `json:"marked_by"`
	MarkedAt      time.Time `json:"marked_at"`
}

// CreateExceptionFromBlockIDRequest is the payload for POST /v1/exceptions:fromBlockId.
type CreateExceptionFromBlockIDRequest struct {
	BlockID    string `json:"block_id"`
	TTLSeconds int64  `json:"ttl_seconds"` // 60..2592000 (up to 30 days)
	Reason     string `json:"reason"`
}

// Exception models a rule exception (W14-G2-01).
type Exception struct {
	ID         string    `json:"id"`
	BlockID    string    `json:"block_id"`
	PolicyID   string    `json:"policy_id"`
	RuleID     uint32    `json:"rule_id"`
	Field      string    `json:"field"`
	Reason     string    `json:"reason"`
	State      string    `json:"state"` // SUBMITTED, APPROVED, REJECTED, EXPIRED, REVOKED
	CreatedBy  string    `json:"created_by"`
	ApprovedBy string    `json:"approved_by,omitempty"`
	CreatedAt  time.Time `json:"created_at"`
	ExpiresAt  time.Time `json:"expires_at"`
}

// ListExceptionsResponse is the response for GET /v1/exceptions.
type ListExceptionsResponse struct {
	Exceptions []Exception `json:"exceptions"`
}

// ApproveExceptionResponse is the response for POST /v1/exceptions/{id}:approve.
type ApproveExceptionResponse struct {
	Exception Exception `json:"exception"`
}

// SearchEventsRequest defines search criteria for querying security events.
type SearchEventsRequest struct {
	From       time.Time `json:"from"`
	To         time.Time `json:"to"`
	PolicyID   string    `json:"policy_id,omitempty"`
	Action     string    `json:"action,omitempty"`
	ClientIP   string    `json:"client_ip,omitempty"`
	RuleID     uint32    `json:"rule_id,omitempty"`
	NodeID     string    `json:"node_id,omitempty"`
	HTTPMethod string    `json:"http_method,omitempty"`
	PageSize   int       `json:"page_size,omitempty"`
	PageToken  string    `json:"page_token,omitempty"`
}

// SearchEventsResponse contains the list of matched events and pagination information.
type SearchEventsResponse struct {
	Events        []ingest.Event `json:"events"`
	NextPageToken string         `json:"next_page_token,omitempty"`
	TotalMatched  uint64         `json:"total_matched"`
}

// PageCursor stores pagination state encoded within PageToken.
type PageCursor struct {
	Offset int `json:"offset"`
}

// EncodePageToken serializes a PageCursor into an opaque base64 string.
func EncodePageToken(offset int) string {
	cursor := PageCursor{Offset: offset}
	b, _ := json.Marshal(cursor)
	return base64.URLEncoding.EncodeToString(b)
}

// DecodePageToken deserializes an opaque base64 string into an offset.
func DecodePageToken(token string) (int, error) {
	if token == "" {
		return 0, nil
	}
	b, err := base64.URLEncoding.DecodeString(token)
	if err != nil {
		return 0, fmt.Errorf("decoding page_token: %w", err)
	}
	var cursor PageCursor
	if err := json.Unmarshal(b, &cursor); err != nil {
		return 0, fmt.Errorf("unmarshaling page_token: %w", err)
	}
	if cursor.Offset < 0 {
		return 0, nil
	}
	return cursor.Offset, nil
}
