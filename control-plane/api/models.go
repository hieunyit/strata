package api

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
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
