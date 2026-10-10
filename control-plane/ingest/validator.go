package ingest

import (
	"errors"
	"fmt"
	"strings"
	"time"
	"unicode/utf8"
)

const (
	MaxSnippetLength   = 1024 // 1 KB max per match snippet
	MaxClockSkewFuture = 10 * time.Minute
	MaxEventAge        = 90 * 24 * time.Hour
)

var (
	ErrEmptyBlockID      = errors.New("block_id is required")
	ErrInvalidBlockID    = errors.New("invalid block_id format")
	ErrZeroTimestamp     = errors.New("timestamp is required")
	ErrFutureTimestamp   = errors.New("timestamp is too far in the future")
	ErrExpiredTimestamp  = errors.New("timestamp exceeds 90-day retention limit")
	ErrInvalidAction     = errors.New("invalid action")
	ErrInvalidHTTPMethod = errors.New("invalid http_method")
)

// Valid Crockford Base32 characters: 0-9, A-Z (excluding I, L, O, U)
func isCrockfordChar(b byte) bool {
	switch {
	case b >= '0' && b <= '9':
		return true
	case b >= 'A' && b <= 'Z':
		return b != 'I' && b != 'L' && b != 'O' && b != 'U'
	case b >= 'a' && b <= 'z':
		return b != 'i' && b != 'l' && b != 'o' && b != 'u'
	default:
		return false
	}
}

// ValidateBlockID validates Crockford Base32 Block ID or Event ID:
// e.g. STR-8F3K-Q2VD-7XNM-A1PC or EVT-8F3K-Q2VD-7XNM-A1PC (23 characters)
func ValidateBlockID(id string) error {
	if len(id) == 0 {
		return ErrEmptyBlockID
	}
	if len(id) != 23 {
		return fmt.Errorf("%w: length must be 23 characters, got %d", ErrInvalidBlockID, len(id))
	}
	prefix := id[:4]
	if prefix != "STR-" && prefix != "EVT-" {
		return fmt.Errorf("%w: prefix must be STR- or EVT-, got %s", ErrInvalidBlockID, prefix)
	}

	for i := 4; i < 23; i++ {
		if i == 8 || i == 13 || i == 18 {
			if id[i] != '-' {
				return fmt.Errorf("%w: expected '-' at position %d", ErrInvalidBlockID, i)
			}
		} else {
			if !isCrockfordChar(id[i]) {
				return fmt.Errorf("%w: invalid character '%c' at position %d", ErrInvalidBlockID, id[i], i)
			}
		}
	}
	return nil
}

// ValidateAction ensures action is one of block, shadow, pass, error.
func ValidateAction(action string) error {
	switch strings.ToLower(action) {
	case "block", "shadow", "pass", "error":
		return nil
	default:
		return fmt.Errorf("%w: %q", ErrInvalidAction, action)
	}
}

// ValidateHTTPMethod ensures http_method is valid.
func ValidateHTTPMethod(method string) error {
	m := strings.ToUpper(strings.TrimSpace(method))
	if len(m) == 0 || len(m) > 16 {
		return fmt.Errorf("%w: invalid length %d", ErrInvalidHTTPMethod, len(m))
	}
	switch m {
	case "GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS", "CONNECT", "TRACE":
		return nil
	}
	// Allow non-standard methods if ASCII alphanumeric
	for i := 0; i < len(m); i++ {
		b := m[i]
		if (b < 'A' || b > 'Z') && (b < '0' || b > '9') && b != '_' && b != '-' {
			return fmt.Errorf("%w: invalid character in custom method %q", ErrInvalidHTTPMethod, m)
		}
	}
	return nil
}

// TruncateSnippetUTF8 ensures snippet length is at most maxLen bytes and valid UTF-8.
func TruncateSnippetUTF8(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	s = s[:maxLen]
	for len(s) > 0 && !utf8.ValidString(s) {
		s = s[:len(s)-1]
	}
	return s
}

// ValidateEvent performs comprehensive schema validation and normalization on an Event.
func ValidateEvent(evt *Event, now time.Time) error {
	if evt == nil {
		return errors.New("event cannot be nil")
	}

	// 1. Block ID
	evt.BlockID = strings.ToUpper(strings.TrimSpace(evt.BlockID))
	if err := ValidateBlockID(evt.BlockID); err != nil {
		return fmt.Errorf("validating block_id: %w", err)
	}

	// 2. Timestamp
	if evt.Timestamp.IsZero() {
		return ErrZeroTimestamp
	}
	if now.IsZero() {
		now = time.Now().UTC()
	}
	if evt.Timestamp.After(now.Add(MaxClockSkewFuture)) {
		return fmt.Errorf("%w: event time %s is beyond clock skew threshold", ErrFutureTimestamp, evt.Timestamp)
	}
	if now.Sub(evt.Timestamp) > MaxEventAge {
		return fmt.Errorf("%w: event time %s is older than %s", ErrExpiredTimestamp, evt.Timestamp, MaxEventAge)
	}

	// 3. Action
	evt.Action = strings.ToLower(strings.TrimSpace(evt.Action))
	if err := ValidateAction(evt.Action); err != nil {
		return fmt.Errorf("validating action: %w", err)
	}

	// 4. HTTP Method
	if evt.HTTPMethod != "" {
		if err := ValidateHTTPMethod(evt.HTTPMethod); err != nil {
			return fmt.Errorf("validating http_method: %w", err)
		}
		evt.HTTPMethod = strings.ToUpper(strings.TrimSpace(evt.HTTPMethod))
	}

	// 5. Snippet truncation for violations
	for i := range evt.Violations {
		if len(evt.Violations[i].Snippet) > MaxSnippetLength {
			evt.Violations[i].Snippet = TruncateSnippetUTF8(evt.Violations[i].Snippet, MaxSnippetLength)
		}
	}

	// 6. Defaults
	if evt.ReceivedAt.IsZero() {
		evt.ReceivedAt = now
	}

	return nil
}
