package ingest

import (
	"strings"
	"testing"
	"time"
)

func TestValidateBlockID(t *testing.T) {
	tests := []struct {
		name    string
		id      string
		wantErr bool
	}{
		{"Valid STR Block ID", "STR-8F3K-Q2VD-7XNM-A1PC", false},
		{"Valid EVT Event ID", "EVT-8F3K-Q2VD-7XNM-A1PC", false},
		{"Empty ID", "", true},
		{"Too short", "STR-8F3K-Q2VD", true},
		{"Too long", "STR-8F3K-Q2VD-7XNM-A1PC-EXTRA", true},
		{"Invalid prefix", "WAF-8F3K-Q2VD-7XNM-A1PC", true},
		{"Missing dashes", "STR8F3KQ2VD7XNMA1PC0000", true},
		{"Invalid Crockford char I", "STR-8F3I-Q2VD-7XNM-A1PC", true},
		{"Invalid Crockford char L", "STR-8F3L-Q2VD-7XNM-A1PC", true},
		{"Invalid Crockford char O", "STR-8F3O-Q2VD-7XNM-A1PC", true},
		{"Invalid Crockford char U", "STR-8F3U-Q2VD-7XNM-A1PC", true},
		{"Lowercase valid chars", "str-8f3k-q2vd-7xnm-a1pc", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateBlockID(strings.ToUpper(tt.id))
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidateBlockID(%q) error = %v, wantErr %v", tt.id, err, tt.wantErr)
			}
		})
	}
}

func TestValidateEvent(t *testing.T) {
	now := time.Now().UTC()

	validEvent := func() Event {
		return Event{
			BlockID:       "STR-8F3K-Q2VD-7XNM-A1PC",
			Timestamp:     now.Add(-1 * time.Minute),
			NodeID:        "node-01",
			ConnectorType: "nginx",
			PolicyID:      "default",
			PolicyVersion: 1,
			ClientIP:      "192.0.2.1",
			HTTPMethod:    "POST",
			HTTPHost:      "example.test",
			HTTPPath:      "/api/v1/login",
			StatusCode:    403,
			Action:        "block",
			ScoreProtocol: 0,
			ScoreSQLi:     25,
			ScoreXSS:      0,
			ScoreAnomaly:  25,
			MatchedRules:  []uint32{942100},
			Violations: []Violation{
				{RuleID: 942100, Layer: "sqli", Field: "body.username", Snippet: "' OR 1=1--"},
			},
		}
	}

	t.Run("Valid event passes", func(t *testing.T) {
		e := validEvent()
		if err := ValidateEvent(&e, now); err != nil {
			t.Fatalf("unexpected validation error: %v", err)
		}
		if e.ReceivedAt.IsZero() {
			t.Errorf("expected received_at to be populated")
		}
	})

	t.Run("Zero timestamp fails", func(t *testing.T) {
		e := validEvent()
		e.Timestamp = time.Time{}
		if err := ValidateEvent(&e, now); err == nil {
			t.Errorf("expected error for zero timestamp")
		}
	})

	t.Run("Future timestamp fails beyond skew", func(t *testing.T) {
		e := validEvent()
		e.Timestamp = now.Add(20 * time.Minute)
		if err := ValidateEvent(&e, now); err == nil {
			t.Errorf("expected error for future timestamp")
		}
	})

	t.Run("Expired timestamp fails", func(t *testing.T) {
		e := validEvent()
		e.Timestamp = now.Add(-95 * 24 * time.Hour)
		if err := ValidateEvent(&e, now); err == nil {
			t.Errorf("expected error for expired timestamp")
		}
	})

	t.Run("Invalid action fails", func(t *testing.T) {
		e := validEvent()
		e.Action = "drop" // only block, shadow, pass, error allowed
		if err := ValidateEvent(&e, now); err == nil {
			t.Errorf("expected error for invalid action")
		}
	})

	t.Run("Snippet truncation to 1 KB", func(t *testing.T) {
		e := validEvent()
		oversized := strings.Repeat("A", 2000)
		e.Violations[0].Snippet = oversized
		if err := ValidateEvent(&e, now); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(e.Violations[0].Snippet) != MaxSnippetLength {
			t.Errorf("expected snippet truncated to %d bytes, got %d", MaxSnippetLength, len(e.Violations[0].Snippet))
		}
	})
}

// The time in a Block ID is the one libstrata put there: an ID built the
// way engine/src/block_id.rs builds it decodes back to its millisecond.
func TestBlockIDTime(t *testing.T) {
	ms := uint64(time.Date(2026, 10, 13, 4, 47, 16, 123e6, time.UTC).UnixMilli())
	node, random := uint64(0x155), uint64(0xabcdef1)
	// 80 bits: 42 of time, 10 of node, 28 random; hi = top 16 bits
	hi := ms >> 26
	lo := (ms&((1<<26)-1))<<38 | node<<28 | random
	sym := make([]byte, 0, 16)
	for i := 15; i >= 0; i-- {
		shift := uint(5 * i)
		var v uint64
		switch {
		case shift >= 64:
			v = hi >> (shift - 64)
		case shift > 59:
			v = lo>>shift | hi<<(64-shift)
		default:
			v = lo >> shift
		}
		sym = append(sym, crockfordAlphabet[v&31])
	}
	id := "STR-" + string(sym[0:4]) + "-" + string(sym[4:8]) + "-" + string(sym[8:12]) + "-" + string(sym[12:16])
	got, ok := BlockIDTime(id)
	if !ok || got.UnixMilli() != int64(ms) {
		t.Fatalf("BlockIDTime(%s) = %v %v, want %v", id, got, ok, time.UnixMilli(int64(ms)).UTC())
	}
	if got2, _ := BlockIDTime(strings.ToLower(id)); !got2.Equal(got) {
		t.Errorf("lower case: %v", got2)
	}
	// the fields of engine/src/block_id.rs round_trip_fields: time 0x2abcdef0123
	if v, ok := BlockIDTime("STR-NBSQ-QG28-TNDB-SQQH"); !ok || v.UnixMilli() != 0x2abcdef0123 {
		t.Errorf("engine vector: %v %v", v.UnixMilli(), ok)
	}
	if _, ok := BlockIDTime("STR-0000-0000-0000-000"); ok {
		t.Error("a short ID decoded")
	}
}
