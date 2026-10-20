package api

import (
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/strata/strata/control-plane/ingest"
)

// CP-A08: with ClickHouse unreachable, every event and statistics endpoint
// answers 503 EVENTS_UNAVAILABLE, never an empty result a client could
// take for "no events".
func TestEventsUnavailableIsNotEmpty(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	ln.Close() // nothing listens there
	ch, err := ingest.OpenClickHouseStore(ingest.ClickHouseConfig{Addr: addr, Database: "default", Username: "default"})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ch.Close() })
	s := NewServer(ServerConfig{Auth: tokenRoles{}}, ch)
	for _, path := range []string{
		"/v1/stats/overview",
		"/v1/stats/timeline",
		"/v1/stats/geo",
		"/v1/events:search",
		"/v1/events/STR-0000-0000-0000-0001",
	} {
		req := httptest.NewRequest(http.MethodGet, path, nil)
		if path == "/v1/events:search" {
			req = httptest.NewRequest(http.MethodPost, path, strings.NewReader("{}"))
		}
		req.Header.Set("Authorization", "Bearer viewer")
		rec := httptest.NewRecorder()
		s.Handler().ServeHTTP(rec, req)
		var body ErrorResponse
		_ = json.Unmarshal(rec.Body.Bytes(), &body)
		if rec.Code != http.StatusServiceUnavailable || body.Reason != ReasonEventsUnavailable {
			t.Errorf("%s: %d %s", path, rec.Code, rec.Body)
		}
	}
}
