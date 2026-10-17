package api

import (
	"bufio"
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/strata/strata/control-plane/ingest"
)

func TestWatchGeoSSE(t *testing.T) {
	store := ingest.NewMockEventStore()
	events := []ingest.Event{
		{
			BlockID:    "STR-0000-0000-0000-0001",
			Timestamp:  time.Now().UTC().Add(-2 * time.Minute),
			PolicyID:   "pilot-api",
			Action:     "block",
			CountryISO: "VN",
			City:       "Ho Chi Minh City",
			ASN:        7552,
			ASOrg:      "Viettel",
		},
	}
	if err := store.SaveEvents(t.Context(), events); err != nil {
		t.Fatal(err)
	}

	server := NewServer(ServerConfig{Auth: tokenRoles{}}, store)
	ts := httptest.NewServer(server.Handler())
	defer ts.Close()

	// 1. Establish SSE connection with interval=1 second
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, ts.URL+"/v1/stats/geo:watch?interval=1", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer viewer")

	client := &http.Client{Timeout: 0}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 OK, got %d", resp.StatusCode)
	}
	contentType := resp.Header.Get("Content-Type")
	if !strings.HasPrefix(contentType, "text/event-stream") {
		t.Fatalf("expected text/event-stream content type, got %s", contentType)
	}

	// 2. Read events line by line
	scanner := bufio.NewScanner(resp.Body)
	sawSnapshot := false
	sawUpdate := false

	readDone := make(chan struct{})
	go func() {
		defer close(readDone)
		for scanner.Scan() {
			line := scanner.Text()
			if strings.HasPrefix(line, "event: geo_snapshot") {
				sawSnapshot = true
			}
			if strings.HasPrefix(line, "event: geo_update") {
				sawUpdate = true
			}
			if sawSnapshot && sawUpdate {
				return
			}
		}
	}()

	select {
	case <-readDone:
		if !sawSnapshot {
			t.Errorf("expected to receive initial geo_snapshot")
		}
		if !sawUpdate {
			t.Errorf("expected to receive periodic geo_update within 5 seconds")
		}
	case <-ctx.Done():
		t.Fatalf("timed out waiting for SSE updates (sawSnapshot=%v, sawUpdate=%v)", sawSnapshot, sawUpdate)
	}

	// 3. POST /v1/stats/geo:watch returns 405 Method Not Allowed
	postReq, _ := http.NewRequest(http.MethodPost, ts.URL+"/v1/stats/geo:watch", nil)
	postReq.Header.Set("Authorization", "Bearer viewer")
	postResp, err := client.Do(postReq)
	if err != nil {
		t.Fatal(err)
	}
	postResp.Body.Close()
	if postResp.StatusCode != http.StatusMethodNotAllowed {
		t.Errorf("expected 405 for POST, got %d", postResp.StatusCode)
	}
}
