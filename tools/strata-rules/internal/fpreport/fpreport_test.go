package fpreport

import (
	"bytes"
	"context"
	"encoding/base64"
	"fmt"
	"io"
	"math"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestLoadCIDRs(t *testing.T) {
	tmpDir := t.TempDir()

	validFile := filepath.Join(tmpDir, "valid_cidrs.txt")
	validContent := `# Example CIDR / IP file
# Line comment

192.0.2.1
# IPv6 single address
2001:db8::1

198.51.100.0/24
2001:db8:cafe::/48
`
	if err := os.WriteFile(validFile, []byte(validContent), 0o644); err != nil {
		t.Fatalf("failed to write valid test file: %v", err)
	}

	cidrs, err := LoadCIDRs(validFile)
	if err != nil {
		t.Fatalf("LoadCIDRs returned unexpected error: %v", err)
	}

	expected := []string{
		"192.0.2.1/32",
		"2001:db8::1/128",
		"198.51.100.0/24",
		"2001:db8:cafe::/48",
	}

	if len(cidrs) != len(expected) {
		t.Fatalf("expected %d CIDRs, got %d: %v", len(expected), len(cidrs), cidrs)
	}
	for i, c := range cidrs {
		if c != expected[i] {
			t.Errorf("at index %d: expected %q, got %q", i, expected[i], c)
		}
	}

	invalidFile := filepath.Join(tmpDir, "invalid_cidrs.txt")
	invalidContent := `# Line 1 comment
192.0.2.1
# Line 3 comment
not-a-valid-ip-or-cidr
198.51.100.0/24
`
	if err := os.WriteFile(invalidFile, []byte(invalidContent), 0o644); err != nil {
		t.Fatalf("failed to write invalid test file: %v", err)
	}

	_, err = LoadCIDRs(invalidFile)
	if err == nil {
		t.Fatalf("expected error for invalid CIDR file, got nil")
	}
	if !strings.Contains(err.Error(), ":4:") && !strings.Contains(err.Error(), "line 4") {
		t.Errorf("expected error to mention line 4, got: %v", err)
	}
}

func findAttackSourcesExample() (string, error) {
	candidates := []string{
		"../../../../deploy/lab/attack-sources.example.txt",
		"../../../deploy/lab/attack-sources.example.txt",
		"deploy/lab/attack-sources.example.txt",
	}
	for _, c := range candidates {
		if _, err := os.Stat(c); err == nil {
			abs, err := filepath.Abs(c)
			if err == nil {
				return abs, nil
			}
			return c, nil
		}
	}
	return "", fmt.Errorf("deploy/lab/attack-sources.example.txt not found in candidate paths")
}

func TestLoadCIDRs_ExampleFile(t *testing.T) {
	p, err := findAttackSourcesExample()
	if err != nil {
		t.Fatalf("locating attack-sources.example.txt: %v", err)
	}
	cidrs, err := LoadCIDRs(p)
	if err != nil {
		t.Fatalf("LoadCIDRs failed on example file: %v", err)
	}
	expected := []string{"203.0.113.0/24", "198.51.100.77/32"}
	if len(cidrs) != len(expected) {
		t.Fatalf("expected %d CIDRs, got %d: %v", len(expected), len(cidrs), cidrs)
	}
	for i, c := range cidrs {
		if c != expected[i] {
			t.Errorf("at index %d: expected %q, got %q", i, expected[i], c)
		}
	}
}

func TestQuery_MockServer(t *testing.T) {
	handlerCalled := false
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		handlerCalled = true
		if r.Method != http.MethodPost {
			t.Errorf("expected POST method, got %s", r.Method)
		}

		q := r.URL.Query()
		if got := q.Get("param_since_s"); got != "86400" {
			t.Errorf("expected param_since_s=86400, got %q", got)
		}
		if got := q.Get("param_policies"); got != "['pilot-verify', 'pilot-upload']" {
			t.Errorf("expected param_policies=['pilot-verify', 'pilot-upload'], got %q", got)
		}
		if got := q.Get("param_exclude"); got != "['192.0.2.0/24']" {
			t.Errorf("expected param_exclude=['192.0.2.0/24'], got %q", got)
		}
		if got := q.Get("database"); got != "testdb" {
			t.Errorf("expected database=testdb, got %q", got)
		}

		bodyBytes, err := io.ReadAll(r.Body)
		if err != nil {
			t.Fatalf("failed to read request body: %v", err)
		}
		body := string(bodyBytes)

		// Must use SQL parameter syntax, not string concatenation
		if !strings.Contains(body, "{since_s:UInt32}") {
			t.Errorf("body missing {since_s:UInt32}")
		}
		if !strings.Contains(body, "{policies:Array(String)}") {
			t.Errorf("body missing {policies:Array(String)}")
		}
		if !strings.Contains(body, "{exclude:Array(String)}") {
			t.Errorf("body missing {exclude:Array(String)}")
		}
		if strings.Contains(body, "86400") {
			t.Errorf("body should not contain literal 86400")
		}
		if strings.Contains(body, "pilot-verify") {
			t.Errorf("body should not contain literal pilot-verify")
		}
		if strings.Contains(body, "192.0.2.0/24") {
			t.Errorf("body should not contain literal 192.0.2.0/24")
		}

		// Return JSONEachRow: test both quoted UInt64 string and unquoted number
		respBody := `{"day":"2026-10-13","rule_id":942100,"events":"3","sources":"3","top_policy":"pilot-verify"}
{"day":"2026-10-13","rule_id":941100,"events":1,"sources":1,"top_policy":"pilot-upload"}
`
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(respBody))
	}))
	defer ts.Close()

	opts := Options{
		ClickHouseURL: ts.URL,
		Database:      "testdb",
		Since:         24 * time.Hour,
		Policies:      []string{"pilot-verify", "pilot-upload"},
		ExcludeCIDRs:  []string{"192.0.2.0/24"},
	}

	rows, err := Query(context.Background(), opts)
	if err != nil {
		t.Fatalf("Query failed: %v", err)
	}
	if !handlerCalled {
		t.Fatalf("mock server handler was not called")
	}

	if len(rows) != 2 {
		t.Fatalf("expected 2 rows, got %d", len(rows))
	}

	if rows[0].Day != "2026-10-13" || rows[0].RuleID != 942100 || rows[0].Events != 3 || rows[0].Sources != 3 || rows[0].TopPolicy != "pilot-verify" {
		t.Errorf("row 0 mismatch: %+v", rows[0])
	}
	if rows[1].Day != "2026-10-13" || rows[1].RuleID != 941100 || rows[1].Events != 1 || rows[1].Sources != 1 || rows[1].TopPolicy != "pilot-upload" {
		t.Errorf("row 1 mismatch: %+v", rows[1])
	}
}

func TestQuery_MockServerError(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte("DB::Exception: Table default.events doesn't exist"))
	}))
	defer ts.Close()

	opts := Options{
		ClickHouseURL: ts.URL,
		Since:         24 * time.Hour,
	}

	_, err := Query(context.Background(), opts)
	if err == nil {
		t.Fatalf("expected error on status 500, got nil")
	}
	if !strings.Contains(err.Error(), "500") || !strings.Contains(err.Error(), "Table default.events doesn't exist") {
		t.Errorf("error did not contain expected status and body: %v", err)
	}
}

func TestMarkdown(t *testing.T) {
	// Case 1: with rows
	rows := []Row{
		{
			Day:       "2026-10-13",
			RuleID:    942100,
			Events:    12,
			Sources:   5,
			TopPolicy: "pilot-verify",
		},
	}
	opts := Options{
		Since:        24 * time.Hour,
		Policies:     []string{"pilot-verify"},
		ExcludeCIDRs: []string{"192.0.2.0/24"},
	}

	var buf bytes.Buffer
	Markdown(&buf, rows, opts)
	output := buf.String()

	if !strings.Contains(output, "## Báo cáo nghi FP (shadow)") {
		t.Errorf("missing header in output: %s", output)
	}
	if !strings.Contains(output, "Khoảng thời gian: 24h") {
		t.Errorf("missing time window: %s", output)
	}
	if !strings.Contains(output, "Policy: pilot-verify") {
		t.Errorf("missing policy info: %s", output)
	}
	if !strings.Contains(output, "CIDR loại trừ: 1") {
		t.Errorf("missing CIDR count: %s", output)
	}
	if !strings.Contains(output, "| Ngày | Rule ID | Sự kiện | Nguồn | Policy nhiều nhất |") {
		t.Errorf("missing table header: %s", output)
	}
	if !strings.Contains(output, "| 2026-10-13 | 942100 | 12 | 5 | pilot-verify |") {
		t.Errorf("missing table row: %s", output)
	}

	// Case 2: empty rows
	buf.Reset()
	Markdown(&buf, nil, Options{Since: 48 * time.Hour})
	emptyOutput := buf.String()

	if !strings.Contains(emptyOutput, "Không có sự kiện shadow nghi FP.") {
		t.Errorf("missing empty notice: %s", emptyOutput)
	}
	if strings.Contains(emptyOutput, "| Ngày | Rule ID |") {
		t.Errorf("empty report should not include table header: %s", emptyOutput)
	}
}

func TestQuery_Authorization(t *testing.T) {
	var gotAuth string
	var hasAuth bool
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		_, hasAuth = r.Header["Authorization"]
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"day":"2026-10-13","rule_id":942100,"events":1,"sources":1,"top_policy":"pilot-verify"}` + "\n"))
	}))
	defer ts.Close()

	// Case 1: user and password provided -> Authorization header present
	_, err := Query(context.Background(), Options{
		ClickHouseURL: ts.URL,
		User:          "strata",
		Password:      "secretpass",
		Since:         24 * time.Hour,
	})
	if err != nil {
		t.Fatalf("Query failed: %v", err)
	}
	expectedAuth := "Basic " + base64.StdEncoding.EncodeToString([]byte("strata:secretpass"))
	if gotAuth != expectedAuth {
		t.Errorf("expected Authorization header %q, got %q", expectedAuth, gotAuth)
	}

	// Case 2: empty user and password -> no Authorization header
	gotAuth = ""
	hasAuth = false
	_, err = Query(context.Background(), Options{
		ClickHouseURL: ts.URL,
		Since:         24 * time.Hour,
	})
	if err != nil {
		t.Fatalf("Query failed: %v", err)
	}
	if hasAuth || gotAuth != "" {
		t.Errorf("expected no Authorization header when user and password are empty, got %q", gotAuth)
	}
}

func TestQuery_ValidateSince(t *testing.T) {
	reqCount := 0
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		reqCount++
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"day":"2026-10-13","rule_id":942100,"events":1,"sources":1,"top_policy":"pilot-verify"}` + "\n"))
	}))
	defer ts.Close()

	tests := []struct {
		name      string
		since     time.Duration
		wantErr   string
		shouldReq bool
	}{
		{name: "zero", since: 0, wantErr: "since must be positive", shouldReq: false},
		{name: "negative", since: -1 * time.Hour, wantErr: "since must be positive", shouldReq: false},
		{name: "subsecond", since: 500 * time.Millisecond, wantErr: "since must be positive", shouldReq: false},
		{name: "1s ok", since: 1 * time.Second, wantErr: "", shouldReq: true},
		{name: "24h ok", since: 24 * time.Hour, wantErr: "", shouldReq: true},
		{name: "too large", since: (time.Duration(math.MaxUint32) + 10) * time.Second, wantErr: "since too large", shouldReq: false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			before := reqCount
			_, err := Query(context.Background(), Options{
				ClickHouseURL: ts.URL,
				Since:         tc.since,
			})
			diff := reqCount - before
			if tc.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("expected error containing %q, got %v", tc.wantErr, err)
				}
				if diff != 0 {
					t.Errorf("expected 0 requests sent on error, got %d", diff)
				}
			} else {
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
				if diff != 1 {
					t.Errorf("expected 1 request sent on success, got %d", diff)
				}
			}
		})
	}
}

func TestQuery_Timeout(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-time.After(2 * time.Second):
		case <-r.Context().Done():
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"day":"2026-10-13","rule_id":942100,"events":1,"sources":1,"top_policy":"pilot-verify"}` + "\n"))
	}))
	defer ts.Close()

	start := time.Now()
	_, err := Query(context.Background(), Options{
		ClickHouseURL: ts.URL,
		Since:         24 * time.Hour,
		Timeout:       200 * time.Millisecond,
	})
	elapsed := time.Since(start)

	if err == nil {
		t.Fatalf("expected timeout error, got nil")
	}
	if elapsed >= 1*time.Second {
		t.Errorf("expected Query to return error in < 1s, took %v", elapsed)
	}
}
