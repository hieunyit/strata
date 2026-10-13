package fpreport

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"math/rand"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

type testEvent struct {
	BlockID       string   `json:"block_id"`
	Timestamp     string   `json:"timestamp"`
	NodeID        string   `json:"node_id"`
	ConnectorType string   `json:"connector_type"`
	PolicyID      string   `json:"policy_id"`
	PolicyVersion uint64   `json:"policy_version"`
	ClientIP      string   `json:"client_ip"`
	Identity      string   `json:"identity"`
	RequestID     string   `json:"request_id"`
	HTTPMethod    string   `json:"http_method"`
	HTTPHost      string   `json:"http_host"`
	HTTPPath      string   `json:"http_path"`
	StatusCode    uint16   `json:"status_code"`
	Action        string   `json:"action"`
	ScoreProtocol int32    `json:"score_protocol"`
	ScoreSQLi     int32    `json:"score_sqli"`
	ScoreXSS      int32    `json:"score_xss"`
	ScoreAnomaly  int32    `json:"score_anomaly"`
	MatchedRules  []uint32 `json:"matched_rules"`
}

func execCH(ctx context.Context, chURL, db, query string) error {
	u, err := url.Parse(chURL)
	if err != nil {
		return err
	}
	if db != "" {
		q := u.Query()
		q.Set("database", db)
		u.RawQuery = q.Encode()
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, u.String(), strings.NewReader(query))
	if err != nil {
		return err
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("clickhouse status %d: %s", resp.StatusCode, strings.TrimSpace(string(b)))
	}
	return nil
}

func insertTestEvents(ctx context.Context, chURL, db string, events []testEvent) error {
	var sb strings.Builder
	for _, ev := range events {
		b, err := json.Marshal(ev)
		if err != nil {
			return err
		}
		sb.Write(b)
		sb.WriteByte('\n')
	}

	u, err := url.Parse(chURL)
	if err != nil {
		return err
	}
	q := u.Query()
	q.Set("database", db)
	q.Set("query", "INSERT INTO events FORMAT JSONEachRow")
	u.RawQuery = q.Encode()

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, u.String(), strings.NewReader(sb.String()))
	if err != nil {
		return err
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("insert events status %d: %s", resp.StatusCode, strings.TrimSpace(string(b)))
	}
	return nil
}

func findSchemaSQL() (string, error) {
	candidates := []string{
		"../../../../control-plane/ingest/schema.sql",
		"../../../control-plane/ingest/schema.sql",
		"control-plane/ingest/schema.sql",
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
	return "", fmt.Errorf("control-plane/ingest/schema.sql not found in candidate paths")
}

func TestClickHouseIntegration(t *testing.T) {
	chURL := os.Getenv("STRATA_TEST_CLICKHOUSE_URL")
	if chURL == "" {
		t.Skip("STRATA_TEST_CLICKHOUSE_URL not set; skipping ClickHouse integration test")
	}

	ctx := context.Background()
	dbName := fmt.Sprintf("fpreport_test_%d_%d", time.Now().UnixNano(), rand.Intn(100000))

	// Create database
	if err := execCH(ctx, chURL, "", "CREATE DATABASE "+dbName); err != nil {
		t.Fatalf("failed to create test database %s: %v", dbName, err)
	}
	t.Cleanup(func() {
		_ = execCH(ctx, chURL, "", "DROP DATABASE IF EXISTS "+dbName)
	})

	// Execute schema.sql statements
	schemaPath, err := findSchemaSQL()
	if err != nil {
		t.Fatalf("locating schema.sql: %v", err)
	}
	schemaBytes, err := os.ReadFile(schemaPath)
	if err != nil {
		t.Fatalf("reading schema.sql at %s: %v", schemaPath, err)
	}
	for _, stmt := range strings.Split(string(schemaBytes), ";") {
		stmt = strings.TrimSpace(stmt)
		if stmt == "" {
			continue
		}
		if err := execCH(ctx, chURL, dbName, stmt); err != nil {
			t.Fatalf("executing statement in schema.sql: %v (stmt: %s)", err, stmt)
		}
	}

	now := time.Now().UTC()
	todayStr := now.Format("2006-01-02")
	tsNow := now.Format("2006-01-02 15:04:05.000")
	tsOld := now.Add(-72 * time.Hour).Format("2006-01-02 15:04:05.000")

	// 1. 3 shadow events, policy pilot-verify, rule 942100, from 3 IPs 198.51.100.1-3
	events1 := []testEvent{
		{
			BlockID: "BLK-001", Timestamp: tsNow, NodeID: "node-1", ConnectorType: "nginx",
			PolicyID: "pilot-verify", PolicyVersion: 1, ClientIP: "198.51.100.1",
			Action: "shadow", MatchedRules: []uint32{942100},
		},
		{
			BlockID: "BLK-002", Timestamp: tsNow, NodeID: "node-1", ConnectorType: "nginx",
			PolicyID: "pilot-verify", PolicyVersion: 1, ClientIP: "198.51.100.2",
			Action: "shadow", MatchedRules: []uint32{942100},
		},
		{
			BlockID: "BLK-003", Timestamp: tsNow, NodeID: "node-1", ConnectorType: "nginx",
			PolicyID: "pilot-verify", PolicyVersion: 1, ClientIP: "198.51.100.3",
			Action: "shadow", MatchedRules: []uint32{942100},
		},
	}
	if err := insertTestEvents(ctx, chURL, dbName, events1); err != nil {
		t.Fatalf("inserting events step 1: %v", err)
	}

	// Verify step 1: exactly (today, 942100, events=3, sources=3)
	t.Run("Step1_ThreeShadowEvents", func(t *testing.T) {
		opts := Options{
			ClickHouseURL: chURL,
			Database:      dbName,
			Since:         24 * time.Hour,
			Policies:      []string{"pilot-verify"},
		}
		rows, err := Query(ctx, opts)
		if err != nil {
			t.Fatalf("Query failed: %v", err)
		}
		if len(rows) != 1 {
			t.Fatalf("expected 1 row, got %d: %+v", len(rows), rows)
		}
		if rows[0].Day != todayStr || rows[0].RuleID != 942100 || rows[0].Events != 3 || rows[0].Sources != 3 || rows[0].TopPolicy != "pilot-verify" {
			t.Errorf("step 1 row mismatch: %+v (expected day=%s, rule=942100, events=3, sources=3, top_policy=pilot-verify)", rows[0], todayStr)
		}
	})

	// 2. 1 shadow event duplicate block_id BLK-001 (inserted twice)
	events2 := []testEvent{
		{
			BlockID: "BLK-001", Timestamp: tsNow, NodeID: "node-1", ConnectorType: "nginx",
			PolicyID: "pilot-verify", PolicyVersion: 1, ClientIP: "198.51.100.1",
			Action: "shadow", MatchedRules: []uint32{942100},
		},
	}
	if err := insertTestEvents(ctx, chURL, dbName, events2); err != nil {
		t.Fatalf("inserting duplicate event step 2: %v", err)
	}

	// Verify step 2: events is still 3
	t.Run("Step2_DuplicateBlockID", func(t *testing.T) {
		opts := Options{
			ClickHouseURL: chURL,
			Database:      dbName,
			Since:         24 * time.Hour,
			Policies:      []string{"pilot-verify"},
		}
		rows, err := Query(ctx, opts)
		if err != nil {
			t.Fatalf("Query failed: %v", err)
		}
		if len(rows) != 1 {
			t.Fatalf("expected 1 row, got %d: %+v", len(rows), rows)
		}
		if rows[0].Events != 3 {
			t.Errorf("expected events=3 after inserting duplicate block_id, got %d", rows[0].Events)
		}
	})

	// 3. 1 event with matched_rules [941100, 941100, 942100]
	events3 := []testEvent{
		{
			BlockID: "BLK-004", Timestamp: tsNow, NodeID: "node-1", ConnectorType: "nginx",
			PolicyID: "pilot-verify", PolicyVersion: 1, ClientIP: "198.51.100.1",
			Action: "shadow", MatchedRules: []uint32{941100, 941100, 942100},
		},
	}
	if err := insertTestEvents(ctx, chURL, dbName, events3); err != nil {
		t.Fatalf("inserting event step 3: %v", err)
	}

	// Verify step 3: 941100 counted 1 time, 942100 added 1 (events=4)
	t.Run("Step3_ArrayDistinctRuleCount", func(t *testing.T) {
		opts := Options{
			ClickHouseURL: chURL,
			Database:      dbName,
			Since:         24 * time.Hour,
			Policies:      []string{"pilot-verify"},
		}
		rows, err := Query(ctx, opts)
		if err != nil {
			t.Fatalf("Query failed: %v", err)
		}
		byRule := make(map[uint32]Row)
		for _, r := range rows {
			byRule[r.RuleID] = r
		}
		r941, ok := byRule[941100]
		if !ok || r941.Events != 1 {
			t.Errorf("expected rule 941100 events=1, got %+v", r941)
		}
		r942, ok := byRule[942100]
		if !ok || r942.Events != 4 {
			t.Errorf("expected rule 942100 events=4, got %+v", r942)
		}
	})

	// Insert events for remaining conditions (4, 5, 6, 7, 8)
	remainingEvents := []testEvent{
		// 4. CA ÂM: action='block' rule 930100
		{
			BlockID: "BLK-005", Timestamp: tsNow, NodeID: "node-1", ConnectorType: "nginx",
			PolicyID: "pilot-verify", PolicyVersion: 1, ClientIP: "198.51.100.4",
			Action: "block", MatchedRules: []uint32{930100},
		},
		// 5. CA ÂM: shadow from 203.0.113.7 rule 932100
		{
			BlockID: "BLK-006", Timestamp: tsNow, NodeID: "node-1", ConnectorType: "nginx",
			PolicyID: "pilot-verify", PolicyVersion: 1, ClientIP: "203.0.113.7",
			Action: "shadow", MatchedRules: []uint32{932100},
		},
		// 6. CA ÂM: shadow old 3 days, rule 933100
		{
			BlockID: "BLK-007", Timestamp: tsOld, NodeID: "node-1", ConnectorType: "nginx",
			PolicyID: "pilot-verify", PolicyVersion: 1, ClientIP: "198.51.100.5",
			Action: "shadow", MatchedRules: []uint32{933100},
		},
		// 7. Policy filter: policy example-api, rule 934100
		{
			BlockID: "BLK-008", Timestamp: tsNow, NodeID: "node-1", ConnectorType: "nginx",
			PolicyID: "example-api", PolicyVersion: 1, ClientIP: "198.51.100.6",
			Action: "shadow", MatchedRules: []uint32{934100},
		},
		// 8. client_ip empty or not an IP: rule 935100
		{
			BlockID: "BLK-009", Timestamp: tsNow, NodeID: "node-1", ConnectorType: "nginx",
			PolicyID: "pilot-verify", PolicyVersion: 1, ClientIP: "",
			Action: "shadow", MatchedRules: []uint32{935100},
		},
		{
			BlockID: "BLK-010", Timestamp: tsNow, NodeID: "node-1", ConnectorType: "nginx",
			PolicyID: "pilot-verify", PolicyVersion: 1, ClientIP: "not-an-ip",
			Action: "shadow", MatchedRules: []uint32{935100},
		},
	}
	if err := insertTestEvents(ctx, chURL, dbName, remainingEvents); err != nil {
		t.Fatalf("inserting remaining events: %v", err)
	}

	// 4. CA ÂM: action='block' rule 930100 must not appear
	t.Run("Step4_NegativeActionBlock", func(t *testing.T) {
		opts := Options{
			ClickHouseURL: chURL,
			Database:      dbName,
			Since:         24 * time.Hour,
			Policies:      []string{"pilot-verify"},
		}
		rows, err := Query(ctx, opts)
		if err != nil {
			t.Fatalf("Query failed: %v", err)
		}
		for _, r := range rows {
			if r.RuleID == 930100 {
				t.Fatalf("rule 930100 with action=block appeared in results: %+v", r)
			}
		}
	})

	// 5. CA ÂM: 203.0.113.7 rule 932100 with exclude-ips containing 203.0.113.0/24 -> does not appear;
	// when NOT passing exclude -> DOES appear
	t.Run("Step5_NegativeExcludeCIDR", func(t *testing.T) {
		// With exclude
		optsWith := Options{
			ClickHouseURL: chURL,
			Database:      dbName,
			Since:         24 * time.Hour,
			Policies:      []string{"pilot-verify"},
			ExcludeCIDRs:  []string{"203.0.113.0/24"},
		}
		rowsWith, err := Query(ctx, optsWith)
		if err != nil {
			t.Fatalf("Query with exclude failed: %v", err)
		}
		for _, r := range rowsWith {
			if r.RuleID == 932100 {
				t.Fatalf("rule 932100 appeared despite 203.0.113.0/24 exclude: %+v", r)
			}
		}

		// Without exclude
		optsWithout := Options{
			ClickHouseURL: chURL,
			Database:      dbName,
			Since:         24 * time.Hour,
			Policies:      []string{"pilot-verify"},
			ExcludeCIDRs:  nil,
		}
		rowsWithout, err := Query(ctx, optsWithout)
		if err != nil {
			t.Fatalf("Query without exclude failed: %v", err)
		}
		found := false
		for _, r := range rowsWithout {
			if r.RuleID == 932100 {
				found = true
				break
			}
		}
		if !found {
			t.Fatalf("rule 932100 did not appear when exclude was omitted")
		}
	})

	// 6. CA ÂM: shadow old 3 days, since=24h -> does not appear
	t.Run("Step6_NegativeOldEvent", func(t *testing.T) {
		opts := Options{
			ClickHouseURL: chURL,
			Database:      dbName,
			Since:         24 * time.Hour,
			Policies:      []string{"pilot-verify"},
		}
		rows, err := Query(ctx, opts)
		if err != nil {
			t.Fatalf("Query failed: %v", err)
		}
		for _, r := range rows {
			if r.RuleID == 933100 {
				t.Fatalf("old rule 933100 appeared with since=24h: %+v", r)
			}
		}
	})

	// 7. Policy filter: shadow policy example-api, running with --policy pilot-verify -> does not appear
	t.Run("Step7_PolicyFilter", func(t *testing.T) {
		opts := Options{
			ClickHouseURL: chURL,
			Database:      dbName,
			Since:         24 * time.Hour,
			Policies:      []string{"pilot-verify"},
		}
		rows, err := Query(ctx, opts)
		if err != nil {
			t.Fatalf("Query failed: %v", err)
		}
		for _, r := range rows {
			if r.RuleID == 934100 {
				t.Fatalf("rule 934100 from policy example-api appeared with policy filter pilot-verify: %+v", r)
			}
		}
	})

	// 8. client_ip empty or not an IP: query must NOT error, even when exclude CIDR is specified
	t.Run("Step8_InvalidClientIPNoError", func(t *testing.T) {
		opts := Options{
			ClickHouseURL: chURL,
			Database:      dbName,
			Since:         24 * time.Hour,
			Policies:      []string{"pilot-verify"},
			ExcludeCIDRs:  []string{"192.0.2.0/24", "203.0.113.0/24"},
		}
		rows, err := Query(ctx, opts)
		if err != nil {
			t.Fatalf("Query failed when client_ip contains empty or invalid IPs: %v", err)
		}
		found := false
		for _, r := range rows {
			if r.RuleID == 935100 {
				found = true
				if r.Events != 2 {
					t.Errorf("rule 935100 events mismatch: expected 2, got %d", r.Events)
				}
				break
			}
		}
		if !found {
			t.Fatalf("expected rule 935100 in results")
		}
	})
}
