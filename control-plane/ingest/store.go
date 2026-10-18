package ingest

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/ClickHouse/clickhouse-go/v2"
	"github.com/ClickHouse/clickhouse-go/v2/lib/driver"
)

var (
	ErrEventNotFound = errors.New("event not found")
)

// SearchFilter specifies multi-dimensional filters for querying events.
type SearchFilter struct {
	From       time.Time
	To         time.Time
	PolicyID   string
	Action     string
	ClientIP   string
	RuleID     uint32
	NodeID     string
	HTTPMethod string
	Limit      int
	Offset     int
}

// SearchResult holds search query results.
type SearchResult struct {
	Events []Event
	Total  uint64
}

// EventStore abstracts storage operations for security events.
type EventStore interface {
	SaveEvents(ctx context.Context, events []Event) error
	GetEvent(ctx context.Context, blockID string) (*Event, error)
	SearchEvents(ctx context.Context, filter SearchFilter) (*SearchResult, error)
	GetNodeSeq(ctx context.Context, nodeID string) (uint64, error)
	SetNodeSeq(ctx context.Context, nodeID string, seq uint64) error
	Close() error
}

// ClickHouseStore is a production EventStore implementation backed by ClickHouse.
type ClickHouseStore struct {
	conn      driver.Conn
	tableName string
}

// ClickHouseConfig holds connection settings for ClickHouse.
type ClickHouseConfig struct {
	Addr     string
	Database string
	Username string
	Password string
	Table    string
}

// NewClickHouseStore connects to ClickHouse and ensures the events table exists.
func NewClickHouseStore(ctx context.Context, cfg ClickHouseConfig) (*ClickHouseStore, error) {
	if cfg.Table == "" {
		cfg.Table = "events"
	}
	opts := &clickhouse.Options{
		Addr: []string{cfg.Addr},
		Auth: clickhouse.Auth{
			Database: cfg.Database,
			Username: cfg.Username,
			Password: cfg.Password,
		},
		Settings: clickhouse.Settings{
			"max_execution_time": 10,
		},
		Compression: &clickhouse.Compression{
			Method: clickhouse.CompressionLZ4,
		},
		DialTimeout: 5 * time.Second,
	}

	conn, err := clickhouse.Open(opts)
	if err != nil {
		return nil, fmt.Errorf("opening clickhouse connection: %w", err)
	}

	if err := conn.Ping(ctx); err != nil {
		return nil, fmt.Errorf("pinging clickhouse: %w", err)
	}

	return &ClickHouseStore{
		conn:      conn,
		tableName: cfg.Table,
	}, nil
}

// EnsureTTL sets the retention of the events table to days (W09-G2-01): the
// table's TTL is changed when it differs, and ClickHouse then drops the
// rows past it in the background (and on OPTIMIZE ... FINAL). days <= 0
// leaves the table as it is.
func (s *ClickHouseStore) EnsureTTL(ctx context.Context, days int) error {
	if days <= 0 {
		return nil
	}
	var create string
	if err := s.conn.QueryRow(ctx,
		"SELECT create_table_query FROM system.tables WHERE database = currentDatabase() AND name = ?",
		s.tableName).Scan(&create); err != nil {
		return fmt.Errorf("reading the events table: %w", err)
	}
	want := fmt.Sprintf("TTL timestamp + toIntervalDay(%d)", days)
	if strings.Contains(create, want) {
		return nil
	}
	if err := s.conn.Exec(ctx, fmt.Sprintf("ALTER TABLE %s MODIFY TTL timestamp + INTERVAL %d DAY", s.tableName, days)); err != nil {
		return fmt.Errorf("setting the events TTL to %d days: %w", days, err)
	}
	return nil
}

// contextColumns are the columns added after the first schema (RV-G2-01,
// RV-N-01): tables made before them get them with EnsureColumns.
var contextColumns = []string{
	"user_agent String CODEC(ZSTD(1))",
	"referer String CODEC(ZSTD(1))",
	"headers Nested(name LowCardinality(String), value String)",
	"inspection LowCardinality(String)",
	"rule_costs Nested(rule_id UInt32, samples UInt64, total_ns UInt64, max_ns UInt64)",
}

// EnsureColumns adds the columns of later schemas to an events table made
// before them (schema.sql only runs when ClickHouse creates its volume).
// Adding a column is a metadata change: old rows read the default.
func (s *ClickHouseStore) EnsureColumns(ctx context.Context) error {
	for _, c := range contextColumns {
		if err := s.conn.Exec(ctx, fmt.Sprintf("ALTER TABLE %s ADD COLUMN IF NOT EXISTS %s", s.tableName, c)); err != nil {
			return fmt.Errorf("adding column %q to the events table: %w", c, err)
		}
	}
	return nil
}

// Conn returns the underlying ClickHouse connection.
func (s *ClickHouseStore) Conn() driver.Conn {
	return s.conn
}

// SaveEvents writes a batch of events to ClickHouse using native batch protocol.
func (s *ClickHouseStore) SaveEvents(ctx context.Context, events []Event) error {
	if len(events) == 0 {
		return nil
	}

	query := fmt.Sprintf(`INSERT INTO %s (
		block_id, timestamp, node_id, connector_type, policy_id, policy_version,
		client_ip, identity, request_id, http_method, http_host, http_path,
		status_code, action, score_protocol, score_sqli, score_xss, score_anomaly,
		matched_rules, violations.rule_id, violations.layer, violations.field, violations.snippet,
		received_at, user_agent, referer, headers.name, headers.value, inspection,
		rule_costs.rule_id, rule_costs.samples, rule_costs.total_ns, rule_costs.max_ns
	)`, s.tableName)

	batch, err := s.conn.PrepareBatch(ctx, query)
	if err != nil {
		return fmt.Errorf("preparing batch insert: %w", err)
	}

	for _, e := range events {
		ruleIDs := make([]uint32, 0, len(e.Violations))
		layers := make([]string, 0, len(e.Violations))
		fields := make([]string, 0, len(e.Violations))
		snippets := make([]string, 0, len(e.Violations))

		for _, v := range e.Violations {
			ruleIDs = append(ruleIDs, v.RuleID)
			layers = append(layers, v.Layer)
			fields = append(fields, v.Field)
			snippets = append(snippets, v.Snippet)
		}
		hNames := make([]string, len(e.Headers))
		hValues := make([]string, len(e.Headers))
		for i, h := range e.Headers {
			hNames[i], hValues[i] = h.Name, h.Value
		}
		costs := validRuleCosts(e.RuleCosts)
		costIDs := make([]uint32, len(costs))
		costSamples, costTotals, costMax := make([]uint64, len(costs)), make([]uint64, len(costs)), make([]uint64, len(costs))
		for i, c := range costs {
			costIDs[i], costSamples[i], costTotals[i], costMax[i] = c.RuleID, c.Samples, c.TotalNS, c.MaxNS
		}

		err := batch.Append(
			e.BlockID,
			e.Timestamp,
			e.NodeID,
			e.ConnectorType,
			e.PolicyID,
			e.PolicyVersion,
			e.ClientIP,
			e.Identity,
			e.RequestID,
			e.HTTPMethod,
			e.HTTPHost,
			e.HTTPPath,
			e.StatusCode,
			e.Action,
			e.ScoreProtocol,
			e.ScoreSQLi,
			e.ScoreXSS,
			e.ScoreAnomaly,
			e.MatchedRules,
			ruleIDs,
			layers,
			fields,
			snippets,
			e.ReceivedAt,
			e.UserAgent,
			e.Referer,
			hNames,
			hValues,
			e.Inspection,
			costIDs, costSamples, costTotals, costMax,
		)
		if err != nil {
			return fmt.Errorf("appending event %s to batch: %w", e.BlockID, err)
		}
	}

	if err := batch.Send(); err != nil {
		return fmt.Errorf("sending batch to clickhouse: %w", err)
	}

	return nil
}

// GetEvent performs a point lookup by block_id (the primary key). The time a
// Block ID carries is the event's timestamp, so the lookup first reads only
// the partitions (days) around it; an event stored with another timestamp
// is still found by the lookup over every partition that follows a miss.
func (s *ClickHouseStore) GetEvent(ctx context.Context, blockID string) (*Event, error) {
	if t, ok := BlockIDTime(blockID); ok {
		// Normal events are timestamped near their ID's creation. Start with
		// one narrow partition range; the wider probe and global fallback
		// still cover long requests, clock skew and older producers.
		for _, radius := range []time.Duration{time.Second, 24 * time.Hour} {
			e, err := s.getEvent(ctx, blockID, "AND timestamp BETWEEN ? AND ?", t.Add(-radius), t.Add(radius))
			if !errors.Is(err, ErrEventNotFound) {
				return e, err
			}
		}
	}
	return s.getEvent(ctx, blockID, "")
}

func (s *ClickHouseStore) getEvent(ctx context.Context, blockID, extra string, args ...any) (*Event, error) {
	query := fmt.Sprintf(`
		SELECT 
			block_id, timestamp, node_id, connector_type, policy_id, policy_version,
			client_ip, identity, request_id, http_method, http_host, http_path,
			status_code, action, score_protocol, score_sqli, score_xss, score_anomaly,
			matched_rules, violations.rule_id, violations.layer, violations.field, violations.snippet,
			received_at, user_agent, referer, headers.name, headers.value, inspection,
			rule_costs.rule_id, rule_costs.samples, rule_costs.total_ns, rule_costs.max_ns
		FROM %s FINAL
		WHERE block_id = ? %s
		LIMIT 1`, s.tableName, extra)

	row := s.conn.QueryRow(ctx, query, append([]any{blockID}, args...)...)

	var (
		e                                Event
		ruleIDs                          []uint32
		layers                           []string
		fields                           []string
		snippets                         []string
		hNames                           []string
		hValues                          []string
		costIDs                          []uint32
		costSamples, costTotals, costMax []uint64
	)

	err := row.Scan(
		&e.BlockID,
		&e.Timestamp,
		&e.NodeID,
		&e.ConnectorType,
		&e.PolicyID,
		&e.PolicyVersion,
		&e.ClientIP,
		&e.Identity,
		&e.RequestID,
		&e.HTTPMethod,
		&e.HTTPHost,
		&e.HTTPPath,
		&e.StatusCode,
		&e.Action,
		&e.ScoreProtocol,
		&e.ScoreSQLi,
		&e.ScoreXSS,
		&e.ScoreAnomaly,
		&e.MatchedRules,
		&ruleIDs,
		&layers,
		&fields,
		&snippets,
		&e.ReceivedAt,
		&e.UserAgent,
		&e.Referer,
		&hNames,
		&hValues,
		&e.Inspection,
		&costIDs, &costSamples, &costTotals, &costMax,
	)
	if err != nil {
		// Any other error, ClickHouse exceptions included, is a real failure.
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrEventNotFound
		}
		return nil, fmt.Errorf("scanning event row: %w", err)
	}

	e.Violations = make([]Violation, len(ruleIDs))
	for i := range ruleIDs {
		e.Violations[i] = Violation{
			RuleID:  ruleIDs[i],
			Layer:   layers[i],
			Field:   fields[i],
			Snippet: snippets[i],
		}
	}

	for i := range hNames {
		if i < len(hValues) {
			e.Headers = append(e.Headers, Header{Name: hNames[i], Value: hValues[i]})
		}
	}
	if len(costIDs) <= MaxEventRuleCosts && len(costSamples) == len(costIDs) && len(costTotals) == len(costIDs) && len(costMax) == len(costIDs) {
		for i, id := range costIDs {
			e.RuleCosts = append(e.RuleCosts, RuleCost{RuleID: id, Samples: costSamples[i], TotalNS: costTotals[i], MaxNS: costMax[i]})
		}
		e.RuleCosts = validRuleCosts(e.RuleCosts)
	}

	return &e, nil
}

// SearchEvents filters events matching the specified criteria.
func (s *ClickHouseStore) SearchEvents(ctx context.Context, filter SearchFilter) (*SearchResult, error) {
	whereClauses := []string{"1=1"}
	args := []any{}

	if !filter.From.IsZero() {
		whereClauses = append(whereClauses, "timestamp >= ?")
		args = append(args, filter.From)
	}
	if !filter.To.IsZero() {
		whereClauses = append(whereClauses, "timestamp <= ?")
		args = append(args, filter.To)
	}
	if filter.PolicyID != "" {
		whereClauses = append(whereClauses, "policy_id = ?")
		args = append(args, filter.PolicyID)
	}
	if filter.Action != "" {
		whereClauses = append(whereClauses, "action = ?")
		args = append(args, filter.Action)
	}
	if filter.ClientIP != "" {
		whereClauses = append(whereClauses, "client_ip = ?")
		args = append(args, filter.ClientIP)
	}
	if filter.RuleID > 0 {
		whereClauses = append(whereClauses, "has(matched_rules, ?)")
		args = append(args, filter.RuleID)
	}
	if filter.NodeID != "" {
		whereClauses = append(whereClauses, "node_id = ?")
		args = append(args, filter.NodeID)
	}
	if filter.HTTPMethod != "" {
		whereClauses = append(whereClauses, "http_method = ?")
		args = append(args, filter.HTTPMethod)
	}

	limit := filter.Limit
	if limit <= 0 {
		limit = 50
	}
	if limit > 200 {
		limit = 200
	}
	offset := filter.Offset
	if offset < 0 {
		offset = 0
	}

	whereSQL := ""
	for i, c := range whereClauses {
		if i == 0 {
			whereSQL = c
		} else {
			whereSQL += " AND " + c
		}
	}

	// 1. Get total count
	countQuery := fmt.Sprintf("SELECT count() FROM %s FINAL WHERE %s", s.tableName, whereSQL)
	var total uint64
	if err := s.conn.QueryRow(ctx, countQuery, args...).Scan(&total); err != nil {
		return nil, fmt.Errorf("counting events: %w", err)
	}

	// 2. Select data. The page is chosen on (timestamp, block_id) only, then
	// its rows are read through the primary key: sorting 24 hours of events
	// with every column read 2.5 GB for 10 million events, the two columns
	// a tenth of it (W09-G2-01).
	dataQuery := fmt.Sprintf(`
		SELECT 
			block_id, timestamp, node_id, connector_type, policy_id, policy_version,
			client_ip, identity, request_id, http_method, http_host, http_path,
			status_code, action, score_protocol, score_sqli, score_xss, score_anomaly,
			matched_rules, violations.rule_id, violations.layer, violations.field, violations.snippet,
			received_at
		FROM %[1]s FINAL
		WHERE (block_id, timestamp) IN (
			SELECT block_id, timestamp FROM %[1]s FINAL
			WHERE %[2]s
			ORDER BY timestamp DESC, block_id DESC
			LIMIT ? OFFSET ?)
		ORDER BY timestamp DESC, block_id DESC
		LIMIT ?`, s.tableName, whereSQL)

	queryArgs := append(args, limit, offset, limit)
	rows, err := s.conn.Query(ctx, dataQuery, queryArgs...)
	if err != nil {
		return nil, fmt.Errorf("querying events: %w", err)
	}
	defer rows.Close()

	var events []Event
	for rows.Next() {
		var (
			e        Event
			ruleIDs  []uint32
			layers   []string
			fields   []string
			snippets []string
		)
		err := rows.Scan(
			&e.BlockID,
			&e.Timestamp,
			&e.NodeID,
			&e.ConnectorType,
			&e.PolicyID,
			&e.PolicyVersion,
			&e.ClientIP,
			&e.Identity,
			&e.RequestID,
			&e.HTTPMethod,
			&e.HTTPHost,
			&e.HTTPPath,
			&e.StatusCode,
			&e.Action,
			&e.ScoreProtocol,
			&e.ScoreSQLi,
			&e.ScoreXSS,
			&e.ScoreAnomaly,
			&e.MatchedRules,
			&ruleIDs,
			&layers,
			&fields,
			&snippets,
			&e.ReceivedAt,
		)
		if err != nil {
			return nil, fmt.Errorf("scanning search row: %w", err)
		}

		e.Violations = make([]Violation, len(ruleIDs))
		for i := range ruleIDs {
			e.Violations[i] = Violation{
				RuleID:  ruleIDs[i],
				Layer:   layers[i],
				Field:   fields[i],
				Snippet: snippets[i],
			}
		}
		events = append(events, e)
	}

	return &SearchResult{
		Events: events,
		Total:  total,
	}, nil
}

// GetNodeSeq returns the last committed sequence number for nodeID from ClickHouse.
func (s *ClickHouseStore) GetNodeSeq(ctx context.Context, nodeID string) (uint64, error) {
	query := `SELECT last_seq FROM node_seq WHERE node_id = ? ORDER BY updated_at DESC LIMIT 1`
	var seq uint64
	err := s.conn.QueryRow(ctx, query, nodeID).Scan(&seq)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return 0, nil
		}
		return 0, fmt.Errorf("getting node seq: %w", err)
	}
	return seq, nil
}

// SetNodeSeq persists the sequence watermark for nodeID to ClickHouse.
func (s *ClickHouseStore) SetNodeSeq(ctx context.Context, nodeID string, seq uint64) error {
	query := `INSERT INTO node_seq (node_id, last_seq, updated_at) VALUES (?, ?, now64(3))`
	err := s.conn.Exec(ctx, query, nodeID, seq)
	if err != nil {
		return fmt.Errorf("setting node seq: %w", err)
	}
	return nil
}

// Close closes the underlying ClickHouse connection.
func (s *ClickHouseStore) Close() error {
	return s.conn.Close()
}

// MockEventStore is a thread-safe in-memory store for unit tests and benchmarks.
type MockEventStore struct {
	mu           sync.RWMutex
	eventsByID   map[string]Event
	eventsList   []Event
	nodeSeqs     map[string]uint64
	saveErr      error
	saveCount    int
	onSaveEvents func(events []Event)
	// RV-N-01
	policyRequests []PolicyRequests
}

// NewMockEventStore initializes an in-memory mock store.
func NewMockEventStore() *MockEventStore {
	return &MockEventStore{
		eventsByID: make(map[string]Event),
		eventsList: make([]Event, 0),
		nodeSeqs:   make(map[string]uint64),
	}
}

func (m *MockEventStore) GetNodeSeq(ctx context.Context, nodeID string) (uint64, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.nodeSeqs[nodeID], nil
}

func (m *MockEventStore) SetNodeSeq(ctx context.Context, nodeID string, seq uint64) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.nodeSeqs[nodeID] = seq
	return nil
}

func (m *MockEventStore) SetSaveError(err error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.saveErr = err
}

func (m *MockEventStore) SetOnSave(fn func(events []Event)) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.onSaveEvents = fn
}

func (m *MockEventStore) SaveEvents(ctx context.Context, events []Event) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.saveErr != nil {
		return m.saveErr
	}

	for _, e := range events {
		m.eventsByID[e.BlockID] = e
		m.eventsList = append(m.eventsList, e)
	}
	m.saveCount += len(events)

	if m.onSaveEvents != nil {
		m.onSaveEvents(events)
	}
	return nil
}

func (m *MockEventStore) GetEvent(ctx context.Context, blockID string) (*Event, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	e, found := m.eventsByID[blockID]
	if !found {
		return nil, ErrEventNotFound
	}
	return &e, nil
}

func (m *MockEventStore) SearchEvents(ctx context.Context, filter SearchFilter) (*SearchResult, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	var matched []Event
	for _, e := range m.eventsList {
		if !filter.From.IsZero() && e.Timestamp.Before(filter.From) {
			continue
		}
		if !filter.To.IsZero() && e.Timestamp.After(filter.To) {
			continue
		}
		if filter.PolicyID != "" && e.PolicyID != filter.PolicyID {
			continue
		}
		if filter.Action != "" && e.Action != filter.Action {
			continue
		}
		if filter.ClientIP != "" && e.ClientIP != filter.ClientIP {
			continue
		}
		if filter.NodeID != "" && e.NodeID != filter.NodeID {
			continue
		}
		if filter.RuleID > 0 {
			hasRule := false
			for _, r := range e.MatchedRules {
				if r == filter.RuleID {
					hasRule = true
					break
				}
			}
			if !hasRule {
				continue
			}
		}
		matched = append(matched, e)
	}

	total := uint64(len(matched))
	start := filter.Offset
	if start > len(matched) {
		start = len(matched)
	}
	limit := filter.Limit
	if limit <= 0 {
		limit = 50
	}
	end := start + limit
	if end > len(matched) {
		end = len(matched)
	}

	return &SearchResult{
		Events: matched[start:end],
		Total:  total,
	}, nil
}

func (m *MockEventStore) Close() error {
	return nil
}

func (m *MockEventStore) Count() int {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return len(m.eventsList)
}
