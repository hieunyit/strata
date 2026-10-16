package lifecycle

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/strata/strata/tools/strata-rules/internal/fpreport"
)

// FPSQL: suspected false positives per rule and policy, with the same
// conditions as fp-report (shadow events, attack sources excluded).
const FPSQL = `SELECT rule_id,
       policy_id,
       uniqExact(block_id) AS events,
       uniqExact(client_ip) AS sources,
       topK(1)(http_path)[1] AS top_path
FROM events
ARRAY JOIN arrayDistinct(matched_rules) AS rule_id
WHERE action = 'shadow'
  AND timestamp >= now64(3) - toIntervalSecond({since_s:UInt32})
  AND (empty({policies:Array(String)}) OR has({policies:Array(String)}, policy_id))
  AND NOT ((isIPv4String(client_ip) OR isIPv6String(client_ip)) AND arrayExists(c -> isIPAddressInRange(client_ip, c), {exclude:Array(String)}))
GROUP BY rule_id, policy_id
FORMAT JSONEachRow`

// RequestsSQL: requests per policy (RV-N-01 counters).
const RequestsSQL = `SELECT policy_id, sum(requests) AS requests
FROM policy_requests
WHERE timestamp >= now64(3) - toIntervalSecond({since_s:UInt32})
GROUP BY policy_id
FORMAT JSONEachRow`

// MatchesSQL: events per rule over the old-rule window, any action.
const MatchesSQL = `SELECT rule_id, count() AS events
FROM events
ARRAY JOIN arrayDistinct(matched_rules) AS rule_id
WHERE timestamp >= now64(3) - toIntervalSecond({old_s:UInt32})
GROUP BY rule_id
FORMAT JSONEachRow`

// BudgetFindingsSQL (#98): per policy, requests whose CPU budget ran out
// after some rule matched (error events, inspection partial, with a rule
// other than the limit rules 100020-100022): what fail_on_findings: block
// would answer 503.
const BudgetFindingsSQL = `SELECT policy_id, uniqExact(block_id) AS events
FROM events
WHERE action = 'error' AND inspection = 'partial'
  AND timestamp >= now64(3) - toIntervalSecond({since_s:UInt32})
  AND (empty({policies:Array(String)}) OR has({policies:Array(String)}, policy_id))
  AND length(arrayFilter(r -> r NOT IN (100020, 100021, 100022), matched_rules)) > 0
GROUP BY policy_id
FORMAT JSONEachRow`

// SinceSQL: how far back the event store goes.
const SinceSQL = `SELECT toUnixTimestamp(min(timestamp)) AS since, count() AS n FROM events FORMAT JSONEachRow`

// Query reads the statistics of the review from ClickHouse.
func Query(ctx context.Context, ch fpreport.Options, opt Options) (Stats, error) {
	opt = opt.withDefaults()
	st := Stats{FP: map[uint32]map[string]FP{}, Matches: map[uint32]uint64{}}
	params := url.Values{}
	params.Set("param_since_s", strconv.FormatInt(int64(opt.Window/time.Second), 10))
	params.Set("param_old_s", strconv.FormatInt(int64(opt.OldAfter/time.Second), 10))
	params.Set("param_policies", fpreport.FormatStringArray(ch.Policies))
	params.Set("param_exclude", fpreport.FormatStringArray(ch.ExcludeCIDRs))

	err := run(ctx, ch, FPSQL, params, func(r map[string]any) {
		id := uint32(u64(r["rule_id"]))
		pol, _ := r["policy_id"].(string)
		path, _ := r["top_path"].(string)
		if st.FP[id] == nil {
			st.FP[id] = map[string]FP{}
		}
		st.FP[id][pol] = FP{Events: u64(r["events"]), Sources: u64(r["sources"]), TopPath: path}
	})
	if err != nil {
		return st, fmt.Errorf("false positives: %w", err)
	}
	req := map[string]uint64{}
	err = run(ctx, ch, RequestsSQL, params, func(r map[string]any) {
		pol, _ := r["policy_id"].(string)
		req[pol] = u64(r["requests"])
	})
	switch {
	case err == nil:
		st.Requests = req
	case strings.Contains(err.Error(), "UNKNOWN_TABLE") || strings.Contains(err.Error(), "Code: 60"):
		// a store from before RV-N-01: no denominator
	default:
		return st, fmt.Errorf("requests per policy: %w", err)
	}
	err = run(ctx, ch, MatchesSQL, params, func(r map[string]any) {
		st.Matches[uint32(u64(r["rule_id"]))] = u64(r["events"])
	})
	if err != nil {
		return st, fmt.Errorf("matches: %w", err)
	}
	st.BudgetFindings = map[string]uint64{}
	err = run(ctx, ch, BudgetFindingsSQL, params, func(r map[string]any) {
		pol, _ := r["policy_id"].(string)
		st.BudgetFindings[pol] = u64(r["events"])
	})
	if err != nil {
		return st, fmt.Errorf("budget out with findings: %w", err)
	}
	err = run(ctx, ch, SinceSQL, params, func(r map[string]any) {
		if u64(r["n"]) > 0 {
			st.DataSince = time.Unix(int64(u64(r["since"])), 0).UTC()
		}
	})
	if err != nil {
		return st, fmt.Errorf("data window: %w", err)
	}
	return st, nil
}

// u64 reads a JSONEachRow number: ClickHouse quotes 64-bit integers.
func u64(v any) uint64 {
	switch n := v.(type) {
	case float64:
		return uint64(n)
	case string:
		x, _ := strconv.ParseUint(n, 10, 64)
		return x
	case json.Number:
		x, _ := strconv.ParseUint(string(n), 10, 64)
		return x
	}
	return 0
}

func run(ctx context.Context, ch fpreport.Options, sql string, params url.Values, row func(map[string]any)) error {
	u, err := url.Parse(ch.ClickHouseURL)
	if err != nil {
		return fmt.Errorf("invalid clickhouse url: %w", err)
	}
	q := u.Query()
	for k, v := range params {
		q[k] = v
	}
	if ch.Database != "" {
		q.Set("database", ch.Database)
	}
	u.RawQuery = q.Encode()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, u.String(), strings.NewReader(sql))
	if err != nil {
		return err
	}
	if ch.User != "" || ch.Password != "" {
		req.SetBasicAuth(ch.User, ch.Password)
	}
	timeout := ch.Timeout
	if timeout <= 0 {
		timeout = 60 * time.Second
	}
	resp, err := (&http.Client{Timeout: timeout}).Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("clickhouse (status %d): %s", resp.StatusCode, strings.TrimSpace(string(b)))
	}
	sc := bufio.NewScanner(resp.Body)
	sc.Buffer(make([]byte, 64*1024), 10*1024*1024)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		var m map[string]any
		if err := json.Unmarshal([]byte(line), &m); err != nil {
			return fmt.Errorf("row %q: %w", line, err)
		}
		row(m)
	}
	return sc.Err()
}
