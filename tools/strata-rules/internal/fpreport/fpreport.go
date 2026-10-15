// Package fpreport queries ClickHouse for false positive candidates in shadow mode.
package fpreport

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"
)

// Options holds parameters for querying and reporting shadow false positives.
type Options struct {
	ClickHouseURL string
	Database      string
	User          string
	Password      string
	Since         time.Duration
	Policies      []string
	ExcludeCIDRs  []string
	Timeout       time.Duration
}

// Row represents one rule's shadow statistics on a specific day.
type Row struct {
	Day       string
	RuleID    uint32
	Events    uint64
	Sources   uint64
	TopPolicy string
}

// QuerySQL is the ClickHouse query template executed for FP detection in shadow mode.
// The (isIPv4String(client_ip) OR isIPv6String(client_ip)) guard precedes arrayExists
// because isIPAddressInRange errors on non-IP strings. This relies on ClickHouse's
// short_circuit_function_evaluation (enabled by default); Step8 in integration tests guards this behavior.
const QuerySQL = `SELECT toString(toDate(timestamp)) AS day,
       rule_id,
       uniqExact(block_id) AS events,
       uniqExact(client_ip) AS sources,
       topK(1)(policy_id)[1] AS top_policy
FROM events
ARRAY JOIN arrayDistinct(matched_rules) AS rule_id
WHERE action = 'shadow'
  AND timestamp >= now64(3) - toIntervalSecond({since_s:UInt32})
  AND (empty({policies:Array(String)}) OR has({policies:Array(String)}, policy_id))
  AND NOT ((isIPv4String(client_ip) OR isIPv6String(client_ip)) AND arrayExists(c -> isIPAddressInRange(client_ip, c), {exclude:Array(String)}))
GROUP BY day, rule_id
ORDER BY day DESC, events DESC, rule_id
FORMAT JSONEachRow`

type jsonUInt32 uint32

func (u *jsonUInt32) UnmarshalJSON(b []byte) error {
	s := strings.Trim(string(b), `"`)
	val, err := strconv.ParseUint(s, 10, 32)
	if err != nil {
		return err
	}
	*u = jsonUInt32(val)
	return nil
}

type jsonUInt64 uint64

func (u *jsonUInt64) UnmarshalJSON(b []byte) error {
	s := strings.Trim(string(b), `"`)
	val, err := strconv.ParseUint(s, 10, 64)
	if err != nil {
		return err
	}
	*u = jsonUInt64(val)
	return nil
}

// FormatStringArray writes items as a ClickHouse Array(String) literal for
// a query parameter.
func FormatStringArray(items []string) string {
	if len(items) == 0 {
		return "[]"
	}
	var sb strings.Builder
	sb.WriteByte('[')
	for i, item := range items {
		if i > 0 {
			sb.WriteString(", ")
		}
		sb.WriteByte('\'')
		escaped := strings.ReplaceAll(item, `\`, `\\`)
		escaped = strings.ReplaceAll(escaped, `'`, `\'`)
		sb.WriteString(escaped)
		sb.WriteByte('\'')
	}
	sb.WriteByte(']')
	return sb.String()
}

// Query executes the ClickHouse query via HTTP interface with parameters passed in query string.
func Query(ctx context.Context, opts Options) ([]Row, error) {
	sinceSeconds := int64(opts.Since / time.Second)
	if sinceSeconds <= 0 {
		return nil, fmt.Errorf("since must be positive")
	}
	if sinceSeconds > math.MaxUint32 {
		return nil, fmt.Errorf("since too large")
	}

	if opts.ClickHouseURL == "" {
		return nil, fmt.Errorf("clickhouse url is required")
	}
	u, err := url.Parse(opts.ClickHouseURL)
	if err != nil {
		return nil, fmt.Errorf("invalid clickhouse url: %w", err)
	}

	q := u.Query()
	if opts.Database != "" {
		q.Set("database", opts.Database)
	}
	q.Set("param_since_s", strconv.FormatUint(uint64(sinceSeconds), 10))
	q.Set("param_policies", FormatStringArray(opts.Policies))
	q.Set("param_exclude", FormatStringArray(opts.ExcludeCIDRs))
	u.RawQuery = q.Encode()

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, u.String(), strings.NewReader(QuerySQL))
	if err != nil {
		return nil, fmt.Errorf("creating http request: %w", err)
	}
	if opts.User != "" || opts.Password != "" {
		req.SetBasicAuth(opts.User, opts.Password)
	}

	timeout := opts.Timeout
	if timeout <= 0 {
		timeout = 60 * time.Second
	}
	client := &http.Client{Timeout: timeout}

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("clickhouse request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("clickhouse error (status %d): %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}

	var rows []Row
	scanner := bufio.NewScanner(resp.Body)
	buf := make([]byte, 64*1024)
	scanner.Buffer(buf, 10*1024*1024)

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		var jr struct {
			Day       string     `json:"day"`
			RuleID    jsonUInt32 `json:"rule_id"`
			Events    jsonUInt64 `json:"events"`
			Sources   jsonUInt64 `json:"sources"`
			TopPolicy string     `json:"top_policy"`
		}
		if err := json.Unmarshal([]byte(line), &jr); err != nil {
			return nil, fmt.Errorf("parsing clickhouse json row: %w", err)
		}
		rows = append(rows, Row{
			Day:       jr.Day,
			RuleID:    uint32(jr.RuleID),
			Events:    uint64(jr.Events),
			Sources:   uint64(jr.Sources),
			TopPolicy: jr.TopPolicy,
		})
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("reading clickhouse response: %w", err)
	}
	return rows, nil
}

// LoadCIDRs loads IPs or CIDRs from a text file, ignoring empty lines and comments (#).
// Single IPs are converted to /32 (IPv4) or /128 (IPv6).
// Returns an error with line number if any entry is invalid.
func LoadCIDRs(path string) ([]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var cidrs []string
	scanner := bufio.NewScanner(f)
	lineNum := 0
	for scanner.Scan() {
		lineNum++
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if strings.Contains(line, "/") {
			prefix, err := netip.ParsePrefix(line)
			if err != nil {
				return nil, fmt.Errorf("%s:%d: invalid CIDR %q: %w", path, lineNum, line, err)
			}
			cidrs = append(cidrs, prefix.String())
		} else {
			addr, err := netip.ParseAddr(line)
			if err != nil {
				return nil, fmt.Errorf("%s:%d: invalid IP %q: %w", path, lineNum, line, err)
			}
			if addr.Is4() {
				cidrs = append(cidrs, addr.String()+"/32")
			} else if addr.Is6() {
				cidrs = append(cidrs, addr.String()+"/128")
			} else {
				return nil, fmt.Errorf("%s:%d: invalid IP address %q", path, lineNum, line)
			}
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("reading %s: %w", path, err)
	}
	return cidrs, nil
}

// Markdown formats the shadow FP report as Markdown.
func Markdown(w io.Writer, rows []Row, opts Options) {
	sinceStr := opts.Since.String()
	if opts.Since > 0 && opts.Since%time.Hour == 0 {
		sinceStr = fmt.Sprintf("%dh", int(opts.Since.Hours()))
	}
	polStr := "tất cả"
	if len(opts.Policies) > 0 {
		polStr = strings.Join(opts.Policies, ", ")
	}

	fmt.Fprintln(w, "## Báo cáo nghi FP (shadow)")
	fmt.Fprintf(w, "\nKhoảng thời gian: %s | Policy: %s | CIDR loại trừ: %d\n\n", sinceStr, polStr, len(opts.ExcludeCIDRs))

	if len(rows) == 0 {
		fmt.Fprintln(w, "Không có sự kiện shadow nghi FP.")
		return
	}

	fmt.Fprintln(w, "| Ngày | Rule ID | Sự kiện | Nguồn | Policy nhiều nhất |")
	fmt.Fprintln(w, "| --- | ---: | ---: | ---: | --- |")
	for _, r := range rows {
		fmt.Fprintf(w, "| %s | %d | %d | %d | %s |\n", r.Day, r.RuleID, r.Events, r.Sources, r.TopPolicy)
	}
}
