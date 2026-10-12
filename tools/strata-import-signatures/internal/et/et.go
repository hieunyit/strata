// Package et converts ET Open (Suricata) HTTP rules to the IR. Only SIDs
// 2000000-2099999 (the BSD-licensed part of ET Open) are imported; any
// other SID is refused. Only rules on requests (to_server) are kept.
//
// Each content or pcre in a sticky buffer becomes one condition of an all
// match on the request variable of that buffer. Suricata's positional
// modifiers between contents (distance, within, offset, depth other than
// at the start) have no IR equivalent: they are dropped, so the rule
// matches a superset; the report counts the rules where that happened.
package et

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/strata/strata/tools/strata-import-signatures/internal/irout"
)

// SIDs that may be imported, and the rule ids they get (rules/README.md:
// 450000-499999 imported ET Open).
const (
	MinSID = 2000000
	MaxSID = 2099999
	MinID  = 450000
	MaxID  = 499999
)

// Files of ET Open with rules on traffic to web servers.
var Files = []string{
	"emerging-web_server.rules",
	"emerging-web_specific_apps.rules",
	"emerging-exploit.rules",
	"emerging-scan.rules",
}

// ErrSID refuses a SID outside the BSD range.
var ErrSID = errors.New("SID outside 2000000-2099999 (not the BSD part of ET Open)")

// Result of the import of one file.
type Result struct {
	File    string
	Read    int // HTTP rules in the SID range
	Other   int // rules of the file left aside: not HTTP, or SID outside the range
	Rules   []irout.Rule
	Tests   []irout.Test
	Skipped []irout.Skipped
	Loose   int // imported with positional constraints dropped
}

// Import converts the listed files of an ET Open rules directory.
func Import(dir, version string, ids *irout.IDs) ([]*Result, error) {
	var out []*Result
	for _, f := range Files {
		raw, err := os.ReadFile(filepath.Join(dir, f))
		if err != nil {
			return nil, err
		}
		res := &Result{File: f}
		for _, line := range strings.Split(string(raw), "\n") {
			line = strings.TrimSpace(line)
			if !strings.HasPrefix(line, "alert ") {
				continue
			}
			r, err := Parse(line)
			if err != nil || r.Proto != "http" {
				res.Other++
				continue
			}
			if r.SID < MinSID || r.SID > MaxSID {
				res.Other++
				continue
			}
			res.Read++
			rule, tests, loose, err := Convert(r, version, ids)
			if err != nil {
				res.Skipped = append(res.Skipped, irout.Skipped{Upstream: strconv.Itoa(r.SID), Name: r.Msg, Reason: err.Error()})
				continue
			}
			if loose {
				res.Loose++
			}
			res.Rules = append(res.Rules, rule)
			res.Tests = append(res.Tests, tests...)
		}
		out = append(out, res)
	}
	return out, nil
}

// Rule is a parsed Suricata rule.
type Rule struct {
	Proto, Src, Dst string
	Msg             string
	SID             int
	Opts            []Opt
	Meta            map[string][]string
}

// Opt is one option: keyword and value (unquoted).
type Opt struct{ Key, Val string }

var headRe = regexp.MustCompile(`^alert\s+(\S+)\s+(\S+)\s+\S+\s+(->|<>)\s+(\S+)\s+\S+\s*\((.*)\)\s*$`)

// Parse reads one rule line.
func Parse(line string) (*Rule, error) {
	m := headRe.FindStringSubmatch(line)
	if m == nil {
		return nil, errors.New("not a rule")
	}
	r := &Rule{Proto: m[1], Src: m[2], Dst: m[4], Meta: map[string][]string{}}
	body := m[5]
	for len(body) > 0 {
		body = strings.TrimLeft(body, " ")
		if body == "" {
			break
		}
		// key[:value]; up to an unescaped ; outside quotes
		var b strings.Builder
		inQ, i := false, 0
		for ; i < len(body); i++ {
			c := body[i]
			if c == '\\' && i+1 < len(body) {
				b.WriteByte(c)
				b.WriteByte(body[i+1])
				i++
				continue
			}
			if c == '"' {
				inQ = !inQ
			}
			if c == ';' && !inQ {
				break
			}
			b.WriteByte(c)
		}
		if i >= len(body) && inQ {
			return nil, errors.New("unterminated quote")
		}
		opt := strings.TrimSpace(b.String())
		body = body[min(i+1, len(body)):]
		if opt == "" {
			continue
		}
		k, v, _ := strings.Cut(opt, ":")
		o := Opt{Key: strings.TrimSpace(k), Val: strings.TrimSpace(v)}
		switch o.Key {
		case "msg":
			r.Msg = unquote(o.Val)
		case "sid":
			r.SID, _ = strconv.Atoi(o.Val)
		case "metadata":
			for _, kv := range strings.Split(o.Val, ",") {
				f := strings.Fields(kv)
				if len(f) >= 2 {
					r.Meta[f[0]] = append(r.Meta[f[0]], strings.Join(f[1:], " "))
				}
			}
		}
		r.Opts = append(r.Opts, o)
	}
	if r.SID == 0 {
		return nil, errors.New("no sid")
	}
	return r, nil
}

func unquote(s string) string {
	s = strings.TrimSpace(s)
	if len(s) >= 2 && s[0] == '"' && s[len(s)-1] == '"' {
		s = s[1 : len(s)-1]
	}
	return s
}

// buffer: the request variable of a sticky buffer.
type buffer struct {
	target irout.Target
	body   bool // the rule needs the request body
	uri    bool
	// decode: Suricata's normalized URI is the raw one percent-decoded,
	// without path normalization (// stays): uri_raw with url_decode
	decode bool
}

var buffers = map[string]buffer{
	"http.uri":            {target: irout.Target{Var: "uri_raw"}, uri: true, decode: true},
	"http_uri":            {target: irout.Target{Var: "uri_raw"}, uri: true, decode: true},
	"http.uri.raw":        {target: irout.Target{Var: "uri_raw"}, uri: true},
	"http_raw_uri":        {target: irout.Target{Var: "uri_raw"}, uri: true},
	"http.method":         {target: irout.Target{Var: "method"}},
	"http_method":         {target: irout.Target{Var: "method"}},
	"http.request_body":   {target: irout.Target{Var: "request_body"}, body: true},
	"http_client_body":    {target: irout.Target{Var: "request_body"}, body: true},
	"file.data":           {target: irout.Target{Var: "request_body"}, body: true}, // to_server: the request body
	"http.header":         {target: irout.Target{Var: "request_headers"}},
	"http_header":         {target: irout.Target{Var: "request_headers"}},
	"http.header_names":   {target: irout.Target{Var: "request_headers_names"}},
	"http.user_agent":     {target: irout.Target{Var: "request_headers", Key: "User-Agent"}},
	"http_user_agent":     {target: irout.Target{Var: "request_headers", Key: "User-Agent"}},
	"http.cookie":         {target: irout.Target{Var: "request_headers", Key: "Cookie"}},
	"http_cookie":         {target: irout.Target{Var: "request_headers", Key: "Cookie"}},
	"http.host":           {target: irout.Target{Var: "request_headers", Key: "Host"}},
	"http_host":           {target: irout.Target{Var: "request_headers", Key: "Host"}},
	"http.referer":        {target: irout.Target{Var: "request_headers", Key: "Referer"}},
	"http.content_type":   {target: irout.Target{Var: "request_headers", Key: "Content-Type"}},
	"http.content_len":    {target: irout.Target{Var: "request_headers", Key: "Content-Length"}},
	"http.accept":         {target: irout.Target{Var: "request_headers", Key: "Accept"}},
	"http.connection":     {target: irout.Target{Var: "request_headers", Key: "Connection"}},
	"http.request_line":   {target: irout.Target{Var: "request_line"}},
	"http.protocol":       {target: irout.Target{Var: "protocol"}},
	"http.request_header": {target: irout.Target{Var: "request_headers"}}, // "Name: value": split below
}

// Suricata transforms on the sticky buffer, as IR transformations.
var transforms = map[string]string{
	"url_decode": "url_decode", "to_lowercase": "lowercase",
	"strip_whitespace": "remove_whitespace", "compress_whitespace": "compress_whitespace",
}

// pcre flags naming a buffer (when no sticky buffer is set).
var pcreBuffers = map[byte]string{'U': "http.uri", 'I': "http.uri.raw", 'P': "http.request_body", 'H': "http.header",
	'C': "http.cookie", 'M': "http.method", 'V': "http.user_agent", 'W': "http.host"}

// keywords that make a rule impossible to express (state across requests,
// byte arithmetic, response, Lua...).
var unsupported = map[string]bool{
	"flowbits": true, "xbits": true, "byte_test": true, "byte_jump": true, "byte_extract": true, "byte_math": true,
	"isdataat": true, "dsize": true, "base64_decode": true, "base64_data": true, "lua": true, "luajit": true,
	"http.stat_code": true, "http.stat_msg": true, "http.response_body": true, "http.server": true,
	"http.response_line": true, "http.location": true, "http.response_header": true, "http_stat_code": true,
	"http_server_body": true, "http.start": true, "pkt_data": true, "dataset": true, "datarep": true,
	"entropy": true, "transform": true, "dotprefix": true, "header_lowercase": true, "to_uppercase": true, "xor": true,
	"to_sha256": true, "to_md5": true, "pcrexform": true,
	"http_header_names": false,
}

// ignored: no effect on what matches (alerting, documentation, speed).
var ignored = map[string]bool{
	"msg": true, "sid": true, "rev": true, "gid": true, "classtype": true, "reference": true, "metadata": true,
	"priority": true, "target": true, "fast_pattern": true, "threshold": true, "detection_filter": true,
	"noalert": true, "tag": true, "prefilter": true, "app-layer-protocol": false,
}

// Convert turns one HTTP rule into an IR rule and its test requests.
func Convert(r *Rule, version string, ids *irout.IDs) (irout.Rule, []irout.Test, bool, error) {
	if r.SID < MinSID || r.SID > MaxSID {
		return nil, nil, false, ErrSID
	}
	toServer := false
	var conds []irout.Cond
	var parts []samplePart
	cur, curName := buffer{}, ""
	body, loose, sampleOK := false, false, true
	li, pi := -1, -1 // indexes of the condition and sample part content modifiers apply to
	var xf []string  // transforms of the current sticky buffer
	counted := false // the last content became a header count (names are case-insensitive)
	contentsInBuf := map[string]int{}
	for _, o := range r.Opts {
		switch {
		case o.Key == "flow":
			for _, f := range strings.Split(o.Val, ",") {
				switch strings.TrimSpace(f) {
				case "to_server", "from_client":
					toServer = true
				case "to_client", "from_server":
					return nil, nil, false, errors.New("response traffic")
				}
			}
		case ignored[o.Key]:
		case unsupported[o.Key]:
			return nil, nil, false, fmt.Errorf("%s not supported", o.Key)
		case buffers[o.Key] != (buffer{}):
			cur, curName = buffers[o.Key], o.Key
			li, pi, xf = -1, -1, nil
			if cur.decode {
				xf = []string{"url_decode"}
			}
		case transforms[o.Key] != "":
			if curName == "" {
				return nil, nil, false, fmt.Errorf("%s outside a buffer", o.Key)
			}
			xf = append(xf, transforms[o.Key])
			sampleOK = sampleOK && o.Key == "to_lowercase"
		case o.Key == "content" || o.Key == "uricontent":
			b, name := cur, curName
			if o.Key == "uricontent" {
				b, name = buffers["http.uri"], "http.uri"
			}
			if name == "" {
				return nil, nil, false, errors.New("content outside an HTTP buffer (raw stream)")
			}
			neg := strings.HasPrefix(o.Val, "!")
			lit, err := content(strings.TrimPrefix(o.Val, "!"))
			if err != nil {
				return nil, nil, false, err
			}
			t := b.target
			if name == "http.request_header" {
				// "Name: value": the value of that header
				i := strings.Index(lit, ": ")
				if i <= 0 || i+2 >= len(lit) {
					return nil, nil, false, errors.New("http.request_header content is not \"Name: value\"")
				}
				t = irout.Target{Var: "request_headers", Key: lit[:i]}
				lit = lit[i+2:]
			}
			if name == "http.header_names" {
				// "\r\nName\r\n": that header is present (absent, negated)
				n := strings.Trim(lit, "\r\n")
				if n != lit && n != "" && !strings.ContainsAny(n, "\r\n") {
					op := "gt"
					if neg {
						op = "eq"
					}
					conds = append(conds, irout.Cond{Targets: []irout.Target{{Var: "request_headers", Key: n, Count: true}}, Op: op, Value: 0})
					li, pi = -1, -1
					kind := "contains"
					if neg {
						kind = "absent"
					}
					parts = append(parts, samplePart{target: irout.Target{Var: "request_headers", Key: n}, value: "1", kind: kind})
					counted = true
					continue
				}
				if neg || strings.ContainsAny(n, "\r\n") {
					return nil, nil, false, errors.New("header_names content across names")
				}
			}
			if neg && t.Key == "" && (t.Var == "request_headers" || t.Var == "request_headers_names") {
				// per value in the IR, over the whole buffer in Suricata
				loose = true
			}
			counted = false
			body = body || b.body
			c := literalCond(t, lit, neg, b.decode || o.Key == "uricontent")
			switch {
			case o.Key == "content" && len(xf) > 0:
				c.Transforms = append([]string{}, xf...)
			case o.Key == "uricontent":
				c.Transforms = []string{"url_decode"}
			}
			conds = append(conds, c)
			li = len(conds) - 1
			contentsInBuf[name]++
			kind := "contains"
			if contentsInBuf[name] > 1 {
				kind = "follow"
			}
			sv := lit
			if b.decode {
				sv = strings.ReplaceAll(sv, "%", "%25") // decoded once by the rule
			}
			parts = append(parts, samplePart{target: t, value: sv, kind: kind, neg: neg})
			pi = len(parts) - 1
		case o.Key == "nocase" && li < 0 && counted:
		case o.Key == "nocase":
			if li < 0 {
				return nil, nil, false, errors.New("nocase without content")
			}
			setNocase(&conds[li])
		case o.Key == "startswith" || (o.Key == "depth" && pi >= 0 && parts[pi].kind == "contains" && o.Val == strconv.Itoa(len(parts[pi].value))):
			if li < 0 {
				return nil, nil, false, errors.New("startswith without content")
			}
			anchor(&conds[li], "^")
			parts[pi].kind = "prefix"
		case o.Key == "endswith":
			if li < 0 {
				return nil, nil, false, errors.New("endswith without content")
			}
			anchor(&conds[li], "$")
			parts[pi].kind = "suffix"
		case o.Key == "bsize" && li < 0:
			// the size of the buffer itself
			if curName == "" || curName == "http.request_header" {
				return nil, nil, false, errors.New("bsize without a buffer")
			}
			c, err := lengthCond(cur.target, o.Val)
			if err != nil {
				return nil, nil, false, err
			}
			c.Transforms = append(append([]string{}, xf...), "length")
			conds = append(conds, c)
			sampleOK = false
		case o.Key == "bsize":
			if n, err := strconv.Atoi(o.Val); err == nil && n == len(parts[pi].value) && parts[pi].kind != "follow" {
				anchor(&conds[li], "^")
				anchor(&conds[li], "$")
				parts[pi].kind = "exact"
				continue
			}
			c, err := lengthCond(conds[li].Targets[0], o.Val)
			if err != nil {
				return nil, nil, false, err
			}
			conds = append(conds, c)
			sampleOK = false
		case o.Key == "urilen":
			c, err := lengthCond(irout.Target{Var: "uri_raw"}, o.Val)
			c.Transforms = []string{"url_decode", "length"}
			if err != nil {
				return nil, nil, false, err
			}
			conds = append(conds, c)
			li, pi = -1, -1
			sampleOK = false
		case o.Key == "distance" || o.Key == "within" || o.Key == "offset" || o.Key == "depth":
			loose = true
		case o.Key == "pcre":
			c, b, err := pcre(o.Val, cur, curName)
			if err != nil {
				return nil, nil, false, err
			}
			body = body || b.body
			conds = append(conds, c)
			li, pi = -1, -1
			sampleOK = false
		default:
			return nil, nil, false, fmt.Errorf("%s not supported", o.Key)
		}
	}
	if !toServer {
		return nil, nil, false, errors.New("no to_server flow")
	}
	if len(conds) == 0 {
		return nil, nil, false, errors.New("no content")
	}
	if len(conds) > irout.MaxConds {
		return nil, nil, false, fmt.Errorf("more than %d conditions: %d", irout.MaxConds, len(conds))
	}
	positive := false
	for _, c := range conds {
		positive = positive || !c.Negate
	}
	if !positive {
		return nil, nil, false, errors.New("only negated contents")
	}
	id, err := ids.Get(strconv.Itoa(r.SID))
	if err != nil {
		return nil, nil, false, err
	}
	score, sev := severity(r.Meta)
	stage := "request_headers"
	if body {
		stage = "request_body"
	}
	meta := map[string]any{"source": "et-open", "upstream_id": strconv.Itoa(r.SID), "upstream_version": version,
		"license": "BSD-3-Clause", "author": "Proofpoint Emerging Threats", "attack_type": attackType(r)}
	if tags := r.Meta["tag"]; len(tags) > 0 {
		meta["tags"] = uniqLower(tags)
	}
	name := strings.TrimSpace(r.Msg)
	if name == "" {
		name = "ET " + strconv.Itoa(r.SID)
	}
	rule := irout.Rule{"id": id, "name": name, "layer": "managed", "stage": stage,
		"match": irout.Match(conds, true), "score": score, "severity": sev, "metadata": meta}
	tests := []irout.Test{irout.NoMatch(id)}
	if sampleOK {
		if req, ok := sample(parts); ok {
			tests = append(tests, irout.Test{Rule: id, Name: fmt.Sprintf("%d-generated", id), Expect: "match", Generated: true, Request: req})
		}
	}
	return rule, tests, loose, nil
}

// content decodes a content value: quoted, with |hex| blocks and \ escapes.
func content(v string) (string, error) {
	v = unquote(v)
	var b strings.Builder
	for i := 0; i < len(v); i++ {
		switch c := v[i]; c {
		case '\\':
			if i+1 < len(v) {
				i++
				b.WriteByte(v[i])
			}
		case '|':
			j := strings.IndexByte(v[i+1:], '|')
			if j < 0 {
				return "", errors.New("unterminated hex block")
			}
			for _, h := range strings.Fields(v[i+1 : i+1+j]) {
				for len(h) >= 2 {
					n, err := strconv.ParseUint(h[:2], 16, 8)
					if err != nil {
						return "", fmt.Errorf("bad hex %q", h)
					}
					b.WriteByte(byte(n))
					h = h[2:]
				}
				if h != "" {
					return "", fmt.Errorf("odd hex %q", h)
				}
			}
			i += j + 1
		default:
			b.WriteByte(c)
		}
	}
	if b.Len() == 0 {
		return "", errors.New("empty content")
	}
	return b.String(), nil
}

// literalCond: contains when the bytes are printable, else a regex. On a
// URL-decoded buffer, + is also a space (url_decode turns + into a space,
// Suricata's URI normalization keeps it).
func literalCond(t irout.Target, lit string, neg bool, decoded bool) irout.Cond {
	c := irout.Cond{Targets: []irout.Target{t}, Negate: neg}
	if decoded && strings.Contains(lit, "+") {
		c.Op, c.Value = "rx", strings.ReplaceAll(irout.Literal(lit), `\+`, "[+ ]")
		return c
	}
	if irout.Printable(lit) {
		c.Op, c.Value = "contains", lit
	} else {
		c.Op, c.Value = "rx", irout.Literal(lit)
	}
	return c
}

// setNocase: case-insensitive, by lowercasing both sides.
func setNocase(c *irout.Cond) {
	c.Transforms = append(c.Transforms, "lowercase")
	switch v := c.Value.(type) {
	case string:
		if c.Op == "rx" {
			c.Value = lowerRegexLiteral(v)
		} else {
			c.Value = strings.ToLower(v)
		}
	}
}

// lowerRegexLiteral lowercases a regex made by irout.Literal (letters
// only; \xHH escapes keep their case-insensitive hex).
func lowerRegexLiteral(p string) string { return strings.ToLower(p) }

// anchor turns a contains into begins_with / ends_with / streq, or anchors
// its regex.
func anchor(c *irout.Cond, a string) {
	switch c.Op {
	case "contains":
		if a == "^" {
			c.Op = "begins_with"
		} else {
			c.Op = "ends_with"
		}
	case "begins_with":
		if a == "$" {
			c.Op = "streq"
		}
	case "ends_with":
		if a == "^" {
			c.Op = "streq"
		}
	case "rx":
		p := c.Value.(string)
		if a == "^" && !strings.HasPrefix(p, "^") {
			p = "^" + p
		}
		if a == "$" && !strings.HasSuffix(p, "$") {
			p += "$"
		}
		c.Value = p
	}
}

var sizeRe = regexp.MustCompile(`^\s*(<|>|<=|>=)?\s*(\d+)\s*(?:<>\s*(\d+))?\s*$`)

// lengthCond: bsize / urilen as a length condition.
func lengthCond(t irout.Target, v string) (irout.Cond, error) {
	m := sizeRe.FindStringSubmatch(v)
	if m == nil || m[3] != "" {
		return irout.Cond{}, fmt.Errorf("size %q not supported", v)
	}
	n, _ := strconv.Atoi(m[2])
	op := map[string]string{"": "eq", "<": "lt", ">": "gt", "<=": "le", ">=": "ge"}[m[1]]
	return irout.Cond{Targets: []irout.Target{t}, Transforms: []string{"length"}, Op: op, Value: n}, nil
}

var pcreRe = regexp.MustCompile(`^"?(!?)/(.*)/([A-Za-z]*)"?$`)

// pcre converts a pcre option; Perl-only constructs (lookaround,
// backreferences, possessive quantifiers) are not RE2 and refused.
func pcre(v string, cur buffer, curName string) (irout.Cond, buffer, error) {
	m := pcreRe.FindStringSubmatch(strings.TrimSpace(v))
	if m == nil {
		return irout.Cond{}, cur, fmt.Errorf("pcre not understood: %s", v)
	}
	neg, pat, flags := m[1] == "!", m[2], m[3]
	b, name := cur, curName
	var inline string
	for i := 0; i < len(flags); i++ {
		f := flags[i]
		switch {
		case f == 'i' || f == 's' || f == 'm':
			inline += string(f)
		case f == 'R' || f == 'O' || f == 'G' || f == 'B':
			// relative to the previous match, override, raw: dropped
		case pcreBuffers[f] != "":
			b, name = buffers[pcreBuffers[f]], pcreBuffers[f]
		default:
			return irout.Cond{}, cur, fmt.Errorf("pcre flag %c not supported", f)
		}
	}
	if name == "" {
		return irout.Cond{}, cur, errors.New("pcre outside an HTTP buffer (raw stream)")
	}
	if inline != "" {
		pat = "(?" + inline + ")" + pat
	}
	if !irout.RE2(pat) {
		return irout.Cond{}, cur, fmt.Errorf("pcre is not RE2: /%s/", m[2])
	}
	c := irout.Cond{Targets: []irout.Target{b.target}, Op: "rx", Value: pat, Negate: neg}
	if b.decode {
		c.Transforms = []string{"url_decode"}
	}
	return c, b, nil
}

// severity: signature_severity, lowered by confidence. One ET rule alone
// does not block (at most 80 of the 100 threshold): ET signatures match
// loosely here (positional modifiers dropped), so they add to the score.
func severity(meta map[string][]string) (int, string) {
	sev := "Major"
	if s := meta["signature_severity"]; len(s) > 0 {
		sev = s[0]
	}
	score, name := 60, "error"
	switch sev {
	case "Critical":
		score, name = 80, "critical"
	case "Minor":
		score, name = 30, "warning"
	case "Informational":
		score, name = 10, "notice"
	}
	if c := meta["confidence"]; len(c) > 0 && c[0] == "Low" {
		score /= 2
	}
	return score, name
}

func attackType(r *Rule) string {
	s := strings.ToLower(r.Msg + " " + strings.Join(r.Meta["tag"], " "))
	for _, c := range []struct{ word, typ string }{
		{"sql", "sql-injection"}, {"xss", "xss"}, {"cross site", "xss"}, {"traversal", "path-traversal"},
		{"file inclusion", "file-inclusion"}, {"rfi", "file-inclusion"}, {"lfi", "file-inclusion"},
		{"command injection", "command-injection"}, {"command execution", "rce"}, {"code execution", "rce"},
		{"rce", "rce"}, {"webshell", "rce"}, {"scan", "scanner"}, {"xxe", "xxe"}, {"ssrf", "ssrf"},
	} {
		if strings.Contains(s, c.word) {
			return c.typ
		}
	}
	return "other"
}

func uniqLower(s []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, x := range s {
		x = strings.ToLower(strings.ReplaceAll(x, " ", "_"))
		if !seen[x] {
			seen[x] = true
			out = append(out, x)
		}
	}
	sort.Strings(out)
	return out
}

type samplePart struct {
	target irout.Target
	value  string
	kind   string // contains, follow (after the previous content), prefix, suffix, exact
	neg    bool
}

// sample builds a request holding the contents in order, or false.
func sample(parts []samplePart) (map[string]any, bool) {
	type acc struct {
		prefix, suffix string
		mid            []string
		exact          *string
	}
	byT := map[irout.Target]*acc{}
	var order []irout.Target
	need := map[string]bool{} // headers a negated content looks at: present, without it
	absent := map[string]bool{}
	for _, p := range parts {
		if p.kind == "absent" {
			absent[strings.ToLower(p.target.Key)] = true
			continue
		}
		if p.neg {
			if p.target.Var == "request_headers" && p.target.Key != "" {
				need[p.target.Key] = true
			}
			continue
		}
		if p.target.Var == "uri_raw" {
			p.target.Var = "uri" // one request target: raw and normalized contents in order
		}
		if !irout.Printable(p.value) && p.target.Var != "request_body" {
			return nil, false
		}
		a := byT[p.target]
		if a == nil {
			a = &acc{}
			byT[p.target] = a
			order = append(order, p.target)
		}
		switch p.kind {
		case "prefix":
			if a.prefix != "" || len(a.mid) > 0 {
				return nil, false
			}
			a.prefix = p.value
		case "suffix":
			a.suffix = p.value
		case "exact":
			v := p.value
			a.exact = &v
		default:
			a.mid = append(a.mid, p.value)
		}
	}
	req := map[string]any{"method": "GET", "uri": "/"}
	headers := map[string]any{"Host": "api.example.test", "User-Agent": irout.BenignUA}
	methodSet := false
	for _, t := range order {
		a := byT[t]
		val := a.prefix + strings.Join(a.mid, "") + a.suffix
		if a.exact != nil {
			if val != "" && val != *a.exact {
				return nil, false
			}
			val = *a.exact
		}
		switch t.Var {
		case "method":
			req["method"], methodSet = val, true
		case "uri", "uri_raw":
			if !strings.HasPrefix(val, "/") {
				val = "/" + val
			}
			req["uri"] = val
		case "request_body":
			req["body"] = val
			if !methodSet {
				req["method"] = "POST"
			}
			if _, ok := headers["Content-Type"]; !ok {
				headers["Content-Type"] = "application/x-www-form-urlencoded"
			}
		case "request_headers":
			if t.Key == "" {
				headers["X-Sample"] = val
			} else {
				headers[t.Key] = val
			}
		case "request_headers_names":
			headers[val] = "1"
		case "protocol":
			req["protocol"] = val
		default:
			return nil, false
		}
	}
	for k := range need {
		if _, ok := headers[k]; !ok {
			headers[k] = "sample"
		}
	}
	for k := range headers {
		if absent[strings.ToLower(k)] {
			delete(headers, k)
		}
	}
	if b, ok := req["body"].(string); ok && !irout.Printable(b) {
		return nil, false // the test format holds text
	}
	u, _ := req["uri"].(string)
	if strings.ContainsAny(u, " \"<>\\^`{|}") || !irout.Printable(u) {
		return nil, false
	}
	req["headers"] = headers
	return req, true
}
