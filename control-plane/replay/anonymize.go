// Package replay holds the traffic samples replay runs again through the
// engine (W11-G2-01): the anonymization of a request, the Parquet format
// and their place in object storage. Specification:
// docs/spec/replay-sample.md (format 1); test vectors:
// docs/spec/examples/replay-anon-v1.json.
//
// Only sensitive values are replaced by keyed hashes (PO decision
// 14/10/2026): the structure of the request and the ordinary values stay,
// so that content rules still run on replay.
package replay

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"mime"
	"mime/multipart"
	"net/textproto"
	"net/url"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

// Request is one request as the sampler saw it (not anonymized).
type Request struct {
	TsMs    int64
	NodeID  string
	Policy  string
	Method  string
	RawURI  string // as sent: path and query
	URI     string // normalized path
	Args    string // query string
	Proto   string
	Client  string
	Headers [][2]string // in arrival order
	Body    []byte
	Action  string   // verdict when sampled
	Rules   []uint32 // rules matched when sampled
}

// Record is one row of a sample file (docs/spec/replay-sample.md › File).
type Record struct {
	TsMs          int64  `parquet:"ts_ms" json:"ts_ms"`
	NodeID        string `parquet:"node_id" json:"node_id"`
	Policy        string `parquet:"policy" json:"policy"`
	Method        string `parquet:"method" json:"method"`
	RawURI        string `parquet:"raw_uri" json:"raw_uri"`
	URI           string `parquet:"uri" json:"uri"`
	Args          string `parquet:"args" json:"args"`
	Proto         string `parquet:"proto" json:"proto"`
	Client        string `parquet:"client" json:"client"`
	Headers       string `parquet:"headers" json:"headers"` // JSON [[name, value], ...]
	Body          []byte `parquet:"body" json:"body"`
	BodyLen       int64  `parquet:"body_len" json:"body_len"`
	BodyTruncated bool   `parquet:"body_truncated" json:"body_truncated"`
	Action        string `parquet:"action" json:"action"`
	Rules         string `parquet:"rules" json:"rules"`
}

// DefaultMaxBody is the body kept per request.
const DefaultMaxBody = 64 << 10

// Anonymizer replaces sensitive values with keyed hashes.
type Anonymizer struct {
	Key     []byte // 32 random bytes, kept by the control plane only
	KeyID   string
	MaxBody int // 0: DefaultMaxBody
}

// NewAnonymizer checks the key.
func NewAnonymizer(key []byte, keyID string) (*Anonymizer, error) {
	if len(key) < 32 {
		return nil, fmt.Errorf("replay: anonymization key is %d bytes, want at least 32", len(key))
	}
	if keyID == "" {
		return nil, fmt.Errorf("replay: anonymization key needs an id")
	}
	return &Anonymizer{Key: key, KeyID: keyID}, nil
}

// Token of a sensitive value: ~h:<16 hex>:<class><length>.
func (a *Anonymizer) Token(v string) string {
	m := hmac.New(sha256.New, a.Key)
	m.Write([]byte(v))
	return "~h:" + hex.EncodeToString(m.Sum(nil)[:8]) + ":" + class(v) + strconv.Itoa(len(v))
}

func class(v string) string {
	digits, letters, other := 0, 0, 0
	for i := 0; i < len(v); i++ {
		c := v[i]
		switch {
		case c >= '0' && c <= '9':
			digits++
		case (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z'):
			letters++
		default:
			other++
		}
	}
	switch {
	case other > 0 || len(v) == 0:
		return "s"
	case letters == 0:
		return "d"
	case digits == 0:
		return "a"
	}
	return "x"
}

var sensitiveHeaders = map[string]bool{
	"authorization": true, "proxy-authorization": true, "cookie": true, "set-cookie": true,
	"x-api-key": true, "x-auth-token": true, "x-csrf-token": true, "x-xsrf-token": true,
	"x-forwarded-for": true, "x-real-ip": true, "forwarded": true, "true-client-ip": true,
	"cf-connecting-ip": true,
}

var sensitiveNameParts = []string{
	"password", "passwd", "pwd", "secret", "token", "otp", "pin", "cvv", "card", "cccd", "cmnd",
	"ssn", "passport", "apikey", "api_key", "auth", "session", "phone", "mobile", "email", "dob",
	"birth", "name", "user", "address", "account", "iban",
}

// SensitiveName reports whether a parameter, JSON key or form field named
// name holds a sensitive value.
func SensitiveName(name string) bool {
	n := strings.ToLower(name)
	for _, p := range sensitiveNameParts {
		if strings.Contains(n, p) {
			return true
		}
	}
	return false
}

var (
	reJWT    = regexp.MustCompile(`eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*`)
	reEmail  = regexp.MustCompile(`[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}`)
	reDigits = regexp.MustCompile(`\+?[0-9](?:[0-9 -]*[0-9])?`)
	rePhone  = regexp.MustCompile(`^(?:\+84|84|0)[35789][0-9]{8}$`)
)

type span struct{ start, end int }

// MaskValue replaces the parts of s that look like personal data (JWT,
// email, Vietnamese phone number, CCCD, card number) with tokens; the rest
// of s stays.
func (a *Anonymizer) MaskValue(s string) string {
	var spans []span
	for _, re := range []*regexp.Regexp{reJWT, reEmail} {
		for _, m := range re.FindAllStringIndex(s, -1) {
			spans = append(spans, span{m[0], m[1]})
		}
	}
	for _, m := range reDigits.FindAllStringIndex(s, -1) {
		spans = append(spans, digitSpans(s, m[0], m[1])...)
	}
	if len(spans) == 0 {
		return s
	}
	// earliest first, the longest at one position; drop overlaps
	sort.Slice(spans, func(i, j int) bool {
		if spans[i].start != spans[j].start {
			return spans[i].start < spans[j].start
		}
		return spans[i].end > spans[j].end
	})
	var b strings.Builder
	at := 0
	for _, sp := range spans {
		if sp.start < at {
			continue
		}
		b.WriteString(s[at:sp.start])
		b.WriteString(a.Token(s[sp.start:sp.end]))
		at = sp.end
	}
	b.WriteString(s[at:])
	return b.String()
}

// digitSpans: the personal numbers in the digit run s[start:end] (which
// may hold spaces and dashes): the whole run when it is a card number,
// else each separated group that is a phone, CCCD or card number. A run
// is maximal, so no group touches another digit.
func digitSpans(s string, start, end int) []span {
	run := s[start:end]
	digits := strings.NewReplacer(" ", "", "-", "", "+", "").Replace(run)
	if strings.ContainsAny(run, " -") && !strings.HasPrefix(run, "+") && card(digits) {
		return []span{{start, end}}
	}
	var out []span
	i := start
	for i < end {
		j := i
		for j < end && s[j] != ' ' && s[j] != '-' {
			j++
		}
		g := s[i:j]
		d := strings.TrimPrefix(g, "+")
		allDigits := d != "" && strings.Trim(d, "0123456789") == ""
		if allDigits && (rePhone.MatchString(g) || (g == d && (len(d) == 12 || card(d)))) {
			out = append(out, span{i, j})
		}
		i = j + 1
	}
	return out
}

// card: 13 to 19 digits passing the Luhn check.
func card(d string) bool {
	if len(d) < 13 || len(d) > 19 {
		return false
	}
	sum := 0
	for i := 0; i < len(d); i++ {
		c := d[len(d)-1-i]
		if c < '0' || c > '9' {
			return false
		}
		n := int(c - '0')
		if i%2 == 1 {
			n *= 2
			if n > 9 {
				n -= 9
			}
		}
		sum += n
	}
	return sum%10 == 0
}

// Anonymize turns a request into a sample record.
func (a *Anonymizer) Anonymize(r Request) Record {
	max := a.MaxBody
	if max <= 0 {
		max = DefaultMaxBody
	}
	body, truncated := r.Body, false
	if len(body) > max {
		body, truncated = body[:max], true
	}
	ct := header(r.Headers, "content-type")
	anonBody := a.body(ct, body)

	headers := make([][2]string, 0, len(r.Headers))
	for _, h := range r.Headers {
		name, value := h[0], h[1]
		if strings.EqualFold(name, "content-length") && !truncated && len(r.Body) > 0 {
			// the body changed length: keep the header true to it
			value = strconv.Itoa(len(anonBody))
		} else {
			value = a.headerValue(name, value)
		}
		headers = append(headers, [2]string{name, value})
	}
	hj, _ := json.Marshal(headers) // [][2]string always marshals

	rules := make([]string, len(r.Rules))
	for i, id := range r.Rules {
		rules[i] = strconv.FormatUint(uint64(id), 10)
	}
	path, query, hasQuery := strings.Cut(r.RawURI, "?")
	raw := a.path(path)
	if hasQuery {
		raw += "?" + a.query(query)
	}
	return Record{
		TsMs: r.TsMs, NodeID: r.NodeID, Policy: r.Policy, Method: r.Method,
		RawURI: raw, URI: a.MaskValue(r.URI), Args: a.query(r.Args), Proto: r.Proto,
		Client: a.Token(r.Client), Headers: string(hj),
		Body: anonBody, BodyLen: int64(len(r.Body)), BodyTruncated: truncated,
		Action: r.Action, Rules: strings.Join(rules, ","),
	}
}

func header(hs [][2]string, name string) string {
	for _, h := range hs {
		if strings.EqualFold(h[0], name) {
			return h[1]
		}
	}
	return ""
}

func (a *Anonymizer) headerValue(name, value string) string {
	n := strings.ToLower(name)
	if !sensitiveHeaders[n] {
		return a.MaskValue(value)
	}
	switch n {
	case "authorization", "proxy-authorization":
		if scheme, cred, ok := strings.Cut(value, " "); ok && scheme != "" && !strings.ContainsAny(scheme, "=:") {
			return scheme + " " + a.Token(cred)
		}
	case "cookie":
		parts := strings.Split(value, ";")
		for i, p := range parts {
			k, v, ok := strings.Cut(p, "=")
			if ok {
				parts[i] = k + "=" + a.Token(v)
			} else {
				parts[i] = a.Token(p)
			}
		}
		return strings.Join(parts, ";")
	}
	return a.Token(value)
}

// path: each segment, decoded for the check, written back as it came
// unless a value was replaced.
func (a *Anonymizer) path(p string) string {
	segs := strings.Split(p, "/")
	for i, s := range segs {
		segs[i] = a.encoded(s, false, url.PathUnescape, url.PathEscape)
	}
	return strings.Join(segs, "/")
}

// query: name=value pairs split on '&', names kept.
func (a *Anonymizer) query(q string) string {
	if q == "" {
		return q
	}
	pairs := strings.Split(q, "&")
	for i, p := range pairs {
		k, v, ok := strings.Cut(p, "=")
		name, err := url.QueryUnescape(k)
		if err != nil {
			name = k
		}
		if !ok {
			pairs[i] = a.encoded(k, false, url.QueryUnescape, url.QueryEscape)
			continue
		}
		pairs[i] = k + "=" + a.encoded(v, SensitiveName(name), url.QueryUnescape, url.QueryEscape)
	}
	return strings.Join(pairs, "&")
}

// encoded anonymizes a percent-encoded value. The raw text is kept unless
// it changes, so that encodings (double encoding, odd escapes) still reach
// the engine on replay.
func (a *Anonymizer) encoded(raw string, sensitive bool, unescape func(string) (string, error), escape func(string) string) string {
	if raw == "" {
		return raw
	}
	dec, err := unescape(raw)
	if err != nil {
		dec = raw
	}
	if sensitive {
		return escape(a.Token(dec))
	}
	if m := a.MaskValue(dec); m != dec {
		return escape(m)
	}
	return raw
}

func (a *Anonymizer) body(ct string, b []byte) []byte {
	if len(b) == 0 {
		return b
	}
	mt, params, _ := mime.ParseMediaType(ct)
	switch {
	case mt == "application/x-www-form-urlencoded":
		return []byte(a.query(string(b)))
	case mt == "application/json" || strings.HasSuffix(mt, "+json"):
		if out, err := a.json(b); err == nil {
			return out
		}
	case mt == "multipart/form-data" && params["boundary"] != "":
		if out, err := a.multipart(b, params["boundary"]); err == nil {
			return out
		}
	}
	return []byte(a.MaskValue(string(b)))
}

// json rewrites a JSON document compactly, keys in their order.
func (a *Anonymizer) json(b []byte) ([]byte, error) {
	d := json.NewDecoder(bytes.NewReader(b))
	d.UseNumber()
	var out bytes.Buffer
	if err := a.jsonValue(d, &out, false, 0); err != nil {
		return nil, err
	}
	if _, err := d.Token(); err != io.EOF {
		return nil, fmt.Errorf("replay: trailing data after the JSON document")
	}
	return out.Bytes(), nil
}

const maxJSONDepth = 64

func (a *Anonymizer) jsonValue(d *json.Decoder, out *bytes.Buffer, sensitive bool, depth int) error {
	if depth > maxJSONDepth {
		return fmt.Errorf("replay: JSON nested deeper than %d", maxJSONDepth)
	}
	t, err := d.Token()
	if err != nil {
		return err
	}
	switch v := t.(type) {
	case json.Delim:
		switch v {
		case '{':
			out.WriteByte('{')
			for i := 0; d.More(); i++ {
				kt, err := d.Token()
				if err != nil {
					return err
				}
				k, _ := kt.(string)
				if i > 0 {
					out.WriteByte(',')
				}
				writeJSONString(out, k)
				out.WriteByte(':')
				if err := a.jsonValue(d, out, sensitive || SensitiveName(k), depth+1); err != nil {
					return err
				}
			}
			out.WriteByte('}')
		case '[':
			out.WriteByte('[')
			for i := 0; d.More(); i++ {
				if i > 0 {
					out.WriteByte(',')
				}
				if err := a.jsonValue(d, out, sensitive, depth+1); err != nil {
					return err
				}
			}
			out.WriteByte(']')
		}
		_, err := d.Token() // the closing delimiter
		return err
	case string:
		if sensitive {
			writeJSONString(out, a.Token(v))
		} else {
			writeJSONString(out, a.MaskValue(v))
		}
	case json.Number:
		switch m := a.MaskValue(v.String()); {
		case sensitive:
			writeJSONString(out, a.Token(v.String()))
		case m != v.String():
			writeJSONString(out, m)
		default:
			out.WriteString(v.String())
		}
	case bool:
		out.WriteString(strconv.FormatBool(v))
	case nil:
		out.WriteString("null")
	}
	return nil
}

func writeJSONString(out *bytes.Buffer, s string) {
	e := json.NewEncoder(out)
	e.SetEscapeHTML(false)
	_ = e.Encode(s) // a string always encodes
	out.Truncate(out.Len() - 1)
}

// multipart rewrites the parts: headers kept (in a stable order), text
// fields anonymized, file contents always a token.
func (a *Anonymizer) multipart(b []byte, boundary string) ([]byte, error) {
	r := multipart.NewReader(bytes.NewReader(b), boundary)
	var out bytes.Buffer
	for {
		p, err := r.NextRawPart()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, err
		}
		content, err := io.ReadAll(p)
		if err != nil {
			return nil, err
		}
		fmt.Fprintf(&out, "--%s\r\n", boundary)
		writePartHeader(&out, p.Header)
		out.WriteString("\r\n")
		switch {
		case p.FileName() != "":
			out.WriteString(a.Token(string(content)))
		case SensitiveName(p.FormName()):
			out.WriteString(a.Token(string(content)))
		default:
			out.WriteString(a.MaskValue(string(content)))
		}
		out.WriteString("\r\n")
	}
	fmt.Fprintf(&out, "--%s--\r\n", boundary)
	return out.Bytes(), nil
}

func writePartHeader(out *bytes.Buffer, h textproto.MIMEHeader) {
	keys := make([]string, 0, len(h))
	for k := range h {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		for _, v := range h[k] {
			fmt.Fprintf(out, "%s: %s\r\n", k, v)
		}
	}
}
