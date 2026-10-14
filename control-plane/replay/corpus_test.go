package replay

import (
	"bytes"
	"encoding/json"
	"fmt"
	"math/rand"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// W12-N-01: libstrata anonymizes samples at the connector and must give the
// records this writer gives. Besides the vectors of the specification, a
// corpus of generated requests (fixed seed) is shared with libstrata's
// tests: URL escapes, cookies, JSON with escapes and surrogates, multipart
// with odd headers and line endings, media type parameters, invalid UTF-8.
// Regenerate with: go test ./replay -run TestDifferentialCorpus -update

const corpusSize = 400

var corpusPieces = struct {
	text, names, values, cts []string
}{
	text: []string{"plain", "0912345678", "+84912345678", "84 912 345 678", "001099012345", "0010990123456",
		"4111 1111 1111 1111", "4111-1111-1111-1111", "4111111111111112", "alice@example.test", "a.b+c@sub.example.test",
		"eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.c2ln", "' OR 1=1--", "<script>alert(1)</script>", "../../etc/passwd",
		"%2e%2e%2f", "%253Cscript%253E", "100%", "%zz", "a+b c", "Nguyễn Văn A", "\xff\xfe", "x\u2028y", "\t\r\n",
		"İnstance", "teK", "1760000000000", "-", " ", "", "tab\tsep", "quote\"back\\slash", "&amp;", "=", "?", "/",
	},
	names: []string{"q", "id", "user", "Password", "access_token", "full_name", "phoneNumber", "page", "filename",
		"Pİn", "note", "data", "email_address", "x", "", "a%20b", "pass+word", "sessionId"},
	cts: []string{"application/json", "application/x-www-form-urlencoded", "text/plain", "application/problem+json",
		"multipart/form-data; boundary=XyZ", "multipart/form-data; boundary=\"q b\"", "multipart/form-data", "Application/JSON; charset=utf-8",
		"application/json;;", "application/json; a=1; a=2", "multipart/form-data; boundary=XyZ; boundary*=utf-8''XyZ",
		"bad type/", "", "application/xml"},
}

func pick(r *rand.Rand, s []string) string { return s[r.Intn(len(s))] }

func genText(r *rand.Rand) string {
	n := 1 + r.Intn(3)
	parts := make([]string, n)
	for i := range parts {
		parts[i] = pick(r, corpusPieces.text)
	}
	return strings.Join(parts, pick(r, []string{" ", "", ",", ";", "-", "/"}))
}

func genQuery(r *rand.Rand) string {
	n := r.Intn(4)
	var ps []string
	for i := 0; i < n; i++ {
		v := genText(r)
		if r.Intn(2) == 0 {
			v = strings.NewReplacer(" ", "+", "&", "%26", "#", "%23").Replace(v)
		}
		switch r.Intn(5) {
		case 0:
			ps = append(ps, pick(r, corpusPieces.names))
		default:
			ps = append(ps, pick(r, corpusPieces.names)+"="+v)
		}
	}
	return strings.Join(ps, "&")
}

func genJSON(r *rand.Rand, depth int) string {
	switch k := r.Intn(9); {
	case depth > 3 || k < 3:
		switch r.Intn(7) {
		case 0:
			return pick(r, []string{"0", "-1.5e3", "42", "1760000000000", "0.5", "4111111111111111", "84912345678"})
		case 1:
			return pick(r, []string{"true", "false", "null"})
		case 2:
			return `"` + pick(r, []string{`\u00e9`, `\ud83d\ude00`, `\ud800`, `\udc00x`, `\n\t\"\\\/`, `\u2028`}) + `"`
		default:
			b, _ := json.Marshal(genText(r))
			return string(b)
		}
	case k < 6:
		n := r.Intn(4)
		var es []string
		for i := 0; i < n; i++ {
			es = append(es, genJSON(r, depth+1))
		}
		return "[" + strings.Join(es, pick(r, []string{",", ", ", " ,\n"})) + "]"
	default:
		n := r.Intn(4)
		var es []string
		for i := 0; i < n; i++ {
			k, _ := json.Marshal(pick(r, corpusPieces.names))
			es = append(es, string(k)+pick(r, []string{":", " : "})+genJSON(r, depth+1))
		}
		return "{" + strings.Join(es, ",") + "}"
	}
}

func genMultipart(r *rand.Rand, boundary string) string {
	nl := "\r\n"
	if r.Intn(5) == 0 {
		nl = "\n"
	}
	var b strings.Builder
	if r.Intn(4) == 0 {
		b.WriteString("preamble" + nl)
	}
	for i, n := 0, 1+r.Intn(3); i < n; i++ {
		b.WriteString("--" + boundary + pick(r, []string{"", " ", "\t"}) + nl)
		disp := pick(r, []string{
			`form-data; name="` + pick(r, corpusPieces.names) + `"`,
			`form-data; name="doc"; filename="id card.jpg"`,
			`form-data; name="f"; filename*=utf-8''%E1%BA%A3nh.png`,
			`attachment; name="password"`,
			`form-data; name=note`,
			`form-data; name="a"; name="b"`,
			`form-data; name="x"; filename=""`,
		})
		b.WriteString(pick(r, []string{"Content-Disposition", "content-disposition", "CONTENT-DISPOSITION"}) + ": " + disp + nl)
		if r.Intn(3) == 0 {
			b.WriteString("Content-Type: " + pick(r, []string{"text/plain", "image/jpeg"}) + nl)
		}
		if r.Intn(6) == 0 {
			b.WriteString("X-Note: first" + nl + "  folded" + nl)
		}
		b.WriteString(nl)
		b.WriteString(genText(r))
		if r.Intn(6) == 0 {
			b.WriteString(nl + "--" + boundary + "x not a boundary")
		}
		b.WriteString(nl)
	}
	switch r.Intn(6) {
	case 0: // no final boundary
	case 1:
		b.WriteString("--" + boundary + "--")
	default:
		b.WriteString("--" + boundary + "--" + nl)
	}
	return b.String()
}

func genRequest(r *rand.Rand, i int) Request {
	path := "/" + strings.Join([]string{pick(r, []string{"v1", "api", "a%2Fb", "%E1%BA%A3", "x;y", "user"}), escapeSegment(genText(r))}, "/")
	q := genQuery(r)
	raw := path
	if q != "" || r.Intn(3) == 0 {
		raw += "?" + q
	}
	ct := pick(r, corpusPieces.cts)
	var body string
	switch {
	case strings.Contains(strings.ToLower(ct), "json"):
		body = genJSON(r, 0)
		if r.Intn(8) == 0 {
			body = body[:len(body)/2] // broken
		}
	case strings.HasPrefix(ct, "multipart"):
		bd := "XyZ"
		if strings.Contains(ct, `"q b"`) {
			bd = "q b"
		}
		body = genMultipart(r, bd)
	case strings.Contains(ct, "urlencoded"):
		body = genQuery(r)
	default:
		if r.Intn(2) == 0 {
			body = genText(r)
		}
	}
	hs := [][2]string{{"Host", "api.example.test"}}
	if ct != "" {
		hs = append(hs, [2]string{pick(r, []string{"Content-Type", "content-type"}), ct})
	}
	for _, h := range []string{"Authorization", "Cookie", "X-Forwarded-For", "User-Agent", "Referer", "COOKIE", "X-Api-Key"} {
		if r.Intn(3) == 0 {
			v := genText(r)
			switch h {
			case "Authorization":
				v = pick(r, []string{"Bearer ", "Basic ", "", "a=b ", ":x "}) + v
			case "Cookie", "COOKIE":
				v = "sid=" + v + "; theme=dark;flag"
			}
			hs = append(hs, [2]string{h, v})
		}
	}
	if body != "" {
		hs = append(hs, [2]string{"Content-Length", fmt.Sprint(len(body))})
	}
	return Request{TsMs: 1791939600000 + int64(i), NodeID: "edge-01", Policy: "example-api",
		Method: pick(r, []string{"GET", "POST", "PUT"}), RawURI: raw, URI: path, Args: q, Proto: "HTTP/1.1",
		Client: pick(r, []string{"198.51.100.7", "2001:db8::7"}), Headers: hs, Body: []byte(body),
		Action: pick(r, []string{"allow", "log", "block"}), Rules: []uint32{uint32(r.Intn(3)) * 941100}}
}

// escapeSegment: a path segment as a client might send it, some bytes escaped
func escapeSegment(s string) string {
	return strings.NewReplacer(" ", "%20", "?", "%3F", "#", "%23", "/", "%2F").Replace(s)
}

// corpusCase: every field as bytes (base64 in JSON), so that invalid
// UTF-8 survives the file.
type corpusCase struct {
	TsMs    int64       `json:"ts_ms"`
	In      [][]byte    `json:"in"` // node, policy, method, raw_uri, uri, args, proto, client, body, action
	Headers [][2][]byte `json:"headers"`
	Rules   []uint32    `json:"rules"`
	Out     [][]byte    `json:"out"` // raw_uri, uri, args, client, headers, body, rules
	BodyLen int64       `json:"body_len"`
	Trunc   bool        `json:"body_truncated"`
}

type corpusFile struct {
	Comment string       `json:"comment"`
	KeyHex  string       `json:"key_hex"`
	KeyID   string       `json:"key_id"`
	MaxBody int          `json:"max_body"`
	Cases   []corpusCase `json:"cases"`
}

func TestDifferentialCorpus(t *testing.T) {
	a := anon(t)
	a.MaxBody = 200 // also exercise truncation
	r := rand.New(rand.NewSource(20261014))
	var got []corpusCase
	for i := 0; i < corpusSize; i++ {
		req := genRequest(r, i)
		rec := a.Anonymize(req)
		b := func(s string) []byte { return []byte(s) }
		c := corpusCase{TsMs: req.TsMs, Rules: req.Rules, BodyLen: rec.BodyLen, Trunc: rec.BodyTruncated,
			In: [][]byte{b(req.NodeID), b(req.Policy), b(req.Method), b(req.RawURI), b(req.URI), b(req.Args), b(req.Proto),
				b(req.Client), req.Body, b(req.Action)},
			Out: [][]byte{b(rec.RawURI), b(rec.URI), b(rec.Args), b(rec.Client), b(rec.Headers), rec.Body, b(rec.Rules)}}
		for _, h := range req.Headers {
			c.Headers = append(c.Headers, [2][]byte{b(h[0]), b(h[1])})
		}
		got = append(got, c)
	}
	path := filepath.Join("..", "..", "engine", "tests", "fixtures", "anon-corpus-v1.json")
	if *update {
		vf := corpusFile{Comment: "Generated by control-plane/replay TestDifferentialCorpus. Test key only.",
			KeyHex: strings.Repeat("5a", 32), KeyID: "test-1", MaxBody: a.MaxBody, Cases: got}
		b, err := json.Marshal(vf)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, append(b, '\n'), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("%v (go test ./replay -run TestDifferentialCorpus -update)", err)
	}
	var want corpusFile
	if err := json.Unmarshal(b, &want); err != nil {
		t.Fatal(err)
	}
	if len(want.Cases) != len(got) {
		t.Fatalf("%d cases, want %d", len(got), len(want.Cases))
	}
	for i := range got {
		g, _ := json.Marshal(got[i])
		w, _ := json.Marshal(want.Cases[i])
		if !bytes.Equal(g, w) {
			t.Errorf("case %d:\n got %s\nwant %s", i, g, w)
		}
	}
}
