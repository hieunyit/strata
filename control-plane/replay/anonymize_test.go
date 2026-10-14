package replay

import (
	"bytes"
	"context"
	"encoding/json"
	"flag"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/strata/strata/control-plane/policy"
)

var update = flag.Bool("update", false, "rewrite docs/spec/examples/replay-anon-v1.json")

// test key of the vectors; never use it anywhere else
var testKey = bytes.Repeat([]byte{0x5a}, 32)

func anon(t *testing.T) *Anonymizer {
	t.Helper()
	a, err := NewAnonymizer(testKey, "test-1")
	if err != nil {
		t.Fatal(err)
	}
	return a
}

func TestToken(t *testing.T) {
	a := anon(t)
	tok := a.Token("0912345678")
	if !strings.HasPrefix(tok, "~h:") || !strings.HasSuffix(tok, ":d10") || len(tok) != len("~h:")+16+len(":d10") {
		t.Fatalf("token %q", tok)
	}
	if a.Token("0912345678") != tok || a.Token("0912345679") == tok {
		t.Fatal("token is not a function of the value")
	}
	b, _ := NewAnonymizer(bytes.Repeat([]byte{1}, 32), "test-2")
	if b.Token("0912345678") == tok {
		t.Fatal("token does not depend on the key")
	}
	for v, c := range map[string]string{"123": "d3", "abc": "a3", "a1": "x2", "a-1": "s3", "": "s0"} {
		if got := a.Token(v); !strings.HasSuffix(got, ":"+c) {
			t.Errorf("%q: %s", v, got)
		}
	}
	if _, err := NewAnonymizer([]byte("short"), "k"); err == nil {
		t.Fatal("short key accepted")
	}
}

func TestMaskValue(t *testing.T) {
	a := anon(t)
	tok := a.Token
	cases := map[string]string{
		"plain text 42":                  "plain text 42",
		"mail alice@example.test now":    "mail " + tok("alice@example.test") + " now",
		"call 0912345678":                "call " + tok("0912345678"),
		"+84912345678":                   tok("+84912345678"),
		"id 001099012345.":               "id " + tok("001099012345") + ".",
		"order 2026101400123":            "order 2026101400123", // 13 digits, not Luhn
		"card 4111 1111 1111 1111 ok":    "card " + tok("4111 1111 1111 1111") + " ok",
		"card 4111111111111111":          "card " + tok("4111111111111111"),
		"ts 1760000000000":               "ts 1760000000000",
		"0912345678 0987654321":          tok("0912345678") + " " + tok("0987654321"),
		"x09123456789":                   "x09123456789", // 11 digits: no phone, no CCCD
		"' OR 1=1 -- 0912345678":         "' OR 1=1 -- " + tok("0912345678"),
		"Bearer eyJhbGciOi.eyJzdWIi.sig": "Bearer " + tok("eyJhbGciOi.eyJzdWIi.sig"),
	}
	for in, want := range cases {
		if got := a.MaskValue(in); got != want {
			t.Errorf("%q:\n got %q\nwant %q", in, got, want)
		}
	}
}

func TestSensitiveName(t *testing.T) {
	for _, n := range []string{"password", "new_Password", "otp", "user_email", "CCCD", "access_token", "phoneNumber", "full_name", "username", "address"} {
		if !SensitiveName(n) {
			t.Errorf("%s not sensitive", n)
		}
	}
	for _, n := range []string{"q", "page", "id", "comment", "redirect", "lang"} {
		if SensitiveName(n) {
			t.Errorf("%s sensitive", n)
		}
	}
}

// vectors: shared with libstrata (W12-N-01), docs/spec/replay-sample.md › 4
func vectorRequests() []Request {
	return []Request{
		{
			TsMs: 1791939600000, NodeID: "edge-01", Policy: "example-api", Method: "POST",
			RawURI: "/v1/verify?user=alice%40example.test&q=1%27%20OR%201%3D1&token=abc123",
			URI:    "/v1/verify", Args: "user=alice%40example.test&q=1%27%20OR%201%3D1&token=abc123", Proto: "HTTP/1.1",
			Client: "198.51.100.7",
			Headers: [][2]string{
				{"Host", "api.example.test"}, {"Authorization", "Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.c2ln"},
				{"Cookie", "sid=s3cr3t; theme=dark"}, {"User-Agent", "sqlmap/1.8"},
				{"Content-Type", "application/json"}, {"Content-Length", "106"},
			},
			Body:   []byte(`{"cccd":"001099012345","name":"Nguyen Van A","phone":"0912345678","note":"call 0987654321","q":"' UNION SELECT 1--","n":42}`),
			Action: "block", Rules: []uint32{942100, 942190},
		},
		{
			TsMs: 1791939601000, NodeID: "edge-01", Policy: "example-api", Method: "POST",
			RawURI: "/v1/upload/0912345678", URI: "/v1/upload/0912345678", Proto: "HTTP/2.0", Client: "2001:db8::7",
			Headers: [][2]string{
				{"Content-Type", "multipart/form-data; boundary=XyZ"}, {"X-Forwarded-For", "203.0.113.9"},
			},
			Body: []byte("--XyZ\r\nContent-Disposition: form-data; name=\"comment\"\r\n\r\n<script>alert(1)</script> mail bob@example.test\r\n" +
				"--XyZ\r\nContent-Disposition: form-data; name=\"password\"\r\n\r\nhunter2\r\n" +
				"--XyZ\r\nContent-Disposition: form-data; name=\"doc\"; filename=\"id.jpg\"\r\nContent-Type: image/jpeg\r\n\r\n\xff\xd8\xff\xe0JFIF-photo-of-an-ID\r\n" +
				"--XyZ--\r\n"),
			Action: "log", Rules: []uint32{941100},
		},
		{
			TsMs: 1791939602000, NodeID: "edge-02", Policy: "example-web", Method: "GET",
			RawURI: "/search?q=%253Cscript%253E&page=2", URI: "/search", Args: "q=%253Cscript%253E&page=2", Proto: "HTTP/1.1",
			Client: "192.0.2.10", Headers: [][2]string{{"Host", "www.example.test"}}, Action: "allow",
		},
		{
			TsMs: 1791939603000, NodeID: "edge-02", Policy: "example-web", Method: "POST",
			RawURI: "/login", URI: "/login", Proto: "HTTP/1.1", Client: "192.0.2.11",
			Headers: [][2]string{{"Content-Type", "application/x-www-form-urlencoded"}},
			Body:    []byte("username=alice&password=hunter2&remember=on&otp=123456"),
			Action:  "allow",
		},
	}
}

type vectorFile struct {
	Comment string `json:"comment"`
	KeyHex  string `json:"key_hex"`
	KeyID   string `json:"key_id"`
	// the policy's privacy settings (#75), when the vectors use some
	SensitiveFields []string       `json:"sensitive_fields,omitempty"`
	MaskPatterns    []string       `json:"mask_patterns,omitempty"`
	Cases           []vectorRecord `json:"cases"`
}

type vectorRecord struct {
	Input  vectorInput `json:"input"`
	Output Record      `json:"output"`
}

type vectorInput struct {
	Request
	Body string `json:"body"`
}

func TestVectors(t *testing.T) {
	a := anon(t)
	path := filepath.Join("..", "..", "docs", "spec", "examples", "replay-anon-v1.json")
	var got []vectorRecord
	for _, r := range vectorRequests() {
		got = append(got, vectorRecord{Input: vectorInput{Request: r, Body: string(r.Body)}, Output: a.Anonymize(r)})
	}
	if *update {
		vf := vectorFile{
			Comment: "Replay sample anonymization vectors, format 1 (docs/spec/replay-sample.md). Test key only.",
			KeyHex:  strings.Repeat("5a", 32), KeyID: "test-1", Cases: got,
		}
		b, err := json.MarshalIndent(vf, "", "  ")
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, append(b, '\n'), 0o644); err != nil {
			t.Fatal(err)
		}
		// the same records as a sample file, read by engine/replay's tests
		recs := make([]Record, len(got))
		for i := range got {
			recs[i] = got[i].Output
		}
		var pq bytes.Buffer
		if err := WriteParquet(&pq, a.KeyID, recs); err != nil {
			t.Fatal(err)
		}
		fx := filepath.Join("..", "..", "engine", "replay", "tests", "fixtures", "samples-v1.parquet")
		if err := os.WriteFile(fx, pq.Bytes(), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("%v (go test ./replay -run TestVectors -update)", err)
	}
	var want vectorFile
	if err := json.Unmarshal(b, &want); err != nil {
		t.Fatal(err)
	}
	if len(want.Cases) != len(got) {
		t.Fatalf("%d vectors, want %d", len(got), len(want.Cases))
	}
	for i := range got {
		g, _ := json.Marshal(got[i].Output)
		w, _ := json.Marshal(want.Cases[i].Output)
		if !bytes.Equal(g, w) {
			t.Errorf("vector %d:\n got %s\nwant %s", i, g, w)
		}
	}
}

// no original sensitive value survives anywhere in a record
func TestNoSensitiveValueLeaks(t *testing.T) {
	a := anon(t)
	secrets := []string{
		"alice@example.test", "alice%40example.test", "abc123", "eyJhbGciOiJIUzI1NiJ9", "s3cr3t", "001099012345", "0912345678",
		"0987654321", "198.51.100.7", "2001:db8::7", "203.0.113.9", "bob@example.test", "hunter2", "JFIF-photo-of-an-ID",
		"123456", "192.0.2.10", "Nguyen Van A", "username=alice",
	}
	for i, r := range vectorRequests() {
		rec := a.Anonymize(r)
		all, _ := json.Marshal(rec)
		blob := string(all) + string(rec.Body)
		for _, s := range secrets {
			if strings.Contains(blob, s) {
				t.Errorf("request %d: %q survived: %s", i, s, blob)
			}
		}
	}
	// and the attack payloads are still there for the rules
	rec := a.Anonymize(vectorRequests()[0])
	if !strings.Contains(string(rec.Body), "' UNION SELECT 1--") || !strings.Contains(rec.RawURI, "q=1%27%20OR%201%3D1") {
		t.Fatalf("payload lost: %s %s", rec.RawURI, rec.Body)
	}
	if !strings.Contains(rec.Headers, "sqlmap/1.8") {
		t.Fatalf("user agent lost: %s", rec.Headers)
	}
	rec = a.Anonymize(vectorRequests()[1])
	if !strings.Contains(string(rec.Body), "<script>alert(1)</script>") {
		t.Fatalf("multipart payload lost: %q", rec.Body)
	}
	rec = a.Anonymize(vectorRequests()[2])
	if rec.Args != "q=%253Cscript%253E&page=2" {
		t.Fatalf("double encoding not kept: %s", rec.Args)
	}
}

func TestBodyLimitAndContentLength(t *testing.T) {
	a := anon(t)
	a.MaxBody = 16
	r := Request{Policy: "example-api", NodeID: "n", Headers: [][2]string{{"Content-Length", "40"}},
		Body: []byte("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")}
	rec := a.Anonymize(r)
	if !rec.BodyTruncated || rec.BodyLen != 40 || len(rec.Body) != 16 || !strings.Contains(rec.Headers, `"40"`) {
		t.Fatalf("%+v", rec)
	}
	// JSON rewritten shorter: Content-Length follows the body
	a.MaxBody = 0
	rec = a.Anonymize(vectorRequests()[0])
	var hs [][2]string
	_ = json.Unmarshal([]byte(rec.Headers), &hs)
	for _, h := range hs {
		if h[0] == "Content-Length" && h[1] != strings.TrimSpace(itoa(len(rec.Body))) {
			t.Fatalf("Content-Length %s for %d bytes", h[1], len(rec.Body))
		}
	}
}

func itoa(n int) string { b, _ := json.Marshal(n); return string(b) }

func TestJSONDepthAndBadJSON(t *testing.T) {
	a := anon(t)
	deep := strings.Repeat("[", 200) + strings.Repeat("]", 200)
	r := Request{Headers: [][2]string{{"Content-Type", "application/json"}}, Body: []byte(deep)}
	if got := string(a.Anonymize(r).Body); got != deep {
		t.Fatalf("too deep JSON is not passed as raw text: %.40s", got)
	}
	r.Body = []byte(`{"email": "carol@example.test"`) // truncated JSON: raw rules apply
	if got := string(a.Anonymize(r).Body); strings.Contains(got, "carol@") {
		t.Fatalf("leak in broken JSON: %s", got)
	}
}

func TestParquetRoundTrip(t *testing.T) {
	a := anon(t)
	var recs []Record
	for _, r := range vectorRequests()[:2] {
		recs = append(recs, a.Anonymize(r))
	}
	var buf bytes.Buffer
	if err := WriteParquet(&buf, a.KeyID, recs); err != nil {
		t.Fatal(err)
	}
	keyID, back, err := ReadParquet(buf.Bytes())
	if err != nil || keyID != "test-1" {
		t.Fatalf("%q %v", keyID, err)
	}
	g, _ := json.Marshal(back)
	w, _ := json.Marshal(recs)
	if !bytes.Equal(g, w) {
		t.Fatalf("round trip:\n got %s\nwant %s", g, w)
	}
	if _, _, err := ReadParquet([]byte("not parquet")); err == nil {
		t.Fatal("garbage read")
	}
}

type memObjects struct{ m map[string][]byte }

func (o *memObjects) Put(_ context.Context, key string, data []byte, _ string) error {
	o.m[key] = data
	return nil
}
func (o *memObjects) Get(_ context.Context, key string) ([]byte, error) { return o.m[key], nil }

func TestStoreKeysAndChecks(t *testing.T) {
	a := anon(t)
	mem := &memObjects{m: map[string][]byte{}}
	s := &Store{Objects: mem}
	recs := []Record{a.Anonymize(vectorRequests()[0]), a.Anonymize(vectorRequests()[1])}
	key, err := s.Put(context.Background(), a.KeyID, recs)
	if err != nil {
		t.Fatal(err)
	}
	if key != "replay/v1/example-api/2026/10/14/edge-01-1791939600000-1.parquet" {
		t.Fatalf("key %s", key)
	}
	if _, back, err := ReadParquet(mem.m[key]); err != nil || len(back) != 2 {
		t.Fatalf("%v %d", err, len(back))
	}
	mixed := []Record{recs[0], a.Anonymize(vectorRequests()[2])}
	if _, err := s.Put(context.Background(), a.KeyID, mixed); err == nil {
		t.Fatal("two policies in one file accepted")
	}
	bad := recs[0]
	bad.NodeID = "../etc"
	if _, err := s.Put(context.Background(), a.KeyID, []Record{bad}); err == nil {
		t.Fatal("node id with a slash accepted")
	}
}

// Real MinIO (W11-G2-01 "lưu được vào MinIO"): STRATA_TEST_MINIO_ENDPOINT
// (host:port), _BUCKET, _ACCESS_KEY, _SECRET_KEY.
func TestStoreInMinIO(t *testing.T) {
	ep := os.Getenv("STRATA_TEST_MINIO_ENDPOINT")
	if ep == "" {
		t.Skip("STRATA_TEST_MINIO_ENDPOINT not set")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	obj, err := policy.NewS3(ctx, policy.S3Config{
		Endpoint: ep, Bucket: os.Getenv("STRATA_TEST_MINIO_BUCKET"),
		AccessKey: os.Getenv("STRATA_TEST_MINIO_ACCESS_KEY"), SecretKey: os.Getenv("STRATA_TEST_MINIO_SECRET_KEY"),
	})
	if err != nil {
		t.Fatal(err)
	}
	a := anon(t)
	s := &Store{Objects: obj}
	recs := []Record{a.Anonymize(vectorRequests()[0]), a.Anonymize(vectorRequests()[1])}
	key, err := s.Put(ctx, a.KeyID, recs)
	if err != nil {
		t.Fatal(err)
	}
	data, err := obj.Get(ctx, key)
	if err != nil {
		t.Fatal(err)
	}
	keyID, back, err := ReadParquet(data)
	if err != nil || keyID != a.KeyID || len(back) != 2 || back[0].Rules != "942100,942190" {
		t.Fatalf("%s: %q %d %v", key, keyID, len(back), err)
	}
	t.Logf("stored and read back %s (%d bytes)", key, len(data))
}

// #75: vectors with a policy's privacy settings, for libstrata's writer
// too (engine/tests/anon_vectors.rs); go test ./replay -run
// TestPrivacyVectors -update writes them.
func TestPrivacyVectors(t *testing.T) {
	a := anon(t)
	fields, patterns := []string{"ma_khach_hang", "X-Branch-Code"}, []string{`KH[0-9]{8}`}
	if err := a.SetPrivacy(fields, patterns); err != nil {
		t.Fatal(err)
	}
	reqs := []Request{
		{
			TsMs: 1791939600000, NodeID: "edge-01", Policy: "example-api", Method: "POST",
			RawURI: "/v1/orders?Ma_Khach_Hang=C0012345&ref=KH12345678&q=1%27%20OR%201%3D1",
			URI:    "/v1/orders", Args: "Ma_Khach_Hang=C0012345&ref=KH12345678&q=1%27%20OR%201%3D1", Proto: "HTTP/1.1",
			Client:  "198.51.100.7",
			Headers: [][2]string{{"Host", "api.example.test"}, {"X-Branch-Code", "HN-042"}, {"Content-Type", "application/json"}},
			Body:    []byte(`{"order":{"ma_khach_hang":"C0012345","note":"KH12345678 ok"},"q":"' UNION SELECT 1--"}`),
			Action:  "block", Rules: []uint32{942100},
		},
		{
			TsMs: 1791939600001, NodeID: "edge-01", Policy: "example-api", Method: "POST",
			RawURI: "/v1/forms", URI: "/v1/forms", Proto: "HTTP/1.1", Client: "198.51.100.8",
			Headers: [][2]string{{"Host", "api.example.test"}, {"Content-Type", "multipart/form-data; boundary=b"}},
			Body:    []byte("--b\r\nContent-Disposition: form-data; name=\"MA_KHACH_HANG\"\r\n\r\nC0012345\r\n--b\r\nContent-Disposition: form-data; name=\"ref\"\r\n\r\nKH12345678\r\n--b--\r\n"),
			Action:  "allow",
		},
	}
	path := filepath.Join("..", "..", "docs", "spec", "examples", "replay-anon-v1-privacy.json")
	var got []vectorRecord
	for _, r := range reqs {
		rec := a.Anonymize(r)
		for _, secret := range []string{"C0012345", "KH12345678", "HN-042"} {
			if b, _ := json.Marshal(rec); bytes.Contains(b, []byte(secret)) || bytes.Contains(rec.Body, []byte(secret)) {
				t.Errorf("%q survives in %s", secret, b)
			}
		}
		got = append(got, vectorRecord{Input: vectorInput{Request: r, Body: string(r.Body)}, Output: rec})
	}
	if *update {
		vf := vectorFile{
			Comment: "Replay sample anonymization vectors with a policy's privacy settings (#75; docs/spec/replay-sample.md). Test key only.",
			KeyHex:  strings.Repeat("5a", 32), KeyID: "test-1", SensitiveFields: fields, MaskPatterns: patterns, Cases: got,
		}
		b, err := json.MarshalIndent(vf, "", "  ")
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, append(b, '\n'), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("%v (go test ./replay -run TestPrivacyVectors -update)", err)
	}
	var want vectorFile
	if err := json.Unmarshal(b, &want); err != nil {
		t.Fatal(err)
	}
	if len(want.Cases) != len(got) {
		t.Fatalf("%d vectors, want %d", len(got), len(want.Cases))
	}
	for i := range got {
		g, _ := json.Marshal(got[i].Output)
		w, _ := json.Marshal(want.Cases[i].Output)
		if !bytes.Equal(g, w) {
			t.Errorf("vector %d:\n got %s\nwant %s", i, g, w)
		}
	}
	// without the settings the values stay (the vectors show something)
	plain := anon(t).Anonymize(reqs[0])
	if !strings.Contains(plain.RawURI, "C0012345") || !bytes.Contains(plain.Body, []byte("KH12345678")) {
		t.Fatalf("built-in lists alone already hide them: %+v", plain)
	}
}
