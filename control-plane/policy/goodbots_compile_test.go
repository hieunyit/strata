package policy

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// W18-G2-02: the crawler ranges reach the bundle through the real
// strata-compile (STRATA_COMPILE=<path>), as section GOOD_BOTS ("SGB1").
func TestCompilerCarriesGoodBots(t *testing.T) {
	bin := os.Getenv("STRATA_COMPILE")
	if bin == "" {
		t.Skip("STRATA_COMPILE not set")
	}
	dir := t.TempDir()
	key := filepath.Join(dir, "seed")
	if err := os.WriteFile(key, bytes.Repeat([]byte{7}, 32), 0o600); err != nil {
		t.Fatal(err)
	}
	ir := `{"ir_version": 1, "ruleset": {"name": "good-bots", "version": "1"}, "rules": [{"id": 500001,
	  "name": "Crawler User-Agent from outside its published IP ranges", "layer": "managed", "stage": "request_headers",
	  "score": 100, "severity": "error", "metadata": {"source": "strata", "license": "Apache-2.0"},
	  "match": {"all": [{"targets": [{"var": "bot_verified"}], "operator": {"type": "streq", "value": "false"}}]}}]}`
	irFile := filepath.Join(dir, "ir.json")
	if err := os.WriteFile(irFile, []byte(ir), 0o600); err != nil {
		t.Fatal(err)
	}
	ranges := []byte(`{"version": "v", "crawlers": {"googlebot": ["66.249.64.0/27"]}}`)
	c := &Compiler{Binary: bin, KeyFile: key, Rules: []string{irFile}, Timeout: time.Minute}
	pols := []Named{{Name: "example-api", Spec: Spec{Mode: "enforce"}}}

	c.GoodBots = func(context.Context) ([]byte, error) { return ranges, nil }
	b, err := c.Build(t.Context(), 1, pols)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(b, []byte("SGB1")) || !bytes.Contains(b, []byte("googlebot")) {
		t.Fatal("bundle without the crawler ranges")
	}
	c.GoodBots = func(context.Context) ([]byte, error) { return nil, nil }
	if b, err = c.Build(t.Context(), 2, pols); err != nil || bytes.Contains(b, []byte("SGB1")) {
		t.Fatalf("no list stored: %v, section %v", err, bytes.Contains(b, []byte("SGB1")))
	}
	c.GoodBots = func(context.Context) ([]byte, error) { return nil, errors.New("store down") }
	if _, err := c.Build(t.Context(), 3, pols); err == nil || !strings.Contains(err.Error(), "store down") {
		t.Fatalf("store failure: %v", err)
	}
	// a list the compiler refuses fails the deploy
	c.GoodBots = func(context.Context) ([]byte, error) {
		return []byte(`{"crawlers": {"googlebot": ["0.0.0.0/0"]}}`), nil
	}
	if _, err := c.Build(t.Context(), 4, pols); err == nil || !strings.Contains(err.Error(), "broader") {
		t.Fatalf("broad prefix: %v", err)
	}
}

// S3.Get of a missing key is ErrObjectNotFound (STRATA_TEST_S3_ENDPOINT,
// bucket strata-bundles, keys STRATA_S3_ACCESS_KEY / STRATA_S3_SECRET_KEY).
func TestS3GetMissingKey(t *testing.T) {
	ep := os.Getenv("STRATA_TEST_S3_ENDPOINT")
	if ep == "" {
		t.Skip("STRATA_TEST_S3_ENDPOINT not set")
	}
	s, err := NewS3(t.Context(), S3Config{Endpoint: ep, Bucket: "strata-bundles",
		AccessKey: os.Getenv("STRATA_S3_ACCESS_KEY"), SecretKey: os.Getenv("STRATA_S3_SECRET_KEY")})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.Get(t.Context(), "goodbots/no-such-object.json"); !IsObjectNotFound(err) {
		t.Fatalf("missing key: %v", err)
	}
	if err := s.Put(t.Context(), "goodbots/test.json", []byte("{}"), ""); err != nil {
		t.Fatal(err)
	}
	if b, err := s.Get(t.Context(), "goodbots/test.json"); err != nil || string(b) != "{}" || IsObjectNotFound(err) {
		t.Fatalf("existing key: %q %v", b, err)
	}
}
