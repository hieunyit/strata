package botip

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
)

type mockUploader struct {
	mu      sync.Mutex
	uploads map[string][]byte
}

func (m *mockUploader) Put(_ context.Context, key string, data []byte, _ string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.uploads == nil {
		m.uploads = make(map[string][]byte)
	}
	m.uploads[key] = data
	return nil
}

func TestBotIPSyncer(t *testing.T) {
	// 1. Setup mock remote crawler feed servers
	googleHandler := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"prefixes": []map[string]string{
				{"ipv4Prefix": "66.249.64.0/19"},
				{"ipv4Prefix": "66.249.96.0/20"},
				{"ipv6Prefix": "2001:4860:4801::/48"},
				{"ipv4Prefix": "invalid-cidr"}, // Should be ignored gracefully
			},
		})
	})
	googleServer := httptest.NewServer(googleHandler)
	defer googleServer.Close()

	bingHandler := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"prefixes": []map[string]string{
				{"ipv4Prefix": "157.55.39.0/24"},
				{"ipv4Prefix": "207.46.13.0/24"},
			},
		})
	})
	bingServer := httptest.NewServer(bingHandler)
	defer bingServer.Close()

	cfHandler := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		_, _ = w.Write([]byte("# Cloudflare IP ranges\n173.245.48.0/20\n103.21.244.0/22\n\n# comment\n"))
	})
	cfServer := httptest.NewServer(cfHandler)
	defer cfServer.Close()

	feeds := []CrawlerFeed{
		{Name: "googlebot", URL: googleServer.URL, Format: "google"},
		{Name: "bingbot", URL: bingServer.URL, Format: "bing"},
		{Name: "cloudflare", URL: cfServer.URL, Format: "plain"},
	}

	uploader := &mockUploader{}
	syncer := NewSyncer(uploader, feeds)

	// 2. Run Sync
	ctx := context.Background()
	bundle, err := syncer.Sync(ctx)
	if err != nil {
		t.Fatalf("Sync failed: %v", err)
	}

	if bundle == nil {
		t.Fatal("expected non-nil bundle")
	}

	if len(bundle.Crawlers["googlebot"]) != 3 {
		t.Errorf("expected 3 valid googlebot prefixes, got %d", len(bundle.Crawlers["googlebot"]))
	}
	if len(bundle.Crawlers["bingbot"]) != 2 {
		t.Errorf("expected 2 valid bingbot prefixes, got %d", len(bundle.Crawlers["bingbot"]))
	}
	if len(bundle.Crawlers["cloudflare"]) != 2 {
		t.Errorf("expected 2 valid cloudflare prefixes, got %d", len(bundle.Crawlers["cloudflare"]))
	}
	if bundle.TotalCIDRs != 7 {
		t.Errorf("expected 7 total CIDRs, got %d", bundle.TotalCIDRs)
	}

	// 3. Verify upload to MinIO/storage
	if _, ok := uploader.uploads["bot-ip/good_bots.json"]; !ok {
		t.Errorf("expected bot-ip/good_bots.json to be uploaded")
	}

	// 4. Test ContainsIP
	// Googlebot IP: 66.249.64.15
	if !ContainsIP("66.249.64.15", bundle.Crawlers["googlebot"]) {
		t.Errorf("expected 66.249.64.15 to be in googlebot prefixes")
	}
	// Spoofed IP: 1.2.3.4 claiming to be Googlebot
	if ContainsIP("1.2.3.4", bundle.Crawlers["googlebot"]) {
		t.Errorf("expected 1.2.3.4 NOT to be in googlebot prefixes")
	}
	// Bingbot IP: 157.55.39.100
	if !ContainsIP("157.55.39.100", bundle.Crawlers["bingbot"]) {
		t.Errorf("expected 157.55.39.100 to be in bingbot prefixes")
	}
}
