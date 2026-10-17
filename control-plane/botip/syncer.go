package botip

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"strings"
	"time"

	"github.com/minio/minio-go/v7"
)

// CrawlerFeed defines a remote source of verified bot IP ranges.
type CrawlerFeed struct {
	Name   string
	URL    string
	Format string // "google", "bing", "plain"
}

// DefaultCrawlerFeeds lists official public IP endpoints of reputable search engines and services.
var DefaultCrawlerFeeds = []CrawlerFeed{
	{
		Name:   "googlebot",
		URL:    "https://developers.google.com/search/apis/ipranges/googlebot.json",
		Format: "google",
	},
	{
		Name:   "bingbot",
		URL:    "https://www.bing.com/toolbox/bingbot.json",
		Format: "bing",
	},
	{
		Name:   "cloudflare",
		URL:    "https://www.cloudflare.com/ips-v4",
		Format: "plain",
	},
}

// GoodBotIPBundle represents the aggregated, canonical bot IP dataset bundled for WAF nodes.
type GoodBotIPBundle struct {
	Version    string              `json:"version"`
	UpdatedAt  time.Time           `json:"updated_at"`
	Crawlers   map[string][]string `json:"crawlers"`
	TotalCIDRs int                 `json:"total_cidrs"`
}

// ObjectUploader abstracts cloud storage uploads (MinIO/S3).
type ObjectUploader interface {
	Put(ctx context.Context, key string, data []byte, contentType string) error
}

// MinIOUploader implements ObjectUploader via minio.Client.
type MinIOUploader struct {
	client *minio.Client
	bucket string
}

// NewMinIOUploader creates an uploader for a target MinIO bucket.
func NewMinIOUploader(client *minio.Client, bucket string) *MinIOUploader {
	return &MinIOUploader{
		client: client,
		bucket: bucket,
	}
}

// Put uploads bytes to MinIO.
func (u *MinIOUploader) Put(ctx context.Context, key string, data []byte, contentType string) error {
	_, err := u.client.PutObject(ctx, u.bucket, key, bytes.NewReader(data), int64(len(data)), minio.PutObjectOptions{
		ContentType: contentType,
	})
	return err
}

// Syncer handles periodic synchronization of verified bot IP lists.
type Syncer struct {
	client   *http.Client
	uploader ObjectUploader
	feeds    []CrawlerFeed
}

// NewSyncer instantiates a Syncer with specified feeds and storage.
func NewSyncer(uploader ObjectUploader, feeds []CrawlerFeed) *Syncer {
	if feeds == nil {
		feeds = DefaultCrawlerFeeds
	}
	return &Syncer{
		client: &http.Client{
			Timeout: 10 * time.Second,
		},
		uploader: uploader,
		feeds:    feeds,
	}
}

// FetchFeed downloads and parses CIDRs from a given crawler feed.
func (s *Syncer) FetchFeed(ctx context.Context, feed CrawlerFeed) ([]string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, feed.URL, nil)
	if err != nil {
		return nil, fmt.Errorf("creating request: %w", err)
	}
	req.Header.Set("User-Agent", "Strata-WAF-BotIP-Syncer/1.0")

	resp, err := s.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("fetching feed %s: %w", feed.Name, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected status %d from %s", resp.StatusCode, feed.URL)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, 5*1024*1024))
	if err != nil {
		return nil, fmt.Errorf("reading feed %s: %w", feed.Name, err)
	}

	var rawCIDRs []string

	switch feed.Format {
	case "google", "bing":
		// Googlebot & Bingbot format: {"prefixes": [{"ipv4Prefix": "..."}, {"ipv6Prefix": "..."}]}
		var doc struct {
			Prefixes []struct {
				IPv4Prefix string `json:"ipv4Prefix"`
				IPv6Prefix string `json:"ipv6Prefix"`
			} `json:"prefixes"`
		}
		if err := json.Unmarshal(body, &doc); err != nil {
			return nil, fmt.Errorf("unmarshaling json prefixes for %s: %w", feed.Name, err)
		}
		for _, p := range doc.Prefixes {
			if p.IPv4Prefix != "" {
				rawCIDRs = append(rawCIDRs, p.IPv4Prefix)
			}
			if p.IPv6Prefix != "" {
				rawCIDRs = append(rawCIDRs, p.IPv6Prefix)
			}
		}
	case "plain":
		// Plain text lines with CIDRs
		lines := strings.Split(string(body), "\n")
		for _, line := range lines {
			line = strings.TrimSpace(line)
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}
			rawCIDRs = append(rawCIDRs, line)
		}
	default:
		return nil, fmt.Errorf("unknown feed format %q for %s", feed.Format, feed.Name)
	}

	// Validate, canonicalize, and deduplicate CIDRs
	seen := make(map[string]bool)
	validated := make([]string, 0, len(rawCIDRs))
	for _, cidr := range rawCIDRs {
		prefix, err := netip.ParsePrefix(cidr)
		if err != nil {
			// Skip or warn invalid prefix
			continue
		}
		canonical := prefix.Masked().String()
		if !seen[canonical] {
			seen[canonical] = true
			validated = append(validated, canonical)
		}
	}

	return validated, nil
}

// Sync pulls all configured feeds, creates the canonical bundle, and saves to storage.
func (s *Syncer) Sync(ctx context.Context) (*GoodBotIPBundle, error) {
	now := time.Now().UTC()
	bundle := &GoodBotIPBundle{
		Version:   now.Format("20060102.150405"),
		UpdatedAt: now,
		Crawlers:  make(map[string][]string),
	}

	total := 0
	for _, feed := range s.feeds {
		cidrs, err := s.FetchFeed(ctx, feed)
		if err != nil {
			return nil, fmt.Errorf("syncing feed %s: %w", feed.Name, err)
		}
		bundle.Crawlers[feed.Name] = cidrs
		total += len(cidrs)
	}
	bundle.TotalCIDRs = total

	data, err := json.MarshalIndent(bundle, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("marshaling bot ip bundle: %w", err)
	}

	if s.uploader != nil {
		// Upload current latest
		if err := s.uploader.Put(ctx, "bot-ip/good_bots.json", data, "application/json"); err != nil {
			return nil, fmt.Errorf("uploading latest good_bots.json: %w", err)
		}
		// Upload timestamped archival version
		archiveKey := fmt.Sprintf("bot-ip/good_bots-%s.json", bundle.Version)
		if err := s.uploader.Put(ctx, archiveKey, data, "application/json"); err != nil {
			return nil, fmt.Errorf("uploading archive %s: %w", archiveKey, err)
		}
	}

	return bundle, nil
}

// ContainsIP checks if a given IP address belongs to any CIDR prefix in the list.
func ContainsIP(ipStr string, cidrs []string) bool {
	addr, err := netip.ParseAddr(ipStr)
	if err != nil {
		return false
	}
	for _, c := range cidrs {
		prefix, err := netip.ParsePrefix(c)
		if err != nil {
			continue
		}
		if prefix.Contains(addr) {
			return true
		}
	}
	return false
}
