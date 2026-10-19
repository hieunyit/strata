// Package goodbots keeps the IP ranges the big crawlers' owners publish
// (W18-G2-02): a job fetches them on a schedule (daily by default), checks
// them, stores each version in the object store, and every bundle built
// afterwards carries the latest (strata-compile --good-bots, section
// GOOD_BOTS), where rule 500001 checks crawler User-Agents against them
// (W18-R-02).
//
// Objects: goodbots/<version>.json and goodbots/latest.json (a copy).
// <version> is the SHA-256 of the crawlers' ranges, so replicas fetching
// the same lists store the same object.
package goodbots

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/netip"
	"net/url"
	"sort"
	"sync"
	"sync/atomic"
	"time"
)

// Feed is a crawler's published list, in the JSON shape Google, Bing and
// Apple use: {"creationTime": "...", "prefixes": [{"ipv4Prefix": ...}, {"ipv6Prefix": ...}]}.
type Feed struct {
	Name string // crawler name of the engine (libstrata goodbots::CLAIMS)
	URL  string
}

// DefaultFeeds: the crawlers libstrata recognizes in User-Agents.
var DefaultFeeds = []Feed{
	{Name: "applebot", URL: "https://search.developer.apple.com/applebot.json"},
	{Name: "bingbot", URL: "https://www.bing.com/toolbox/bingbot.json"},
	{Name: "googlebot", URL: "https://developers.google.com/static/search/apis/ipranges/googlebot.json"},
}

// Limits, as libstrata checks them (engine/src/goodbots.rs).
const (
	MaxFeedBytes = 4 << 20
	MaxPrefixes  = 65536
	MinV4Bits    = 8
	MinV6Bits    = 16
	LatestKey    = "goodbots/latest.json"
)

// Objects is the object store (policy.S3 in the server). Get returns an
// error matching IsNotFound for a missing object.
type Objects interface {
	Put(ctx context.Context, key string, data []byte, sha256hex string) error
	Get(ctx context.Context, key string) ([]byte, error)
}

// Source records where a crawler's ranges come from.
type Source struct {
	URL          string    `json:"url"`
	FetchedAt    time.Time `json:"fetched_at"`
	CreationTime string    `json:"creation_time,omitempty"`
	Prefixes     int       `json:"prefixes"`
}

// List is a stored version, the file strata-compile --good-bots reads.
type List struct {
	Version   string              `json:"version"`
	UpdatedAt time.Time           `json:"updated_at"`
	Crawlers  map[string][]string `json:"crawlers"`
	Sources   map[string]Source   `json:"sources"`
}

// ParseFeed reads a published list: its prefixes, canonical, sorted and
// unique, and its creation time. A list with a prefix that is invalid,
// has host bits set or is broader than /8 (IPv4) or /16 (IPv6), or with no
// prefix, is refused whole: one bad entry means the source cannot be
// trusted.
func ParseFeed(b []byte) ([]string, string, error) {
	var doc struct {
		CreationTime string `json:"creationTime"`
		Prefixes     []struct {
			IPv4 string `json:"ipv4Prefix"`
			IPv6 string `json:"ipv6Prefix"`
		} `json:"prefixes"`
	}
	if err := json.Unmarshal(b, &doc); err != nil {
		return nil, "", fmt.Errorf("not a crawler range list: %w", err)
	}
	if len(doc.Prefixes) == 0 || len(doc.Prefixes) > MaxPrefixes {
		return nil, "", fmt.Errorf("%d prefixes (1 to %d)", len(doc.Prefixes), MaxPrefixes)
	}
	seen := map[netip.Prefix]bool{}
	for _, p := range doc.Prefixes {
		s, v4 := p.IPv4, true
		if s == "" {
			s, v4 = p.IPv6, false
		}
		if s == "" || (p.IPv4 != "" && p.IPv6 != "") {
			return nil, "", errors.New("an entry needs exactly one of ipv4Prefix, ipv6Prefix")
		}
		pfx, err := netip.ParsePrefix(s)
		if err != nil || pfx.Addr().Is4() != v4 || pfx.Addr().Zone() != "" {
			return nil, "", fmt.Errorf("prefix %q is invalid", s)
		}
		if pfx != pfx.Masked() {
			return nil, "", fmt.Errorf("prefix %q has host bits set", s)
		}
		if (v4 && pfx.Bits() < MinV4Bits) || (!v4 && pfx.Bits() < MinV6Bits) {
			return nil, "", fmt.Errorf("prefix %q is too broad", s)
		}
		seen[pfx] = true
	}
	out := make([]string, 0, len(seen))
	for p := range seen {
		out = append(out, p.String())
	}
	sort.Strings(out)
	if len(doc.CreationTime) > 64 {
		doc.CreationTime = doc.CreationTime[:64]
	}
	return out, doc.CreationTime, nil
}

// version is the SHA-256 of the crawlers' ranges (sorted names and lists).
func version(crawlers map[string][]string) string {
	names := make([]string, 0, len(crawlers))
	for n := range crawlers {
		names = append(names, n)
	}
	sort.Strings(names)
	h := sha256.New()
	for _, n := range names {
		_, _ = fmt.Fprintf(h, "%s\n", n)
		for _, p := range crawlers[n] {
			_, _ = fmt.Fprintf(h, "%s\n", p)
		}
		_, _ = h.Write([]byte{0})
	}
	return hex.EncodeToString(h.Sum(nil))
}

// Updater fetches, checks and stores the lists.
type Updater struct {
	Feeds   []Feed // default DefaultFeeds
	Objects Objects
	Client  *http.Client // default: one minute timeout
	Now     func() time.Time
	// IsNotFound tells a missing object from a failing store.
	IsNotFound func(error) bool

	mu          sync.Mutex
	lastSuccess atomic.Int64
	failures    atomic.Uint64
}

// LastSuccess is when every feed was last fetched well (zero before).
func (u *Updater) LastSuccess() time.Time {
	if ns := u.lastSuccess.Load(); ns != 0 {
		return time.Unix(0, ns).UTC()
	}
	return time.Time{}
}

// Failures counts the feeds that failed to fetch or check.
func (u *Updater) Failures() uint64 { return u.failures.Load() }

func (u *Updater) now() time.Time {
	if u.Now != nil {
		return u.Now().UTC()
	}
	return time.Now().UTC()
}

// Latest reads goodbots/latest.json; nil when there is none yet.
func Latest(ctx context.Context, objects Objects, isNotFound func(error) bool) (*List, error) {
	raw, err := objects.Get(ctx, LatestKey)
	if err != nil {
		if isNotFound != nil && isNotFound(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("good bots: reading %s: %w", LatestKey, err)
	}
	var l List
	if err := json.Unmarshal(raw, &l); err != nil || len(l.Crawlers) == 0 || l.Version != version(l.Crawlers) {
		return nil, fmt.Errorf("good bots: %s is damaged", LatestKey)
	}
	return &l, nil
}

// Update fetches every feed. A feed that fails keeps the crawler's ranges
// of the latest version (an error is returned and counted, but the others
// are still updated); a crawler never fetched well is left out. Returns
// the version now latest and whether it changed.
func (u *Updater) Update(ctx context.Context) (string, bool, error) {
	u.mu.Lock()
	defer u.mu.Unlock()
	prev, err := Latest(ctx, u.Objects, u.IsNotFound)
	if err != nil {
		u.failures.Add(1)
		return "", false, err
	}
	next := List{UpdatedAt: u.now(), Crawlers: map[string][]string{}, Sources: map[string]Source{}}
	feeds := u.Feeds
	if feeds == nil {
		feeds = DefaultFeeds
	}
	var errs []error
	for _, f := range feeds {
		prefixes, created, err := u.fetch(ctx, f)
		if err != nil {
			u.failures.Add(1)
			errs = append(errs, fmt.Errorf("%s: %w", f.Name, err))
			if prev != nil && len(prev.Crawlers[f.Name]) > 0 {
				next.Crawlers[f.Name] = prev.Crawlers[f.Name]
				next.Sources[f.Name] = prev.Sources[f.Name]
			}
			continue
		}
		next.Crawlers[f.Name] = prefixes
		next.Sources[f.Name] = Source{URL: redact(f.URL), FetchedAt: next.UpdatedAt, CreationTime: created, Prefixes: len(prefixes)}
	}
	joined := errors.Join(errs...)
	if len(next.Crawlers) == 0 {
		return "", false, joined
	}
	next.Version = version(next.Crawlers)
	if prev != nil && prev.Version == next.Version {
		// nothing new to store (a failed feed kept its previous ranges)
		if joined == nil {
			u.lastSuccess.Store(next.UpdatedAt.UnixNano())
		}
		return next.Version, false, joined
	}
	raw, err := json.MarshalIndent(next, "", "  ")
	if err != nil {
		return "", false, err
	}
	sum := sha256.Sum256(raw)
	for _, key := range []string{"goodbots/" + next.Version + ".json", LatestKey} {
		if err := u.Objects.Put(ctx, key, raw, hex.EncodeToString(sum[:])); err != nil {
			u.failures.Add(1)
			return "", false, fmt.Errorf("good bots: storing %s: %w", key, err)
		}
	}
	if joined == nil {
		u.lastSuccess.Store(next.UpdatedAt.UnixNano())
	}
	return next.Version, true, joined
}

func (u *Updater) fetch(ctx context.Context, f Feed) ([]string, string, error) {
	p, err := url.Parse(f.URL)
	if err != nil || (p.Scheme != "https" && p.Scheme != "http") || p.Host == "" {
		return nil, "", fmt.Errorf("feed %s: only http(s) URLs", redact(f.URL))
	}
	c := http.Client{Timeout: time.Minute}
	if u.Client != nil {
		c = *u.Client
	}
	c.CheckRedirect = func(r *http.Request, via []*http.Request) error {
		if len(via) >= 5 || (r.URL.Scheme != "https" && r.URL.Scheme != "http") {
			return errors.New("redirect refused")
		}
		return nil
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, f.URL, nil)
	if err != nil {
		return nil, "", fmt.Errorf("feed %s: bad request", redact(f.URL))
	}
	req.Header.Set("Accept", "application/json")
	resp, err := c.Do(req)
	if err != nil {
		var ue *url.Error
		if errors.As(err, &ue) {
			err = ue.Err
		}
		return nil, "", fmt.Errorf("feed %s: %w", redact(f.URL), err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return nil, "", fmt.Errorf("feed %s: HTTP %d", redact(f.URL), resp.StatusCode)
	}
	b, err := io.ReadAll(io.LimitReader(resp.Body, MaxFeedBytes+1))
	if err != nil {
		return nil, "", fmt.Errorf("feed %s: %w", redact(f.URL), err)
	}
	if len(b) > MaxFeedBytes {
		return nil, "", fmt.Errorf("feed %s: larger than %d bytes", redact(f.URL), MaxFeedBytes)
	}
	prefixes, created, err := ParseFeed(b)
	if err != nil {
		return nil, "", fmt.Errorf("feed %s: %w", redact(f.URL), err)
	}
	return prefixes, created, nil
}

// redact drops the query and user info of a URL (a mirror's token).
func redact(s string) string {
	p, err := url.Parse(s)
	if err != nil {
		return "(invalid URL)"
	}
	p.User, p.RawQuery, p.Fragment = nil, "", ""
	return p.String()
}

// Run updates now and then every every; after a failure, again in an hour
// (or every, if shorter). Logs only: bundles keep the latest stored list.
func (u *Updater) Run(ctx context.Context, every time.Duration) {
	retry := min(time.Hour, every)
	for {
		v, changed, err := u.Update(ctx)
		next := every
		switch {
		case err != nil && v == "":
			log.Printf("[WARN] good bots: %v (retry in %s)", err, retry)
			next = retry
		case err != nil:
			log.Printf("[WARN] good bots: version %s stored, but: %v (retry in %s)", v[:12], err, retry)
			next = retry
		case changed:
			log.Printf("[INFO] good bots: version %s stored; bundles built from now carry it", v[:12])
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(next):
		}
	}
}

// ForCompiler returns the latest list for strata-compile --good-bots: nil
// when none is stored yet (bundles then carry no ranges and rule 500001
// does not match); an error when the store fails, so that a deploy does not
// silently drop the ranges.
func ForCompiler(objects Objects, isNotFound func(error) bool) func(context.Context) ([]byte, error) {
	return func(ctx context.Context) ([]byte, error) {
		l, err := Latest(ctx, objects, isNotFound)
		if err != nil || l == nil {
			return nil, err
		}
		return json.Marshal(struct {
			Version  string              `json:"version"`
			Crawlers map[string][]string `json:"crawlers"`
		}{l.Version, l.Crawlers})
	}
}
