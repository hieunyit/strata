package health

import (
	"archive/tar"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"
)

var number = regexp.MustCompile(`^[0-9]{1,20}$`)
var pair = regexp.MustCompile(`^[0-9]{1,20}/[0-9]{1,20}$`)
var version = regexp.MustCompile(`^(dev|v?[0-9]+\.[0-9]+\.[0-9]+([.+-][a-zA-Z0-9.-]+)?)$`)
var allowedChecks = map[string]bool{}

func init() {
	for _, id := range strings.Fields("postgres lease clickhouse artifact_disk postgres_disk clickhouse_disk ingest_queue invalid_events ingest_lag event_clock_skew requests not_inspected body_skipped breaker shadow_events fleet failed_operations heartbeat bundle_drift certificate fail_open dropped_events spool_bytes spool_capacity spool_pending spool_dropped") {
		allowedChecks[id] = true
	}
}

// SupportSnapshot is an allowlist, not an attempt to regex-redact raw logs.
// Unknown fields, identifiers, arbitrary advice and string values never escape.
func SupportSnapshot(s Snapshot) Snapshot {
	if !version.MatchString(s.Version) {
		s.Version = "redacted"
	}
	if s.Scope != "global" && s.Scope != "applications" {
		s.Scope = "unknown"
	}
	clean := func(in []Check) []Check {
		out := []Check{}
		for _, c := range in {
			if !allowedChecks[c.ID] {
				continue
			}
			c.Advice = c.ID
			switch c.State {
			case Healthy, Degraded, Unknown, Stale, Unavailable:
			default:
				c.State = Unknown
			}
			if c.Value != nil {
				valid := number.MatchString(*c.Value)
				if c.ID == "certificate" {
					valid = *c.Value == "healthy" || *c.Value == "unknown" || *c.Value == "expired" || *c.Value == "expiring"
				}
				if c.ID == "bundle_drift" {
					valid = pair.MatchString(*c.Value)
				}
				if !valid {
					c.Value = nil
				}
			}
			switch c.Unit {
			case "count", "bytes", "seconds", "requests_15m", "events_15m", "actual/desired", "":
			default:
				c.Unit = ""
			}
			out = append(out, c)
		}
		return out
	}
	s.Checks = clean(s.Checks)
	nodes := []Node{}
	for i, n := range s.Nodes {
		nodes = append(nodes, Node{ID: fmt.Sprintf("node-%03d", i+1), Checks: clean(n.Checks)})
	}
	s.Nodes = nodes
	return s
}

var allowedConfig = map[string]bool{"local-auth": true, "ui": true, "single-control-plane": true, "in-memory": true, "events-ttl-days": true, "objects-keep-bundles": true, "replay-threads": true, "rollout-soak": true, "lease-ttl": true, "replay-timeout": true, "canary-min-requests": true, "canary-block-factor": true, "canary-block-floor": true, "canary-error-factor": true, "canary-error-delta": true, "canary-latency-factor": true, "canary-latency-delta": true}
var safeSetting = regexp.MustCompile(`^(true|false|[0-9]+(\.[0-9]+)?(ns|us|µs|ms|s|m|h)?([0-9]+(\.[0-9]+)?(ns|us|µs|ms|s|m|h))*)$`)

func SupportConfig(config map[string]string) map[string]string {
	out := map[string]string{}
	for key, value := range config {
		if allowedConfig[key] && len(value) <= 64 && safeSetting.MatchString(value) {
			out[key] = value
		}
	}
	return out
}

// WriteSupport writes a private archive with fixed members and hash manifest.
// Existing paths, including symlinks, are never replaced.
func WriteSupport(path string, snapshot Snapshot, config map[string]string) (err error) {
	snapshot = SupportSnapshot(snapshot)
	payload, err := json.MarshalIndent(snapshot, "", "  ")
	if err != nil {
		return err
	}
	settings, err := json.MarshalIndent(SupportConfig(config), "", "  ")
	if err != nil {
		return err
	}
	var logs strings.Builder
	for _, c := range snapshot.Checks {
		fmt.Fprintf(&logs, "%s %s %s\n", snapshot.At.Format(time.RFC3339), c.ID, c.State)
	}
	entries := map[string][]byte{"health.json": payload, "config.json": settings, "doctor.log": []byte(logs.String())}
	type file struct {
		Name   string `json:"name"`
		Size   int    `json:"size"`
		SHA256 string `json:"sha256"`
	}
	manifest := struct {
		Format  int    `json:"format"`
		Version string `json:"version"`
		Files   []file `json:"files"`
	}{Format: 1, Version: snapshot.Version}
	names := []string{}
	for name := range entries {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		data := entries[name]
		if len(data) > 4<<20 {
			return errors.New("support: report too large")
		}
		sum := sha256.Sum256(data)
		manifest.Files = append(manifest.Files, file{Name: name, Size: len(data), SHA256: hex.EncodeToString(sum[:])})
	}
	entries["manifest.json"], err = json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		return err
	}
	names = append(names, "manifest.json")
	tmp, err := os.CreateTemp(filepath.Dir(path), ".strata-support-*")
	if err != nil {
		return err
	}
	defer func() { _ = os.Remove(tmp.Name()) }()
	zipped := gzip.NewWriter(tmp)
	archive := tar.NewWriter(zipped)
	closed := false
	defer func() {
		if !closed {
			err = errors.Join(err, archive.Close(), zipped.Close())
		}
		err = errors.Join(err, tmp.Close())
	}()
	for _, name := range names {
		data := entries[name]
		if err := archive.WriteHeader(&tar.Header{Name: name, Mode: 0600, Size: int64(len(data)), ModTime: snapshot.At}); err != nil {
			return err
		}
		if _, err := archive.Write(data); err != nil {
			return err
		}
	}
	if err := archive.Close(); err != nil {
		return err
	}
	if err := zipped.Close(); err != nil {
		return err
	}
	closed = true
	if err := tmp.Sync(); err != nil {
		return err
	}
	// The temp file is in the same directory, and Link gives O_EXCL semantics.
	return os.Link(tmp.Name(), path)
}
