// Package apidiscovery consumes a dedicated trusted backend-observation feed.
// It never treats security violation events as representative traffic.
package apidiscovery

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"mime"
	"net/netip"
	"net/url"
	"regexp"
	"strings"
	"time"
)

type Observation struct {
	ID              string    `json:"id"`
	RouteID         string    `json:"route_id"`
	Method          string    `json:"method"`
	Path            string    `json:"path"`
	ContentType     string    `json:"content_type"`
	BodyBytes       int64     `json:"body_bytes"`
	BackendStatus   int       `json:"backend_status"`
	BackendResponse bool      `json:"backend_response"`
	SourceIP        string    `json:"source_ip"`
	At              time.Time `json:"at"`
}
type Sample struct {
	Key         string    `json:"key"`
	RouteID     string    `json:"route_id"`
	Method      string    `json:"method"`
	Path        string    `json:"path"`
	ContentType string    `json:"content_type"`
	BodyBytes   int64     `json:"body_bytes"`
	Source      string    `json:"source"`
	At          time.Time `json:"at"`
}

var observationID = regexp.MustCompile(`^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$`)
var methods = map[string]bool{"GET": true, "HEAD": true, "POST": true, "PUT": true, "PATCH": true, "DELETE": true, "OPTIONS": true}
var literals = map[string]bool{}

func init() {
	for _, s := range strings.Fields("api v1 v2 v3 users user orders order products product accounts account auth login logout sessions session search health ready status items item public private admin profile settings files upload download reports events payments payment invoices invoice cart checkout token refresh oauth callback webhooks metrics version") {
		literals[s] = true
	}
}

// Unknown path segments become parameters, including alphabetic identifiers.
// A small public vocabulary prevents emails, tokens and names entering storage.
func NormalizePath(raw string) (string, error) {
	if len(raw) == 0 || len(raw) > 2048 || raw[0] != '/' {
		return "", fmt.Errorf("discovery: invalid path")
	}
	raw, _, _ = strings.Cut(raw, "?")
	raw, _, _ = strings.Cut(raw, "#")
	decoded, err := url.PathUnescape(raw)
	if err != nil || strings.ContainsAny(decoded, "\r\n\t\\\x00") {
		return "", fmt.Errorf("discovery: invalid path")
	}
	parts := strings.Split(strings.TrimSuffix(decoded, "/"), "/")
	if len(parts) > 33 {
		return "", fmt.Errorf("discovery: too many segments")
	}
	n := 0
	forceParameter := false
	for i := 1; i < len(parts); i++ {
		segment := parts[i]
		if segment == "" || segment == "." || segment == ".." {
			return "", fmt.Errorf("discovery: noncanonical path")
		}
		if forceParameter || !literals[segment] {
			n++
			parts[i] = fmt.Sprintf("{param%d}", n)
			forceParameter = false
		} else {
			forceParameter = segment == "users" || segment == "user" || segment == "accounts" || segment == "account" || segment == "orders" || segment == "order" || segment == "sessions" || segment == "session" || segment == "products" || segment == "product" || segment == "invoices" || segment == "invoice" || segment == "files"
		}
	}
	normalized := strings.Join(parts, "/")
	if normalized == "" {
		normalized = "/"
	}
	if len(normalized) > 512 {
		return "", fmt.Errorf("discovery: path too long")
	}
	return normalized, nil
}
func Normalize(v Observation, key []byte, scope string, now time.Time) (Sample, error) {
	var out Sample
	if len(key) != 32 || !observationID.MatchString(v.ID) || !methods[v.Method] || !v.BackendResponse || v.BackendStatus < 200 || v.BackendStatus > 299 || v.BodyBytes < 0 || v.BodyBytes > 16<<20 || v.At.Before(now.Add(-24*time.Hour)) || v.At.After(now.Add(5*time.Second)) {
		return out, fmt.Errorf("discovery: ineligible observation")
	}
	ip, err := netip.ParseAddr(v.SourceIP)
	if err != nil || ip.Zone() != "" || ip.IsUnspecified() || ip.IsMulticast() {
		return out, fmt.Errorf("discovery: invalid source")
	}
	ip = ip.Unmap()
	path, err := NormalizePath(v.Path)
	if err != nil {
		return out, err
	}
	media := "none"
	if v.ContentType != "" {
		if len(v.ContentType) > 256 {
			return out, fmt.Errorf("discovery: content type too long")
		}
		media, _, err = mime.ParseMediaType(v.ContentType)
		if err != nil {
			return out, fmt.Errorf("discovery: invalid content type")
		}
		switch media {
		case "application/json", "application/x-www-form-urlencoded", "multipart/form-data", "text/plain", "application/octet-stream":
		default:
			media = "other"
		}
	}
	h := hmac.New(sha256.New, key)
	_, _ = h.Write([]byte("strata/discovery/v1/" + scope + "/" + v.At.UTC().Format("2006-01-02") + "/" + ip.String()))
	identity := hmac.New(sha256.New, key)
	_, _ = identity.Write([]byte("strata/discovery/observation/v1/" + scope + "/" + v.ID))
	return Sample{Key: hex.EncodeToString(identity.Sum(nil)), RouteID: v.RouteID, Method: v.Method, Path: path, ContentType: media, BodyBytes: v.BodyBytes, Source: hex.EncodeToString(h.Sum(nil)), At: v.At.UTC()}, nil
}

type Gate struct {
	Enabled           bool
	ApprovalReference string
	ApprovalExpires   time.Time
	TrustedCollectors map[string]bool
	Key               []byte
}

func (g Gate) Approved(now time.Time) bool {
	return g.Enabled && len(g.Key) == 32 && len(g.ApprovalReference) > 0 && len(g.ApprovalReference) <= 128 && now.Before(g.ApprovalExpires) && len(g.TrustedCollectors) > 0
}
