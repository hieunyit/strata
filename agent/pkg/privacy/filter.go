// Package privacy applies the bounded P-01 field/pattern rules to Go sinks.
// It complements connector anonymization; it never restores masked source data.
package privacy

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net/url"
	"regexp"
	"strings"
)

const Mask = "[MASKED]"
const MaxText = 64 << 10

var nameParts = strings.Fields("password passwd pwd secret token otp pin cvv card cccd cmnd ssn passport apikey api_key auth session phone mobile email dob birth name user address account iban")
var pseudonym = regexp.MustCompile(`^(~h:[0-9a-f]{16}:[a-z][0-9]{1,6}|hmac:[0-9a-f]{32})$`)

// IsPseudonym recognizes the bounded P-01 anonymized wire representation.
func IsPseudonym(value string) bool { return len(value) <= 64 && pseudonym.MatchString(value) }

var builtins = []*regexp.Regexp{
	regexp.MustCompile(`eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*`),
	regexp.MustCompile(`[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}`),
	regexp.MustCompile(`\b[0-9]{12,19}\b`),
	regexp.MustCompile(`(?i)\bbearer[ \t]+[A-Za-z0-9._~+/-]+`),
	regexp.MustCompile(`(?i)\b(password|passwd|secret|token|api_key|session)[=:][^\s&;]+`),
}

type Filter struct {
	fields      map[string]bool
	patterns    []*regexp.Regexp
	identityKey []byte
	strict      bool
}

func Strict() *Filter { return &Filter{strict: true} }

// WithIdentityKey returns a copy; published filters remain immutable for readers.
func (f *Filter) WithIdentityKey(key []byte) (*Filter, error) {
	if len(key) != 32 {
		return nil, errors.New("privacy: invalid identity key")
	}
	var nonzero byte
	for _, b := range key {
		nonzero |= b
	}
	if nonzero == 0 {
		return nil, errors.New("privacy: invalid identity key")
	}
	if f == nil {
		f = &Filter{}
	}
	out := *f
	out.identityKey = append([]byte(nil), key...)
	return &out, nil
}

func (f *Filter) Identity(value string) string {
	if value == "" {
		return ""
	}
	if f != nil && len(f.identityKey) == 32 {
		if strings.HasPrefix(value, "hmac:") && len(value) == 37 {
			if _, err := hex.DecodeString(value[5:]); err == nil {
				return value
			}
		}
		h := hmac.New(sha256.New, f.identityKey)
		_, _ = h.Write([]byte(value))
		return "hmac:" + hex.EncodeToString(h.Sum(nil)[:16])
	}
	return f.Text(value)
}

func New(fields, patterns []string) (*Filter, error) {
	if len(fields) > 64 || len(patterns) > 16 {
		return nil, errors.New("privacy: too many settings")
	}
	f := &Filter{fields: map[string]bool{}}
	for _, name := range fields {
		if name == "" || len(name) > 64 {
			return nil, errors.New("privacy: invalid sensitive field")
		}
		f.fields[strings.ToLower(name)] = true
	}
	for _, p := range patterns {
		if p == "" || len(p) > 256 {
			return nil, errors.New("privacy: invalid mask pattern")
		}
		r, err := regexp.Compile(p)
		if err != nil || r.MatchString("") {
			return nil, errors.New("privacy: invalid mask pattern")
		}
		f.patterns = append(f.patterns, r)
	}
	return f, nil
}

func SensitiveName(name string) bool {
	name = strings.ToLower(name)
	switch name {
	case "cookie", "set-cookie", "x-forwarded-for", "x-real-ip", "forwarded", "true-client-ip", "cf-connecting-ip":
		return true
	}
	for _, part := range nameParts {
		if strings.Contains(name, part) {
			return true
		}
	}
	return false
}

func (f *Filter) Sensitive(name string) bool {
	return SensitiveName(name) || f != nil && f.fields[strings.ToLower(name)]
}

func (f *Filter) Text(value string) string {
	if f != nil && f.strict && value != "" {
		return Mask
	}
	if IsPseudonym(value) {
		return value
	}
	if len(value) > MaxText {
		return Mask
	}
	for _, r := range builtins {
		value = r.ReplaceAllString(value, Mask)
		if len(value) > MaxText {
			return Mask
		}
	}
	if f != nil {
		for _, r := range f.patterns {
			value = r.ReplaceAllString(value, Mask)
			if len(value) > MaxText {
				return Mask
			}
		}
	}
	return value
}

func (f *Filter) Field(name, value string) string {
	if value == "" {
		return ""
	}
	if f.Sensitive(name) {
		if (f == nil || !f.strict) && IsPseudonym(value) {
			return f.Text(value)
		}
		return Mask
	}
	// Engine fields carry a variable prefix, e.g. ARGS:customer_id.
	if _, suffix, ok := strings.Cut(name, ":"); ok && f.Sensitive(suffix) {
		return Mask
	}
	if _, suffix, ok := strings.Cut(name, ":"); ok {
		if at := strings.LastIndexByte(suffix, '.'); at >= 0 && f.Sensitive(suffix[at+1:]) {
			return Mask
		}
	}
	return f.Text(value)
}

func (f *Filter) Query(raw string) string {
	if len(raw) > MaxText {
		return "redacted=" + url.QueryEscape(Mask)
	}
	pairs := strings.Split(raw, "&")
	if len(pairs) > 1024 {
		return "redacted=" + url.QueryEscape(Mask)
	}
	for i, pair := range pairs {
		key, value, hasValue := strings.Cut(pair, "=")
		decodedKey, err := url.QueryUnescape(key)
		if err != nil {
			return "redacted=" + url.QueryEscape(Mask)
		}
		decodedValue, err := url.QueryUnescape(value)
		if err != nil {
			return "redacted=" + url.QueryEscape(Mask)
		}
		maskedKey, maskedValue := f.Text(decodedKey), f.Field(decodedKey, decodedValue)
		if maskedKey != decodedKey {
			key = url.QueryEscape(maskedKey)
		}
		if maskedValue != decodedValue {
			value = url.QueryEscape(maskedValue)
		}
		if hasValue {
			pairs[i] = key + "=" + value
		} else {
			pairs[i] = key
		}
	}
	return strings.Join(pairs, "&")
}

func (f *Filter) URL(raw string) string {
	if raw == "" {
		return ""
	}
	if len(raw) > MaxText {
		return Mask
	}
	u, err := url.Parse(raw)
	if err != nil {
		return Mask
	}
	u.User = nil
	u.Fragment = ""
	maskedPath := f.Text(u.Path)
	if maskedPath != u.Path {
		u.Path = maskedPath
		u.RawPath = ""
	}
	u.RawQuery = f.Query(u.RawQuery)
	return u.String()
}
