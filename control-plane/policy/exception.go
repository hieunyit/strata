package policy

import (
	"fmt"
	"regexp"
	"strings"
	"unicode"
	"unicode/utf8"
)

// Exception removes only one field from one managed rule in an exact route.
// ID/reason/source are policy metadata; node artifacts contain scope and expiry.
type Exception struct {
	ID            string `json:"id"`
	RuleID        uint32 `json:"rule_id"`
	Method        string `json:"method"`
	Host          string `json:"host"`
	Path          string `json:"path"`
	Field         string `json:"field"`
	ExpiresUnixMS int64  `json:"expires_unix_ms"`
	Reason        string `json:"reason"`
	SourceBlockID string `json:"source_block_id,omitempty"`
}

var (
	exceptionIDPattern     = regexp.MustCompile(`^exc-[a-f0-9]{32}$`)
	exceptionMethodPattern = regexp.MustCompile(`^[A-Z-]{1,32}$`)
	exceptionHostPattern   = regexp.MustCompile(`^[a-zA-Z0-9.\-:\[\]]{1,253}$`)
	exceptionHeaderPattern = regexp.MustCompile("^[a-zA-Z0-9!#$%&'+.^_`|~-]+$")
	exceptionBlockPattern  = regexp.MustCompile(`^STR-[A-Z0-9]{4}-[A-Z0-9]{4}-[A-Z0-9]{4}-[A-Z0-9]{4}$`)
)

// Validate mirrors the runtime codec. Expired entries remain valid policy data;
// they must stay inactive at runtime and can be removed by a later draft.
func (e Exception) Validate() error {
	if !exceptionIDPattern.MatchString(e.ID) || e.RuleID == 0 || e.ExpiresUnixMS <= 0 {
		return fmt.Errorf("exception: valid id, rule_id and positive expiry required")
	}
	if !exceptionMethodPattern.MatchString(e.Method) || !exceptionHostPattern.MatchString(e.Host) {
		return fmt.Errorf("exception: exact method and host required")
	}
	if !utf8.ValidString(e.Path) || !strings.HasPrefix(e.Path, "/") || len(e.Path) > 2048 || strings.ContainsAny(e.Path, "?#\\*") {
		return fmt.Errorf("exception: exact path required")
	}
	for _, b := range []byte(e.Path) {
		if b < 0x21 || b == 0x7f {
			return fmt.Errorf("exception: invalid path byte")
		}
	}
	variable, name, ok := strings.Cut(e.Field, ":")
	if !ok || !utf8.ValidString(name) || len(e.Field) > 160 || len(name) == 0 || len(name) > 128 || strings.Contains(name, "*") {
		return fmt.Errorf("exception: exact bounded field required")
	}
	switch variable {
	case "REQUEST_HEADERS":
		if !exceptionHeaderPattern.MatchString(name) {
			return fmt.Errorf("exception: invalid header name")
		}
	case "ARGS":
		for _, r := range name {
			if unicode.IsControl(r) || unicode.IsSpace(r) {
				return fmt.Errorf("exception: invalid argument name")
			}
		}
	default:
		return fmt.Errorf("exception: only ARGS and REQUEST_HEADERS supported")
	}
	if !utf8.ValidString(e.Reason) || strings.TrimSpace(e.Reason) == "" || len(e.Reason) > 500 {
		return fmt.Errorf("exception: reason must be 1..500 bytes")
	}
	if e.SourceBlockID != "" && !exceptionBlockPattern.MatchString(e.SourceBlockID) {
		return fmt.Errorf("exception: invalid source_block_id")
	}
	return nil
}
