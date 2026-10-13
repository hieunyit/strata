package corpus

import (
	"strings"
	"testing"
)

func TestClean(t *testing.T) {
	keep := map[string]string{
		"' OR '1'='1":               "' OR '1'='1",
		"<script>alert(1)</script>": "<script>alert(1)</script>",
		"Exploit String: <IMG SRC=javascript:alert('XSS')>": "<IMG SRC=javascript:alert('XSS')>",
		"/etc/passwd": "/etc/passwd",
		"|id":         "|id",
	}
	for in, want := range keep {
		if got, ok := Clean(in); !ok || got != want {
			t.Errorf("Clean(%q) = %q, %v; want %q", in, got, ok, want)
		}
	}
	for _, in := range []string{"", "   ", "# credit to rsnake", "Exploit Name: Obfuscated DOM element creation",
		"Exploit Description: This vector breaks double quoted attributes and produces an alert.",
		"delete", "having", "A very short cross browser header injection", "Exploit String:"} {
		if got, ok := Clean(in); ok {
			t.Errorf("Clean(%q) kept %q", in, got)
		}
	}
}

func TestPreEncodedPayloadsAreSentAsWritten(t *testing.T) {
	enc := Payload{Payload: "%27%7C%7Cecho%20X$((1%2B1))&", AttackType: "command-injection"}
	reqs := Requests(enc, "x")
	if !strings.HasSuffix(reqs[0].URI, "q=%27%7C%7Cecho%20X$((1%2B1))&") {
		t.Errorf("pre-encoded payload escaped again: %s", reqs[0].URI)
	}
	if reqs[1].Body != "comment=%27%7C%7Cecho%20X$((1%2B1))&" {
		t.Errorf("form: %s", reqs[1].Body)
	}
	raw := Payload{Payload: "50% off; rm -rf /", AttackType: "command-injection"}
	if r := Requests(raw, "y"); !strings.Contains(r[0].URI, "50%25+off") {
		t.Errorf("a payload with a raw %% and spaces must be escaped: %s", r[0].URI)
	}
}
