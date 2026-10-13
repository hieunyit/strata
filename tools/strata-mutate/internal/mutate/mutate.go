// Package mutate makes variants of attack payloads the way attackers try to
// slip past a WAF (W09-S-02): each transform keeps what the payload does
// for a target that decodes it, and changes how it looks to the WAF.
package mutate

import (
	"net/url"
	"strings"

	"golang.org/x/text/unicode/norm"
)

// Variant is one way a payload is sent: the value of the parameter, and
// when Split is set, a second value of the same parameter (HPP), the
// target joining the two.
type Variant struct {
	Transform string
	Value     string
	Split     string
	// Encoded: Value (and Split) are already URL-encoded and go into the
	// request as they are
	Encoded bool
}

// Transforms, in report order.
var Transforms = []string{
	"double-url-encoding",
	"case-swap",
	"sql-comment-spaces",
	"tab-spaces",
	"vertical-tab-spaces",
	"nbsp-spaces",
	"unicode-nfd",
	"unicode-nfc",
	"parameter-splitting",
	"case-swap+sql-comment-spaces",
	"double-url-encoding+case-swap",
}

// Of returns the variants of payload, one per transform, without those that
// leave the payload as it is (a transform with nothing to work on).
func Of(payload string) []Variant {
	var out []Variant
	add := func(name, v string) {
		if v != payload {
			out = append(out, Variant{Transform: name, Value: v})
		}
	}
	// the request carries %25XX for each %XX: a target that decodes twice
	// gets the payload back, a WAF that decodes once sees %XX
	out = append(out, Variant{Transform: "double-url-encoding", Value: url.QueryEscape(url.QueryEscape(payload)), Encoded: true})
	add("case-swap", caseSwap(payload))
	add("sql-comment-spaces", strings.ReplaceAll(payload, " ", "/**/"))
	add("tab-spaces", strings.ReplaceAll(payload, " ", "\t"))
	add("vertical-tab-spaces", strings.ReplaceAll(payload, " ", "\v"))
	add("nbsp-spaces", strings.ReplaceAll(payload, " ", " "))
	add("unicode-nfd", norm.NFD.String(payload))
	add("unicode-nfc", norm.NFC.String(payload))
	if len(payload) >= 4 {
		mid := len(payload) / 2
		for mid < len(payload) && !utf8Start(payload[mid]) {
			mid++
		}
		out = append(out, Variant{Transform: "parameter-splitting", Value: payload[:mid], Split: payload[mid:]})
	}
	add("case-swap+sql-comment-spaces", strings.ReplaceAll(caseSwap(payload), " ", "/**/"))
	if cs := caseSwap(payload); cs != payload {
		out = append(out, Variant{Transform: "double-url-encoding+case-swap", Value: url.QueryEscape(url.QueryEscape(cs)), Encoded: true})
	}
	return out
}

// caseSwap alternates upper and lower case over the ASCII letters
// (sElEcT): case-insensitive targets read the same.
func caseSwap(s string) string {
	b := []byte(s)
	up := false
	for i, c := range b {
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z':
			if up {
				b[i] = c &^ 0x20
			} else {
				b[i] = c | 0x20
			}
			up = !up
		}
	}
	return string(b)
}

func utf8Start(c byte) bool { return c&0xc0 != 0x80 }
