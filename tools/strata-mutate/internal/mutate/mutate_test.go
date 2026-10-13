package mutate

import (
	"net/url"
	"strings"
	"testing"
)

func byName(vs []Variant) map[string]Variant {
	m := map[string]Variant{}
	for _, v := range vs {
		m[v.Transform] = v
	}
	return m
}

func TestTransforms(t *testing.T) {
	v := byName(Of("1' UNION SELECT password FROM users"))
	if got := v["case-swap"].Value; got != "1' uNiOn SeLeCt PaSsWoRd FrOm UsErS" {
		t.Errorf("case-swap: %q", got)
	}
	if got := v["sql-comment-spaces"].Value; got != "1'/**/UNION/**/SELECT/**/password/**/FROM/**/users" {
		t.Errorf("sql-comment-spaces: %q", got)
	}
	if got := v["tab-spaces"].Value; strings.Contains(got, " ") || !strings.Contains(got, "\t") {
		t.Errorf("tab-spaces: %q", got)
	}
	if got := v["nbsp-spaces"].Value; !strings.Contains(got, " ") {
		t.Errorf("nbsp-spaces: %q", got)
	}
	// double encoding decodes back in two steps
	d := v["double-url-encoding"]
	if !d.Encoded || strings.Contains(d.Value, "'") {
		t.Fatalf("double-url-encoding: %+v", d)
	}
	once, _ := url.QueryUnescape(d.Value)
	twice, _ := url.QueryUnescape(once)
	if twice != "1' UNION SELECT password FROM users" || once == twice {
		t.Errorf("double-url-encoding decodes to %q then %q", once, twice)
	}
	// splitting: the two halves give the payload back
	s := v["parameter-splitting"]
	if s.Value+s.Split != "1' UNION SELECT password FROM users" || s.Value == "" || s.Split == "" {
		t.Errorf("parameter-splitting: %+v", s)
	}
}

func TestUnicode(t *testing.T) {
	// é composed (U+00E9) and decomposed (e + U+0301)
	v := byName(Of("café<script>"))
	if got := v["unicode-nfd"].Value; got != "café<script>" {
		t.Errorf("nfd: %q", got)
	}
	if _, ok := v["unicode-nfc"]; ok {
		t.Error("nfc of an NFC payload is the payload: no variant expected")
	}
	if got := byName(Of("café"))["unicode-nfc"].Value; got != "café" {
		t.Errorf("nfc: %q", got)
	}
}

func TestNoOpTransformsAreLeftOut(t *testing.T) {
	// no letters, no spaces, ASCII: only encoding and splitting apply
	v := byName(Of("../../../../"))
	for _, name := range []string{"case-swap", "sql-comment-spaces", "tab-spaces", "unicode-nfd", "unicode-nfc"} {
		if _, ok := v[name]; ok {
			t.Errorf("%s made a variant that is the payload", name)
		}
	}
	if _, ok := v["double-url-encoding"]; !ok {
		t.Error("double-url-encoding missing")
	}
	// a short payload is not split
	if _, ok := byName(Of("ab"))["parameter-splitting"]; ok {
		t.Error("split a 2-byte payload")
	}
	// splitting never cuts a UTF-8 sequence
	s := byName(Of("abéécd"))["parameter-splitting"]
	if !strings.HasSuffix(s.Value, "é") && !strings.HasPrefix(s.Split, "é") {
		t.Errorf("split inside a rune: %q | %q", s.Value, s.Split)
	}
}
