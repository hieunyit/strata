package investigation

import (
	"bytes"
	"strings"
	"testing"
)

func TestCSVInjection(t *testing.T) {
	for _, s := range []string{"=cmd()", "+1", "-1", "@SUM(A1)", "\tvalue", "\rvalue", "  =cmd()", "\ufeff=cmd()", "\n@SUM(A1)"} {
		if got := CSVCell(s); got != "'"+s {
			t.Errorf("unsafe %q -> %q", s, got)
		}
	}
	for _, s := range []string{"GET", "/api/search", "hello,world", "a\"b", "123", ""} {
		if CSVCell(s) != s {
			t.Errorf("changed ordinary cell %q", s)
		}
	}
	var out bytes.Buffer
	if err := writeRow(&out, []string{"=cmd()", "comma,value", "quoted\"value"}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "'=cmd()") || !strings.Contains(out.String(), `"comma,value"`) {
		t.Fatal(out.String())
	}
}
