package seclang

import (
	"reflect"
	"strings"
	"testing"
)

const sample = `# comment
SecRule REQUEST_METHOD "@rx ^(?:GET|HEAD)$" \
    "id:920170,\
    phase:1,\
    block,\
    t:none,\
    msg:'GET or HEAD Request with Body Content',\
    tag:'paranoia-level/1',\
    severity:'CRITICAL',\
    chain"
    SecRule REQUEST_HEADERS:Content-Length "!@rx ^0?$" \
        "t:none,t:lowercase,\
        setvar:'tx.inbound_anomaly_score_pl1=+%{tx.critical_anomaly_score}'"

SecRule &REQUEST_HEADERS:Host|ARGS|!ARGS:foo "@eq 0" "id:920280,phase:1,pass,nolog"
SecRule REQUEST_URI "attack" "id:900100,phase:2,deny"
SecAction "id:900990,phase:1,pass,t:none,nolog,setvar:tx.crs_setup_version=4250"
SecMarker "END-REQUEST-920"
`

func parse(t *testing.T, src string) *File {
	t.Helper()
	f, err := Parse("x.conf", src)
	if err != nil {
		t.Fatal(err)
	}
	return f
}

func TestParseRules(t *testing.T) {
	f := parse(t, sample)
	if len(f.Errors) != 0 {
		t.Fatalf("errors: %v", f.Errors)
	}
	if len(f.Rules) != 4 {
		t.Fatalf("%d rules, want 4 (the chain folds into 920170)", len(f.Rules))
	}
	r := f.Rules[0]
	if r.ID != 920170 || r.Phase != "1" || r.Severity != "CRITICAL" || r.Line != 2 || len(r.Chain) != 2 {
		t.Fatalf("920170: %+v", r)
	}
	if r.Msg != "GET or HEAD Request with Body Content" || r.ParanoiaLevel() != 1 {
		t.Errorf("meta: msg %q pl %d", r.Msg, r.ParanoiaLevel())
	}
	if got := r.Operators(); !reflect.DeepEqual(got, []string{"@rx", "!@rx"}) {
		t.Errorf("operators %v", got)
	}
	if got := r.Transforms(); !reflect.DeepEqual(got, []string{"none", "lowercase"}) {
		t.Errorf("transforms %v", got)
	}
	if got := r.Variables(); !reflect.DeepEqual(got, []string{"REQUEST_METHOD", "REQUEST_HEADERS:Content-Length"}) {
		t.Errorf("variables %v", got)
	}
	if r.Chain[1].Line != 11 || !strings.HasPrefix(r.Chain[1].Argument, "^0") {
		t.Errorf("chain link: %+v", r.Chain[1])
	}

	if got := f.Rules[1].Variables(); !reflect.DeepEqual(got, []string{"&REQUEST_HEADERS:Host", "ARGS", "!ARGS:foo"}) {
		t.Errorf("negated and counted variables: %v", got)
	}
	if f.Rules[2].Chain[0].Operator != "rx" {
		t.Errorf("an operator without @name is rx, got %q", f.Rules[2].Chain[0].Operator)
	}
	a := f.Rules[3]
	if a.ID != 900990 || a.Directive != "SecAction" || len(a.Variables()) != 0 || !reflect.DeepEqual(a.Transforms(), []string{"none"}) {
		t.Errorf("SecAction: %+v", a)
	}
	if f.Directives["SecRule"] != 4 || f.Directives["SecAction"] != 1 || f.Directives["SecMarker"] != 1 {
		t.Errorf("directives %v", f.Directives)
	}
}

func TestSyntaxErrorsAreReported(t *testing.T) {
	f := parse(t, `SecRule ARGS "@rx a" "id:1,phase:2,deny`+"\n") // no closing quote
	if len(f.Errors) == 0 {
		t.Fatal("no syntax error reported")
	}
	f = parse(t, `SecRule ARGS "@rx a" "id:2,phase:2,deny,chain"`+"\n")
	if len(f.Errors) == 0 || !strings.Contains(f.Errors[len(f.Errors)-1], "chain") {
		t.Fatalf("unterminated chain: %v", f.Errors)
	}
}
