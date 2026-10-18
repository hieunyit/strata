package policy

import (
	"encoding/json"
	"strings"
	"testing"
)

func exampleException() Exception {
	return Exception{ID: "exc-0123456789abcdef0123456789abcdef", RuleID: 700011,
		Method: "GET", Host: "api.example.test", Path: "/search", Field: "ARGS:Name",
		ExpiresUnixMS: 4000000000000, Reason: "example legitimate query", SourceBlockID: "STR-0000-0000-0000-0001"}
}
func TestExceptionSpecRoundTripAndBounds(t *testing.T) {
	good := exampleException()
	for _, field := range []string{"ARGS:Name", "ARGS:tên", "ARGS:Name|base64", "REQUEST_HEADERS:X-Example-Filter"} {
		e := good
		e.Field = field
		raw, err := json.Marshal(Spec{Mode: "enforce", Exceptions: []Exception{e}})
		if err != nil {
			t.Fatal(err)
		}
		got, err := Parse(raw)
		if err != nil || len(got.Exceptions) != 1 || got.Exceptions[0] != e {
			t.Fatalf("round trip: %+v %v", got, err)
		}
	}
	edits := []func(*Exception){
		func(e *Exception) { e.ID = "exc-bad" }, func(e *Exception) { e.RuleID = 0 }, func(e *Exception) { e.Method = "get" },
		func(e *Exception) { e.Host = "*.example.test" }, func(e *Exception) { e.Path = "/search/*" },
		func(e *Exception) { e.Path = "/search?a=1" }, func(e *Exception) { e.Path = "/bad\x7f" },
		func(e *Exception) { e.Path = "/" + strings.Repeat("a", 2048) }, func(e *Exception) { e.Field = "ARGS:*" },
		func(e *Exception) { e.Field = "REQUEST_BODY" }, func(e *Exception) { e.Field = "REQUEST_HEADERS:a b" },
		func(e *Exception) { e.Field = "ARGS:a\u2003b" }, func(e *Exception) { e.Field = "ARGS:" + strings.Repeat("a", 129) },
		func(e *Exception) { e.ExpiresUnixMS = 0 }, func(e *Exception) { e.Reason = "  " },
		func(e *Exception) { e.Reason = strings.Repeat("a", 501) }, func(e *Exception) { e.SourceBlockID = "bad" },
	}
	for i, edit := range edits {
		e := good
		edit(&e)
		if err := (Spec{Mode: "enforce", Exceptions: []Exception{e}}).Validate(); err == nil {
			t.Errorf("invalid %d accepted", i)
		}
	}
	if err := (Spec{Mode: "enforce", Exceptions: []Exception{good, good}}).Validate(); err == nil {
		t.Fatal("duplicate accepted")
	}
	if err := (Spec{Mode: "enforce", Exceptions: make([]Exception, 129)}).Validate(); err == nil {
		t.Fatal("excess count accepted")
	}
	good.ExpiresUnixMS = 1
	if err := good.Validate(); err != nil {
		t.Fatal("expiry is runtime, not deletion", err)
	}
}
