package privacy

import (
	"strings"
	"testing"
)

func TestPolicyPrivacyAcrossStructuredAndTextSinks(t *testing.T) {
	f, err := New([]string{"customer_id"}, []string{`PRIVATE-[0-9]+`})
	if err != nil {
		t.Fatal(err)
	}
	for _, v := range []string{f.Field("ARGS:customer_id", "customer-secret"), f.URL("/api?%70assword=example-password&q=public&customer_id=customer-secret#private"), string(f.Body([]byte(`{"nested":{"password":"example-password"},"customer_id":"customer-secret","text":"PRIVATE-123 email@example.test"}`))), f.Text("Bearer example-credential PRIVATE-123")} {
		for _, secret := range []string{"customer-secret", "example-password", "example-credential", "PRIVATE-123", "email@example.test", "#private"} {
			if strings.Contains(v, secret) {
				t.Fatal("privacy leak", secret)
			}
		}
	}
	if got := f.URL("/api?q=public"); got != "/api?q=public" {
		t.Fatal("ordinary route changed", got)
	}
	if f.Field("ARGS:customer_id", "x") != Mask {
		t.Fatal("engine variable prefix ignored")
	}
	for _, pattern := range []string{"(unclosed", "a*", strings.Repeat("x", 257)} {
		if _, err := New(nil, []string{pattern}); err == nil {
			t.Fatal("invalid pattern accepted")
		}
	}
	if string(f.Body([]byte(strings.Repeat("[", 40)+`"x"`+strings.Repeat("]", 40)))) != Mask {
		t.Fatal("unbounded JSON depth")
	}
	if f.Text(strings.Repeat("x", MaxText+1)) != Mask {
		t.Fatal("unbounded text")
	}
	if strings.Contains(f.Query("password=%xx"), "%xx") {
		t.Fatal("malformed query leaked")
	}
}

func TestReplayPreservesDuplicateKeysNumbersAndOrdinaryEncoding(t *testing.T) {
	f, err := New(nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	raw := `{"q":"<attack>","q":"safe","escaped":"\u003cattack\u003e","big":900719925474099312345}`
	if got := string(f.Body([]byte(raw))); got != raw {
		t.Fatalf("JSON structure changed: %s", got)
	}
	query := "z=1&a=%2f&q=one%20two&z=2"
	if got := f.Query(query); got != query {
		t.Fatalf("ordinary query changed: %s", got)
	}
	path := "/api/%2f?q=ordinary%20text"
	if got := f.URL(path); got != path {
		t.Fatalf("ordinary URI changed: %s", got)
	}
	if got := string(f.Body([]byte("1=1 AND 2=2"))); got != "1=1 AND 2=2" {
		t.Fatal("plaintext interpreted as a form", got)
	}
	if got := string(f.Body([]byte(`{"password":"example-secret"}{}`))); got != Mask {
		t.Fatal("malformed JSON leaked", got)
	}
}

func TestAnonymousSourceValuesRemainComparable(t *testing.T) {
	f, err := New(nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	token := "~h:1234567890123456:a12"
	if f.Field("password", token) != token {
		t.Fatal("protected token lost equality")
	}
	if got := string(f.Body([]byte(`{"password":"` + token + `"}`))); got != `{"password":"`+token+`"}` {
		t.Fatal("protected JSON token lost equality", got)
	}
	for _, raw := range []string{"192.0.2.1", "hmac:not-a-hash", "~h:plain-secret:a12"} {
		if IsPseudonym(raw) {
			t.Fatal("raw identity passed pseudonym validation")
		}
	}
}

func TestMaskReplacementCannotAmplifyWithoutBound(t *testing.T) {
	f, err := New(nil, []string{".", ".", "."})
	if err != nil {
		t.Fatal(err)
	}
	if got := f.Text(strings.Repeat("a", MaxText)); got != Mask {
		t.Fatal("mask amplification not bounded", len(got))
	}
	json := `{` + strings.TrimSuffix(strings.Repeat(`"pin":0,`, 9000), ",") + `}`
	if got := f.Body([]byte(json)); len(got) > MaxText {
		t.Fatal("JSON output unbounded", len(got))
	}
}
