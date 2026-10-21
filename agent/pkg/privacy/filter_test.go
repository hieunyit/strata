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
