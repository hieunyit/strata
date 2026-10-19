package main

import (
	"strings"
	"testing"
)

func TestPolicyPinFlagsRequireStandalone(t *testing.T) {
	for _, flag := range []string{"--required-policy=example-api", "--require-full-enforce"} {
		_, err := execute(t, "run", flag)
		if err == nil || !strings.Contains(err.Error(), "requires --standalone") {
			t.Fatalf("%s: %v", flag, err)
		}
	}
}
