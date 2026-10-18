package rulehealth

import (
	"errors"
	"testing"
	"time"
)

func TestWriterObservationPreservesScopeCountsAndError(t *testing.T) {
	source := &evaluationSource{matches: 100, reports: 5}
	now := time.Now().UTC()
	s := NewService(source, source)
	e, err := s.Observe(t.Context(), delegationSpec(), 942100, "example-api", 7, now)
	if err != nil || e.RuleID != 942100 || e.PolicyName != "example-api" || e.BundleVersion != 7 || !e.To.Equal(now) || e.To.Sub(e.From) != 5*time.Minute || e.Matches != 100 || e.Reports != 5 {
		t.Fatalf("observation: %+v %v", e, err)
	}
	sentinel := errors.New("query unavailable")
	source.reportErr = sentinel
	if _, err = s.Observe(t.Context(), delegationSpec(), 942100, "example-api", 7, now); !errors.Is(err, sentinel) {
		t.Fatalf("error hidden: %v", err)
	}
}
