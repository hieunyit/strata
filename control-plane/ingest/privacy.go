package ingest

import "github.com/strata/strata/agent/pkg/privacy"

func RedactEvent(e Event, f *privacy.Filter) Event {
	e.HTTPPath = f.URL(e.HTTPPath)
	e.UserAgent = f.Text(e.UserAgent)
	e.Referer = f.URL(e.Referer)
	e.Identity = f.Identity(e.Identity)
	hs := append([]Header(nil), e.Headers...)
	for i := range hs {
		hs[i].Value = f.Field(hs[i].Name, hs[i].Value)
	}
	e.Headers = hs
	vs := append([]Violation(nil), e.Violations...)
	for i := range vs {
		vs[i].Snippet = f.Field(vs[i].Field, vs[i].Snippet)
	}
	e.Violations = vs
	return e
}
