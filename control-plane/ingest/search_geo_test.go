package ingest

import (
	"context"
	"testing"
	"time"
)

// W19-F-01: the events search takes the map's filters, counted as the
// geo aggregates count them: country and ASN of verified locations, the
// attack type from the rules matched.
func TestSearchEventsGeoFilters(t *testing.T) {
	ch := geoIPTestStore(t)
	ctx, cancel := context.WithTimeout(t.Context(), 60*time.Second)
	defer cancel()
	now := time.Now().UTC().Truncate(time.Second)
	ev := func(id, country string, asn uint32, version string, rules ...uint32) Event {
		return Event{BlockID: id, Timestamp: now, ReceivedAt: now, NodeID: "example-node", PolicyID: "example-api",
			Action: "block", CountryISO: country, ASN: asn, GeoIPVersion: version, MatchedRules: rules}
	}
	if err := ch.SaveEvents(ctx, []Event{
		ev("STR-0000-0000-0000-0001", "VN", 7552, "v1", 942100),
		ev("STR-0000-0000-0000-0002", "VN", 45899, "v1", 941100),
		ev("STR-0000-0000-0000-0003", "US", 15169, "v1", 942100),
		ev("STR-0000-0000-0000-0004", "VN", 7552, "", 942100), // location not verified
		ev("STR-0000-0000-0000-0005", "INTERNAL", 0, "", 942100),
	}); err != nil {
		t.Fatal(err)
	}
	ids := func(f SearchFilter) []string {
		f.Limit = 20
		r, err := ch.SearchEvents(context.Background(), f)
		if err != nil {
			t.Fatal(err)
		}
		var out []string
		for _, e := range r.Events {
			out = append(out, e.BlockID[len(e.BlockID)-1:])
		}
		if int(r.Total) != len(out) {
			t.Errorf("total %d, %d rows", r.Total, len(out))
		}
		return out
	}
	for _, c := range []struct {
		f    SearchFilter
		want string
	}{
		{SearchFilter{CountryISO: "VN"}, "12"},
		{SearchFilter{CountryISO: "INTERNAL"}, "5"},
		{SearchFilter{ASN: 7552}, "1"},
		{SearchFilter{CountryISO: "VN", AttackType: "sqli"}, "1"},
		{SearchFilter{AttackType: "xss"}, "2"},
		{SearchFilter{CountryISO: "VN", ASN: 15169}, ""},
	} {
		got := ""
		for _, id := range ids(c.f) {
			got += id
		}
		if sorted := sortString(got); sorted != c.want {
			t.Errorf("%+v: %q, want %q", c.f, sorted, c.want)
		}
	}
}

func sortString(s string) string {
	b := []byte(s)
	for i := range b {
		for j := i + 1; j < len(b); j++ {
			if b[j] < b[i] {
				b[i], b[j] = b[j], b[i]
			}
		}
	}
	return string(b)
}
