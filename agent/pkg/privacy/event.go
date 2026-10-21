package privacy

import (
	eventv1 "github.com/strata/strata/agent/gen/strata/event/v1"
	"google.golang.org/protobuf/proto"
)

// Event copies producer memory before applying the same filter to every sink.
func (f *Filter) Event(input *eventv1.Event) *eventv1.Event {
	if input == nil {
		return nil
	}
	out := proto.Clone(input).(*eventv1.Event)
	out.Path = f.URL(out.Path)
	out.UserAgent = f.Text(out.UserAgent)
	out.Referer = f.URL(out.Referer)
	out.Identity = f.Identity(out.Identity)
	for _, h := range out.Headers {
		if h == nil {
			continue
		}
		h.Value = []byte(f.Field(h.Name, string(h.Value)))
	}
	for _, m := range out.Matches {
		if m == nil {
			continue
		}
		m.Snippet = []byte(f.Field(m.Field, string(m.Snippet)))
	}
	if f != nil && f.strict {
		out.ClientIp = Mask
		out.RequestId = Mask
		out.Host = Mask
		out.Headers = nil
		for _, m := range out.Matches {
			if m != nil {
				m.Field = Mask
			}
		}
	}
	return out
}
