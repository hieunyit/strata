package replay

import (
	"encoding/json"
	"mime"
	"strings"

	"github.com/strata/strata/agent/pkg/privacy"
)

func privateRecord(r Record, f *privacy.Filter) Record {
	r.RawURI = f.URL(r.RawURI)
	r.URI = f.URL(r.URI)
	r.Args = f.Query(r.Args)
	if r.Client != "" && !privacy.IsPseudonym(r.Client) {
		r.Client = privacy.Mask
	}
	var pairs [][2]string
	if json.Unmarshal([]byte(r.Headers), &pairs) != nil {
		r.Headers = "[]"
		r.Body = privacy.Strict().Body(r.Body)
		return r
	}
	contentType := ""
	for _, pair := range pairs {
		if strings.EqualFold(pair[0], "Content-Type") {
			contentType, _, _ = mime.ParseMediaType(pair[1])
		}
	}
	if contentType == "application/x-www-form-urlencoded" {
		r.Body = []byte(f.Query(string(r.Body)))
	} else if (contentType == "application/json" || strings.HasSuffix(contentType, "+json")) && !json.Valid(r.Body) {
		r.Body = []byte(privacy.Mask)
	} else {
		r.Body = f.Body(r.Body)
	}
	for i := range pairs {
		pairs[i][1] = f.Field(pairs[i][0], pairs[i][1])
	}
	encoded, err := json.Marshal(pairs)
	if err != nil {
		r.Headers = "[]"
	} else {
		r.Headers = string(encoded)
	}
	return r
}

func retainedRecordBytes(r Record) int64 {
	return int64(1024 + cap(r.Body) + len(r.NodeID) + len(r.Policy) + len(r.Method) + len(r.RawURI) + len(r.URI) + len(r.Args) + len(r.Proto) + len(r.Client) + len(r.Headers) + len(r.Action) + len(r.Rules) + len(r.Canary))
}
