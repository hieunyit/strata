package replay

import (
	"encoding/json"

	"github.com/strata/strata/agent/pkg/privacy"
)

func privateRecord(r Record, f *privacy.Filter) Record {
	r.RawURI = f.URL(r.RawURI)
	r.URI = f.URL(r.URI)
	r.Args = f.Query(r.Args)
	r.Body = f.Body(r.Body)
	var pairs [][2]string
	if json.Unmarshal([]byte(r.Headers), &pairs) != nil {
		r.Headers = "[]"
		return r
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
