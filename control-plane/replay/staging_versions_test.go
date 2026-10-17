package replay

import (
	"context"
	"errors"
	"testing"

	"github.com/strata/strata/control-plane/policy"
	"github.com/strata/strata/control-plane/store"
)

func TestReplayPassesCandidateVersionsToSnapshot(t *testing.T) {
	r, ops, _ := newRunner(t)
	called := false
	r.Prepare = func(ctx context.Context, ps []policy.Named) (*policy.Prepared, error) {
		called = true
		if len(ps) != 2 || ps[0].ResourceID != "example-api" || ps[0].Version != 2 || ps[1].ResourceID != "example-web" || ps[1].Version != 4 {
			t.Fatalf("candidate versions: %+v", ps)
		}
		return nil, errors.New("stop after metadata assertion")
	}
	ops.queue = []store.Operation{{ID: "candidate-versions", PolicyID: "example-api", Version: 2}}
	r.RunOnce(t.Context())
	if !called {
		t.Fatal("snapshot not called")
	}
}
