package store

import (
	"github.com/strata/strata/control-plane/localauth/localauthtest"
	"testing"
	"time"
)

func TestOperationalCounterGrowthBaselineAndReset(t *testing.T) {
	pool := localauthtest.Pool(t)
	st := New(pool)
	ctx := t.Context()
	now := time.Now().UTC()
	if _, err := pool.Exec(ctx, `INSERT INTO connector_groups(id,name) VALUES('example-group','Example');INSERT INTO nodes(id,group_id) VALUES('node-a','example-group')`); err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct {
		n             uint64
		offset        time.Duration
		growth, known bool
	}{{9, 0, false, false}, {10, time.Minute, true, true}, {10, 2 * time.Minute, false, true}, {1, 3 * time.Minute, false, false}, {12, 10 * time.Minute, false, false}, {13, 11 * time.Minute, true, true}} {
		growth, known, err := st.OperationCounterGrowth(ctx, "fail_open", "node-a", c.n, now.Add(c.offset))
		if err != nil || growth != c.growth || known != c.known {
			t.Fatalf("counter %+v: %v/%v %v", c, growth, known, err)
		}
	}
}
