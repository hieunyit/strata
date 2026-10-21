package health

import (
	"github.com/strata/strata/control-plane/auth"
	"github.com/strata/strata/control-plane/localauth/localauthtest"
	"github.com/strata/strata/control-plane/store"
	"testing"
	"time"
)

func TestHealthNodeScopeAndPersistence(t *testing.T) {
	pool := localauthtest.Pool(t)
	st := store.New(pool)
	ctx := t.Context()
	now := time.Now().UTC()
	if _, err := pool.Exec(ctx, `INSERT INTO connector_groups(id,name) VALUES('edge','Edge');INSERT INTO nodes(id,group_id,connected,last_seen_at) VALUES('own','edge',true,now()),('other','edge',true,now())`); err != nil {
		t.Fatal(err)
	}
	if err := st.RecordNodeTelemetry(ctx, "own", store.NodeTelemetry{MetricsAvailable: true, FailOpen: 12, Spool: &store.SpoolTelemetry{Bytes: 100, LimitBytes: 1000}}, now); err != nil {
		t.Fatal(err)
	}
	nodes, truncated, err := store.New(pool).HealthNodes(ctx, []string{"own"})
	if err != nil || truncated || len(nodes) != 1 || nodes[0].Telemetry.FailOpen != 12 {
		t.Fatalf("persisted health: %+v %v", nodes, err)
	}
	service := Service{Store: st, Now: func() time.Time { return now }}
	p := &auth.Principal{Roles: []auth.Role{auth.RoleViewer}, Access: &auth.Access{Resources: map[string]map[auth.Permission]bool{"nodes/own": {auth.PermNodesRead: true}}}}
	result := service.Collect(ctx, p)
	if len(result.Nodes) != 1 || result.Nodes[0].ID != "own" {
		t.Fatal("node scope leaked")
	}
	for _, c := range result.Nodes[0].Checks {
		if c.ID == "fail_open" && c.Value != nil {
			t.Fatal("route scope disclosed shared node counts")
		}
	}
}
