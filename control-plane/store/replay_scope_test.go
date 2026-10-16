package store_test

import (
	"testing"

	"github.com/strata/strata/control-plane/localauth/localauthtest"
	"github.com/strata/strata/control-plane/store"
)

func TestReplaySampleScopeInPostgres(t *testing.T) {
	p := localauthtest.Pool(t)
	ctx := t.Context()
	_, err := p.Exec(ctx, `INSERT INTO connector_groups(id,name) VALUES ('edge','Edge');
		INSERT INTO policies(id,name,etag,created_by) VALUES ('p','example-api','e','test');
		INSERT INTO bundles(version,sha256,object_key,size_bytes,created_by,contents)
		VALUES (1,decode(repeat('00',32),'hex'),'bundle-1',1,'test','{"p":1}');
		INSERT INTO nodes(id,group_id,bundle_version) VALUES ('node-a','edge',1);`)
	if err != nil {
		t.Fatal(err)
	}
	s := store.New(p)
	if key, _, err := s.ReplaySampleScope(ctx, "node-a"); err != nil || key != "" {
		t.Fatalf("sampling disabled: %s %v", key, err)
	}
	r, _, err := s.SetReplaySampling(ctx, "edge", 100, false, nil, store.Audit{Actor: "test", Action: "sampling", Resource: "edge"})
	if err != nil {
		t.Fatal(err)
	}
	key, policies, err := s.ReplaySampleScope(ctx, "node-a")
	if err != nil || key != r.KeyID || !policies["example-api"] || len(policies) != 1 {
		t.Fatalf("scope: %s %v %v", key, policies, err)
	}
	if _, err := p.Exec(ctx, `UPDATE nodes SET revoked_at=now() WHERE id='node-a'`); err != nil {
		t.Fatal(err)
	}
	if key, _, err := s.ReplaySampleScope(ctx, "node-a"); err != nil || key != "" {
		t.Fatalf("revoked scope: %s %v", key, err)
	}
}
