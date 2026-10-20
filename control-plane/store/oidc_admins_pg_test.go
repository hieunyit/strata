package store_test

import (
	"context"
	"testing"

	"github.com/strata/strata/control-plane/store"
)

func TestOIDCAdminSignInsInPostgres(t *testing.T) {
	s := store.New(migratedPool(t))
	ctx := context.Background()
	if ok, err := s.OIDCAdminSignedIn(ctx); err != nil || ok {
		t.Fatalf("empty: %v %v", ok, err)
	}
	if err := s.RecordOIDCAdmin(ctx, "local:admin", "admin"); err == nil {
		t.Fatal("a local subject recorded as an OIDC admin")
	}
	for range 2 {
		if err := s.RecordOIDCAdmin(ctx, "oidc:1234", "alice"); err != nil {
			t.Fatal(err)
		}
	}
	if ok, err := s.OIDCAdminSignedIn(ctx); err != nil || !ok {
		t.Fatalf("after a sign-in: %v %v", ok, err)
	}
}
