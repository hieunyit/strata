package store_test

import (
	"context"
	"errors"
	"sync"
	"testing"

	"github.com/strata/strata/control-plane/auth"
	"github.com/strata/strata/control-plane/store"
)

func TestBindingChangesCannotLockOutGlobalAdministrators(t *testing.T) {
	pool := migratedPool(t)
	st := store.New(pool)
	ctx := t.Context()
	app, err := st.SaveApplication(ctx, store.Application{ID: "example-app", Name: "Example", Owner: "Owner"}, true, "create", store.Audit{Subject: "system:test", Actor: "test"})
	if err != nil {
		t.Fatal(err)
	}
	a := &auth.Principal{Subject: "local:admin-a", Roles: []auth.Role{auth.RoleAdmin}}
	with := func(p *auth.Principal) context.Context { return auth.WithPrincipal(ctx, p) }
	audit := func(p *auth.Principal) store.Audit {
		return store.Audit{Subject: p.Subject, Actor: p.Subject, Action: "binding.test"}
	}
	scoped := store.ApplicationBinding{Subject: a.Subject, Role: "viewer", ApplicationID: &app.ID}
	if _, err := st.AddApplicationBinding(with(a), scoped, audit(a)); !errors.Is(err, auth.ErrScopeDenied) {
		t.Fatalf("administrator restricted their own only global authority: %v", err)
	}
	global, err := st.AddApplicationBinding(with(a), store.ApplicationBinding{Subject: a.Subject, Role: "admin"}, audit(a))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := st.AddApplicationBinding(with(a), scoped, audit(a)); err != nil {
		t.Fatal(err)
	}
	if err := st.DeleteApplicationBinding(with(a), global.ID, audit(a)); !errors.Is(err, auth.ErrScopeDenied) {
		t.Fatalf("administrator removed their last global binding: %v", err)
	}
	// Two requests authenticated before either mutation must not demote each
	// other's global authority and leave no administrator behind.
	x := &auth.Principal{Subject: "local:admin-x", Roles: []auth.Role{auth.RoleAdmin}}
	y := &auth.Principal{Subject: "local:admin-y", Roles: []auth.Role{auth.RoleAdmin}}
	var wg sync.WaitGroup
	errs := make(chan error, 2)
	start := make(chan struct{})
	for _, pair := range [][2]*auth.Principal{{x, y}, {y, x}} {
		wg.Add(1)
		go func(actor, target *auth.Principal) {
			defer wg.Done()
			<-start
			_, err := st.AddApplicationBinding(with(actor), store.ApplicationBinding{Subject: target.Subject, Role: "viewer", ApplicationID: &app.ID}, audit(actor))
			errs <- err
		}(pair[0], pair[1])
	}
	close(start)
	wg.Wait()
	close(errs)
	allowed, denied := 0, 0
	for err := range errs {
		if err == nil {
			allowed++
		} else if errors.Is(err, auth.ErrScopeDenied) {
			denied++
		} else {
			t.Fatal(err)
		}
	}
	if allowed != 1 || denied != 1 {
		t.Fatalf("concurrent binding changes: allowed=%d denied=%d", allowed, denied)
	}
}
