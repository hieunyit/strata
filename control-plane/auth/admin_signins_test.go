package auth

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"
)

type fixedAuth map[string]*Principal

func (f fixedAuth) Authenticate(_ context.Context, raw string) (*Principal, error) {
	if p, ok := f[raw]; ok {
		return p, nil
	}
	return nil, ErrUnauthenticated
}

// CP-A06: admins are recorded, once per account, others never; a failed
// write is tried again at the next sign-in.
func TestRecordAdmins(t *testing.T) {
	var mu sync.Mutex
	var got []string
	fail := true
	r := &RecordAdmins{
		Authenticator: fixedAuth{
			"admin":    {Subject: "oidc:a", Name: "alice", Roles: []Role{RoleViewer, RoleAdmin}},
			"operator": {Subject: "oidc:o", Roles: []Role{RoleOperator}},
		},
		Record: func(_ context.Context, subject, _ string) error {
			mu.Lock()
			defer mu.Unlock()
			if fail {
				fail = false
				return errors.New("database down")
			}
			got = append(got, subject)
			return nil
		},
	}
	count := func() int {
		mu.Lock()
		defer mu.Unlock()
		return len(got)
	}
	settle := func() { time.Sleep(50 * time.Millisecond) }
	ctx := context.Background()
	if _, err := r.Authenticate(ctx, "nobody"); err == nil {
		t.Fatal("unknown token accepted")
	}
	if _, err := r.Authenticate(ctx, "operator"); err != nil {
		t.Fatal(err)
	}
	if _, err := r.Authenticate(ctx, "admin"); err != nil { // the write fails
		t.Fatal(err)
	}
	settle()
	if count() != 0 {
		t.Fatalf("recorded %v", got)
	}
	for range 3 { // tried again, then not repeated within the hour
		if _, err := r.Authenticate(ctx, "admin"); err != nil {
			t.Fatal(err)
		}
		settle()
	}
	if count() != 1 || got[0] != "oidc:a" {
		t.Fatalf("recorded %v", got)
	}
}

func TestScopedAdminsDoNotUnlockOIDCOnly(t *testing.T){
 for _,p:=range []*Principal{
  {Subject:"oidc:scoped",Roles:[]Role{RoleAdmin},Access:&Access{}},
  {Subject:"local:admin",Roles:[]Role{RoleAdmin}},
 } {if isAdmin(p){t.Fatalf("non-global OIDC administrator counted: %s",p.Subject)}}
}
