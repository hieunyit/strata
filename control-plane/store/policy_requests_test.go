package store_test

import (
	"errors"
	"reflect"
	"strings"
	"sync"
	"testing"

	"github.com/strata/strata/control-plane/localauth/localauthtest"
	"github.com/strata/strata/control-plane/store"
)

func TestPolicyEditRequestInPostgres(t *testing.T) {
	pool := localauthtest.Pool(t)
	ctx := t.Context()
	s := store.New(pool)
	audit := store.Audit{Actor: "operator", Subject: "operator-sub", Channel: "api", Action: "policy.create", Resource: "policies/example-api"}
	first, err := s.CreatePolicy(ctx, store.Policy{ID: "example-api", Name: "example-api", Spec: []byte(`{"mode":"shadow"}`)}, audit)
	if err != nil {
		t.Fatal(err)
	}
	audit.RequestID = "exception-request"
	audit.Action = "exceptions.fromBlockId"
	spec := []byte(`{"mode":"enforce"}`)
	const n = 12
	var wg sync.WaitGroup
	replies := make(chan store.Policy, n)
	for range n {
		wg.Add(1)
		go func() {
			defer wg.Done()
			p, err := store.New(pool).UpdatePolicyOnce(ctx, first.ID, first.Etag, spec, audit)
			if err != nil {
				t.Error(err)
				return
			}
			replies <- p
		}()
	}
	wg.Wait()
	close(replies)
	var edited store.Policy
	count := 0
	for p := range replies {
		if count == 0 {
			edited = p
		}
		if !reflect.DeepEqual(p, edited) {
			t.Errorf("concurrent retries differ")
		}
		count++
	}
	if count != n || edited.CurrentVersion != 2 || edited.Etag == first.Etag {
		t.Fatalf("replies=%d version=%d", count, edited.CurrentVersion)
	}
	entries, err := s.AuditEntries(ctx, 100)
	if err != nil || len(entries) != 2 {
		t.Fatalf("audit entries=%d: %v", len(entries), err)
	}
	if _, err := s.UpdatePolicyOnce(ctx, first.ID, first.Etag, []byte(`{"mode":"shadow"}`), audit); !errors.Is(err, store.ErrRequestReused) {
		t.Fatalf("different command accepted: %v", err)
	}
	laterAudit := audit
	laterAudit.RequestID = "later"
	later, err := s.UpdatePolicyOnce(ctx, first.ID, edited.Etag, []byte(`{"mode":"shadow"}`), laterAudit)
	if err != nil || later.CurrentVersion != 3 {
		t.Fatalf("later edit: %+v %v", later, err)
	}
	retry, err := store.New(pool).UpdatePolicyOnce(ctx, first.ID, first.Etag, spec, audit)
	if err != nil || !reflect.DeepEqual(retry, edited) {
		t.Fatalf("delayed retry changed response: %+v %v", retry, err)
	}
	versions, err := s.ListPolicyVersions(ctx, first.ID)
	if err != nil || len(versions) != 3 || versions[1].State != store.VersionDraft {
		t.Fatalf("versions=%+v err=%v", versions, err)
	}
	rollback := audit
	rollback.RequestID = "rollback"
	rollback.Channel = "invalid"
	if _, err := s.UpdatePolicyOnce(ctx, first.ID, later.Etag, spec, rollback); err == nil {
		t.Fatal("invalid audit committed")
	}
	current, err := s.GetPolicy(ctx, first.ID)
	if err != nil || current.Etag != later.Etag {
		t.Fatal("audit failure leaked policy update")
	}
	rollback.Channel = "api"
	if _, err := s.UpdatePolicyOnce(ctx, first.ID, later.Etag, spec, rollback); err != nil {
		t.Fatalf("rollback leaked request reservation: %v", err)
	}
	missing := audit
	missing.RequestID = ""
	if _, err := s.UpdatePolicyOnce(ctx, first.ID, later.Etag, spec, missing); err == nil {
		t.Fatal("missing request accepted")
	}
	stale := audit
	stale.RequestID = "stale"
	if _, err := s.UpdatePolicyOnce(ctx, first.ID, first.Etag, spec, stale); !errors.Is(err, store.ErrEtagMismatch) {
		t.Fatalf("stale edit accepted: %v", err)
	}
}

func TestPolicyEditRequestRejectsInvalidInputBeforeIO(t *testing.T) {
	valid := store.Audit{Subject: "operator-sub", RequestID: "request"}
	tests := []struct {
		id, etag string
		spec     []byte
		a        store.Audit
	}{
		{"", "etag", []byte(`{}`), valid},
		{"policy", "", []byte(`{}`), valid},
		{"policy", "etag", []byte(`{`), valid},
		{"policy", "etag", []byte(`{}`), store.Audit{RequestID: "request"}},
		{"policy", "etag", []byte(`{}`), store.Audit{Subject: "operator-sub"}},
		{"policy", "etag", []byte(`{}`), store.Audit{Subject: "operator-sub", RequestID: strings.Repeat("x", 129)}},
		{"policy", "etag", []byte(`"` + strings.Repeat("x", 256*1024) + `"`), valid},
	}
	for i, tt := range tests {
		if _, err := store.New(nil).UpdatePolicyOnce(t.Context(), tt.id, tt.etag, tt.spec, tt.a); err == nil {
			t.Errorf("case %d accepted", i)
		}
	}
}
