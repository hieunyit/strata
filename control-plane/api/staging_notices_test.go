package api

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/strata/strata/control-plane/ingest"
	"github.com/strata/strata/control-plane/store"
)

type noticeReadFunc func(context.Context, *time.Time, string, int) ([]store.StagingNotice, error)

func (f noticeReadFunc) StagingNotices(c context.Context, b *time.Time, id string, n int) ([]store.StagingNotice, error) {
	return f(c, b, id, n)
}

func TestStagingNoticeReadPermissionPaginationAndNoWrites(t *testing.T) {
	calls := 0
	now := time.Now().UTC()
	reader := noticeReadFunc(func(_ context.Context, before *time.Time, id string, n int) ([]store.StagingNotice, error) {
		calls++
		if n != 2 {
			t.Errorf("unbounded limit: %d", n)
		}
		if before != nil {
			if !before.Equal(now) || id != "example-b" {
				t.Error("cursor lost")
			}
			return nil, nil
		}
		return []store.StagingNotice{{ID: "example-b", CreatedAt: now, Matches: "18446744073709551615", Reports: "5", RolloutState: "PENDING"}, {ID: "example-a", CreatedAt: now}}, nil
	})
	s := NewServer(ServerConfig{Auth: tokenRoles{}, StagingNotices: reader}, ingest.NewMockEventStore())
	path := "/v1/rules/staging-actions?limit=1"
	for _, tc := range []struct {
		role string
		want int
	}{{"", 401}, {"viewer", 403}, {"operator", 403}, {"approver", 200}, {"admin", 200}} {
		code, body := do(t, s, "GET", path, tc.role, nil)
		if code != tc.want {
			t.Fatalf("%s: %d %v", tc.role, code, body)
		}
		if code == 200 {
			rows := body["notices"].([]any)
			if len(rows) != 1 || rows[0].(map[string]any)["matches"] != "18446744073709551615" || body["next_cursor"] == "" {
				t.Fatal(body)
			}
		}
	}
	_, first := do(t, s, "GET", path, "approver", nil)
	if code, body := do(t, s, "GET", path+"&cursor="+first["next_cursor"].(string), "approver", nil); code != 200 || len(body["notices"].([]any)) != 0 {
		t.Fatalf("next: %d %v", code, body)
	}
	req := httptest.NewRequest("GET", path, nil)
	req.Header.Set("Authorization", "Bearer approver")
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, req)
	if w.Header().Get("Cache-Control") != "no-store" || calls != 5 {
		t.Fatalf("cache/authorization reached store: %d %s", calls, w.Header().Get("Cache-Control"))
	}
	if code, _ := do(t, s, "POST", path, "approver", nil); code != 405 {
		t.Fatal("write method accepted")
	}
}

func TestStagingNoticeRejectsBadInputAndHidesErrors(t *testing.T) {
	calls := 0
	s := NewServer(ServerConfig{Auth: tokenRoles{}, StagingNotices: noticeReadFunc(func(context.Context, *time.Time, string, int) ([]store.StagingNotice, error) {
		calls++
		return nil, errors.New("private-fixture-db-detail")
	})}, ingest.NewMockEventStore())
	for _, query := range []string{"limit=0", "limit=51", "limit=a", "limit=1&limit=2", "unknown=1", "cursor=", "cursor=%%%", "cursor=e30", "cursor=a&cursor=b", "cursor=" + strings.Repeat("a", 1025)} {
		if code, body := do(t, s, "GET", "/v1/rules/staging-actions?"+query, "approver", nil); code != 400 {
			t.Fatalf("%s: %d %v", query, code, body)
		}
	}
	if calls != 0 {
		t.Fatal("invalid input queried store")
	}
	if code, body := do(t, s, "GET", "/v1/rules/staging-actions", "approver", nil); code != 503 || strings.Contains(body["error"].(string), "private-") {
		t.Fatalf("error leak: %d %v", code, body)
	}
	empty := NewServer(ServerConfig{Auth: tokenRoles{}}, ingest.NewMockEventStore())
	if code, _ := do(t, empty, http.MethodGet, "/v1/rules/staging-actions", "approver", nil); code != 404 {
		t.Fatalf("missing store: %d", code)
	}
}
