package api

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/strata/strata/control-plane/admin"
	"github.com/strata/strata/control-plane/auth"
	"github.com/strata/strata/control-plane/ingest"
	"github.com/strata/strata/control-plane/localauth"
	"github.com/strata/strata/control-plane/localauth/localauthtest"
	"github.com/strata/strata/control-plane/policy"
	"github.com/strata/strata/control-plane/store"
)

func TestExceptionDraftBrowserLab(t *testing.T) {
	host, network, build, output := os.Getenv("STRATA_BROWSER_HOST_REPO"), os.Getenv("STRATA_BROWSER_NETWORK"), os.Getenv("STRATA_BROWSER_UI_BUILD"), os.Getenv("STRATA_EXCEPTION_EVIDENCE_DIR")
	if host == "" || network == "" || build == "" || output == "" {
		t.Skip("isolated exception browser fixture not configured")
	}
	if _, err := os.Stat(filepath.Join(build, "index.html")); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(output, 0755); err != nil {
		t.Fatal("new evidence directory required:", err)
	}
	pool := localauthtest.Pool(t)
	fixture, pg, original := exceptionServerWithPool(t, pool)
	stored, err := fixture.handler.store.GetEvent(t.Context(), exceptionBlock)
	if err != nil {
		t.Fatal(err)
	}
	event := *stored
	event.NodeID, event.PolicyVersion, event.ConnectorType = "example-node", 1, "nginx"
	event.ClientIP, event.RequestID, event.StatusCode = "198.51.100.42", "example-request", 403
	event.ReceivedAt, event.MatchedRules = event.Timestamp, []uint32{700011}
	event.ScoreSQLi, event.ScoreAnomaly = 100, 100
	seeded := ingest.NewMockEventStore()
	if err := seeded.SaveEvents(t.Context(), []ingest.Event{event}); err != nil {
		t.Fatal(err)
	}
	accounts := localauth.NewStore(pool)
	sessions, err := localauth.NewService(accounts, 15*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	var secret [24]byte
	if _, err = rand.Read(secret[:]); err != nil {
		t.Fatal(err)
	}
	password := hex.EncodeToString(secret[:])
	for _, role := range []string{"operator", "viewer", "approver"} {
		hash, err := localauth.HashPassword(password)
		if err != nil {
			t.Fatal(err)
		}
		if _, err = accounts.CreateUser(t.Context(), "example-"+role, hash, []string{role}, "system:lab"); err != nil {
			t.Fatal(err)
		}
	}
	dispatch := auth.Dispatch{Local: sessions, LocalPrefix: localauth.TokenPrefix}
	adm, err := admin.New(t.Context(), dispatch, admin.BuildInfo{Version: "example-browser"}, admin.Deps{Policies: pg, Operations: pg, ReplayKick: func() {}})
	if err != nil {
		t.Fatal(err)
	}
	defer adm.Close()
	cfg := fixture.cfg
	cfg.Auth, cfg.Admin = dispatch, adm.Gateway
	cfg.Local = &localauth.Handler{Service: sessions, Store: accounts}
	cfg.StagingNotices = pg
	server := NewServer(cfg, seeded)
	mux := http.NewServeMux()
	mux.Handle("/v1/", server.Handler())
	mux.Handle("/", http.FileServer(http.Dir(build)))
	httpServer := httptest.NewServer(mux)
	defer httpServer.Close()
	ctx, cancel := context.WithTimeout(t.Context(), 2*time.Minute)
	defer cancel()
	cmd := exec.CommandContext(ctx, "docker", "run", "--rm", "--network", network, "--cpuset-cpus=11-12", "-u", fmt.Sprintf("%d:%d", os.Getuid(), os.Getgid()),
		"-v", host+":/src", "-w", "/src/ui", "-e", "STRATA_EXCEPTION_LAB_URL", "-e", "STRATA_EXCEPTION_LAB_PASSWORD", "-e", "STRATA_EXCEPTION_EVIDENCE_DIR",
		"mcr.microsoft.com/playwright:v1.64.0-noble", "npx", "--no-install", "playwright", "test", "-c", "playwright.exceptions.config.ts", "--output", filepath.Join(output, "results"))
	cmd.Env = append(os.Environ(), "STRATA_EXCEPTION_LAB_URL="+httpServer.URL, "STRATA_EXCEPTION_LAB_PASSWORD="+password, "STRATA_EXCEPTION_EVIDENCE_DIR="+output)
	raw, err := cmd.CombinedOutput()
	t.Logf("%s", raw)
	if err != nil {
		t.Fatal("private exception browser:", err)
	}
	draft, err := pg.GetPolicy(t.Context(), original.ID)
	if err != nil || draft.CurrentVersion != 2 {
		t.Fatalf("draft version: %d %v", draft.CurrentVersion, err)
	}
	spec, err := policy.Parse(draft.Spec)
	if err != nil || len(spec.Exceptions) != 1 {
		t.Fatalf("persisted scope: %+v %v", spec.Exceptions, err)
	}
	e := spec.Exceptions[0]
	if e.RuleID != 700011 || e.Field != "ARGS:Name" || e.Method != "GET" || e.Host != "api.example.test" || e.Path != "/search" || e.SourceBlockID != exceptionBlock || e.Reason != "example legitimate request" {
		t.Fatalf("scope changed: %+v", e)
	}
	version, err := pg.GetPolicyVersion(t.Context(), original.ID, 2)
	if err != nil || version.State != store.VersionDraft {
		t.Fatalf("state: %s %v", version.State, err)
	}
	op, err := pg.LatestReplay(t.Context(), original.ID, 2)
	if err != nil || op.State != store.OpPending {
		t.Fatalf("durable replay queue: %s %v", op.State, err)
	}
	var fields map[string]json.RawMessage
	if err = json.Unmarshal(draft.Spec, &fields); err != nil {
		t.Fatal(err)
	}
	var future struct {
		Keep bool `json:"keep"`
	}
	if err := json.Unmarshal(fields["future_setting"], &future); err != nil || !future.Keep || spec.MaxArgs != 200 {
		t.Fatal("existing settings lost:", err)
	}
	audits, err := pg.AuditEntries(t.Context(), 100)
	if err != nil {
		t.Fatal(err)
	}
	n := 0
	for _, a := range audits {
		if a.Action == "exceptions.fromBlockId" {
			n++
		}
	}
	if n != 1 {
		t.Fatalf("writes from operator/viewer/approver: %d", n)
	}
	t.Logf("PASS browser: one scoped DRAFT v2, replay PENDING, one audited exception write; viewer/approver refused; source policy %s", original.ID)
}
