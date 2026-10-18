package api

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/strata/strata/control-plane/admin"
	"github.com/strata/strata/control-plane/auth"
	"github.com/strata/strata/control-plane/ingest"
	"github.com/strata/strata/control-plane/localauth"
	"github.com/strata/strata/control-plane/localauth/localauthtest"
	"github.com/strata/strata/control-plane/store"
)

func TestMachineCredentialBrowserLab(t *testing.T) {
	host, network, build, out := os.Getenv("STRATA_BROWSER_HOST_REPO"), os.Getenv("STRATA_BROWSER_NETWORK"), os.Getenv("STRATA_BROWSER_UI_BUILD"), os.Getenv("STRATA_MACHINE_EVIDENCE_DIR")
	if host == "" || network == "" || build == "" || out == "" {
		t.Skip("isolated machine browser fixture not configured")
	}
	if _, err := os.Stat(filepath.Join(build, "index.html")); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(out, 0755); err != nil {
		t.Fatal("fresh evidence directory required:", err)
	}
	pool := localauthtest.Pool(t)
	pg := store.New(pool)
	accounts := localauth.NewStore(pool)
	sessions, err := localauth.NewService(accounts, 15*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	var secret [24]byte
	if _, err := rand.Read(secret[:]); err != nil {
		t.Fatal(err)
	}
	password := hex.EncodeToString(secret[:])
	for _, role := range []string{"admin", "viewer", "approver"} {
		hash, err := localauth.HashPassword(password)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := accounts.CreateUser(t.Context(), "example-"+role, hash, []string{role}, "system:lab"); err != nil {
			t.Fatal(err)
		}
	}
	dispatch := auth.Dispatch{Local: sessions, LocalPrefix: localauth.TokenPrefix, ServiceAccountPrefix: auth.ServiceAccountTokenPrefix, ServiceAccount: auth.NewServiceAccountAuthenticator(pg)}
	adm, err := admin.New(t.Context(), dispatch, admin.BuildInfo{Version: "example-machine-browser"}, admin.Deps{Policies: pg, Operations: pg, ReplayKick: func() {}})
	if err != nil {
		t.Fatal(err)
	}
	defer adm.Close()
	api := NewServer(ServerConfig{Auth: dispatch, Admin: adm.Gateway, Local: &localauth.Handler{Service: sessions, Store: accounts}, ServiceAccounts: pg, Audit: pg, StagingNotices: pg}, ingest.NewMockEventStore())
	mux := http.NewServeMux()
	mux.Handle("/v1/", api.Handler())
	mux.Handle("/", http.FileServer(http.Dir(build)))
	server := httptest.NewServer(mux)
	defer server.Close()
	ctx, cancel := context.WithTimeout(t.Context(), 2*time.Minute)
	defer cancel()
	var fixtureID [6]byte
	if _, err := rand.Read(fixtureID[:]); err != nil {
		t.Fatal(err)
	}
	name := "strata-machine-browser-" + hex.EncodeToString(fixtureID[:])
	defer func() {
		cleanup, done := context.WithTimeout(context.Background(), 5*time.Second)
		defer done()
		raw, err := exec.CommandContext(cleanup, "docker", "rm", "-f", name).CombinedOutput()
		if err != nil && !strings.Contains(string(raw), "No such container") {
			t.Errorf("private browser cleanup: %v", err)
		}
	}()
	cmd := exec.CommandContext(ctx, "docker", "run", "--rm", "--name", name, "--network", network, "--cpuset-cpus=11-12", "-u", fmt.Sprintf("%d:%d", os.Getuid(), os.Getgid()), "-v", host+":/src", "-w", "/src/ui",
		"-e", "STRATA_MACHINE_LAB_URL", "-e", "STRATA_MACHINE_LAB_PASSWORD", "-e", "STRATA_MACHINE_EVIDENCE_DIR", "mcr.microsoft.com/playwright:v1.64.0-noble", "npx", "--no-install", "playwright", "test", "-c", "playwright.machine.config.ts", "--output", filepath.Join(out, "results"))
	cmd.Env = append(os.Environ(), "STRATA_MACHINE_LAB_URL="+server.URL, "STRATA_MACHINE_LAB_PASSWORD="+password, "STRATA_MACHINE_EVIDENCE_DIR="+out)
	raw, err := cmd.CombinedOutput()
	t.Logf("%s", raw)
	if err != nil {
		t.Fatal("private machine browser:", err)
	}
	var accountsLeft, tokensLeft, receipts, audits int
	if err := pool.QueryRow(t.Context(), `SELECT (SELECT count(*) FROM machine_accounts),(SELECT count(*) FROM machine_tokens),(SELECT count(*) FROM machine_requests),(SELECT count(*) FROM audit_log WHERE action LIKE '/v1/service-accounts%')`).Scan(&accountsLeft, &tokensLeft, &receipts, &audits); err != nil {
		t.Fatal(err)
	}
	if accountsLeft != 0 || tokensLeft != 0 || receipts != 6 || audits != 6 {
		t.Fatalf("unexpected durable result accounts=%d tokens=%d receipts=%d audits=%d", accountsLeft, tokensLeft, receipts, audits)
	}
	hashes := map[string]string{}
	for label, file := range map[string]string{
		"control-plane/api/service_account_handler.go":     "service_account_handler.go",
		"control-plane/auth/service_account.go":            "../auth/service_account.go",
		"control-plane/store/machine_credentials.go":       "../store/machine_credentials.go",
		"ui/src/components/users/ServiceAccountTokens.tsx": "../../ui/src/components/users/ServiceAccountTokens.tsx",
		"ui/src/pages/UsersPage.tsx":                       "../../ui/src/pages/UsersPage.tsx",
		"ui/src/api/client.ts":                             "../../ui/src/api/client.ts",
		"ui-build/index.html":                              filepath.Join(build, "index.html"),
	} {
		data, err := os.ReadFile(file)
		if err != nil {
			t.Fatal(err)
		}
		sum := sha256.Sum256(data)
		hashes[label] = hex.EncodeToString(sum[:])
	}
	metadata := map[string]any{"hashes": hashes, "audits": audits, "receipts": receipts, "remaining_accounts": accountsLeft, "remaining_tokens": tokensLeft, "scope": "real Chromium/local auth/API/PostgreSQL, response lost after commit, scoped token denial; no NGINX/deploy/production"}
	data, err := json.MarshalIndent(metadata, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(out, "postgres-result.json"), append(data, '\n'), 0644); err != nil {
		t.Fatal(err)
	}
	t.Log("PASS: lost-response retry kept one issuance; one-time secret, scoped auth and revoke; six atomic audited writes; viewer/approver refused")
}
