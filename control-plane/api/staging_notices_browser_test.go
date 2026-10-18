package api

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/strata/strata/control-plane/auth"
	"github.com/strata/strata/control-plane/ingest"
	"github.com/strata/strata/control-plane/localauth"
	"github.com/strata/strata/control-plane/localauth/localauthtest"
	"github.com/strata/strata/control-plane/store"
)

// Opt-in native browser check. The build and host path/network must identify
// this task's private fixture; never defaults to the shared lab's fixed ports.
func TestStagingNoticeBrowserLab(t *testing.T) {
	host := os.Getenv("STRATA_BROWSER_HOST_REPO")
	network := os.Getenv("STRATA_BROWSER_NETWORK")
	build := os.Getenv("STRATA_BROWSER_UI_BUILD")
	output := os.Getenv("STRATA_NOTICE_EVIDENCE_DIR")
	if host == "" || network == "" || build == "" || output == "" {
		t.Skip("isolated browser fixture not configured")
	}
	if _, err := os.Stat(filepath.Join(build, "index.html")); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(output, 0755); err != nil {
		t.Fatal("evidence directory must be new:", err)
	}
	pool := localauthtest.Pool(t)
	seedNoticeReadFixture(t, pool)
	accounts := localauth.NewStore(pool)
	sessions, err := localauth.NewService(accounts, 15*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	var random [24]byte
	if _, err = rand.Read(random[:]); err != nil {
		t.Fatal(err)
	}
	password := hex.EncodeToString(random[:])
	for _, role := range []struct{ name, role string }{{"example-reviewer", "approver"}, {"example-viewer", "viewer"}} {
		hash, err := localauth.HashPassword(password)
		if err != nil {
			t.Fatal(err)
		}
		if _, err = accounts.CreateUser(t.Context(), role.name, hash, []string{role.role}, "system:lab"); err != nil {
			t.Fatal(err)
		}
	}
	server := NewServer(ServerConfig{Auth: auth.Dispatch{Local: sessions, LocalPrefix: localauth.TokenPrefix}, Local: &localauth.Handler{Service: sessions, Store: accounts}, StagingNotices: store.New(pool)}, ingest.NewMockEventStore())
	mux := http.NewServeMux()
	mux.Handle("/v1/", server.Handler())
	mux.Handle("/", http.FileServer(http.Dir(build)))
	httpServer := httptest.NewServer(mux)
	defer httpServer.Close()
	ctx, cancel := context.WithTimeout(t.Context(), 2*time.Minute)
	defer cancel()
	// Password is inherited, never embedded in command arguments or artifacts.
	cmd := exec.CommandContext(ctx, "docker", "run", "--rm", "--network", network, "--cpuset-cpus=11-12", "-u", fmt.Sprintf("%d:%d", os.Getuid(), os.Getgid()),
		"-v", host+":/src", "-w", "/src/ui", "-e", "STRATA_NOTICE_LAB_URL", "-e", "STRATA_NOTICE_LAB_PASSWORD", "-e", "STRATA_NOTICE_EVIDENCE_DIR",
		"mcr.microsoft.com/playwright:v1.64.0-noble", "npx", "--no-install", "playwright", "test", "-c", "playwright.notices.config.ts", "--output", filepath.Join(output, "results"))
	cmd.Env = append(os.Environ(), "STRATA_NOTICE_LAB_URL="+httpServer.URL, "STRATA_NOTICE_LAB_PASSWORD="+password, "STRATA_NOTICE_EVIDENCE_DIR="+output)
	raw, err := cmd.CombinedOutput()
	t.Logf("%s", raw)
	if err != nil {
		t.Fatal("private browser lab:", err)
	}
}
