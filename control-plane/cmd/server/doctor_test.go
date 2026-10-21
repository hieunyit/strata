package main

import (
	"context"
	"encoding/json"
	"errors"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/strata/strata/control-plane/health"
	"github.com/strata/strata/control-plane/localauth/localauthtest"
)

func TestDoctorHelperProcess(t *testing.T) {
	if os.Getenv("STRATA_DOCTOR_HELPER") != "1" {
		return
	}
	os.Args = []string{"strata-control-plane", "doctor", "-json", "-config", os.Getenv("STRATA_DOCTOR_CONFIG"), "-support-bundle", os.Getenv("STRATA_DOCTOR_BUNDLE")}
	main()
}
func TestDoctorReadOnlyAndPrivateSupport(t *testing.T) {
	pool := localauthtest.Pool(t)
	ctx := t.Context()
	var before int
	if err := pool.QueryRow(ctx, "SELECT count(*) FROM pg_tables WHERE schemaname='public'").Scan(&before); err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	cfg := filepath.Join(dir, "config.yaml")
	out := filepath.Join(dir, "support.tar.gz")
	if err := os.WriteFile(cfg, []byte("version: 1\nevents:\n  clickhouse:\n    address: 127.0.0.1:1\n"), 0600); err != nil {
		t.Fatal(err)
	}
	parsed, err := url.Parse(pool.Config().ConnString())
	if err != nil {
		t.Fatal(err)
	}
	query := parsed.Query()
	query.Set("options", "-c default_transaction_read_only=on")
	parsed.RawQuery = query.Encode()
	bounded, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	cmd := exec.CommandContext(bounded, os.Args[0], "-test.run=^TestDoctorHelperProcess$")
	cmd.Env = append(os.Environ(), "STRATA_DOCTOR_HELPER=1", "STRATA_DOCTOR_CONFIG="+cfg, "STRATA_DOCTOR_BUNDLE="+out, "STRATA_POSTGRES_DSN="+parsed.String(), "STRATA_LOCAL_ADMIN_PASSWORD=example-secret-not-for-export")
	output, err := cmd.CombinedOutput()
	var exit *exec.ExitError
	if !errors.As(err, &exit) || (exit.ExitCode() != 2 && exit.ExitCode() != 3) {
		t.Fatalf("doctor should report incomplete dependencies: %v %s", err, output)
	}
	var snapshot health.Snapshot
	if err := json.Unmarshal(output, &snapshot); err != nil {
		t.Fatalf("invalid doctor JSON: %v %s", err, output)
	}
	if strings.Contains(string(output), "example-secret-not-for-export") {
		t.Fatal("doctor printed credential")
	}
	st, err := os.Stat(out)
	if err != nil || st.Mode().Perm() != 0600 {
		t.Fatal("private archive missing")
	}
	var after int
	if err := pool.QueryRow(ctx, "SELECT count(*) FROM pg_tables WHERE schemaname='public'").Scan(&after); err != nil || before != after {
		t.Fatal("doctor changed schema")
	}
}
