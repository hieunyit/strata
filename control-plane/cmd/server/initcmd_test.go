package main

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/strata/strata/control-plane/config"
	"github.com/strata/strata/control-plane/db"
	"github.com/strata/strata/control-plane/localauth"
	"github.com/strata/strata/control-plane/setup"
)

// CP-A05: init on an empty database and data directory makes everything
// a control plane needs, its config loads, the admin signs in; init again
// keeps everything; admin recover sets a new password, unlocks and ends the
// sessions.
func TestInitAndRecoverInPostgres(t *testing.T) {
	dsn := os.Getenv("STRATA_TEST_POSTGRES_DSN")
	if dsn == "" {
		t.Skip("STRATA_TEST_POSTGRES_DSN not set")
	}
	ctx := context.Background()
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)
	t.Cleanup(func() { _ = db.Migrate(context.Background(), pool, 0) })
	_ = db.Migrate(ctx, pool, 0)

	dir := t.TempDir()
	pw := filepath.Join(t.TempDir(), "pw")
	if err := os.WriteFile(pw, []byte("correct horse battery\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("STRATA_POSTGRES_DSN", dsn)
	t.Setenv("STRATA_CLICKHOUSE_PASSWORD", "ch-secret")
	if err := runInit(dir, "cp.example.test", "admin", pw, "", "clickhouse:9000", ""); err != nil {
		t.Fatal(err)
	}
	for _, p := range []string{setup.CACert, setup.ServerCert, setup.NodeCACert, setup.BundleKey, setup.BundlePub, setup.ConfigFile, setup.DSNFile, setup.CHPassword} {
		if _, err := os.Stat(filepath.Join(dir, p)); err != nil {
			t.Errorf("%s: %v", p, err)
		}
	}
	// the written config loads (secrets are files of mode 600)
	cfg, err := config.Load(filepath.Join(dir, setup.ConfigFile))
	if err != nil {
		t.Fatal(err)
	}
	// no -s3-endpoint: artifacts in the data directory (CP-A07)
	if p := cfg.Bundles.Storage.Local.Path; p == nil || *p != filepath.Join(dir, setup.ObjectsDir) || cfg.Bundles.Storage.S3.Endpoint != nil {
		t.Fatalf("storage: local %v, s3 %v", p, cfg.Bundles.Storage.S3.Endpoint)
	}
	svc, err := localauth.NewService(localauth.NewStore(pool), time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	sess, err := svc.Login(ctx, "admin", "correct horse battery", "192.0.2.1", "test")
	if err != nil {
		t.Fatalf("admin login: %v", err)
	}
	// a second init changes nothing and asks for no password
	seed, _ := os.ReadFile(filepath.Join(dir, setup.BundleKey))
	if err := runInit(dir, "other.example.test", "admin", "", "", "x:1", ""); err != nil {
		t.Fatal(err)
	}
	if again, _ := os.ReadFile(filepath.Join(dir, setup.BundleKey)); string(again) != string(seed) {
		t.Fatal("signing key replaced")
	}

	// the admin locks itself out; recover from the host
	for range 6 {
		_, _ = svc.Login(ctx, "admin", "wrong password!!", "192.0.2.1", "test")
	}
	if _, err := svc.Login(ctx, "admin", "correct horse battery", "192.0.2.2", "test"); err == nil {
		t.Fatal("not locked after failures")
	}
	newPW := filepath.Join(t.TempDir(), "new")
	if err := os.WriteFile(newPW, []byte("a brand new passphrase"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := runRecover(dir, "admin", newPW, ""); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.Authenticate(ctx, sess.Token); err == nil {
		t.Fatal("old session survived recovery")
	}
	if _, err := svc.Login(ctx, "admin", "a brand new passphrase", "192.0.2.3", "test"); err != nil {
		t.Fatalf("login after recovery: %v", err)
	}
	var actor string
	if err := pool.QueryRow(ctx, `SELECT actor FROM audit_log WHERE action = 'local_users.set_password' ORDER BY id DESC LIMIT 1`).Scan(&actor); err != nil || !strings.HasPrefix(actor, "system:recover (") {
		t.Fatalf("audit: %q %v", actor, err)
	}
	if err := runRecover(dir, "nobody", newPW, ""); err == nil {
		t.Fatal("recovered an account that does not exist")
	}
	if err := runRecover(dir, "admin", pw+"-missing", ""); err == nil {
		t.Fatal("recovered without a password")
	}
}
