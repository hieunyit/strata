package main

import (
	"context"
	"fmt"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/strata/strata/control-plane/db"
	"github.com/strata/strata/control-plane/store"
)

// ownDatabase makes a database of its own on the test server (a restore
// drops the schema of the database it replaces) and returns its DSN.
func ownDatabase(t *testing.T) string {
	t.Helper()
	dsn := os.Getenv("STRATA_TEST_POSTGRES_DSN")
	if dsn == "" {
		t.Skip("STRATA_TEST_POSTGRES_DSN not set")
	}
	for _, bin := range []string{"pg_dump", "pg_restore"} {
		if _, err := exec.LookPath(bin); err != nil {
			t.Skipf("%s not installed", bin)
		}
	}
	ctx := context.Background()
	admin, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(admin.Close)
	name := fmt.Sprintf("restore_test_%d", time.Now().UnixNano())
	if _, err := admin.Exec(ctx, "CREATE DATABASE "+name); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = admin.Exec(context.Background(), "DROP DATABASE IF EXISTS "+name+" WITH (FORCE)") })
	u, err := url.Parse(dsn)
	if err != nil {
		t.Fatal(err)
	}
	u.Path = "/" + name
	return u.String()
}

func record(t *testing.T, st *store.Store, v uint64) {
	t.Helper()
	if _, err := st.RecordBundle(context.Background(), store.Bundle{Version: v, SHA256: make([]byte, 32), ObjectKey: fmt.Sprintf("bundles/%020d/bundle-%d.sbn", v, v),
		SizeBytes: 1, Contents: map[string]int{}}, store.Audit{Actor: "deployer"}); err != nil {
		t.Fatal(err)
	}
}

// CP-A09: backup, then the system moves on (bundles 4..6 on the nodes, a
// node enrolled), then restore: the database is the backup's, bundles are
// numbered above what the nodes run, nothing is rolled back, rollouts
// under way at backup time are aborted, and the new node is reported.
func TestBackupRestoreInPostgres(t *testing.T) {
	dsn := ownDatabase(t)
	ctx := context.Background()
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)
	latest, _ := db.Latest()
	if err := db.Migrate(ctx, pool, latest); err != nil {
		t.Fatal(err)
	}
	st := store.New(pool)
	for v := uint64(1); v <= 3; v++ {
		record(t, st, v)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO connector_groups (id, name) VALUES ('edge', 'Edge');
		INSERT INTO nodes (id, group_id, bundle_version, desired_bundle_version) VALUES ('node-a', 'edge', 2, 3);
		INSERT INTO rollouts (bundle_version, state, waves, created_by) VALUES (3, 'RUNNING', '[1]', 't')`); err != nil {
		t.Fatal(err)
	}

	dir := t.TempDir()
	for p, data := range map[string]string{"keys/bundle-signing.key": "seed", "pki/ca.pem": "ca", "config.yaml": "version: 1\n",
		"objects/bundles/00000000000000000003/bundle-3.sbn": "bundle 3"} {
		if err := os.MkdirAll(filepath.Join(dir, filepath.Dir(p)), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, p), []byte(data), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	dsnFile := filepath.Join(t.TempDir(), "dsn")
	passFile := filepath.Join(t.TempDir(), "pass")
	_ = os.WriteFile(dsnFile, []byte(dsn), 0o600)
	_ = os.WriteFile(passFile, []byte("a long backup passphrase\n"), 0o600)
	archive := filepath.Join(t.TempDir(), "backup.tar.age")
	if err := runBackup(archive, dir, filepath.Join(dir, "objects"), passFile, dsnFile, "pg_dump"); err != nil {
		t.Fatal(err)
	}
	if err := runBackup(archive, dir, filepath.Join(dir, "objects"), passFile, dsnFile, "pg_dump"); err == nil {
		t.Fatal("an archive was overwritten")
	}
	if raw, _ := os.ReadFile(archive); strings.Contains(string(raw), "PGDMP") {
		t.Fatal("dump in clear")
	}

	// after the backup: bundles 4..6, node-a runs 6, node-b enrolls
	for v := uint64(4); v <= 6; v++ {
		record(t, st, v)
	}
	if _, err := pool.Exec(ctx, `UPDATE nodes SET bundle_version = 6, desired_bundle_version = 6;
		INSERT INTO nodes (id, group_id) VALUES ('node-b', 'edge')`); err != nil {
		t.Fatal(err)
	}

	// a live control plane: refused
	if _, err := pool.Exec(ctx, `INSERT INTO control_plane_lease (id, holder, fencing, renewed_at, expires_at) VALUES (1, 'cp', 1, now(), now() + interval '1 minute')`); err != nil {
		t.Fatal(err)
	}
	target := t.TempDir()
	if err := runRestore(archive, target, filepath.Join(target, "objects"), passFile, dsnFile, "pg_restore", true, false); err == nil || !strings.Contains(err.Error(), "lease") {
		t.Fatalf("restore under a live control plane: %v", err)
	}
	if _, err := pool.Exec(ctx, `UPDATE control_plane_lease SET expires_at = now() - interval '1 second'`); err != nil {
		t.Fatal(err)
	}
	// a file that differs: refused without -overwrite
	_ = os.WriteFile(filepath.Join(target, "config.yaml"), []byte("version: 1\n# other\n"), 0o600)
	if err := runRestore(archive, target, filepath.Join(target, "objects"), passFile, dsnFile, "pg_restore", true, false); err == nil || !strings.Contains(err.Error(), "overwrite") {
		t.Fatalf("conflicting file: %v", err)
	}
	if err := runRestore(archive, target, filepath.Join(target, "objects"), passFile, dsnFile, "pg_restore", true, true); err != nil {
		t.Fatal(err)
	}

	pool.Reset()
	var bundles, desired, floor int64
	var rollout string
	if err := pool.QueryRow(ctx, `SELECT (SELECT max(version) FROM bundles), (SELECT count(*) FROM nodes WHERE desired_bundle_version IS NOT NULL),
		(SELECT version FROM bundle_version_floor), (SELECT state FROM rollouts)`).Scan(&bundles, &desired, &floor, &rollout); err != nil {
		t.Fatal(err)
	}
	if bundles != 3 || desired != 0 || floor != 6 || rollout != "ABORTED" {
		t.Fatalf("after restore: bundles %d, desired %d, floor %d, rollout %s", bundles, desired, floor, rollout)
	}
	var lease bool
	_ = pool.QueryRow(ctx, "SELECT EXISTS (SELECT 1 FROM control_plane_lease)").Scan(&lease)
	if lease {
		t.Fatal("the lease survived the restore")
	}
	// the next deploy is numbered above what node-a runs
	if err := st.WithBundleLock(ctx, func(next uint64) error {
		if next != 7 {
			return fmt.Errorf("next bundle %d, want 7", next)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	for p, want := range map[string]string{"keys/bundle-signing.key": "seed", "config.yaml": "version: 1\n", "objects/bundles/00000000000000000003/bundle-3.sbn": "bundle 3"} {
		if got, err := os.ReadFile(filepath.Join(target, p)); err != nil || string(got) != want {
			t.Errorf("%s: %q %v", p, got, err)
		}
	}
	// restoring again: the floor stays, no file differs any more
	if err := runRestore(archive, target, filepath.Join(target, "objects"), passFile, dsnFile, "pg_restore", true, false); err != nil {
		t.Fatal(err)
	}
	pool.Reset()
	if err := pool.QueryRow(ctx, "SELECT version FROM bundle_version_floor").Scan(&floor); err != nil || floor != 6 {
		t.Fatalf("floor after a second restore: %d %v", floor, err)
	}
}
