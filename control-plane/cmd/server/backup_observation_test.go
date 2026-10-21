package main

import (
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/strata/strata/control-plane/db"
	"github.com/strata/strata/control-plane/store"
	"os"
	"path/filepath"
	"testing"
)

func TestBackupFailureRecordsOnlyOperationalStatus(t *testing.T) {
	ctx := t.Context()
	pool, err := pgxpool.New(ctx, ownDatabase(t))
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()
	latest, err := db.Latest()
	if err != nil {
		t.Fatal(err)
	}
	if err = db.Migrate(ctx, pool, latest); err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	dsnFile := filepath.Join(dir, "dsn")
	if err = os.WriteFile(dsnFile, []byte(pool.Config().ConnString()), 0600); err != nil {
		t.Fatal(err)
	}
	if err = runBackup(filepath.Join(dir, "archive.age"), dir, "", filepath.Join(dir, "missing-passphrase"), dsnFile, "pg_dump"); err == nil {
		t.Fatal("invalid backup succeeded")
	}
	ok, _, err := store.New(pool).BackupObservation(ctx)
	if err != nil || ok {
		t.Fatalf("backup observation %v %v", ok, err)
	}
}
