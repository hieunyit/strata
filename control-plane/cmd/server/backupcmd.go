package main

import (
	"bufio"
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"golang.org/x/term"

	"github.com/strata/strata/control-plane/backup"
	"github.com/strata/strata/control-plane/db"
	"github.com/strata/strata/control-plane/setup"
	"github.com/strata/strata/control-plane/store"
)

// readPassphrase reads the backup passphrase from file or the terminal
// (twice when confirm), never from a flag or the environment.
func readPassphrase(file string, confirm bool) (string, error) {
	if file != "" || confirm {
		return readPassword(file, "backup passphrase")
	}
	fd := int(os.Stdin.Fd())
	if !term.IsTerminal(fd) {
		return "", errors.New("no terminal to ask for the passphrase: give -passphrase-file")
	}
	fmt.Fprint(os.Stderr, "backup passphrase: ")
	b, err := term.ReadPassword(fd)
	fmt.Fprintln(os.Stderr)
	return string(b), err
}

// objectsDefault: the artifacts directory init makes, when it exists.
func objectsDefault(dataDir, objects string) string {
	if objects != "" {
		return objects
	}
	d := filepath.Join(dataDir, setup.ObjectsDir)
	if st, err := os.Stat(d); err == nil && st.IsDir() {
		return d
	}
	return ""
}

// backupCommand: strata-control-plane backup (CP-A09).
func backupCommand(args []string) int {
	fs := flag.NewFlagSet("backup", flag.ContinueOnError)
	out := fs.String("out", "", "Archive to write (created 0600, never overwritten), e.g. strata-backup-2026-10-20.tar.age")
	dir := fs.String("data-dir", "/var/lib/strata", "Data directory (keys, PKI, secrets, config.yaml)")
	objects := fs.String("objects-dir", "", "Artifacts directory (-objects-dir of the control plane; default <data-dir>/objects when it exists; none with an object store)")
	pass := fs.String("passphrase-file", "", "File holding the passphrase the archive is encrypted with (age, scrypt); without it, asked on the terminal")
	dsnFile := fs.String("dsn-file", "", "File holding the PostgreSQL DSN (default: STRATA_POSTGRES_DSN, then <data-dir>/secrets/postgres-dsn)")
	dump := fs.String("pg-dump", "pg_dump", "pg_dump of the server's major version or newer")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if err := runBackup(*out, *dir, objectsDefault(*dir, *objects), *pass, *dsnFile, *dump); err != nil {
		fmt.Fprintln(os.Stderr, "backup:", err)
		return 1
	}
	return 0
}

func runBackup(out, dir, objects, passFile, dsnFile, dumpBin string) (err error) {
	if out == "" {
		return errors.New("give -out")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 6*time.Hour)
	defer cancel()
	dsn, err := dsnFrom(dir, dsnFile)
	if err != nil {
		return err
	}
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		return err
	}
	migration, err := db.Version(ctx, pool)
	pool.Close()
	if err != nil {
		return err
	}
	pass, err := readPassphrase(passFile, true)
	if err != nil {
		return err
	}
	f, err := os.OpenFile(out, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	defer func() {
		if cerr := f.Close(); err == nil {
			err = cerr
		}
		if err != nil {
			_ = os.Remove(out)
		}
	}()
	m, err := backup.Create(ctx, backup.Source{DataDir: dir, ObjectsDir: objects, Product: version, PostgresMigration: migration,
		Dump: backup.PG{DSN: dsn, DumpBin: dumpBin}.Dump}, pass, f)
	if err != nil {
		return err
	}
	if err := f.Sync(); err != nil {
		return err
	}
	fmt.Printf("backup %s: %d files, PostgreSQL schema %d, artifacts included: %v\n", out, len(m.Files), m.PostgresMigration, m.ObjectsIncluded)
	fmt.Println("ClickHouse (event history) is not in it: see docs/design/nginx-module.md › Bản Compact.")
	return nil
}

// restoreCommand: strata-control-plane restore (CP-A09).
func restoreCommand(args []string) int {
	fs := flag.NewFlagSet("restore", flag.ContinueOnError)
	in := fs.String("in", "", "Archive made by strata-control-plane backup")
	dir := fs.String("data-dir", "/var/lib/strata", "Data directory to restore the keys, PKI, secrets and config.yaml to")
	objects := fs.String("objects-dir", "", "Artifacts directory to restore to (default <data-dir>/objects)")
	pass := fs.String("passphrase-file", "", "File holding the archive's passphrase; without it, asked on the terminal")
	dsnFile := fs.String("dsn-file", "", "File holding the PostgreSQL DSN of the database to replace (default: STRATA_POSTGRES_DSN, then <data-dir>/secrets/postgres-dsn)")
	restoreBin := fs.String("pg-restore", "pg_restore", "pg_restore of the server's major version or newer")
	yes := fs.Bool("yes", false, "Do not ask for confirmation (the database is replaced)")
	overwrite := fs.Bool("overwrite", false, "Replace files of the data directory that differ from the backup")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	obj := *objects
	if obj == "" {
		obj = filepath.Join(*dir, setup.ObjectsDir)
	}
	if err := runRestore(*in, *dir, obj, *pass, *dsnFile, *restoreBin, *yes, *overwrite); err != nil {
		fmt.Fprintln(os.Stderr, "restore:", err)
		return 1
	}
	return 0
}

func runRestore(in, dir, objects, passFile, dsnFile, restoreBin string, yes, overwrite bool) error {
	if in == "" {
		return errors.New("give -in")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 6*time.Hour)
	defer cancel()
	// the DSN of the database to replace: from the flags or this host, never
	// from the archive
	dsn, err := dsnFrom(dir, dsnFile)
	if err != nil {
		return err
	}
	pass, err := readPassphrase(passFile, false)
	if err != nil {
		return err
	}
	f, err := os.Open(in)
	if err != nil {
		return err
	}
	defer f.Close()
	staged, err := os.MkdirTemp(filepath.Dir(filepath.Clean(dir)), ".strata-restore-")
	if err != nil {
		staged, err = os.MkdirTemp("", "strata-restore-")
		if err != nil {
			return err
		}
	}
	defer os.RemoveAll(staged)
	m, err := backup.Extract(f, pass, staged)
	if err != nil {
		return err
	}
	latest, err := db.Latest()
	if err != nil {
		return err
	}
	if m.PostgresMigration > latest {
		return fmt.Errorf("the backup has PostgreSQL schema %d, this build knows %d: restore with the version that made it (%s)", m.PostgresMigration, latest, m.Product)
	}
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		return err
	}
	defer pool.Close()
	st := store.New(pool)
	if running, err := leaseHeld(ctx, pool); err != nil {
		return err
	} else if running {
		return errors.New("a control plane holds the lease on this database: stop it first (restore never runs under a live control plane)")
	}
	before, err := st.ReadRestoreState(ctx)
	if err != nil {
		return err
	}
	conflicts, err := backup.Conflicts(staged, m, dir, objects)
	if err != nil {
		return err
	}
	if len(conflicts) > 0 && !overwrite {
		return fmt.Errorf("%d files differ from the backup (e.g. %s): give -overwrite to replace them", len(conflicts), conflicts[0])
	}
	fmt.Printf("backup of %s by %s: PostgreSQL schema %d, %d files, artifacts: %v\n", m.CreatedAt.Format(time.RFC3339), m.Product, m.PostgresMigration, len(m.Files), m.ObjectsIncluded)
	fmt.Printf("the database is REPLACED; %d files of %s are replaced; bundles will be numbered above %d\n", len(conflicts), dir, before.HighestBundle)
	if !yes {
		if !term.IsTerminal(int(os.Stdin.Fd())) {
			return errors.New("not confirmed: give -yes, or run on a terminal")
		}
		fmt.Fprint(os.Stderr, "type RESTORE to go on: ")
		line, _ := bufio.NewReader(os.Stdin).ReadString('\n')
		if strings.TrimSpace(line) != "RESTORE" {
			return errors.New("not confirmed")
		}
	}
	// an empty schema: tables of a newer migration must not survive
	if _, err := pool.Exec(ctx, "DROP SCHEMA IF EXISTS public CASCADE; CREATE SCHEMA public"); err != nil {
		return fmt.Errorf("emptying the database: %w", err)
	}
	if err := (backup.PG{DSN: dsn, RestoreBin: restoreBin}).Restore(ctx, filepath.Join(staged, backup.DumpName)); err != nil {
		return err
	}
	if err := db.Migrate(ctx, pool, latest); err != nil {
		return err
	}
	res, err := st.FinishRestore(ctx, before)
	if err != nil {
		return err
	}
	if err := backup.Install(staged, m, dir, objects); err != nil {
		return err
	}
	fmt.Printf("restored: next bundle above %d; %d rollouts aborted, %d replays failed, %d nodes keep their bundle until the next deploy\n",
		res.Floor, res.AbortedRollouts, res.FailedOperations, res.ClearedDesired)
	if len(res.NodesToReenroll) > 0 {
		fmt.Printf("%d nodes enrolled after the backup must enroll again: %s\n", len(res.NodesToReenroll), strings.Join(res.NodesToReenroll, ", "))
	}
	if !m.ObjectsIncluded {
		fmt.Println("the artifacts were in an object store: restore the bucket from its own backup")
	}
	return nil
}

// leaseHeld: a control plane renewed its lease and it has not expired.
func leaseHeld(ctx context.Context, pool *pgxpool.Pool) (bool, error) {
	var exists, held bool
	if err := pool.QueryRow(ctx, "SELECT to_regclass('public.control_plane_lease') IS NOT NULL").Scan(&exists); err != nil || !exists {
		return false, err
	}
	err := pool.QueryRow(ctx, "SELECT EXISTS (SELECT 1 FROM control_plane_lease WHERE expires_at > now())").Scan(&held)
	return held, err
}
