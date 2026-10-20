package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/user"
	"path/filepath"
	"strings"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"golang.org/x/term"

	"github.com/strata/strata/control-plane/db"
	"github.com/strata/strata/control-plane/localauth"
	"github.com/strata/strata/control-plane/setup"
)

// readPassword reads a password from file (one line) or, without one, from
// the terminal twice without echo. Never from a flag or the environment.
func readPassword(file, prompt string) (string, error) {
	if file != "" {
		data, err := os.ReadFile(file)
		if err != nil {
			return "", err
		}
		return strings.TrimRight(string(data), "\r\n"), nil
	}
	fd := int(os.Stdin.Fd())
	if !term.IsTerminal(fd) {
		return "", errors.New("no terminal to ask for the password: give -admin-password-file")
	}
	fmt.Fprint(os.Stderr, prompt+": ")
	a, err := term.ReadPassword(fd)
	fmt.Fprintln(os.Stderr)
	if err != nil {
		return "", err
	}
	fmt.Fprint(os.Stderr, "again: ")
	b, err := term.ReadPassword(fd)
	fmt.Fprintln(os.Stderr)
	if err != nil {
		return "", err
	}
	if string(a) != string(b) {
		return "", errors.New("the two passwords differ")
	}
	return string(a), nil
}

func dsnFrom(dataDir, dsnFile string) (string, error) {
	if dsnFile != "" {
		data, err := os.ReadFile(dsnFile)
		return strings.TrimSpace(string(data)), err
	}
	if v := os.Getenv("STRATA_POSTGRES_DSN"); v != "" {
		return v, nil
	}
	if data, err := os.ReadFile(filepath.Join(dataDir, setup.DSNFile)); err == nil {
		return strings.TrimSpace(string(data)), nil
	}
	return "", errors.New("no database: set STRATA_POSTGRES_DSN or give -dsn-file")
}

func connect(ctx context.Context, dsn string) (*pgxpool.Pool, error) {
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		return nil, err
	}
	latest, err := db.Latest()
	if err == nil {
		err = db.Migrate(ctx, pool, latest)
	}
	if err != nil {
		pool.Close()
		return nil, err
	}
	return pool, nil
}

// initCommand: strata-control-plane init (CP-A05). Prepares a data
// directory and the database for a new control plane: migrations, the PKI,
// the bundle signing key, the first admin, a configuration file. Creates
// only what is missing; running it again changes nothing that exists.
func initCommand(args []string) int {
	fs := flag.NewFlagSet("init", flag.ContinueOnError)
	dir := fs.String("data-dir", "/var/lib/strata", "Data directory (keys, PKI, secrets, config.yaml)")
	names := fs.String("name", "", "Comma-separated DNS names or IPs agents use to reach Fleet (the certificate's names; default: this host's name)")
	admin := fs.String("admin-user", "admin", "Username of the first admin, created when there is no local account")
	pwFile := fs.String("admin-password-file", "", "File holding the first admin's password; without it, asked on the terminal")
	dsnFile := fs.String("dsn-file", "", "File holding the PostgreSQL DSN (default: STRATA_POSTGRES_DSN, then <data-dir>/secrets/postgres-dsn); kept in the data directory")
	ch := fs.String("clickhouse", "clickhouse:9000", "ClickHouse address written in config.yaml")
	s3 := fs.String("s3-endpoint", "", "Object store written in config.yaml; empty: artifacts in <dir>/objects (CP-A07)")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if err := runInit(*dir, *names, *admin, *pwFile, *dsnFile, *ch, *s3); err != nil {
		fmt.Fprintln(os.Stderr, "init:", err)
		return 1
	}
	return 0
}

func runInit(dir, names, admin, pwFile, dsnFile, ch, s3 string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	unlock, err := setup.Lock(dir)
	if err != nil {
		return err
	}
	defer unlock()
	dsn, err := dsnFrom(dir, dsnFile)
	if err != nil {
		return err
	}
	pool, err := connect(ctx, dsn)
	if err != nil {
		return fmt.Errorf("database: %w", err)
	}
	defer pool.Close()
	var bundles int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM bundles`).Scan(&bundles); err != nil {
		return err
	}
	var r setup.Result
	if err := setup.Secret(dir, setup.DSNFile, dsn, &r); err != nil {
		return err
	}
	if err := setup.Secret(dir, setup.CHPassword, os.Getenv("STRATA_CLICKHOUSE_PASSWORD"), &r); err != nil {
		return err
	}
	list := []string{}
	for _, n := range strings.Split(names, ",") {
		if n = strings.TrimSpace(n); n != "" {
			list = append(list, n)
		}
	}
	if len(list) == 0 {
		host, _ := os.Hostname()
		list = append(list, host)
	}
	if err := setup.PKI(dir, list, time.Now(), &r); err != nil {
		return err
	}
	if err := setup.BundleKeys(dir, bundles > 0, &r); err != nil {
		return err
	}
	if err := setup.Config(dir, ch, s3, &r); err != nil {
		return err
	}
	store := localauth.NewStore(pool)
	n, err := store.CountUsers(ctx)
	if err != nil {
		return err
	}
	if n == 0 {
		pw, err := readPassword(pwFile, "password for the admin "+admin)
		if err != nil {
			return err
		}
		svc, err := localauth.NewService(store, time.Hour)
		if err != nil {
			return err
		}
		if _, err := svc.Bootstrap(ctx, admin, pw); err != nil {
			return err
		}
		r.Created = append(r.Created, "local admin "+admin)
	} else {
		r.Kept = append(r.Kept, fmt.Sprintf("%d local accounts", n))
	}
	for _, c := range r.Created {
		fmt.Println("created:", c)
	}
	for _, k := range r.Kept {
		fmt.Println("kept:   ", k)
	}
	fmt.Printf("\nstart: strata-control-plane -config %s\n", filepath.Join(dir, setup.ConfigFile))
	fmt.Printf("agents trust %s; give them its CA as the Fleet trust bundle\n", filepath.Join(dir, setup.CACert))
	return nil
}

// adminCommand: strata-control-plane admin recover -user <name> (CP-A05).
// For a host operator locked out of the last admin account: sets a new
// password, enables and unlocks the account, ends its sessions, and audits
// the change as system:recover with the host user. Needs the database DSN,
// so only someone with access to this host's secrets can run it.
func adminCommand(args []string) int {
	if len(args) == 0 || args[0] != "recover" {
		fmt.Fprintln(os.Stderr, "usage: strata-control-plane admin recover -user <name> [-password-file f] [-dsn-file f]")
		return 2
	}
	fs := flag.NewFlagSet("admin recover", flag.ContinueOnError)
	name := fs.String("user", "", "Local account to recover")
	pwFile := fs.String("password-file", "", "File holding the new password; without it, asked on the terminal")
	dsnFile := fs.String("dsn-file", "", "File holding the PostgreSQL DSN (default: STRATA_POSTGRES_DSN)")
	dir := fs.String("data-dir", "/var/lib/strata", "Data directory (for secrets/postgres-dsn)")
	if err := fs.Parse(args[1:]); err != nil {
		return 2
	}
	if err := runRecover(*dir, *name, *pwFile, *dsnFile); err != nil {
		fmt.Fprintln(os.Stderr, "admin recover:", err)
		return 1
	}
	return 0
}

func runRecover(dir, name, pwFile, dsnFile string) error {
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	username, err := localauth.NormalizeUsername(name)
	if err != nil {
		return err
	}
	dsn, err := dsnFrom(dir, dsnFile)
	if err != nil {
		return err
	}
	pool, err := connect(ctx, dsn)
	if err != nil {
		return fmt.Errorf("database: %w", err)
	}
	defer pool.Close()
	store := localauth.NewStore(pool)
	if _, err := store.GetUser(ctx, username); err != nil {
		return fmt.Errorf("account %s: %w", username, err)
	}
	pw, err := readPassword(pwFile, "new password for "+username)
	if err != nil {
		return err
	}
	if err := localauth.CheckPassword(pw); err != nil {
		return err
	}
	hash, err := localauth.HashPassword(pw)
	if err != nil {
		return err
	}
	who := "unknown"
	if u, err := user.Current(); err == nil {
		who = u.Username
	}
	host, _ := os.Hostname()
	enabled := false
	if _, err := store.UpdateUser(ctx, username, localauth.Patch{PasswordHash: &hash, Disabled: &enabled, Unlock: true},
		fmt.Sprintf("system:recover (%s@%s)", who, host)); err != nil {
		return err
	}
	fmt.Printf("%s: new password set, account enabled and unlocked, its sessions ended (audited)\n", username)
	return nil
}
