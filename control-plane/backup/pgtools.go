package backup

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// PG runs pg_dump and pg_restore (of the server's major version or newer)
// against the database of DSN. The password never appears in the command
// line: it goes into a private PGPASSFILE for the length of the call.
type PG struct {
	DSN        string // postgres://user:password@host:port/db?sslmode=...
	DumpBin    string // default pg_dump
	RestoreBin string // default pg_restore
}

// passEscape escapes a field of a password file.
func passEscape(s string) string {
	return strings.NewReplacer(`\`, `\\`, `:`, `\:`).Replace(s)
}

// prepare returns the DSN without its password and the environment that
// points libpq at a password file holding it; cleanup removes the file.
func (p PG) prepare() (string, []string, func(), error) {
	u, err := url.Parse(p.DSN)
	if err != nil || (u.Scheme != "postgres" && u.Scheme != "postgresql") || u.Host == "" {
		return "", nil, nil, errors.New("backup: the PostgreSQL DSN must be a URL (postgres://user:password@host:port/db)")
	}
	env := []string{}
	for _, e := range os.Environ() {
		// only ours: a PGPASSWORD or PGPASSFILE around would win or mislead
		if !strings.HasPrefix(e, "PGPASSWORD=") && !strings.HasPrefix(e, "PGPASSFILE=") {
			env = append(env, e)
		}
	}
	cleanup := func() {}
	if pw, ok := u.User.Password(); ok {
		dir, err := os.MkdirTemp("", "strata-pg-")
		if err != nil {
			return "", nil, nil, err
		}
		cleanup = func() { _ = os.RemoveAll(dir) }
		host, port := u.Hostname(), u.Port()
		if port == "" {
			port = "5432"
		}
		line := strings.Join([]string{passEscape(host), port, "*", passEscape(u.User.Username()), passEscape(pw)}, ":") + "\n"
		file := filepath.Join(dir, "pgpass")
		if err := os.WriteFile(file, []byte(line), 0o600); err != nil {
			cleanup()
			return "", nil, nil, err
		}
		env = append(env, "PGPASSFILE="+file)
		u.User = url.User(u.User.Username())
	}
	return u.String(), env, cleanup, nil
}

func (p PG) run(ctx context.Context, bin string, args []string, stdout io.Writer) error {
	dsn, env, cleanup, err := p.prepare()
	if err != nil {
		return err
	}
	defer cleanup()
	return runCommand(ctx, bin, append(args, "--dbname="+dsn), env, stdout)
}

func runCommand(ctx context.Context, bin string, args, env []string, stdout io.Writer) error {
	cmd := exec.CommandContext(ctx, bin, args...)
	cmd.Env = env
	cmd.Stdout = stdout
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		msg := strings.TrimSpace(stderr.String())
		if len(msg) > 2000 {
			msg = msg[:2000]
		}
		return fmt.Errorf("%s: %w: %s", filepath.Base(bin), err, msg)
	}
	return nil
}

// Dump writes a custom-format dump (one consistent snapshot) to w.
func (p PG) Dump(ctx context.Context, w io.Writer) error {
	bin := p.DumpBin
	if bin == "" {
		bin = "pg_dump"
	}
	return p.run(ctx, bin, []string{"--format=custom", "--no-owner", "--no-privileges"}, w)
}

// Restore replaces public and loads the dump in the same transaction.
// Rendering the dump first avoids touching the target when pg_restore is
// missing or the archive cannot be read. psql's single transaction covers
// both the reset and all restored statements, including COPY data.
func (p PG) Restore(ctx context.Context, file string) error {
	bin := p.RestoreBin
	if bin == "" {
		bin = "pg_restore"
	}
	psql := "psql"
	if filepath.IsAbs(bin) {
		psql = filepath.Join(filepath.Dir(bin), "psql")
	}
	if _, err := exec.LookPath(psql); err != nil {
		return fmt.Errorf("backup: psql required for atomic restore: %w", err)
	}
	dir, err := os.MkdirTemp("", "strata-restore-sql-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(dir)
	sql := filepath.Join(dir, "restore.sql")
	if err := os.WriteFile(sql, nil, 0o600); err != nil {
		return err
	}
	if err := runCommand(ctx, bin, []string{"--no-owner", "--no-privileges", "--file=" + sql, file}, os.Environ(), io.Discard); err != nil {
		return err
	}
	reset := filepath.Join(dir, "reset.sql")
	if err := os.WriteFile(reset, []byte("DROP SCHEMA IF EXISTS public CASCADE; CREATE SCHEMA public;\n"), 0o600); err != nil {
		return err
	}
	return p.run(ctx, psql, []string{"--no-psqlrc", "--single-transaction", "--set=ON_ERROR_STOP=1", "--file=" + reset, "--file=" + sql}, io.Discard)
}
