package backup

import (
	"archive/tar"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"filippo.io/age"
)

const pass = "correct horse battery staple"

func write(t *testing.T, p string, data string, mode os.FileMode) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(data), mode); err != nil {
		t.Fatal(err)
	}
}

func dataDir(t *testing.T) string {
	t.Helper()
	d := t.TempDir()
	write(t, filepath.Join(d, "keys/bundle-signing.key"), "seed-32-bytes-of-example-key-xx", 0o600)
	write(t, filepath.Join(d, "pki/ca.pem"), "certificate", 0o644)
	write(t, filepath.Join(d, "config.yaml"), "version: 1\n", 0o600)
	write(t, filepath.Join(d, ".init.lock"), "", 0o600)
	write(t, filepath.Join(d, "objects/bundles/00000000000000000007/bundle-7.sbn"), "bundle 7", 0o600)
	write(t, filepath.Join(d, "objects/bundles/00000000000000000007/.strata-tmp-ab"), "partial", 0o600)
	return d
}

func dump(_ context.Context, w io.Writer) error {
	_, err := io.WriteString(w, "PGDMP custom dump")
	return err
}

func TestRoundTrip(t *testing.T) {
	d := dataDir(t)
	var buf bytes.Buffer
	m, err := Create(t.Context(), Source{DataDir: d, ObjectsDir: filepath.Join(d, "objects"), Dump: dump, Product: "test", PostgresMigration: 28}, pass, &buf)
	if err != nil {
		t.Fatal(err)
	}
	if !m.ObjectsIncluded || m.Files[0].Path != DumpName {
		t.Fatalf("manifest: %+v", m)
	}
	var names []string
	for _, f := range m.Files {
		names = append(names, f.Path)
	}
	// objects once, under objects/; no lock, no file being written
	want := "postgres.dump data/config.yaml data/keys/bundle-signing.key data/pki/ca.pem objects/bundles/00000000000000000007/bundle-7.sbn"
	if strings.Join(names, " ") != want {
		t.Fatalf("files: %v", names)
	}
	// encrypted: no key material in clear
	if bytes.Contains(buf.Bytes(), []byte("seed-32-bytes")) || bytes.Contains(buf.Bytes(), []byte("PGDMP")) {
		t.Fatal("archive not encrypted")
	}
	staged := t.TempDir()
	got, err := Extract(bytes.NewReader(buf.Bytes()), pass, filepath.Join(staged, "x"))
	if err != nil || got.PostgresMigration != 28 || len(got.Files) != 5 {
		t.Fatalf("extract: %+v %v", got, err)
	}
	if _, err := Extract(bytes.NewReader(buf.Bytes()), "wrong passphrase", filepath.Join(staged, "y")); err == nil {
		t.Fatal("wrong passphrase accepted")
	}
	cut := buf.Bytes()[:buf.Len()-100]
	if _, err := Extract(bytes.NewReader(cut), pass, filepath.Join(staged, "z")); err == nil {
		t.Fatal("truncated archive accepted")
	}

	// restore into a fresh place
	nd, no := filepath.Join(t.TempDir(), "data"), filepath.Join(t.TempDir(), "objects")
	if c, err := Conflicts(filepath.Join(staged, "x"), got, nd, no); err != nil || len(c) != 0 {
		t.Fatalf("conflicts: %v %v", c, err)
	}
	if err := Install(filepath.Join(staged, "x"), got, nd, no); err != nil {
		t.Fatal(err)
	}
	for p, mode := range map[string]os.FileMode{
		filepath.Join(nd, "keys/bundle-signing.key"): 0o600, filepath.Join(nd, "pki/ca.pem"): 0o644,
		filepath.Join(no, "bundles/00000000000000000007/bundle-7.sbn"): 0o600,
	} {
		st, err := os.Stat(p)
		if err != nil || st.Mode().Perm() != mode {
			t.Errorf("%s: %v %v", p, st, err)
		}
	}
	if _, err := os.Stat(filepath.Join(nd, "postgres.dump")); err == nil {
		t.Fatal("the dump was installed as a file")
	}
	// a file changed since: a conflict
	write(t, filepath.Join(nd, "config.yaml"), "version: 1\n# edited\n", 0o600)
	if c, _ := Conflicts(filepath.Join(staged, "x"), got, nd, no); len(c) != 1 || !strings.HasSuffix(c[0], "config.yaml") {
		t.Fatalf("conflicts: %v", c)
	}
	// the machine's connection secrets stay; missing, the backup's are installed
	write(t, filepath.Join(d, "secrets/postgres-dsn"), "postgres://old", 0o600)
	var buf2 bytes.Buffer
	m2, err := Create(t.Context(), Source{DataDir: d, Dump: dump}, pass, &buf2)
	if err != nil {
		t.Fatal(err)
	}
	s2 := filepath.Join(staged, "s2")
	if _, err := Extract(bytes.NewReader(buf2.Bytes()), pass, s2); err != nil {
		t.Fatal(err)
	}
	here := filepath.Join(t.TempDir(), "data")
	write(t, filepath.Join(here, "secrets/postgres-dsn"), "postgres://this-machine", 0o600)
	if c, err := Conflicts(s2, m2, here, ""); err != nil || len(c) != 0 {
		t.Fatalf("machine secret as a conflict: %v %v", c, err)
	}
	if err := Install(s2, m2, here, ""); err != nil {
		t.Fatal(err)
	}
	if got, _ := os.ReadFile(filepath.Join(here, "secrets/postgres-dsn")); string(got) != "postgres://this-machine" {
		t.Fatalf("machine secret replaced: %q", got)
	}
	fresh := filepath.Join(t.TempDir(), "data")
	if err := Install(s2, m2, fresh, ""); err != nil {
		t.Fatal(err)
	}
	if got, _ := os.ReadFile(filepath.Join(fresh, "secrets/postgres-dsn")); string(got) != "postgres://old" {
		t.Fatalf("missing machine secret not installed: %q", got)
	}

	// objects in the archive need a place
	if _, err := Conflicts(filepath.Join(staged, "x"), got, nd, ""); err == nil {
		t.Fatal("artifacts without a directory")
	}
}

func TestRefusals(t *testing.T) {
	d := dataDir(t)
	if _, err := Create(t.Context(), Source{DataDir: d, Dump: dump}, "", io.Discard); !errors.Is(err, ErrNoPassphrase) {
		t.Fatalf("no passphrase: %v", err)
	}
	failing := func(context.Context, io.Writer) error { return errors.New("server unreachable") }
	if _, err := Create(t.Context(), Source{DataDir: d, Dump: failing}, pass, io.Discard); err == nil || !strings.Contains(err.Error(), "server unreachable") {
		t.Fatalf("dump failure: %v", err)
	}
	if err := os.Symlink("/etc/passwd", filepath.Join(d, "keys/link")); err != nil {
		t.Fatal(err)
	}
	if _, err := Create(t.Context(), Source{DataDir: d, Dump: dump}, pass, io.Discard); err == nil || !strings.Contains(err.Error(), "not a regular file") {
		t.Fatalf("symlink: %v", err)
	}
}

// archive builds an encrypted tar by hand, for archives Create never makes.
func archive(t *testing.T, entries []tar.Header, bodies []string, manifest *Manifest) []byte {
	t.Helper()
	var buf bytes.Buffer
	r, _ := age.NewScryptRecipient(pass)
	r.SetWorkFactor(10)
	enc, err := age.Encrypt(&buf, r)
	if err != nil {
		t.Fatal(err)
	}
	tw := tar.NewWriter(enc)
	for i, h := range entries {
		h.Size = int64(len(bodies[i]))
		if err := tw.WriteHeader(&h); err != nil {
			t.Fatal(err)
		}
		_, _ = tw.Write([]byte(bodies[i]))
	}
	if manifest != nil {
		raw, _ := json.Marshal(manifest)
		_ = tw.WriteHeader(&tar.Header{Name: ManifestName, Mode: 0o600, Size: int64(len(raw)), Typeflag: tar.TypeReg})
		_, _ = tw.Write(raw)
	}
	_ = tw.Close()
	_ = enc.Close()
	return buf.Bytes()
}

func TestExtractRefusesHostileArchives(t *testing.T) {
	ok := Manifest{Format: Format, Files: []File{{Path: DumpName, Size: 4, SHA256: "88d4266fd4e6338d13b845fcf289579d209c897823b9217da3e161936f031589"}}}
	for name, a := range map[string][]byte{
		"path escape":    archive(t, []tar.Header{{Name: "../../etc/cron.d/x", Typeflag: tar.TypeReg}}, []string{"x"}, &ok),
		"absolute":       archive(t, []tar.Header{{Name: "/etc/passwd", Typeflag: tar.TypeReg}}, []string{"x"}, &ok),
		"symlink":        archive(t, []tar.Header{{Name: "data/k", Typeflag: tar.TypeSymlink, Linkname: "/etc/shadow"}}, []string{""}, &ok),
		"no manifest":    archive(t, []tar.Header{{Name: DumpName, Typeflag: tar.TypeReg}}, []string{"abcd"}, nil),
		"unlisted file":  archive(t, []tar.Header{{Name: DumpName, Typeflag: tar.TypeReg}, {Name: "data/extra", Typeflag: tar.TypeReg}}, []string{"abcd", "x"}, &ok),
		"wrong hash":     archive(t, []tar.Header{{Name: DumpName, Typeflag: tar.TypeReg}}, []string{"abce"}, &ok),
		"newer format":   archive(t, []tar.Header{{Name: DumpName, Typeflag: tar.TypeReg}}, []string{"abcd"}, &Manifest{Format: 2, Files: ok.Files}),
		"missing listed": archive(t, nil, nil, &ok),
	} {
		if _, err := Extract(bytes.NewReader(a), pass, filepath.Join(t.TempDir(), "x")); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	if _, err := Extract(bytes.NewReader(archive(t, []tar.Header{{Name: DumpName, Typeflag: tar.TypeReg}}, []string{"abcd"}, &ok)), pass, filepath.Join(t.TempDir(), "x")); err != nil {
		t.Fatalf("valid archive: %v", err)
	}
}

func TestPasswordNeverOnTheCommandLine(t *testing.T) {
	p := PG{DSN: "postgres://strata:p%3Ass:w0rd@db.example.test:5433/strata?sslmode=disable"}
	dsn, env, cleanup, err := p.prepare()
	if err != nil {
		t.Fatal(err)
	}
	defer cleanup()
	if strings.Contains(dsn, "w0rd") || dsn != "postgres://strata@db.example.test:5433/strata?sslmode=disable" {
		t.Fatalf("dsn %q", dsn)
	}
	var file string
	for _, e := range env {
		if strings.HasPrefix(e, "PGPASSFILE=") {
			file = strings.TrimPrefix(e, "PGPASSFILE=")
		}
		if strings.HasPrefix(e, "PGPASSWORD=") {
			t.Fatal("PGPASSWORD passed on")
		}
	}
	data, err := os.ReadFile(file)
	st, _ := os.Stat(file)
	if err != nil || string(data) != "db.example.test:5433:*:strata:p\\:ss\\:w0rd\n" || st.Mode().Perm() != 0o600 {
		t.Fatalf("pgpass %q %v", data, err)
	}
	cleanup()
	if _, err := os.Stat(file); err == nil {
		t.Fatal("password file left behind")
	}
	if _, _, _, err := (PG{DSN: "host=db user=strata"}).prepare(); err == nil {
		t.Fatal("key=value DSN accepted")
	}
}
