package config

import (
	"flag"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"
)

// the flags of the control plane, as main.go defines them
func mainFlags(t *testing.T) map[string]bool {
	t.Helper()
	src, err := os.ReadFile("../cmd/server/main.go")
	if err != nil {
		t.Fatal(err)
	}
	out := map[string]bool{}
	for _, m := range regexp.MustCompile(`flag\.(?:String|Bool|Int|Uint64|Duration|Float64)\("([a-z0-9-]+)"`).FindAllStringSubmatch(string(src), -1) {
		out[m[1]] = true
	}
	return out
}

func flagSet(t *testing.T) *flag.FlagSet {
	t.Helper()
	fs := flag.NewFlagSet("test", flag.ContinueOnError)
	for name := range mainFlags(t) {
		fs.String(name, "default-"+name, "")
	}
	return fs
}

func write(t *testing.T, dir, name, body string, mode os.FileMode) string {
	t.Helper()
	p := filepath.Join(dir, name)
	if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(body), mode); err != nil {
		t.Fatal(err)
	}
	return p
}

// Every key maps to a flag the control plane has, and every flag but
// -config has a key: a new flag needs its key.
func TestKeysCoverTheFlags(t *testing.T) {
	flags := mainFlags(t)
	if len(flags) < 50 {
		t.Fatalf("found %d flags in main.go", len(flags))
	}
	covered := map[string]bool{}
	for key, m := range Keys() {
		if m[0] == "" && m[1] == "" {
			t.Errorf("%s maps to nothing", key)
		}
		if m[0] != "" {
			if !flags[m[0]] {
				t.Errorf("%s maps to -%s, which main.go does not define", key, m[0])
			}
			covered[m[0]] = true
		}
	}
	for f := range flags {
		if !covered[f] && f != "config" {
			t.Errorf("flag -%s has no configuration key", f)
		}
	}
}

func TestExampleLoadsAndApplies(t *testing.T) {
	f, err := Load("example.yaml")
	if err != nil {
		t.Fatal(err)
	}
	fs := flagSet(t)
	t.Setenv("STRATA_POSTGRES_DSN", "postgres://from-env")
	for _, e := range []string{"STRATA_LOCAL_ADMIN_PASSWORD", "STRATA_CLICKHOUSE_PASSWORD", "STRATA_S3_ACCESS_KEY", "STRATA_S3_SECRET_KEY"} {
		t.Setenv(e, "set")
	}
	src, err := f.Apply(fs, map[string]bool{"addr": true})
	if err != nil {
		t.Fatal(err)
	}
	abs, _ := filepath.Abs("pki/ca.pem")
	for name, want := range map[string]string{
		"addr":                 "default-addr", // given on the command line: kept
		"grpc-addr":            ":8443",
		"tls-ca":               abs, // relative to the file
		"lease-ttl":            "30s",
		"local-session-ttl":    "8h0m0s",
		"rules":                "/opt/strata/rules.yaml",
		"rollout-waves":        "1,10%,100%",
		"objects-dir":          "/var/lib/strata/objects",
		"single-control-plane": "true",
		"events-ttl-days":      "30",
		"in-memory":            "default-in-memory", // not in the file
	} {
		if got := fs.Lookup(name).Value.String(); got != want {
			t.Errorf("-%s = %q, want %q", name, got, want)
		}
	}
	if src["addr"] != FromFlag || src["grpc-addr"] != FromFile || src["in-memory"] != FromDefault || src["$STRATA_POSTGRES_DSN"] != FromEnv {
		t.Errorf("sources: %v", src)
	}
	out := Effective(fs, src)
	if strings.Contains(out, "from-env") || !strings.Contains(out, "$STRATA_POSTGRES_DSN = <redacted>  # env") {
		t.Errorf("effective output:\n%s", out)
	}
}

func TestRefusals(t *testing.T) {
	dir := t.TempDir()
	for name, body := range map[string]string{
		"no version":    "server: {}\n",
		"version 2":     "version: 2\n",
		"unknown key":   "version: 1\nserver:\n  http:\n    listne: \":80\"\n",
		"bare duration": "version: 1\nserver:\n  lease_ttl: 30\n",
		"bad duration":  "version: 1\nreplay:\n  timeout: soon\n",
		"bad signer":    "version: 1\nbundles:\n  signer:\n    type: kms\n",
		"vault and key": "version: 1\nbundles:\n  signer:\n    type: vault\n    key_file: k\n",
		"memory and ch": "version: 1\nevents:\n  in_memory: true\n  clickhouse:\n    address: ch:9000\n",
		"local and s3":  "version: 1\nbundles:\n  storage:\n    local:\n      path: /srv/objects\n    s3:\n      endpoint: minio:9000\n",
		"secret inline": "version: 1\ndatabase:\n  dsn: postgres://user:pw@db/strata\n",
	} {
		p := write(t, dir, strings.ReplaceAll(name, " ", "-")+".yaml", body, 0o600)
		if _, err := Load(p); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

// Secret files: loaded into the environment unless it is set; refused when
// readable by others, a symlink, or empty.
func TestSecretFiles(t *testing.T) {
	dir := t.TempDir()
	write(t, dir, "secrets/dsn", "postgres://strata:pw@db/strata\n", 0o600)
	write(t, dir, "secrets/open", "pw\n", 0o644)
	write(t, dir, "secrets/empty", "\n", 0o600)
	if err := os.Symlink(filepath.Join(dir, "secrets/dsn"), filepath.Join(dir, "secrets/link")); err != nil {
		t.Fatal(err)
	}
	load := func(file string) error {
		p := write(t, dir, "c.yaml", "version: 1\ndatabase:\n  dsn_file: secrets/"+file+"\n", 0o600)
		f, err := Load(p)
		if err != nil {
			return err
		}
		_, err = f.Apply(flagSet(t), nil)
		return err
	}
	t.Setenv("STRATA_POSTGRES_DSN", "")
	if err := load("dsn"); err != nil || os.Getenv("STRATA_POSTGRES_DSN") != "postgres://strata:pw@db/strata" {
		t.Fatalf("dsn: %v %q", err, os.Getenv("STRATA_POSTGRES_DSN"))
	}
	t.Setenv("STRATA_POSTGRES_DSN", "")
	if err := load("link"); err == nil || !strings.Contains(err.Error(), "symlink") {
		t.Errorf("symlink: %v", err)
	}
	for _, bad := range []string{"open", "empty", "link", "missing"} {
		if err := load(bad); err == nil {
			t.Errorf("%s: accepted", bad)
		} else if strings.Contains(err.Error(), "pw") {
			t.Errorf("%s: error shows the secret: %v", bad, err)
		}
	}
	t.Setenv("STRATA_POSTGRES_DSN", "postgres://env-wins")
	if err := load("open"); err != nil || os.Getenv("STRATA_POSTGRES_DSN") != "postgres://env-wins" {
		t.Fatalf("env set: %v %q", err, os.Getenv("STRATA_POSTGRES_DSN"))
	}
}

func TestDurationNeedsUnit(t *testing.T) {
	dir := t.TempDir()
	f, err := Load(write(t, dir, "c.yaml", "version: 1\nserver:\n  lease_ttl: 45s\n", 0o600))
	if err != nil || f.Server.LeaseTTL.Duration != 45*time.Second {
		t.Fatalf("%+v %v", f, err)
	}
}
