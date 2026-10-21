package health

import (
	"archive/tar"
	"compress/gzip"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestSupportBundleAllowlistAndPrivateArchive(t *testing.T) {
	secret := "example-token-do-not-export"
	pii := "198.51.100.22/private-user"
	snapshot := Snapshot{At: time.Now().UTC(), Version: "dev", Scope: "global", Checks: []Check{{ID: "postgres", State: Unavailable, Advice: secret, Value: &secret}, {ID: secret, State: Unknown}}, Nodes: []Node{{ID: pii, Checks: []Check{{ID: "heartbeat", State: Stale, Advice: secret}}}}}
	path := filepath.Join(t.TempDir(), "support.tar.gz")
	if err := WriteSupport(path, snapshot, map[string]string{"dsn": secret, "objects-dir": pii, "local-auth": "true", "replay-timeout": "10m", "ui": secret}); err != nil {
		t.Fatal(err)
	}
	st, err := os.Stat(path)
	if err != nil || st.Mode().Perm() != 0600 {
		t.Fatalf("archive permissions: %v %v", st, err)
	}
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	zip, err := gzip.NewReader(f)
	if err != nil {
		t.Fatal(err)
	}
	defer zip.Close()
	archive := tar.NewReader(zip)
	files := map[string][]byte{}
	for {
		head, err := archive.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		if head.Mode != 0600 {
			t.Fatal("public archive member")
		}
		data, err := io.ReadAll(archive)
		if err != nil {
			t.Fatal(err)
		}
		files[head.Name] = data
		if strings.Contains(string(data), secret) || strings.Contains(string(data), pii) {
			t.Fatalf("sensitive content escaped in %s", head.Name)
		}
	}
	if len(files) != 4 || files["manifest.json"] == nil || files["doctor.log"] == nil {
		t.Fatal("missing fixed members")
	}
	var config map[string]string
	if err := json.Unmarshal(files["config.json"], &config); err != nil {
		t.Fatal(err)
	}
	if config["local-auth"] != "true" || config["replay-timeout"] != "10m" || config["dsn"] != "" {
		t.Fatal("configuration allowlist failed")
	}
	if err := WriteSupport(path, snapshot, nil); err == nil {
		t.Fatal("overwrote existing archive")
	}
	target := filepath.Join(t.TempDir(), "symlink")
	if err := os.Symlink(path, target); err != nil {
		t.Fatal(err)
	}
	if err := WriteSupport(target, snapshot, nil); err == nil {
		t.Fatal("followed output symlink")
	}
}
