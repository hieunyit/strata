package e2e

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/strata/strata/control-plane/ingest"
)

// Every test owns its server, data and port. Never adopt CLICKHOUSE_ADDR or
// the lab at fixed ports: restart tests must not erase somebody else's events.
func losslessClickHouse(t *testing.T) (*ingest.ClickHouseStore, string) {
	t.Helper()
	s, cfg := losslessClickHouseConfig(t)
	return s, cfg.Addr
}

// The config is only passed to owned child processes; never log its password.
func losslessClickHouseConfig(t *testing.T) (*ingest.ClickHouseStore, ingest.ClickHouseConfig) {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), 90*time.Second)
	defer cancel()
	var secret [16]byte
	if _, err := rand.Read(secret[:]); err != nil {
		t.Fatal(err)
	}
	password := hex.EncodeToString(secret[:])
	name := fmt.Sprintf("strata-lossless-%d-%d", os.Getpid(), time.Now().UnixNano())
	out, err := exec.CommandContext(ctx, "docker", "create", "--name", name, "-p", "127.0.0.1::9000",
		"-e", "CLICKHOUSE_USER=strata", "-e", "CLICKHOUSE_PASSWORD="+password,
		"--ulimit", "nofile=262144:262144", "clickhouse/clickhouse-server:25.8.33").CombinedOutput()
	if err != nil {
		t.Fatalf("create isolated ClickHouse: %v: %s", err, out)
	}
	id := strings.TrimSpace(string(out))
	t.Cleanup(func() {
		cleanup, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if out, err := exec.CommandContext(cleanup, "docker", "rm", "-fv", id).CombinedOutput(); err != nil {
			t.Errorf("cleanup own ClickHouse: %v: %s", err, out)
		}
	})
	if out, err := exec.CommandContext(ctx, "docker", "start", id).CombinedOutput(); err != nil {
		t.Fatalf("start isolated ClickHouse: %v: %s", err, out)
	}
	port, err := exec.CommandContext(ctx, "docker", "port", id, "9000/tcp").Output()
	if err != nil {
		t.Fatal(err)
	}
	addr := strings.TrimSpace(string(port))
	for {
		out, err := exec.CommandContext(ctx, "docker", "exec", id, "sh", "-c",
			`exec clickhouse-client --user "$CLICKHOUSE_USER" --password "$CLICKHOUSE_PASSWORD" --connect_timeout 1 --receive_timeout 2 --query 'SELECT 1'`).Output()
		if err == nil && strings.TrimSpace(string(out)) == "1" {
			break
		}
		select {
		case <-ctx.Done():
			t.Fatal("isolated ClickHouse did not become ready")
		case <-time.After(100 * time.Millisecond):
		}
	}
	cfg := ingest.ClickHouseConfig{Addr: addr, Database: "default", Username: "strata", Password: password}
	s, err := ingest.NewClickHouseStore(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := s.Close(); err != nil {
			t.Error(err)
		}
	})
	return s, cfg
}

func TestLosslessFixtureIgnoresLegacyAddresses(t *testing.T) {
	first, addr := losslessClickHouse(t)
	ctx := t.Context()
	if err := first.Conn().Exec(ctx, "CREATE TABLE sentinel (value UInt8) ENGINE=Memory"); err != nil {
		t.Fatal(err)
	}
	if err := first.Conn().Exec(ctx, "INSERT INTO sentinel VALUES(7)"); err != nil {
		t.Fatal(err)
	}
	t.Setenv("CLICKHOUSE_ADDR", addr)
	t.Setenv("CLICKHOUSE_HTTP_ADDR", "127.0.0.1:1")
	_, secondAddr := losslessClickHouse(t)
	if addr == secondAddr {
		t.Fatal("fixture adopted legacy ClickHouse address")
	}
	var value uint8
	if err := first.Conn().QueryRow(ctx, "SELECT value FROM sentinel").Scan(&value); err != nil || value != 7 {
		t.Fatalf("first fixture was changed: %d %v", value, err)
	}
}
