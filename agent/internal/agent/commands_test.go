package agent

import (
	"context"
	"encoding/json"
	"net"
	"path/filepath"
	"strings"
	"testing"
	"time"

	fleetv1 "github.com/strata/strata/agent/gen/strata/fleet/v1"
	"github.com/strata/strata/agent/internal/bundles"
	"github.com/strata/strata/agent/internal/forceshadow"
	"github.com/strata/strata/agent/internal/spool"
)

// CollectDiagnostics answers with versions, bundle and counters only.
func TestDiagnosticsHoldNoSecrets(t *testing.T) {
	dir := t.TempDir()
	sp, err := spool.Open(filepath.Join(dir, "spool"), spool.Options{NoSync: true})
	if err != nil {
		t.Fatal(err)
	}
	defer sp.Close()
	ctl := filepath.Join(dir, "control")
	if _, err := bundles.WriteControl(ctl, 7, [32]byte{}, "bundle-7.sbn"); err != nil {
		t.Fatal(err)
	}
	a := &Agent{Spool: sp, started: time.Now(), cfg: Config{AgentVersion: "0.7.0", NodeID: "node-abc", ControlFile: ctl,
		IdentityDir: "/var/lib/strata/identity", KeyFile: "/secret/node.key", MetricsFile: filepath.Join(dir, "none")}}
	a.ForceShadow = forceshadow.New(ctl, filepath.Join(dir, "force-shadow.json"))
	if r := a.command(context.Background(), &fleetv1.Command{Action: &fleetv1.Command_ForceShadow{ForceShadow: &fleetv1.ForceShadow{PolicyId: "example-api", DurationSeconds: 60}}}); !r.GetOk() {
		t.Fatalf("force shadow: %v", r)
	}
	r := a.command(context.Background(), &fleetv1.Command{Action: &fleetv1.Command_Diagnostics{Diagnostics: &fleetv1.CollectDiagnostics{}}})
	if !r.GetOk() {
		t.Fatalf("%v", r)
	}
	var d Diagnostics
	if err := json.Unmarshal([]byte(r.GetOutput()), &d); err != nil {
		t.Fatal(err)
	}
	if d.AgentVersion != "0.7.0" || d.NodeID != "node-abc" || d.ForceShadow == nil || d.ForceShadow.Policies["example-api"].IsZero() || d.MetricsError == "" {
		t.Fatalf("%s", r.GetOutput())
	}
	for _, s := range []string{"secret", "identity", "PRIVATE", "BEGIN", dir} {
		if strings.Contains(r.GetOutput(), s) {
			t.Errorf("diagnostics contain %q: %s", s, r.GetOutput())
		}
	}
	if len(r.GetOutput()) > 16<<10 {
		t.Errorf("diagnostics of %d bytes", len(r.GetOutput()))
	}
	// Without a bundle directory: refused, not a crash.
	a.ForceShadow = nil
	if r := a.command(context.Background(), &fleetv1.Command{Action: &fleetv1.Command_ForceShadow{ForceShadow: &fleetv1.ForceShadow{DurationSeconds: 60}}}); r.GetOk() {
		t.Fatal("force shadow without a bundle directory")
	}
}

func TestConnTrackerClosesDialedConnections(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			defer c.Close()
		}
	}()
	tr := &connTracker{}
	c1, err := tr.dial(context.Background(), ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	c2, _ := tr.dial(context.Background(), ln.Addr().String())
	_ = c2.Close() // closed by gRPC: forgotten
	if n := tr.closeAll(); n != 1 {
		t.Fatalf("closed %d, want 1", n)
	}
	if _, err := c1.Write([]byte("x")); err == nil {
		t.Fatal("write on a closed connection")
	}
}
