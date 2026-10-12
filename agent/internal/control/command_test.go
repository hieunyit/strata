package control

import (
	"context"
	"sync"
	"testing"
	"time"

	fleetv1 "github.com/strata/strata/agent/gen/strata/fleet/v1"
)

type cmdFleet struct {
	fleetv1.UnimplementedFleetServiceServer
	mu      sync.Mutex
	results []*fleetv1.CommandResult
}

func (f *cmdFleet) Connect(st fleetv1.FleetService_ConnectServer) error {
	if _, err := st.Recv(); err != nil { // Hello
		return nil
	}
	for _, c := range []*fleetv1.Command{
		{Id: "cmd-1", Action: &fleetv1.Command_ForceShadow{ForceShadow: &fleetv1.ForceShadow{PolicyId: "example-api", DurationSeconds: 60}}},
		{Id: "cmd-2", Action: &fleetv1.Command_Diagnostics{Diagnostics: &fleetv1.CollectDiagnostics{}}},
	} {
		if err := st.Send(&fleetv1.ControlMessage{Msg: &fleetv1.ControlMessage_Command{Command: c}}); err != nil {
			return err
		}
	}
	for {
		m, err := st.Recv()
		if err != nil {
			return nil
		}
		if r := m.GetCommandResult(); r != nil {
			f.mu.Lock()
			f.results = append(f.results, r)
			f.mu.Unlock()
		}
	}
}

func (f *cmdFleet) got() map[string]*fleetv1.CommandResult {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := map[string]*fleetv1.CommandResult{}
	for _, r := range f.results {
		out[r.GetCommandId()] = r
	}
	return out
}

// W07-G1-01: each command runs once and its result, with the command's
// id whatever the handler set, goes back on the stream.
func TestCommandsRunAndAnswer(t *testing.T) {
	f := &cmdFleet{}
	var mu sync.Mutex
	ran := map[string]int{}
	c := New(client(t, f), Options{Heartbeat: time.Hour, OnCommand: func(_ context.Context, cmd *fleetv1.Command) *fleetv1.CommandResult {
		mu.Lock()
		ran[cmd.GetId()]++
		mu.Unlock()
		if cmd.GetForceShadow() != nil {
			return &fleetv1.CommandResult{CommandId: "spoofed", Ok: true}
		}
		return &fleetv1.CommandResult{Ok: true, Output: `{"agent_version":"test"}`}
	}})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = c.Run(ctx) }()
	eventually(t, "two results", func() bool { return len(f.got()) == 2 })
	g := f.got()
	if !g["cmd-1"].GetOk() || g["cmd-2"].GetOutput() != `{"agent_version":"test"}` {
		t.Fatalf("results %v", g)
	}
	mu.Lock()
	defer mu.Unlock()
	if ran["cmd-1"] != 1 || ran["cmd-2"] != 1 {
		t.Fatalf("ran %v", ran)
	}
}

// Without a handler a command is answered, not ignored.
func TestCommandWithoutHandlerIsRefused(t *testing.T) {
	f := &cmdFleet{}
	c := New(client(t, f), Options{Heartbeat: time.Hour})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = c.Run(ctx) }()
	eventually(t, "results", func() bool { return len(f.got()) == 2 })
	if r := f.got()["cmd-1"]; r.GetOk() || r.GetError() != "not supported" {
		t.Fatalf("%v", r)
	}
}
