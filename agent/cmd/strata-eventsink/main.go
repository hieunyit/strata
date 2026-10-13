// Command strata-eventsink measures the event socket (W09-Q-01,
// connectors/nginx/scripts/bench.sh and bench-events.sh).
//
// strata-eventsink -socket PATH
//
//	drains strata_event_socket with the agent's own listener and decoder
//	(internal/eventsock) and counts the events; on SIGTERM or SIGINT it
//	prints one JSON line: datagrams received, valid events, truncated and
//	invalid datagrams.
//
// strata-eventsink -send PATH -rate N -seconds S
//
//	sends N events a second for S seconds the way an NGINX worker does
//	(one datagram per event, sendto with MSG_DONTWAIT: a full socket drops
//	the event) and prints one JSON line: sent, dropped, and the CPU time
//	(user + system) of the process per event sent.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"google.golang.org/protobuf/proto"

	eventv1 "github.com/strata/strata/agent/gen/strata/event/v1"
	"github.com/strata/strata/agent/internal/eventsock"
)

func main() {
	path := flag.String("socket", "", "socket path to bind and drain (strata_event_socket without unix:)")
	send := flag.String("send", "", "socket path to send to instead")
	rate := flag.Int("rate", 25000, "events a second (-send)")
	seconds := flag.Int("seconds", 10, "how long to send (-send)")
	flag.Parse()
	var err error
	switch {
	case *send != "":
		err = sender(*send, *rate, time.Duration(*seconds)*time.Second)
	case *path != "":
		err = sink(*path)
	default:
		fmt.Fprintln(os.Stderr, "usage: strata-eventsink -socket PATH | -send PATH [-rate N] [-seconds S]")
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "strata-eventsink:", err)
		os.Exit(1)
	}
}

func sink(path string) error {
	l, err := eventsock.Listen(path)
	if err != nil {
		return err
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer stop()
	var events uint64
	if err := l.Run(ctx, func(*eventv1.Event) { events++ }); err != nil {
		return err
	}
	return json.NewEncoder(os.Stdout).Encode(map[string]uint64{
		"received":  l.C.Received.Load(),
		"events":    events,
		"truncated": l.C.Truncated.Load(),
		"invalid":   l.C.Invalid.Load(),
	})
}

// event is about the size of what the module sends for a shadow block on a
// small request (one protocol match with its snippet).
func event() ([]byte, error) {
	return proto.Marshal(&eventv1.Event{
		BlockId: "EVT-0000-0000-0000-0000", TimeUnixMs: uint64(time.Now().UnixMilli()),
		NodeId: "bench-01", RequestId: "0123456789abcdef0123456789abcdef", PolicyId: "example-api",
		BundleVersion: 1, ClientIp: "192.0.2.10", Method: "GET", Host: "api.example.test",
		Path: "/t", Status: 200, Action: eventv1.Action_ACTION_LOG,
		LayerScores: map[string]int32{"protocol": 100, "anomaly": 100},
		RuleIds:     []uint32{100013},
		Matches: []*eventv1.Match{{RuleId: 100013, Layer: "protocol", Field: "ARGS:x",
			Snippet: []byte("1\x00")}},
	})
}

func sender(path string, rate int, d time.Duration) error {
	b, err := event()
	if err != nil {
		return err
	}
	fd, err := syscall.Socket(syscall.AF_UNIX, syscall.SOCK_DGRAM|syscall.SOCK_CLOEXEC, 0)
	if err != nil {
		return err
	}
	defer syscall.Close(fd)
	to := &syscall.SockaddrUnix{Name: path}
	var sent, dropped uint64
	var r0 syscall.Rusage
	_ = syscall.Getrusage(syscall.RUSAGE_SELF, &r0)
	start := time.Now()
	// in steps of 1 ms: rate/1000 events, then wait for the next step
	per := max(rate/1000, 1)
	for step := 0; time.Since(start) < d; step++ {
		for i := 0; i < per; i++ {
			err := syscall.Sendto(fd, b, syscall.MSG_DONTWAIT, to)
			switch {
			case err == nil:
				sent++
			case errors.Is(err, syscall.EAGAIN) || errors.Is(err, syscall.ENOBUFS):
				dropped++
			default:
				return fmt.Errorf("sendto: %w", err)
			}
		}
		if wait := time.Until(start.Add(time.Duration(step+1) * time.Millisecond)); wait > 0 {
			time.Sleep(wait)
		}
	}
	elapsed := time.Since(start)
	var r1 syscall.Rusage
	_ = syscall.Getrusage(syscall.RUSAGE_SELF, &r1)
	cpu := time.Duration(r1.Utime.Nano()+r1.Stime.Nano()-r0.Utime.Nano()-r0.Stime.Nano()) * time.Nanosecond
	total := max(sent+dropped, 1)
	return json.NewEncoder(os.Stdout).Encode(map[string]any{
		"bytes": len(b), "sent": sent, "dropped": dropped,
		"rate":             float64(sent+dropped) / elapsed.Seconds(),
		"cpu_us_per_event": float64(cpu.Microseconds()) / float64(total),
	})
}
