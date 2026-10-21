package standalone

import (
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/strata/strata/agent/pkg/privacy"
	"google.golang.org/protobuf/encoding/protojson"

	eventv1 "github.com/strata/strata/agent/gen/strata/event/v1"
)

// EventExporter exports security events to JSON Lines files and/or Syslog.
type EventExporter struct {
	Privacy    func(uint64, string) (*privacy.Filter, error)
	mu         sync.Mutex
	file       *os.File
	ownsFile   bool
	closed     bool
	syslogConn net.Conn
	syslogTag  string
	jsonOpts   protojson.MarshalOptions
	exported   uint64
	dropped    uint64
}

// NewEventExporter initializes an exporter with optional JSONL file and Syslog destination.
func NewEventExporter(jsonlPath, syslogAddr, syslogTag string) (*EventExporter, error) {
	if jsonlPath == "" && syslogAddr == "" {
		return nil, errors.New("standalone exporter: at least one event destination is required")
	}
	exp := &EventExporter{
		syslogTag: syslogTag,
		jsonOpts: protojson.MarshalOptions{
			EmitUnpopulated: false,
			UseProtoNames:   true,
		},
	}
	if exp.syslogTag == "" {
		exp.syslogTag = "strata-waf"
	}

	if jsonlPath == "stdout" || jsonlPath == "-" {
		exp.file = os.Stdout
	}
	if jsonlPath != "" && jsonlPath != "stdout" && jsonlPath != "-" {
		if err := os.MkdirAll(filepath.Dir(jsonlPath), 0o755); err != nil {
			return nil, fmt.Errorf("standalone exporter: mkdir %s: %w", filepath.Dir(jsonlPath), err)
		}
		f, err := os.OpenFile(jsonlPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o640)
		if err != nil {
			return nil, fmt.Errorf("standalone exporter: open %s: %w", jsonlPath, err)
		}
		exp.file = f
		exp.ownsFile = true
	}

	if syslogAddr != "" {
		conn, err := dialSyslog(syslogAddr)
		if err != nil {
			if exp.file != nil && exp.ownsFile {
				_ = exp.file.Close()
			}
			return nil, fmt.Errorf("standalone exporter: dial syslog %s: %w", syslogAddr, err)
		}
		exp.syslogConn = conn
	}

	return exp, nil
}

func dialSyslog(addr string) (net.Conn, error) {
	if strings.HasPrefix(addr, "unixgram:") || strings.HasPrefix(addr, "unix:") {
		path := strings.TrimPrefix(strings.TrimPrefix(addr, "unixgram:"), "unix:")
		return net.DialTimeout("unixgram", path, 2*time.Second)
	}
	if addr == "local" || addr == "/dev/log" {
		if conn, err := net.DialTimeout("unixgram", "/dev/log", 2*time.Second); err == nil {
			return conn, nil
		}
		return net.DialTimeout("unix", "/dev/log", 2*time.Second)
	}
	network := "udp"
	hostPort := addr
	if strings.HasPrefix(addr, "tcp://") {
		network = "tcp"
		hostPort = strings.TrimPrefix(addr, "tcp://")
	} else if strings.HasPrefix(addr, "udp://") {
		network = "udp"
		hostPort = strings.TrimPrefix(addr, "udp://")
	}
	return net.DialTimeout(network, hostPort, 2*time.Second)
}

// Export formats the event as JSON and writes to JSONL and/or Syslog.
func (e *EventExporter) Export(ev *eventv1.Event) error {
	var filter *privacy.Filter
	if e.Privacy != nil {
		var err error
		filter, err = e.Privacy(ev.GetBundleVersion(), ev.GetPolicyId())
		if err != nil {
			e.mu.Lock()
			e.dropped++
			e.mu.Unlock()
			return err
		}
	}
	ev = filter.Event(ev)
	data, err := e.jsonOpts.Marshal(ev)
	if err != nil {
		e.mu.Lock()
		e.dropped++
		e.mu.Unlock()
		return fmt.Errorf("standalone exporter: marshal event: %w", err)
	}

	e.mu.Lock()
	defer e.mu.Unlock()

	if e.closed {
		e.dropped++
		return errors.New("standalone exporter: closed")
	}
	// 1. JSON Lines Output
	if e.file != nil {
		if _, err := e.file.Write(append(data, '\n')); err != nil {
			e.dropped++
			return fmt.Errorf("standalone exporter: write jsonl: %w", err)
		}
	}

	// 2. Syslog Output (RFC 3164 / 5424 style: <PRI>TIMESTAMP TAG: MESSAGE)
	if e.syslogConn != nil {
		if err := e.syslogConn.SetWriteDeadline(time.Now().Add(2 * time.Second)); err != nil {
			e.dropped++
			return fmt.Errorf("standalone exporter: set syslog deadline: %w", err)
		}
		// Facility LOG_DAEMON (3) * 8 + Severity LOG_WARNING (4) = 28
		pri := 28
		t := time.Now().Format(time.RFC3339)
		msg := fmt.Sprintf("<%d>1 %s strata %s - - - %s\n", pri, t, e.syslogTag, string(data))
		if _, err := e.syslogConn.Write([]byte(msg)); err != nil {
			e.dropped++
			return fmt.Errorf("standalone exporter: write syslog: %w", err)
		}
	}

	e.exported++
	return nil
}

// Close closes any underlying file handles or network connections.
func (e *EventExporter) Close() error {
	e.mu.Lock()
	defer e.mu.Unlock()

	e.closed = true
	var firstErr error
	if e.file != nil && e.ownsFile {
		if err := e.file.Close(); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	e.file = nil
	if e.syslogConn != nil {
		if err := e.syslogConn.Close(); err != nil && firstErr == nil {
			firstErr = err
		}
		e.syslogConn = nil
	}
	return firstErr
}

// Stats returns exported and dropped event counts.
func (e *EventExporter) Stats() (exported, dropped uint64) {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.exported, e.dropped
}
