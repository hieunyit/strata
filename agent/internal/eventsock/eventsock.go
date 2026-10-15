// Package eventsock receives the events NGINX workers send on
// strata_event_socket: one protobuf strata.event.v1.Event per Unix
// datagram, at most 8 KB (nginx-module.md › "Trang chặn, Block ID & sự
// kiện"). Datagrams come from worker processes and are not trusted: any
// that is truncated, does not decode, or lacks a Block ID is counted and
// dropped.
package eventsock

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"strconv"
	"sync/atomic"
	"syscall"

	"google.golang.org/protobuf/proto"

	eventv1 "github.com/strata/strata/agent/gen/strata/event/v1"
)

const (
	// MaxDatagram is the largest event a worker may send.
	MaxDatagram = 8 << 10
	// maxBlockID bounds the Block ID (STR-XXXX-XXXX-XXXX-XXXX is 23 bytes).
	maxBlockID = 64
)

// Counters are read with atomic loads.
type Counters struct {
	Received  atomic.Uint64
	Invalid   atomic.Uint64 // did not decode or failed validation
	Truncated atomic.Uint64 // larger than MaxDatagram
	Samples   atomic.Uint64 // replay samples (W12-N-01)
	Policies  atomic.Uint64 // per-policy counters datagrams (RV-N-01)
}

// SampleMagic starts a replay sample datagram (libstrata's SAMPLE_MAGIC);
// an Event never starts with 0xff.
const SampleMagic = "\xffSR1"

// CountersMagic starts a per-policy counters datagram (libstrata's
// COUNTERS_MAGIC, RV-N-01). Agents before it count these as invalid.
const CountersMagic = "\xffSC1"

// Listener owns the datagram socket.
type Listener struct {
	conn *net.UnixConn
	path string
	// inherited: the socket came from systemd (strata-agent.socket); its
	// file belongs to systemd and stays when the agent stops (W13-G1-01)
	inherited bool
	C         Counters
	// OnSample, when set before Run, gets the replay samples; without it
	// they are dropped (counted as invalid).
	OnSample func(*eventv1.ReplaySample)
	// OnCounters, when set before Run, gets the per-policy counters
	// datagrams; without it they are dropped (counted as invalid).
	OnCounters func(*eventv1.PolicyCounters)
}

// Listen binds a Unix datagram socket at path, replacing a stale socket
// left by a previous agent, and makes it writable by the group (the
// NGINX workers' group). Started by systemd with strata-agent.socket, it
// takes the socket systemd passes instead (W13-G1-01): systemd keeps it
// open while the agent restarts, so the kernel queues the events of that
// window instead of the workers dropping them, and the workers' connected
// sockets (#29) stay valid.
func Listen(path string) (*Listener, error) {
	if l, err := inherit(path); l != nil || err != nil {
		return l, err
	}
	if fi, err := os.Lstat(path); err == nil {
		if fi.Mode()&os.ModeSocket == 0 {
			return nil, fmt.Errorf("eventsock: %s exists and is not a socket", path)
		}
		if err := os.Remove(path); err != nil {
			return nil, fmt.Errorf("eventsock: remove stale socket: %w", err)
		}
	}
	conn, err := net.ListenUnixgram("unixgram", &net.UnixAddr{Name: path, Net: "unixgram"})
	if err != nil {
		return nil, fmt.Errorf("eventsock: listen %s: %w", path, err)
	}
	// A larger kernel buffer absorbs bursts while the agent is busy; the
	// kernel may cap it at net.core.rmem_max, which is fine.
	_ = conn.SetReadBuffer(4 << 20)
	if err := os.Chmod(path, 0o660); err != nil {
		conn.Close()
		return nil, fmt.Errorf("eventsock: chmod %s: %w", path, err)
	}
	return &Listener{conn: conn, path: path}, nil
}

// Run delivers each valid event to out until ctx is done. out is called
// from Run's goroutine only.
func (l *Listener) Run(ctx context.Context, out func(*eventv1.Event)) error {
	stop := context.AfterFunc(ctx, func() { l.conn.Close() })
	defer stop()
	// One byte more than allowed, so that MSG_TRUNC is set for any
	// datagram above MaxDatagram.
	buf := make([]byte, MaxDatagram+1)
	for {
		n, _, flags, _, err := l.conn.ReadMsgUnix(buf, nil)
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			if errors.Is(err, net.ErrClosed) {
				return fmt.Errorf("eventsock: socket closed: %w", err)
			}
			return fmt.Errorf("eventsock: read: %w", err)
		}
		l.C.Received.Add(1)
		if flags&syscall.MSG_TRUNC != 0 || n > MaxDatagram {
			l.C.Truncated.Add(1)
			continue
		}
		if n >= len(SampleMagic) && string(buf[:len(SampleMagic)]) == SampleMagic {
			s, ok := DecodeSample(buf[len(SampleMagic):n])
			if !ok || l.OnSample == nil {
				l.C.Invalid.Add(1)
				continue
			}
			l.C.Samples.Add(1)
			l.OnSample(s)
			continue
		}
		if n >= len(CountersMagic) && string(buf[:len(CountersMagic)]) == CountersMagic {
			c := &eventv1.PolicyCounters{}
			if proto.Unmarshal(buf[len(CountersMagic):n], c) != nil || l.OnCounters == nil {
				l.C.Invalid.Add(1)
				continue
			}
			l.C.Policies.Add(1)
			l.OnCounters(c)
			continue
		}
		ev, ok := Decode(buf[:n])
		if !ok {
			l.C.Invalid.Add(1)
			continue
		}
		out(ev)
	}
}

// Decode parses one datagram and checks the fields the agent relies on.
func Decode(b []byte) (*eventv1.Event, bool) {
	ev := &eventv1.Event{}
	if err := proto.Unmarshal(b, ev); err != nil {
		return nil, false
	}
	if id := ev.GetBlockId(); id == "" || len(id) > maxBlockID {
		return nil, false
	}
	return ev, true
}

// DecodeSample parses a replay sample (after SampleMagic): it needs its
// anonymization key id and its policy.
func DecodeSample(b []byte) (*eventv1.ReplaySample, bool) {
	s := &eventv1.ReplaySample{}
	if err := proto.Unmarshal(b, s); err != nil {
		return nil, false
	}
	if id := s.GetAnonKeyId(); id == "" || len(id) > 16 || len(s.GetPolicy()) == 0 || len(s.GetPolicy()) > 55 {
		return nil, false
	}
	return s, true
}

// Close closes the socket and removes its path.
func (l *Listener) Close() error {
	err := l.conn.Close()
	if errors.Is(err, net.ErrClosed) {
		err = nil
	}
	if l.inherited {
		return err // systemd's socket: it stays for the next agent
	}
	if rmErr := os.Remove(l.path); rmErr != nil && !errors.Is(rmErr, os.ErrNotExist) && err == nil {
		err = fmt.Errorf("eventsock: remove socket: %w", rmErr)
	}
	return err
}

// inherit returns the datagram socket systemd passed for path (socket
// activation: LISTEN_PID is this process, LISTEN_FDS from fd 3), or nil
// when there is none. The variables are cleared so that no child takes
// the socket too.
func inherit(path string) (*Listener, error) { return inheritFrom(path, 3) }

// inheritFrom: inherit with the first passed descriptor at first (3 for
// systemd; tests pass a descriptor of their own).
func inheritFrom(path string, first int) (*Listener, error) {
	if os.Getenv("LISTEN_PID") != strconv.Itoa(os.Getpid()) {
		return nil, nil
	}
	n, err := strconv.Atoi(os.Getenv("LISTEN_FDS"))
	os.Unsetenv("LISTEN_PID")
	os.Unsetenv("LISTEN_FDS")
	os.Unsetenv("LISTEN_FDNAMES")
	if err != nil || n < 1 {
		return nil, nil
	}
	for fd := first; fd < first+n; fd++ {
		f := os.NewFile(uintptr(fd), "listen-fd")
		pc, err := net.FilePacketConn(f)
		f.Close() // FilePacketConn dups the descriptor
		if err != nil {
			continue
		}
		uc, ok := pc.(*net.UnixConn)
		if !ok {
			pc.Close()
			continue
		}
		if a, ok := uc.LocalAddr().(*net.UnixAddr); !ok || a.Name != path {
			uc.Close()
			continue
		}
		_ = uc.SetReadBuffer(4 << 20)
		return &Listener{conn: uc, path: path, inherited: true}, nil
	}
	return nil, fmt.Errorf("eventsock: systemd passed %d sockets, none bound to %s", n, path)
}
