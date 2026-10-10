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
}

// Listener owns the datagram socket.
type Listener struct {
	conn *net.UnixConn
	path string
	C    Counters
}

// Listen binds a Unix datagram socket at path, replacing a stale socket
// left by a previous agent, and makes it writable by the group (the
// NGINX workers' group).
func Listen(path string) (*Listener, error) {
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

// Close closes the socket and removes its path.
func (l *Listener) Close() error {
	err := l.conn.Close()
	if errors.Is(err, net.ErrClosed) {
		err = nil
	}
	if rmErr := os.Remove(l.path); rmErr != nil && !errors.Is(rmErr, os.ErrNotExist) && err == nil {
		err = fmt.Errorf("eventsock: remove socket: %w", rmErr)
	}
	return err
}
