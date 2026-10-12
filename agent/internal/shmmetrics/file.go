// Package shmmetrics reads the counters NGINX workers keep in the metrics
// file (docs/design/control-file.md › "Metrics file") and exports them in
// the Prometheus format. The file is written by other processes, so every
// field is checked before use.
package shmmetrics

import (
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"sync/atomic"
	"syscall"
	"unsafe"
)

const (
	headerSize    = 64
	layoutVersion = 1
	maxSlots      = 1024
	maxFileSize   = 16 << 20
	magic         = "STRMET1\x00"
)

// Counter indexes within a slot.
const (
	cPID = iota
	cBundleVersion
	cReqAllow
	cReqLog
	cReqChallenge
	cReqBlock
	cBodyBytes
	cFailOpen
	cFailClosed
	cEventsDropped
	cBudgetExceeded
	cEngineNanos
	cEngineBuckets // first of len(BucketBounds)+1 buckets
)

// BucketBounds are the upper bounds of the engine time histogram, in
// seconds; the last bucket (+Inf) has no bound.
var BucketBounds = []float64{50e-6, 100e-6, 200e-6, 500e-6, 1e-3, 2e-3, 5e-3, 10e-3}

// NumCounters is the slot size the agent understands.
var NumCounters = cEngineBuckets + len(BucketBounds) + 1

// Worker is one slot.
type Worker struct {
	Index         int
	PID           uint64
	BundleVersion uint64
	Requests      [4]uint64 // allow, log, challenge, block
	BodyBytes     uint64
	FailOpen      uint64
	FailClosed    uint64
	EventsDropped uint64
	BudgetExceed  uint64
	EngineNanos   uint64
	EngineBuckets []uint64 // per bucket, not cumulative
}

// Snapshot is the content of one metrics file.
type Snapshot struct {
	CreatedMs uint64
	// What the module wrote in the header (0 / empty with an older one).
	ProxyVersion  string // NGINX version
	ModuleVersion string
	ABIVersion    uint32
	Workers       []Worker // slots in use (pid != 0)
}

// ErrLayout marks a file that does not follow the layout.
var ErrLayout = errors.New("shmmetrics: bad layout")

// Read maps the file at path read-only and copies its counters.
func Read(path string) (Snapshot, error) {
	f, err := os.Open(path)
	if err != nil {
		return Snapshot{}, fmt.Errorf("shmmetrics: open: %w", err)
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil {
		return Snapshot{}, fmt.Errorf("shmmetrics: stat: %w", err)
	}
	size := fi.Size()
	if !fi.Mode().IsRegular() || size < headerSize || size > maxFileSize {
		return Snapshot{}, fmt.Errorf("%w: file of %d bytes", ErrLayout, size)
	}
	m, err := syscall.Mmap(int(f.Fd()), 0, int(size), syscall.PROT_READ, syscall.MAP_SHARED)
	if err != nil {
		return Snapshot{}, fmt.Errorf("shmmetrics: mmap: %w", err)
	}
	defer func() { _ = syscall.Munmap(m) }()
	return parse(m)
}

// parse reads a mapped file. m must be 8-byte aligned (mmap is page
// aligned).
func parse(m []byte) (Snapshot, error) {
	if len(m) < headerSize || string(m[:8]) != magic {
		return Snapshot{}, fmt.Errorf("%w: magic", ErrLayout)
	}
	le := binary.LittleEndian
	if v := le.Uint32(m[8:]); v != layoutVersion {
		return Snapshot{}, fmt.Errorf("%w: layout version %d", ErrLayout, v)
	}
	slots := int(le.Uint32(m[12:]))
	slotSize := int(le.Uint32(m[16:]))
	counters := int(le.Uint32(m[20:]))
	switch {
	case slots < 1 || slots > maxSlots:
		return Snapshot{}, fmt.Errorf("%w: %d slots", ErrLayout, slots)
	case counters < NumCounters:
		return Snapshot{}, fmt.Errorf("%w: %d counters, need %d", ErrLayout, counters, NumCounters)
	case slotSize%64 != 0 || slotSize < 8*counters || slotSize > maxFileSize:
		return Snapshot{}, fmt.Errorf("%w: slot of %d bytes", ErrLayout, slotSize)
	case headerSize+slots*slotSize != len(m):
		return Snapshot{}, fmt.Errorf("%w: %d slots of %d bytes in %d bytes", ErrLayout, slots, slotSize, len(m))
	}
	s := Snapshot{CreatedMs: le.Uint64(m[24:]), ProxyVersion: cstr(m[32:48]), ModuleVersion: cstr(m[48:60]), ABIVersion: le.Uint32(m[60:])}
	for i := 0; i < slots; i++ {
		slot := m[headerSize+i*slotSize:]
		c := func(k int) uint64 { return load(slot[8*k:]) }
		if c(cPID) == 0 {
			continue
		}
		w := Worker{
			Index:         i,
			PID:           c(cPID),
			BundleVersion: c(cBundleVersion),
			Requests:      [4]uint64{c(cReqAllow), c(cReqLog), c(cReqChallenge), c(cReqBlock)},
			BodyBytes:     c(cBodyBytes),
			FailOpen:      c(cFailOpen),
			FailClosed:    c(cFailClosed),
			EventsDropped: c(cEventsDropped),
			BudgetExceed:  c(cBudgetExceeded),
			EngineNanos:   c(cEngineNanos),
			EngineBuckets: make([]uint64, len(BucketBounds)+1),
		}
		for b := range w.EngineBuckets {
			w.EngineBuckets[b] = c(cEngineBuckets + b)
		}
		s.Workers = append(s.Workers, w)
	}
	return s, nil
}

// load reads one counter with an atomic load, so that a worker's 64-bit
// store is never seen half done. b starts at an 8-byte aligned address.
// The load is in host order: the file is little endian and so are the
// platforms NGINX and the agent run on (amd64, arm64).
func load(b []byte) uint64 {
	_ = b[7]
	return atomic.LoadUint64((*uint64)(unsafe.Pointer(&b[0])))
}

// cstr: a NUL-padded field, printable ASCII only.
func cstr(b []byte) string {
	n := 0
	for n < len(b) && b[n] >= 0x20 && b[n] < 0x7f {
		n++
	}
	if n < len(b) && b[n] != 0 {
		return ""
	}
	return string(b[:n])
}
