// Package spool keeps event batches on disk until the control plane acks
// them (nginx-module.md › "Giao thức gRPC agent ↔ control plane", Độ tin
// cậy). Batches are appended before they are sent, so neither an agent
// restart nor a control plane outage loses them.
//
// The spool is a directory of segment files seg-<first seq>.log holding
// records
//
//	[len u32][crc32c u32][seq u64][events u32][payload: len bytes]
//
// (little endian; the CRC covers seq, events and payload) and a state file
// holding the highest acked seq. Seqs increase strictly and are never
// reused, also across restarts: the control plane drops any batch whose
// seq is not above the last one it committed.
package spool

import (
	"encoding/binary"
	"errors"
	"fmt"
	"hash/crc32"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
)

const (
	headerSize = 20
	// MaxRecord bounds one batch; a larger length on disk is corruption.
	MaxRecord = 16 << 20

	segPrefix = "seg-"
	segSuffix = ".log"
	stateName = "state"
)

var castagnoli = crc32.MakeTable(crc32.Castagnoli)

// ErrClosed is returned by calls on a closed spool.
var ErrClosed = errors.New("spool: closed")

// Options configures a spool.
type Options struct {
	// MaxBytes caps the spool size; when a new batch does not fit, the
	// oldest segments are dropped. Default 2 GB.
	MaxBytes int64
	// SegmentBytes is the size at which the active segment is rotated.
	// Default 64 MB, at most MaxBytes/4.
	SegmentBytes int64
	// NoSync skips fsync after each append (tests only).
	NoSync bool
}

// Record is one spooled batch.
type Record struct {
	Seq     uint64
	Events  uint32
	Payload []byte
}

// Stats is a snapshot of the spool counters.
type Stats struct {
	Bytes          int64
	Segments       int
	LastSeq        uint64
	AckedSeq       uint64
	DroppedBatches uint64 // dropped because the spool was full
	DroppedEvents  uint64
	TruncatedBytes int64 // corrupt or torn tails cut off at open
}

type segment struct {
	first, last uint64 // last == first-1 while empty
	size        int64
	records     uint64
	events      uint64
	f           *os.File
}

// Spool is safe for concurrent use.
type Spool struct {
	dir  string
	opts Options

	mu     sync.Mutex
	segs   []*segment // oldest first; the last one is active
	acked  uint64
	next   uint64
	stats  Stats
	notify chan struct{}
	closed bool
	// cur is where the record after cur.seq starts, so that sequential
	// Reads do not rescan the segment.
	cur struct {
		seq uint64
		seg *segment
		off int64
	}
}

// Open opens or creates the spool in dir and recovers it: torn or corrupt
// records at the end of a segment are cut off.
func Open(dir string, opts Options) (*Spool, error) {
	if opts.MaxBytes <= 0 {
		opts.MaxBytes = 2 << 30
	}
	if opts.SegmentBytes <= 0 {
		opts.SegmentBytes = 64 << 20
	}
	if opts.SegmentBytes > opts.MaxBytes/4 {
		opts.SegmentBytes = opts.MaxBytes / 4
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("spool: create %s: %w", dir, err)
	}
	s := &Spool{dir: dir, opts: opts, notify: make(chan struct{}, 1)}
	acked, err := readState(filepath.Join(dir, stateName))
	if err != nil {
		return nil, err
	}
	s.acked = acked
	if err := s.load(); err != nil {
		_ = s.closeFiles() // already failing with err
		return nil, err
	}
	s.next = s.acked + 1
	if n := len(s.segs); n > 0 && s.segs[n-1].last >= s.next {
		s.next = s.segs[n-1].last + 1
	}
	if err := s.trimAcked(); err != nil {
		_ = s.closeFiles() // already failing with err
		return nil, err
	}
	if len(s.segs) == 0 {
		if err := s.rotate(); err != nil {
			return nil, err
		}
	}
	return s, nil
}

func (s *Spool) load() error {
	names, err := filepath.Glob(filepath.Join(s.dir, segPrefix+"*"+segSuffix))
	if err != nil {
		return fmt.Errorf("spool: list segments: %w", err)
	}
	type named struct {
		first uint64
		path  string
	}
	var found []named
	for _, p := range names {
		base := strings.TrimSuffix(strings.TrimPrefix(filepath.Base(p), segPrefix), segSuffix)
		first, err := strconv.ParseUint(base, 10, 64)
		if err != nil || first == 0 {
			continue // not ours
		}
		found = append(found, named{first, p})
	}
	sort.Slice(found, func(i, j int) bool { return found[i].first < found[j].first })
	var prev uint64
	for _, n := range found {
		if n.first <= prev {
			return fmt.Errorf("spool: segment %s overlaps the previous one", n.path)
		}
		seg, err := s.scan(n.path, n.first)
		if err != nil {
			return err
		}
		s.segs = append(s.segs, seg)
		prev = seg.last
	}
	return nil
}

// scan validates every record of a segment and truncates the file at the
// first bad one.
func (s *Spool) scan(path string, first uint64) (*segment, error) {
	f, err := os.OpenFile(path, os.O_RDWR, 0o600)
	if err != nil {
		return nil, fmt.Errorf("spool: open %s: %w", path, err)
	}
	seg := &segment{first: first, last: first - 1, f: f}
	fi, err := f.Stat()
	if err != nil {
		f.Close()
		return nil, fmt.Errorf("spool: stat %s: %w", path, err)
	}
	var off int64
	for {
		rec, n, err := readRecord(f, off, true)
		if err != nil || rec.Seq != seg.last+1 {
			break
		}
		seg.last = rec.Seq
		seg.records++
		seg.events += uint64(rec.Events)
		off += n
	}
	if off < fi.Size() {
		if err := f.Truncate(off); err != nil {
			f.Close()
			return nil, fmt.Errorf("spool: truncate %s: %w", path, err)
		}
		s.stats.TruncatedBytes += fi.Size() - off
	}
	seg.size = off
	return seg, nil
}

// readRecord reads the record at off. With verify it also checks the CRC.
func readRecord(f *os.File, off int64, verify bool) (Record, int64, error) {
	var h [headerSize]byte
	if _, err := f.ReadAt(h[:], off); err != nil {
		return Record{}, 0, err
	}
	n := binary.LittleEndian.Uint32(h[0:4])
	if n > MaxRecord {
		return Record{}, 0, fmt.Errorf("spool: record of %d bytes", n)
	}
	rec := Record{
		Seq:     binary.LittleEndian.Uint64(h[8:16]),
		Events:  binary.LittleEndian.Uint32(h[16:20]),
		Payload: make([]byte, n),
	}
	if _, err := f.ReadAt(rec.Payload, off+headerSize); err != nil {
		if errors.Is(err, io.EOF) {
			err = io.ErrUnexpectedEOF
		}
		return Record{}, 0, err
	}
	if verify {
		c := crc32.Update(crc32.Checksum(h[8:20], castagnoli), castagnoli, rec.Payload)
		if c != binary.LittleEndian.Uint32(h[4:8]) {
			return Record{}, 0, errors.New("spool: bad crc")
		}
	}
	return rec, headerSize + int64(n), nil
}

// readSeq reads only the header of the record at off.
func readSeq(f *os.File, off int64) (uint64, int64, error) {
	var h [headerSize]byte
	if _, err := f.ReadAt(h[:], off); err != nil {
		return 0, 0, err
	}
	n := binary.LittleEndian.Uint32(h[0:4])
	if n > MaxRecord {
		return 0, 0, fmt.Errorf("spool: record of %d bytes", n)
	}
	return binary.LittleEndian.Uint64(h[8:16]), headerSize + int64(n), nil
}

func (s *Spool) rotate() error {
	path := filepath.Join(s.dir, fmt.Sprintf("%s%020d%s", segPrefix, s.next, segSuffix))
	f, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		return fmt.Errorf("spool: create segment: %w", err)
	}
	if err := syncDir(s.dir); err != nil {
		f.Close()
		return err
	}
	s.segs = append(s.segs, &segment{first: s.next, last: s.next - 1, f: f})
	s.stats.Segments = len(s.segs)
	return nil
}

// Append stores payload (an encoded batch of events events) under the next
// seq and returns that seq.
func (s *Spool) Append(payload []byte, events uint32) (uint64, error) {
	if len(payload) > MaxRecord {
		return 0, fmt.Errorf("spool: batch of %d bytes exceeds %d", len(payload), MaxRecord)
	}
	need := int64(headerSize + len(payload))
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return 0, ErrClosed
	}
	active := s.segs[len(s.segs)-1]
	if active.size > 0 && active.size+need > s.opts.SegmentBytes {
		if err := s.rotate(); err != nil {
			return 0, err
		}
		active = s.segs[len(s.segs)-1]
	}
	for s.totalBytes()+need > s.opts.MaxBytes && len(s.segs) > 1 {
		if err := s.dropOldest(); err != nil {
			return 0, err
		}
	}
	buf := make([]byte, need)
	seq := s.next
	binary.LittleEndian.PutUint32(buf[0:4], uint32(len(payload)))
	binary.LittleEndian.PutUint64(buf[8:16], seq)
	binary.LittleEndian.PutUint32(buf[16:20], events)
	copy(buf[headerSize:], payload)
	binary.LittleEndian.PutUint32(buf[4:8], crc32.Checksum(buf[8:], castagnoli))
	if _, err := active.f.WriteAt(buf, active.size); err != nil {
		// Cut off whatever part was written so the next append starts clean.
		_ = active.f.Truncate(active.size)
		return 0, fmt.Errorf("spool: write: %w", err)
	}
	if !s.opts.NoSync {
		if err := active.f.Sync(); err != nil {
			return 0, fmt.Errorf("spool: sync: %w", err)
		}
	}
	active.size += need
	active.last = seq
	active.records++
	active.events += uint64(events)
	s.next++
	select {
	case s.notify <- struct{}{}:
	default:
	}
	return seq, nil
}

func (s *Spool) totalBytes() int64 {
	var n int64
	for _, g := range s.segs {
		n += g.size
	}
	return n
}

// dropOldest removes the oldest segment; its unacked batches are lost.
func (s *Spool) dropOldest() error {
	g := s.segs[0]
	if g.last > s.acked {
		lostRecs, lostEvents := g.records, g.events
		if s.acked >= g.first {
			// Part of the segment was acked; count only what was not.
			lostRecs, lostEvents = s.countAfter(g, s.acked)
		}
		s.stats.DroppedBatches += lostRecs
		s.stats.DroppedEvents += lostEvents
	}
	return s.removeFirst()
}

func (s *Spool) countAfter(g *segment, after uint64) (recs, events uint64) {
	var off int64
	for off < g.size {
		rec, n, err := readRecord(g.f, off, false)
		if err != nil {
			break
		}
		if rec.Seq > after {
			recs++
			events += uint64(rec.Events)
		}
		off += n
	}
	return recs, events
}

func (s *Spool) removeFirst() error {
	g := s.segs[0]
	if s.cur.seg == g {
		s.cur.seg = nil
	}
	g.f.Close()
	if err := os.Remove(g.f.Name()); err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("spool: remove segment: %w", err)
	}
	s.segs = s.segs[1:]
	s.stats.Segments = len(s.segs)
	return nil
}

// trimAcked removes segments whose batches are all acked, except the
// active one.
func (s *Spool) trimAcked() error {
	for len(s.segs) > 1 && s.segs[0].last <= s.acked {
		if err := s.removeFirst(); err != nil {
			return err
		}
	}
	return nil
}

// Ack records that the control plane committed every batch up to seq.
// Acks for seqs never handed out are ignored.
func (s *Spool) Ack(seq uint64) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return ErrClosed
	}
	if seq <= s.acked || seq >= s.next {
		return nil
	}
	if err := writeState(s.dir, seq, !s.opts.NoSync); err != nil {
		return err
	}
	s.acked = seq
	return s.trimAcked()
}

// Read returns up to max records with seq above after, oldest first. A
// gap in the returned seqs means batches were dropped while the spool was
// full.
func (s *Spool) Read(after uint64, max int) ([]Record, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil, ErrClosed
	}
	var out []Record
	for _, g := range s.segs {
		if g.last <= after {
			continue
		}
		var off int64
		if s.cur.seg == g && s.cur.seq == after {
			off = s.cur.off
		}
		for off < g.size && len(out) < max {
			seq, n, err := readSeq(g.f, off)
			if err != nil {
				return out, fmt.Errorf("spool: read seq after %d: %w", after, err)
			}
			if seq > after {
				rec, _, err := readRecord(g.f, off, false)
				if err != nil {
					return out, fmt.Errorf("spool: read seq %d: %w", seq, err)
				}
				out = append(out, rec)
				s.cur.seq, s.cur.seg, s.cur.off = seq, g, off+n
			}
			off += n
		}
		if len(out) >= max {
			break
		}
	}
	return out, nil
}

// Notify is signalled after each append.
func (s *Spool) Notify() <-chan struct{} { return s.notify }

// Stats returns a snapshot of the counters.
func (s *Spool) Stats() Stats {
	s.mu.Lock()
	defer s.mu.Unlock()
	st := s.stats
	st.Bytes = s.totalBytes()
	st.Segments = len(s.segs)
	st.LastSeq = s.next - 1
	st.AckedSeq = s.acked
	return st
}

// Close closes the segment files.
func (s *Spool) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil
	}
	s.closed = true
	return s.closeFiles()
}

func (s *Spool) closeFiles() error {
	var first error
	for _, g := range s.segs {
		if err := g.f.Close(); err != nil && first == nil {
			first = fmt.Errorf("spool: close segment: %w", err)
		}
	}
	return first
}
