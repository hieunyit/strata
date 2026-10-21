package spool

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"testing"
)

func open(t *testing.T, dir string, opts Options) *Spool {
	t.Helper()
	opts.NoSync = true
	s, err := Open(dir, opts)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}

func appendN(t *testing.T, s *Spool, n int, size int) []uint64 {
	t.Helper()
	var seqs []uint64
	for i := 0; i < n; i++ {
		p := bytes.Repeat([]byte{byte(i)}, size)
		seq, err := s.Append(p, 2)
		if err != nil {
			t.Fatalf("Append: %v", err)
		}
		seqs = append(seqs, seq)
	}
	return seqs
}

func seqsOf(recs []Record) []uint64 {
	var out []uint64
	for _, r := range recs {
		out = append(out, r.Seq)
	}
	return out
}

func TestAppendReadAck(t *testing.T) {
	s := open(t, t.TempDir(), Options{})
	if got := appendN(t, s, 5, 10); fmt.Sprint(got) != "[1 2 3 4 5]" {
		t.Fatalf("seqs %v", got)
	}
	recs, err := s.Read(0, 3)
	if err != nil {
		t.Fatal(err)
	}
	if fmt.Sprint(seqsOf(recs)) != "[1 2 3]" || recs[2].Events != 2 ||
		!bytes.Equal(recs[2].Payload, bytes.Repeat([]byte{2}, 10)) {
		t.Fatalf("read %+v", recs)
	}
	recs, _ = s.Read(3, 10)
	if fmt.Sprint(seqsOf(recs)) != "[4 5]" {
		t.Fatalf("read after 3: %v", seqsOf(recs))
	}
	if err := s.Ack(3); err != nil {
		t.Fatal(err)
	}
	// Reading again from the ack, as after a reconnect.
	recs, _ = s.Read(3, 10)
	if fmt.Sprint(seqsOf(recs)) != "[4 5]" {
		t.Fatalf("reread after 3: %v", seqsOf(recs))
	}
	if st := s.Stats(); st.LastSeq != 5 || st.AckedSeq != 3 {
		t.Fatalf("stats %+v", st)
	}
	// Acks outside (acked, last] are ignored.
	if err := s.Ack(9); err != nil || s.Stats().AckedSeq != 3 {
		t.Fatalf("ack beyond last: %v %+v", err, s.Stats())
	}
}

func TestReopenKeepsUnackedAndSeq(t *testing.T) {
	dir := t.TempDir()
	s := open(t, dir, Options{SegmentBytes: 100, MaxBytes: 1 << 20})
	appendN(t, s, 10, 30) // 50 bytes per record, 2 per segment
	if err := s.Ack(6); err != nil {
		t.Fatal(err)
	}
	s.Close()

	s = open(t, dir, Options{SegmentBytes: 100, MaxBytes: 1 << 20})
	recs, err := s.Read(s.Stats().AckedSeq, 100)
	if err != nil {
		t.Fatal(err)
	}
	if fmt.Sprint(seqsOf(recs)) != "[7 8 9 10]" {
		t.Fatalf("unacked after reopen: %v", seqsOf(recs))
	}
	if seq := appendN(t, s, 1, 1)[0]; seq != 11 {
		t.Fatalf("next seq %d, want 11", seq)
	}
}

func TestSeqNeverReusedAfterFullAck(t *testing.T) {
	dir := t.TempDir()
	s := open(t, dir, Options{SegmentBytes: 100, MaxBytes: 1 << 20})
	appendN(t, s, 6, 30)
	if err := s.Ack(6); err != nil {
		t.Fatal(err)
	}
	s.Close()
	// Remove every segment: only the state file remembers seq 6.
	segs, _ := filepath.Glob(filepath.Join(dir, "seg-*.log"))
	for _, p := range segs {
		os.Remove(p)
	}
	s = open(t, dir, Options{SegmentBytes: 100, MaxBytes: 1 << 20})
	if seq := appendN(t, s, 1, 1)[0]; seq != 7 {
		t.Fatalf("next seq %d, want 7", seq)
	}
}

func TestAckedSegmentsRemoved(t *testing.T) {
	dir := t.TempDir()
	s := open(t, dir, Options{SegmentBytes: 100, MaxBytes: 1 << 20})
	appendN(t, s, 10, 30)
	if n := s.Stats().Segments; n != 5 {
		t.Fatalf("segments %d, want 5", n)
	}
	if err := s.Ack(10); err != nil {
		t.Fatal(err)
	}
	if st := s.Stats(); st.Segments != 1 {
		t.Fatalf("segments after full ack %+v", st)
	}
	segs, _ := filepath.Glob(filepath.Join(dir, "seg-*.log"))
	if len(segs) != 1 {
		t.Fatalf("files %v", segs)
	}
}

func TestFullDropsOldest(t *testing.T) {
	// 4 records of 50 bytes per 200-byte segment, 800 bytes in total.
	s := open(t, t.TempDir(), Options{SegmentBytes: 200, MaxBytes: 800})
	appendN(t, s, 20, 30)
	st := s.Stats()
	if st.Bytes > 800 {
		t.Fatalf("spool holds %d bytes, cap 800", st.Bytes)
	}
	if st.DroppedBatches == 0 || st.DroppedEvents != 2*st.DroppedBatches {
		t.Fatalf("drop counters %+v", st)
	}
	recs, _ := s.Read(0, 100)
	if uint64(len(recs))+st.DroppedBatches != 20 || recs[len(recs)-1].Seq != 20 {
		t.Fatalf("kept %v, dropped %d", seqsOf(recs), st.DroppedBatches)
	}
	// What is kept is the newest, contiguous.
	for i := 1; i < len(recs); i++ {
		if recs[i].Seq != recs[i-1].Seq+1 {
			t.Fatalf("gap in kept seqs %v", seqsOf(recs))
		}
	}
}

func TestDropCountsOnlyUnacked(t *testing.T) {
	s := open(t, t.TempDir(), Options{SegmentBytes: 200, MaxBytes: 800})
	appendN(t, s, 2, 30)
	if err := s.Ack(1); err != nil {
		t.Fatal(err)
	}
	appendN(t, s, 16, 30) // fills 4 segments, then the first is dropped
	if st := s.Stats(); st.DroppedBatches != 3 {
		t.Fatalf("dropped %d batches, want 3 (seq 2-4)", st.DroppedBatches)
	}
}

func TestRecoverTornAndCorruptTail(t *testing.T) {
	for _, tc := range []struct {
		name string
		hurt func(path string, size int64) error
	}{
		{"torn", func(p string, size int64) error { return os.Truncate(p, size-7) }},
		{"bad crc", func(p string, size int64) error { return writeAt(p, []byte{0xff}, size-1) }},
		{"garbage", func(p string, size int64) error { return writeAt(p, bytes.Repeat([]byte{0xee}, 40), size) }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			s := open(t, dir, Options{})
			appendN(t, s, 3, 30)
			s.Close()
			p := filepath.Join(dir, fmt.Sprintf("seg-%020d.log", 1))
			fi, _ := os.Stat(p)
			if err := tc.hurt(p, fi.Size()); err != nil {
				t.Fatal(err)
			}

			s = open(t, dir, Options{})
			recs, err := s.Read(0, 10)
			if err != nil {
				t.Fatal(err)
			}
			want := "[1 2 3]"
			if tc.name != "garbage" {
				want = "[1 2]"
			}
			if fmt.Sprint(seqsOf(recs)) != want {
				t.Fatalf("recovered %v, want %s", seqsOf(recs), want)
			}
			if s.Stats().TruncatedBytes == 0 {
				t.Fatal("no truncated bytes counted")
			}
			// Appends continue right after the last good record.
			last := recs[len(recs)-1].Seq
			if seq := appendN(t, s, 1, 1)[0]; seq != last+1 {
				t.Fatalf("next seq %d, want %d", seq, last+1)
			}
			recs, _ = s.Read(last, 10)
			if len(recs) != 1 {
				t.Fatalf("read after recovery %v", seqsOf(recs))
			}
		})
	}
}

func TestCorruptStateRefused(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "state"), []byte("nonsense"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(dir, Options{NoSync: true}); err == nil {
		t.Fatal("Open accepted a corrupt state file")
	}
}

func TestOversizedBatchRejected(t *testing.T) {
	s := open(t, t.TempDir(), Options{})
	if _, err := s.Append(make([]byte, MaxRecord+1), 1); err == nil {
		t.Fatal("oversized batch accepted")
	}
	if seq := appendN(t, s, 1, 1)[0]; seq != 1 {
		t.Fatalf("seq %d after rejected append", seq)
	}
}

func TestNotify(t *testing.T) {
	s := open(t, t.TempDir(), Options{})
	appendN(t, s, 3, 1)
	select {
	case <-s.Notify():
	default:
		t.Fatal("no notification after append")
	}
}

func writeAt(path string, b []byte, off int64) error {
	f, err := os.OpenFile(path, os.O_RDWR, 0)
	if err != nil {
		return err
	}
	if _, err := f.WriteAt(b, off); err != nil {
		f.Close()
		return err
	}
	return f.Close()
}

func TestPendingBatchesExcludeAcknowledgedAndDroppedSegments(t *testing.T) {
	s := open(t, t.TempDir(), Options{SegmentBytes: 128, MaxBytes: 400})
	for range 12 {
		if _, err := s.Append(bytes.Repeat([]byte{'x'}, 80), 1); err != nil {
			t.Fatal(err)
		}
	}
	stats := s.Stats()
	if stats.DroppedBatches == 0 || stats.PendingBatches != stats.LastSeq-stats.AckedSeq-stats.DroppedBatches {
		t.Fatalf("dropped sequences counted as pending: %+v", stats)
	}
	if err := s.Ack(stats.LastSeq); err != nil {
		t.Fatal(err)
	}
	if got := s.Stats().PendingBatches; got != 0 {
		t.Fatalf("acknowledged backlog: %d", got)
	}
}
