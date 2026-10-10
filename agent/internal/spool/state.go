package spool

import (
	"encoding/binary"
	"errors"
	"fmt"
	"hash/crc32"
	"os"
	"path/filepath"
)

// The state file is [magic "SSP1"][acked seq u64][crc32c u32] (16 bytes).
const stateMagic = "SSP1"

func readState(path string) (uint64, error) {
	b, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return 0, nil
	}
	if err != nil {
		return 0, fmt.Errorf("spool: read state: %w", err)
	}
	if len(b) != 16 || string(b[:4]) != stateMagic ||
		crc32.Checksum(b[:12], castagnoli) != binary.LittleEndian.Uint32(b[12:]) {
		// Refuse to guess: restarting seqs below the last ack would make
		// the control plane drop new batches as duplicates.
		return 0, fmt.Errorf("spool: corrupt state file %s", path)
	}
	return binary.LittleEndian.Uint64(b[4:12]), nil
}

// writeState replaces the state file atomically (tmp + rename).
func writeState(dir string, acked uint64, sync bool) error {
	var b [16]byte
	copy(b[:4], stateMagic)
	binary.LittleEndian.PutUint64(b[4:12], acked)
	binary.LittleEndian.PutUint32(b[12:], crc32.Checksum(b[:12], castagnoli))
	tmp := filepath.Join(dir, stateName+".tmp")
	f, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		return fmt.Errorf("spool: write state: %w", err)
	}
	if _, err := f.Write(b[:]); err != nil {
		f.Close()
		return fmt.Errorf("spool: write state: %w", err)
	}
	if sync {
		if err := f.Sync(); err != nil {
			f.Close()
			return fmt.Errorf("spool: sync state: %w", err)
		}
	}
	if err := f.Close(); err != nil {
		return fmt.Errorf("spool: close state: %w", err)
	}
	if err := os.Rename(tmp, filepath.Join(dir, stateName)); err != nil {
		return fmt.Errorf("spool: rename state: %w", err)
	}
	if sync {
		return syncDir(dir)
	}
	return nil
}

func syncDir(dir string) error {
	d, err := os.Open(dir)
	if err != nil {
		return fmt.Errorf("spool: open dir: %w", err)
	}
	defer d.Close()
	if err := d.Sync(); err != nil {
		return fmt.Errorf("spool: sync dir: %w", err)
	}
	return nil
}
