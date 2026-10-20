package replay

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"regexp"
	"strconv"
	"sync/atomic"
	"time"

	"github.com/parquet-go/parquet-go"

	"github.com/strata/strata/control-plane/policy"
)

// Format is the sample format version (docs/spec/replay-sample.md).
const Format = "1"

// Metadata keys of a sample file.
const (
	MetaFormat = "strata.replay.format"
	MetaKeyID  = "strata.replay.anon_key_id"
)

// WriteParquet writes records as one sample file.
func WriteParquet(w io.Writer, keyID string, recs []Record) error {
	pw := parquet.NewGenericWriter[Record](w,
		parquet.KeyValueMetadata(MetaFormat, Format),
		parquet.KeyValueMetadata(MetaKeyID, keyID),
		parquet.Compression(&parquet.Zstd),
	)
	if _, err := pw.Write(recs); err != nil {
		return fmt.Errorf("replay: write samples: %w", err)
	}
	if err := pw.Close(); err != nil {
		return fmt.Errorf("replay: write samples: %w", err)
	}
	return nil
}

// ReadParquet reads a sample file back; the format must be Format.
func ReadParquet(data []byte) (keyID string, recs []Record, err error) {
	f, err := parquet.OpenFile(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		return "", nil, fmt.Errorf("replay: read samples: %w", err)
	}
	if v, _ := f.Lookup(MetaFormat); v != Format {
		return "", nil, fmt.Errorf("replay: sample format %q, want %q", v, Format)
	}
	keyID, _ = f.Lookup(MetaKeyID)
	r := parquet.NewGenericReader[Record](f)
	defer r.Close()
	recs = make([]Record, r.NumRows())
	n, err := r.Read(recs)
	if err != nil && err != io.EOF {
		return "", nil, fmt.Errorf("replay: read samples: %w", err)
	}
	return keyID, recs[:n], nil
}

// Store keeps sample files in object storage (the bundles' bucket in the
// lab), under replay/v1/<policy>/<yyyy>/<mm>/<dd>/.
type Store struct {
	Objects policy.Objects
	seq     atomic.Uint64
}

// Key of a sample file of policy from node whose first request is at ts.
func Key(policyName, node string, firstTsMs int64, seq uint64) string {
	t := time.UnixMilli(firstTsMs).UTC()
	return fmt.Sprintf("replay/v1/%s/%04d/%02d/%02d/%s-%d-%s.parquet",
		policyName, t.Year(), t.Month(), t.Day(), node, firstTsMs, strconv.FormatUint(seq, 10))
}

// Put stores records an Anonymizer made, all of one policy and one node, as
// one sample file; returns the object key.
func (s *Store) Put(ctx context.Context, keyID string, recs []Record) (string, error) {
	if len(recs) == 0 {
		return "", fmt.Errorf("replay: no samples")
	}
	p, n := recs[0].Policy, recs[0].NodeID
	if p == "" || !policy.ValidName(p) {
		return "", fmt.Errorf("replay: bad policy name %q", p)
	}
	if !nodePattern.MatchString(n) {
		return "", fmt.Errorf("replay: bad node id %q", n)
	}
	for _, r := range recs {
		if r.Policy != p || r.NodeID != n {
			return "", fmt.Errorf("replay: a sample file holds one policy of one node")
		}
	}
	var buf bytes.Buffer
	if err := WriteParquet(&buf, keyID, recs); err != nil {
		return "", err
	}
	sum := sha256.Sum256(buf.Bytes())
	key := Key(p, n, recs[0].TsMs, s.seq.Add(1))
	if err := s.Objects.Put(ctx, key, buf.Bytes(), hex.EncodeToString(sum[:])); err != nil {
		return "", fmt.Errorf("replay: store %s: %w", key, err)
	}
	return key, nil
}

// nodePattern: node ids go into object keys.
var nodePattern = regexp.MustCompile(`^[A-Za-z0-9._-]{1,128}$`)
