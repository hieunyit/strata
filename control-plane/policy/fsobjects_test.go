package policy

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/strata/strata/agent/pkg/bundlefmt"
	"github.com/strata/strata/control-plane/store"
)

func sumHex(b []byte) string {
	s := sha256.Sum256(b)
	return hex.EncodeToString(s[:])
}

func newFS(t *testing.T) (*FS, string) {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "objects")
	f, err := NewFS(dir, DefaultMutableKeys)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { f.Close() })
	return f, dir
}

func TestFSPutGetOpenList(t *testing.T) {
	f, dir := newFS(t)
	ctx := t.Context()
	data := []byte("signed bundle bytes")
	key := ObjectKey(7)
	if err := f.Put(ctx, key, data, sumHex(data)); err != nil {
		t.Fatal(err)
	}
	got, err := f.Get(ctx, key)
	if err != nil || string(got) != string(data) {
		t.Fatalf("get: %q %v", got, err)
	}
	// FetchBundle resumes at an offset
	r, err := f.Open(ctx, key, 7)
	if err != nil {
		t.Fatal(err)
	}
	rest, _ := io.ReadAll(r)
	r.Close()
	if string(rest) != "bundle bytes" {
		t.Fatalf("open at 7: %q", rest)
	}
	if r, err := f.Open(ctx, key, int64(len(data))); err != nil {
		t.Fatalf("open at the end: %v", err)
	} else {
		r.Close()
	}
	if _, err := f.Open(ctx, key, int64(len(data))+1); err == nil {
		t.Fatal("open past the end")
	}
	// private: replay samples are sensitive
	for _, p := range []string{dir, filepath.Join(dir, "bundles")} {
		if st, _ := os.Stat(p); st.Mode().Perm() != 0o700 {
			t.Errorf("%s: mode %o", p, st.Mode().Perm())
		}
	}
	if st, _ := os.Stat(filepath.Join(dir, key)); st.Mode().Perm() != 0o600 {
		t.Errorf("file mode %o", st.Mode().Perm())
	}
	// no file being written is left behind
	entries, _ := os.ReadDir(filepath.Dir(filepath.Join(dir, key)))
	if len(entries) != 1 {
		t.Fatalf("directory holds %d entries", len(entries))
	}

	for _, k := range []string{"replay/v1/example-api/2026/10/20/node-1-100-2.parquet", "replay/v1/example-api/2026/10/20/node-1-100-1.parquet",
		"replay/v1/example-api/2026/10/21/node-1-200-1.parquet", "replay/v1/example-api-2/2026/10/20/node-1-1-1.parquet"} {
		if err := f.Put(ctx, k, []byte(k), ""); err != nil {
			t.Fatal(err)
		}
	}
	// a file being written and a link are not objects
	if err := os.WriteFile(filepath.Join(dir, "replay/v1/example-api/2026/10/20", tmpPrefix+"x"), []byte("partial"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("/etc/passwd", filepath.Join(dir, "replay/v1/example-api/2026/10/20/link.parquet")); err != nil {
		t.Fatal(err)
	}
	objs, err := f.List(ctx, "replay/v1/example-api/2026/10/20/")
	if err != nil {
		t.Fatal(err)
	}
	if len(objs) != 2 || objs[0].Key != "replay/v1/example-api/2026/10/20/node-1-100-1.parquet" || objs[1].Size != int64(len(objs[1].Key)) {
		t.Fatalf("list: %+v", objs)
	}
	// a prefix that ends inside a segment, as S3 matches it
	if objs, _ := f.List(ctx, "replay/v1/example-api"); len(objs) != 4 {
		t.Fatalf("partial prefix: %+v", objs)
	}
	if objs, err := f.List(ctx, "replay/v1/other/"); err != nil || len(objs) != 0 {
		t.Fatalf("missing prefix: %+v %v", objs, err)
	}
	if objs, err := f.List(ctx, ""); err != nil || len(objs) != 5 {
		t.Fatalf("everything: %+v %v", objs, err)
	}
}

func TestFSMissingIsObjectNotFound(t *testing.T) {
	f, _ := newFS(t)
	if _, err := f.Get(t.Context(), "goodbots/latest.json"); !IsObjectNotFound(err) {
		t.Fatalf("get: %v", err)
	}
	if _, err := f.Open(t.Context(), ObjectKey(1), 0); !IsObjectNotFound(err) {
		t.Fatalf("open: %v", err)
	}
}

func TestFSImmutableAndPointers(t *testing.T) {
	f, _ := newFS(t)
	ctx := t.Context()
	key := ObjectKey(3)
	if err := f.Put(ctx, key, []byte("one"), ""); err != nil {
		t.Fatal(err)
	}
	// the same bytes again: a retried upload succeeds
	if err := f.Put(ctx, key, []byte("one"), ""); err != nil {
		t.Fatalf("same content: %v", err)
	}
	if err := f.Put(ctx, key, []byte("two"), ""); !errors.Is(err, ErrObjectExists) {
		t.Fatalf("other content: %v", err)
	}
	if got, _ := f.Get(ctx, key); string(got) != "one" {
		t.Fatalf("overwritten: %q", got)
	}
	for _, k := range []string{"geoip/latest.json", "geoip/0123abcd/manifest.json", "goodbots/latest.json", "goodbots/0123abcd.json"} {
		for _, v := range []string{"old", "new"} {
			if err := f.Put(ctx, k, []byte(v), ""); err != nil {
				t.Fatalf("%s: %v", k, err)
			}
		}
		if got, _ := f.Get(ctx, k); string(got) != "new" {
			t.Fatalf("%s: %q", k, got)
		}
	}
	// a GeoIP database is immutable like a bundle
	if err := f.Put(ctx, "geoip/0123abcd/city.mmdb", []byte("a"), ""); err != nil {
		t.Fatal(err)
	}
	if err := f.Put(ctx, "geoip/0123abcd/city.mmdb", []byte("b"), ""); !errors.Is(err, ErrObjectExists) {
		t.Fatalf("mmdb: %v", err)
	}
	if err := f.Put(ctx, ObjectKey(4), []byte("data"), sumHex([]byte("other"))); err == nil {
		t.Fatal("wrong SHA-256 accepted")
	}
	if _, err := f.Get(ctx, ObjectKey(4)); !IsObjectNotFound(err) {
		t.Fatalf("written despite the wrong SHA-256: %v", err)
	}
}

// CP-A07 risk: a policy named ".." in replay/v1/<policy>/… must not write
// outside the directory, nor may a link inside it lead out.
func TestFSRefusesEscapes(t *testing.T) {
	f, dir := newFS(t)
	ctx := t.Context()
	for _, k := range []string{"", "/etc/passwd", "replay/v1/../../x", "replay/v1/./x", "a//b", "a/", "..", "bundles/x y", "bundles/x\x00",
		"bundles/" + tmpPrefix + "1", strings.Repeat("a/", maxKeyDepth) + "b", "bundles/" + strings.Repeat("x", 256)} {
		if err := f.Put(ctx, k, []byte("x"), ""); err == nil {
			t.Errorf("put %q accepted", k)
		}
		if _, err := f.Get(ctx, k); err == nil || IsObjectNotFound(err) {
			t.Errorf("get %q: %v", k, err)
		}
	}
	outside := t.TempDir()
	if err := os.WriteFile(filepath.Join(outside, "secret"), []byte("outside"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(dir, "replay")); err != nil {
		t.Fatal(err)
	}
	if _, err := f.Get(ctx, "replay/secret"); err == nil {
		t.Fatal("read through a link out of the directory")
	}
	if err := f.Put(ctx, "replay/new", []byte("x"), ""); err == nil {
		t.Fatal("wrote through a link out of the directory")
	}
	if _, err := os.Stat(filepath.Join(outside, "new")); err == nil {
		t.Fatal("file written outside")
	}
	if objs, err := f.List(ctx, "replay/"); err == nil && len(objs) != 0 {
		t.Fatalf("listed through a link: %+v", objs)
	}
}

// Writers of the same immutable key at once: one content wins, the other
// writer is told, and no reader sees a partial file.
func TestFSConcurrentPuts(t *testing.T) {
	f, _ := newFS(t)
	ctx := t.Context()
	key := ObjectKey(9)
	a, b := []byte(strings.Repeat("a", 1<<16)), []byte(strings.Repeat("b", 1<<16))
	var wg sync.WaitGroup
	errs := make([]error, 8)
	for i := range errs {
		wg.Go(func() {
			data := a
			if i%2 == 1 {
				data = b
			}
			errs[i] = f.Put(ctx, key, data, "")
		})
	}
	wg.Wait()
	got, err := f.Get(ctx, key)
	if err != nil || (string(got) != string(a) && string(got) != string(b)) {
		t.Fatalf("content %d bytes: %v", len(got), err)
	}
	for i, err := range errs {
		mine := a
		if i%2 == 1 {
			mine = b
		}
		if (string(mine) == string(got)) != (err == nil) {
			t.Errorf("writer %d: %v", i, err)
		}
	}
}

// A bundle uploaded by a deploy that failed before it was recorded, or a
// database restored behind its artifacts, is never built over.
func TestFreeVersionSkipsStoredBundles(t *testing.T) {
	f, _ := newFS(t)
	ctx := t.Context()
	if v, err := FreeVersion(ctx, f, 5); err != nil || v != 5 {
		t.Fatalf("empty store: %d %v", v, err)
	}
	for _, v := range []uint64{5, 6, 9} {
		if err := f.Put(ctx, ObjectKey(v), []byte("x"), ""); err != nil {
			t.Fatal(err)
		}
	}
	if v, err := FreeVersion(ctx, f, 5); err != nil || v != 10 {
		t.Fatalf("taken: %d %v", v, err)
	}
	if v, err := FreeVersion(ctx, f, 7); err != nil || v != 7 {
		t.Fatalf("free: %d %v", v, err)
	}
	// a store that cannot list keeps the version
	if v, err := FreeVersion(ctx, putGetOnly{f}, 5); err != nil || v != 5 {
		t.Fatalf("no list: %d %v", v, err)
	}
}

type putGetOnly struct{ Objects }

// failingRecord loses the database write after the upload.
type failingRecord struct {
	*fakeStore
	fail bool
}

func (f *failingRecord) RecordBundle(ctx context.Context, b store.Bundle, a store.Audit) (store.Bundle, error) {
	if f.fail {
		return store.Bundle{}, errors.New("database gone")
	}
	return f.fakeStore.RecordBundle(ctx, b, a)
}

// CP-A07: a deploy that uploaded its bundle and failed to record it does
// not block the next one, which takes the version after it.
func TestDeployOnFilesystemAfterAnUnrecordedUpload(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(nil)
	f, _ := newFS(t)
	st := &failingRecord{fakeStore: &fakeStore{policies: []store.Policy{
		{ID: "api", Name: "example-api", CurrentVersion: 3, Spec: json.RawMessage(`{"mode":"enforce"}`)}}}, fail: true}
	n := 0
	d := &Deployer{Store: st, Objects: f, PubKey: pub, Builder: builderFunc(func(v uint64, p int) []byte {
		n++ // each build differs, as a newer GeoIP or crawler list would make it
		b := signed(priv, v, uint32(p))[:4096]
		b[4000] = byte(n)
		return append(b, ed25519.Sign(priv, b)...)
	})}
	if _, err := d.Deploy(t.Context(), store.Audit{Actor: "alice"}); err == nil {
		t.Fatal("record failure not reported")
	}
	if _, err := f.Get(t.Context(), ObjectKey(1)); err != nil {
		t.Fatalf("the failed deploy's upload: %v", err)
	}
	st.fail = false
	dep, err := d.Deploy(t.Context(), store.Audit{Actor: "alice"})
	if err != nil || dep.Bundle.Version != 2 || dep.Bundle.ObjectKey != ObjectKey(2) {
		t.Fatalf("retry: %+v %v", dep.Bundle, err)
	}
	data, err := f.Get(t.Context(), ObjectKey(2))
	if err != nil {
		t.Fatal(err)
	}
	if h, err := bundlefmt.Verify(data, pub); err != nil || h.Version != 2 {
		t.Fatalf("stored bundle: %+v %v", h, err)
	}
}

type keptBundles struct {
	keep   map[uint64]bool
	newest uint64
}

func (k keptBundles) KeptBundles(context.Context, int) (map[uint64]bool, uint64, error) {
	return k.keep, k.newest, nil
}

// CP-A07: pruning removes what the database does not keep, never a bundle
// above the newest recorded one, and replay samples by the day of their key.
func TestPrunerKeepsWhatTheDatabaseNeeds(t *testing.T) {
	f, dir := newFS(t)
	ctx := t.Context()
	for v := uint64(1); v <= 8; v++ {
		if err := f.Put(ctx, ObjectKey(v), []byte{byte(v)}, ""); err != nil {
			t.Fatal(err)
		}
	}
	samples := []string{"replay/v1/example-api/2026/10/12/n-1-1.parquet", "replay/v1/example-api/2026/10/13/n-1-1.parquet",
		"replay/v1/example-api/2026/10/20/n-1-1.parquet", "replay/v1/example-web/2026/09/30/n-1-1.parquet"}
	for _, k := range samples {
		if err := f.Put(ctx, k, []byte("x"), ""); err != nil {
			t.Fatal(err)
		}
	}
	p := &Pruner{Store: keptBundles{keep: map[uint64]bool{2: true, 5: true, 6: true}, newest: 6}, Objects: f, KeepBundles: 2, SampleDays: 7,
		Now: func() time.Time { return time.Date(2026, 10, 20, 9, 0, 0, 0, time.UTC) }}
	n, err := p.Prune(ctx)
	if err != nil || n.Bundles != 3 || n.Samples != 2 {
		t.Fatalf("pruned %+v %v", n, err)
	}
	for v := uint64(1); v <= 8; v++ {
		_, err := f.Get(ctx, ObjectKey(v))
		if want := v == 2 || v >= 5; (err == nil) != want {
			t.Errorf("bundle %d: %v", v, err)
		}
	}
	for i, k := range samples {
		_, err := f.Get(ctx, k)
		if want := i == 1 || i == 2; (err == nil) != want {
			t.Errorf("%s: %v", k, err)
		}
	}
	// emptied directories go too
	if _, err := os.Stat(filepath.Join(dir, "bundles", fmt.Sprintf("%020d", 1))); !os.IsNotExist(err) {
		t.Fatalf("directory of a removed bundle: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, "replay/v1/example-web")); !os.IsNotExist(err) {
		t.Fatalf("directory of removed samples: %v", err)
	}
	if n, err := p.Prune(ctx); err != nil || n != (Pruned{}) {
		t.Fatalf("second run: %+v %v", n, err)
	}
}

func TestPruneGeoIPKeepsThePointerAndTwoVersions(t *testing.T) {
	f, _ := newFS(t)
	ctx := t.Context()
	for _, k := range []string{"geoip/latest.json", "geoip/aa/city.mmdb", "geoip/aa/manifest.json", "geoip/bb/city.mmdb", "geoip/cc/asn.mmdb"} {
		if err := f.Put(ctx, k, []byte("x"), ""); err != nil {
			t.Fatal(err)
		}
	}
	if err := PruneGeoIP(f)(ctx, []string{"bb", "cc"}); err != nil {
		t.Fatal(err)
	}
	objs, _ := f.List(ctx, "geoip/")
	var keys []string
	for _, o := range objs {
		keys = append(keys, o.Key)
	}
	if strings.Join(keys, " ") != "geoip/bb/city.mmdb geoip/cc/asn.mmdb geoip/latest.json" {
		t.Fatalf("left %v", keys)
	}
}

type nearlyFull struct{ *FS }

func (nearlyFull) FreeBytes() (uint64, error) { return MinFreeBytes - 1, nil }

func TestDeployRefusedWhenTheDirectoryIsNearlyFull(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(nil)
	f, _ := newFS(t)
	if free, err := f.FreeBytes(); err != nil || free == 0 {
		t.Fatalf("free space: %d %v", free, err)
	}
	built := false
	d := &Deployer{Store: &fakeStore{policies: []store.Policy{{ID: "api", Name: "example-api", CurrentVersion: 1, Spec: json.RawMessage(`{"mode":"shadow"}`)}}},
		Objects: nearlyFull{f}, PubKey: pub, Builder: builderFunc(func(v uint64, n int) []byte { built = true; return signed(priv, v, uint32(n)) })}
	if _, err := d.Deploy(t.Context(), store.Audit{Actor: "alice"}); err == nil || !strings.Contains(err.Error(), "free") || built {
		t.Fatalf("deploy: %v (built %v)", err, built)
	}
}
