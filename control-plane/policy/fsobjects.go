package policy

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log"
	"os"
	"path"
	"sort"
	"strings"
	"syscall"
)

// ErrObjectExists: Put of an immutable key that holds other content.
var ErrObjectExists = errors.New("policy: object exists with other content")

// ObjectStore is what the server keeps artifacts in: S3 or FS (CP-A07).
type ObjectStore interface {
	Objects
	Open(ctx context.Context, key string, offset int64) (io.ReadCloser, error)
	List(ctx context.Context, prefix string) ([]ObjectInfo, error)
	Delete(ctx context.Context, key string) error
}

// DefaultMutableKeys are the keys FS lets Put overwrite (path.Match
// patterns): the pointers to the latest GeoIP and crawler ranges, and the
// manifests of a version, which carry the time of the download (the same
// version downloaded again after another one writes it again). Every
// other key (bundles, replay samples, GeoIP databases) is immutable.
var DefaultMutableKeys = []string{"geoip/latest.json", "geoip/*/manifest.json", "goodbots/*.json"}

// tmpPrefix names FS's files being written; keys may not use it.
const tmpPrefix = ".strata-tmp-"

// maxKeyDepth bounds the segments of a key (replay samples have 7).
const maxKeyDepth = 16

// FS keeps objects as files under a directory, for a control plane
// without an object store (CP-A07). Files are opened through os.Root, so
// neither a key nor a symbolic link reaches outside the directory. A Put is
// atomic: readers see the old file or the new one, never a part.
type FS struct {
	root    *os.Root
	dir     string
	mutable []string
}

// MinFreeBytes: a deploy needs this much free space in the directory.
const MinFreeBytes = 256 << 20

// nfsMagic is statfs's f_type of NFS.
const nfsMagic = 0x6969

// NewFS opens dir (created 0700 when missing). mutable: the key patterns
// Put may overwrite (DefaultMutableKeys in the server).
func NewFS(dir string, mutable []string) (*FS, error) {
	if dir == "" {
		return nil, errors.New("policy: object directory not set")
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("policy: object directory: %w", err)
	}
	root, err := os.OpenRoot(dir)
	if err != nil {
		return nil, fmt.Errorf("policy: object directory: %w", err)
	}
	for _, p := range mutable {
		if _, err := path.Match(p, ""); err != nil {
			root.Close()
			return nil, fmt.Errorf("policy: mutable key pattern %q: %w", p, err)
		}
	}
	var st syscall.Statfs_t
	if syscall.Statfs(dir, &st) == nil && st.Type == nfsMagic {
		log.Printf("[WARN] artifacts: %s is on NFS: renames and links may not be atomic there, and two control planes must never share it", dir)
	}
	return &FS{root: root, dir: dir, mutable: mutable}, nil
}

// FreeBytes is the space left for the control plane in the directory.
func (f *FS) FreeBytes() (uint64, error) {
	var st syscall.Statfs_t
	if err := syscall.Statfs(f.dir, &st); err != nil {
		return 0, fmt.Errorf("policy: free space of %s: %w", f.dir, err)
	}
	return st.Bavail * uint64(st.Bsize), nil
}

// Close releases the directory.
func (f *FS) Close() error { return f.root.Close() }

// validKey: segments of [A-Za-z0-9._-], none empty, "." or "..", none
// named like a file being written.
func validKey(key string) error {
	segs := strings.Split(key, "/")
	if key == "" || len(segs) > maxKeyDepth {
		return fmt.Errorf("policy: invalid object key %q", key)
	}
	for _, s := range segs {
		if s == "" || s == "." || s == ".." || len(s) > 255 || strings.HasPrefix(s, tmpPrefix) {
			return fmt.Errorf("policy: invalid object key %q", key)
		}
		for i := 0; i < len(s); i++ {
			if !keyByte(s[i]) {
				return fmt.Errorf("policy: invalid object key %q", key)
			}
		}
	}
	return nil
}

func keyByte(c byte) bool {
	return c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '.' || c == '_' || c == '-'
}

func (f *FS) isMutable(key string) bool {
	for _, p := range f.mutable {
		if ok, _ := path.Match(p, key); ok {
			return true
		}
	}
	return false
}

// Put writes data under key: into a new file in the key's directory,
// synced, then linked (immutable keys: never replaces a file) or renamed
// (mutable keys) into place, and the directory synced. An immutable key
// that already holds the same bytes is a success, other bytes
// ErrObjectExists. sha256hex, when set, must be the data's.
func (f *FS) Put(_ context.Context, key string, data []byte, sha256hex string) error {
	if err := validKey(key); err != nil {
		return err
	}
	if sha256hex != "" {
		sum := sha256.Sum256(data)
		if hex.EncodeToString(sum[:]) != strings.ToLower(sha256hex) {
			return fmt.Errorf("policy: upload %s: SHA-256 differs from the data", key)
		}
	}
	dir := path.Dir(key)
	if err := f.root.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("policy: upload %s: %w", key, err)
	}
	var rnd [8]byte
	if _, err := rand.Read(rnd[:]); err != nil {
		return err
	}
	tmp := path.Join(dir, tmpPrefix+hex.EncodeToString(rnd[:]))
	if err := f.writeTemp(tmp, data); err != nil {
		_ = f.root.Remove(tmp)
		return fmt.Errorf("policy: upload %s: %w", key, err)
	}
	if f.isMutable(key) {
		if err := f.root.Rename(tmp, key); err != nil {
			_ = f.root.Remove(tmp)
			return fmt.Errorf("policy: upload %s: %w", key, err)
		}
	} else {
		err := f.root.Link(tmp, key)
		_ = f.root.Remove(tmp)
		if errors.Is(err, fs.ErrExist) {
			old, rerr := f.root.ReadFile(key)
			if rerr != nil {
				return fmt.Errorf("policy: upload %s: %w", key, rerr)
			}
			if !bytes.Equal(old, data) {
				return fmt.Errorf("policy: upload %s: %w", key, ErrObjectExists)
			}
			return nil
		}
		if err != nil {
			return fmt.Errorf("policy: upload %s: %w", key, err)
		}
	}
	return f.syncDir(dir)
}

func (f *FS) writeTemp(name string, data []byte) error {
	w, err := f.root.OpenFile(name, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	if _, err := w.Write(data); err != nil {
		w.Close()
		return err
	}
	if err := w.Sync(); err != nil {
		w.Close()
		return err
	}
	return w.Close()
}

func (f *FS) syncDir(dir string) error {
	d, err := f.root.Open(dir)
	if err != nil {
		return err
	}
	err = d.Sync()
	if cerr := d.Close(); err == nil {
		err = cerr
	}
	return err
}

func (f *FS) open(key string) (*os.File, error) {
	if err := validKey(key); err != nil {
		return nil, err
	}
	r, err := f.root.Open(key)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, fmt.Errorf("policy: download %s: %w", key, ErrObjectNotFound)
	}
	if err != nil {
		return nil, fmt.Errorf("policy: download %s: %w", key, err)
	}
	st, err := r.Stat()
	if err != nil {
		r.Close()
		return nil, err
	}
	if !st.Mode().IsRegular() {
		r.Close()
		return nil, fmt.Errorf("policy: download %s: not a file", key)
	}
	return r, nil
}

// Get reads an object; a missing key is ErrObjectNotFound.
func (f *FS) Get(_ context.Context, key string) ([]byte, error) {
	r, err := f.open(key)
	if err != nil {
		return nil, err
	}
	defer r.Close()
	return io.ReadAll(r)
}

// Open reads an object from offset on (FetchBundle resumes there).
func (f *FS) Open(_ context.Context, key string, offset int64) (io.ReadCloser, error) {
	r, err := f.open(key)
	if err != nil {
		return nil, err
	}
	st, err := r.Stat()
	if err == nil && (offset < 0 || offset > st.Size()) {
		err = fmt.Errorf("policy: open %s: offset %d outside the object (%d bytes)", key, offset, st.Size())
	}
	if err == nil {
		_, err = r.Seek(offset, io.SeekStart)
	}
	if err != nil {
		r.Close()
		return nil, err
	}
	return r, nil
}

// List returns the objects whose key starts with prefix, in key order.
// Symbolic links and files being written are left out.
func (f *FS) List(_ context.Context, prefix string) ([]ObjectInfo, error) {
	dir := "."
	if i := strings.LastIndexByte(prefix, '/'); i > 0 {
		dir = prefix[:i]
		if validKey(dir) != nil {
			return nil, nil
		}
	}
	var out []ObjectInfo
	err := fs.WalkDir(f.root.FS(), dir, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			if p == dir && errors.Is(err, fs.ErrNotExist) {
				return fs.SkipAll
			}
			return err
		}
		if strings.HasPrefix(d.Name(), tmpPrefix) || !d.Type().IsRegular() || !strings.HasPrefix(p, prefix) {
			return nil
		}
		info, err := d.Info()
		if err != nil {
			if errors.Is(err, fs.ErrNotExist) {
				return nil // removed meanwhile
			}
			return err
		}
		out = append(out, ObjectInfo{Key: p, Size: info.Size()})
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("policy: list %s: %w", prefix, err)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Key < out[j].Key })
	return out, nil
}

// Delete removes an object (a missing one is no error), then its
// directories that became empty.
func (f *FS) Delete(_ context.Context, key string) error {
	if err := validKey(key); err != nil {
		return err
	}
	if err := f.root.Remove(key); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return fmt.Errorf("policy: delete %s: %w", key, err)
	}
	for dir := path.Dir(key); dir != "."; dir = path.Dir(dir) {
		if f.root.Remove(dir) != nil {
			break // not empty
		}
	}
	return nil
}
