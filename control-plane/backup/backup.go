// Package backup makes and reads the backup of a control plane (CP-A09):
// one tar archive encrypted with age (passphrase, scrypt), holding the
// PostgreSQL dump, the data directory (keys, PKI, secrets, configuration)
// and the artifacts kept on the filesystem, with a manifest of their
// SHA-256. The dump is taken first: artifacts are written before the rows
// that name them (CP-A07), so every bundle the dump references is already
// on disk when the files are copied after it.
package backup

import (
	"archive/tar"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"filippo.io/age"
)

// Format of the archive this build writes and reads.
const Format = 1

// Paths in the archive.
const (
	DumpName      = "postgres.dump"
	DataPrefix    = "data/"
	ObjectsPrefix = "objects/"
	ManifestName  = "manifest.json"
)

// File is one file of the archive.
type File struct {
	Path   string `json:"path"`
	Size   int64  `json:"size"`
	SHA256 string `json:"sha256"`
	Mode   uint32 `json:"mode"`
}

// Manifest describes an archive; it is its last entry.
type Manifest struct {
	Format    int       `json:"format"`
	CreatedAt time.Time `json:"created_at"`
	// Product version of the control plane that made it.
	Product string `json:"product"`
	// PostgresMigration: the schema version of the dump.
	PostgresMigration int `json:"postgres_migration"`
	// ObjectsIncluded: the artifacts were on the filesystem and are in
	// the archive (an object store keeps its own).
	ObjectsIncluded bool   `json:"objects_included"`
	Files           []File `json:"files"`
}

// Source is what Create backs up.
type Source struct {
	DataDir string
	// ObjectsDir holds the artifacts (-objects-dir); "" when they are in
	// an object store. It may lie inside DataDir.
	ObjectsDir string
	// Dump writes the PostgreSQL dump (pg_dump -Fc).
	Dump              func(ctx context.Context, w io.Writer) error
	Product           string
	PostgresMigration int
}

// skipped: never in a backup (the lock of init, files being written).
func skipped(name string) bool {
	return name == ".init.lock" || strings.HasPrefix(name, ".strata-tmp-")
}

// ErrNoPassphrase: a backup holds private keys and secrets; it is always
// encrypted.
var ErrNoPassphrase = errors.New("backup: a passphrase is required (the backup holds private keys and secrets)")

// Create writes the encrypted archive of src to out.
func Create(ctx context.Context, src Source, passphrase string, out io.Writer) (Manifest, error) {
	m := Manifest{Format: Format, CreatedAt: time.Now().UTC(), Product: src.Product, PostgresMigration: src.PostgresMigration}
	if passphrase == "" {
		return m, ErrNoPassphrase
	}
	tmp, err := os.MkdirTemp("", "strata-backup-")
	if err != nil {
		return m, err
	}
	defer os.RemoveAll(tmp)
	// 1. the dump, before any artifact
	dumpPath := filepath.Join(tmp, DumpName)
	df, err := os.OpenFile(dumpPath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return m, err
	}
	err = src.Dump(ctx, df)
	if cerr := df.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		return m, fmt.Errorf("backup: PostgreSQL dump: %w", err)
	}

	r, err := age.NewScryptRecipient(passphrase)
	if err != nil {
		return m, err
	}
	enc, err := age.Encrypt(out, r)
	if err != nil {
		return m, err
	}
	tw := tar.NewWriter(enc)
	add := func(name, file string, info fs.FileInfo) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		f, err := os.Open(file)
		if err != nil {
			return err
		}
		defer f.Close()
		mode := uint32(info.Mode().Perm())
		if err := tw.WriteHeader(&tar.Header{Name: name, Mode: int64(mode), Size: info.Size(), ModTime: info.ModTime(), Typeflag: tar.TypeReg}); err != nil {
			return err
		}
		h := sha256.New()
		n, err := io.Copy(io.MultiWriter(tw, h), f)
		if err != nil {
			return err
		}
		if n != info.Size() {
			return fmt.Errorf("backup: %s changed while it was read", file)
		}
		m.Files = append(m.Files, File{Path: name, Size: n, SHA256: hex.EncodeToString(h.Sum(nil)), Mode: mode})
		return nil
	}
	info, err := os.Stat(dumpPath)
	if err != nil {
		return m, err
	}
	if err := add(DumpName, dumpPath, info); err != nil {
		return m, err
	}
	// 2. the data directory, then 3. the artifacts
	objects := ""
	if src.ObjectsDir != "" {
		if objects, err = filepath.Abs(src.ObjectsDir); err != nil {
			return m, err
		}
	}
	walk := func(root, prefix, exclude string) error {
		return filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if exclude != "" && p == exclude {
				return filepath.SkipDir
			}
			if skipped(d.Name()) {
				return nil
			}
			if d.IsDir() {
				return nil
			}
			if !d.Type().IsRegular() {
				return fmt.Errorf("backup: %s is not a regular file (links are not followed)", p)
			}
			rel, err := filepath.Rel(root, p)
			if err != nil {
				return err
			}
			info, err := d.Info()
			if err != nil {
				return err
			}
			return add(prefix+filepath.ToSlash(rel), p, info)
		})
	}
	data, err := filepath.Abs(src.DataDir)
	if err != nil {
		return m, err
	}
	if err := walk(data, DataPrefix, objects); err != nil {
		return m, err
	}
	if objects != "" {
		if _, err := os.Stat(objects); err == nil {
			if err := walk(objects, ObjectsPrefix, ""); err != nil {
				return m, err
			}
			m.ObjectsIncluded = true
		} else if !errors.Is(err, fs.ErrNotExist) {
			return m, err
		}
	}
	// 4. the manifest
	raw, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return m, err
	}
	if err := tw.WriteHeader(&tar.Header{Name: ManifestName, Mode: 0o600, Size: int64(len(raw)), ModTime: m.CreatedAt, Typeflag: tar.TypeReg}); err != nil {
		return m, err
	}
	if _, err := tw.Write(raw); err != nil {
		return m, err
	}
	if err := tw.Close(); err != nil {
		return m, err
	}
	return m, enc.Close()
}

// safeName: a relative path of the archive, without "." or ".." segments.
func safeName(name string) bool {
	if name == "" || strings.HasPrefix(name, "/") || strings.Contains(name, "\\") || path.Clean(name) != name {
		return false
	}
	for _, seg := range strings.Split(name, "/") {
		if seg == "" || seg == "." || seg == ".." {
			return false
		}
	}
	return true
}

// Extract decrypts in into dir (empty, created 0700), checks that every
// file is in the manifest with its size and SHA-256 and that nothing is
// missing, and returns the manifest. Only regular files are accepted.
func Extract(in io.Reader, passphrase, dir string) (Manifest, error) {
	var m Manifest
	id, err := age.NewScryptIdentity(passphrase)
	if err != nil {
		return m, err
	}
	dec, err := age.Decrypt(in, id)
	if err != nil {
		return m, fmt.Errorf("backup: decrypting (wrong passphrase?): %w", err)
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return m, err
	}
	got := map[string]File{}
	var raw []byte
	tr := tar.NewReader(dec)
	for {
		h, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return m, fmt.Errorf("backup: reading the archive: %w", err)
		}
		if h.Typeflag != tar.TypeReg || !safeName(h.Name) {
			return m, fmt.Errorf("backup: refusing archive entry %q", h.Name)
		}
		if h.Name == ManifestName {
			if raw, err = io.ReadAll(io.LimitReader(tr, 64<<20)); err != nil {
				return m, err
			}
			continue
		}
		if _, dup := got[h.Name]; dup {
			return m, fmt.Errorf("backup: %s twice in the archive", h.Name)
		}
		p := filepath.Join(dir, filepath.FromSlash(h.Name))
		if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
			return m, err
		}
		f, err := os.OpenFile(p, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
		if err != nil {
			return m, err
		}
		hs := sha256.New()
		n, err := io.Copy(io.MultiWriter(f, hs), tr)
		if cerr := f.Close(); err == nil {
			err = cerr
		}
		if err != nil {
			return m, err
		}
		got[h.Name] = File{Path: h.Name, Size: n, SHA256: hex.EncodeToString(hs.Sum(nil))}
	}
	if raw == nil {
		return m, errors.New("backup: no manifest: not a Strata backup, or cut short")
	}
	if err := json.Unmarshal(raw, &m); err != nil {
		return m, fmt.Errorf("backup: manifest: %w", err)
	}
	if m.Format != Format {
		return m, fmt.Errorf("backup: format %d, this build reads %d", m.Format, Format)
	}
	for _, f := range m.Files {
		g, ok := got[f.Path]
		if !ok {
			return m, fmt.Errorf("backup: %s is in the manifest but not in the archive", f.Path)
		}
		if g.Size != f.Size || g.SHA256 != f.SHA256 {
			return m, fmt.Errorf("backup: %s does not match its SHA-256 in the manifest", f.Path)
		}
		delete(got, f.Path)
	}
	for p := range got {
		return m, fmt.Errorf("backup: %s is in the archive but not in the manifest", p)
	}
	if !containsDump(m) {
		return m, errors.New("backup: the archive has no PostgreSQL dump")
	}
	return m, nil
}

func containsDump(m Manifest) bool {
	for _, f := range m.Files {
		if f.Path == DumpName {
			return true
		}
	}
	return false
}

// target maps an archive path to where it is restored; "" for the dump.
func target(name, dataDir, objectsDir string) (string, error) {
	switch {
	case name == DumpName:
		return "", nil
	case strings.HasPrefix(name, DataPrefix):
		return filepath.Join(dataDir, filepath.FromSlash(strings.TrimPrefix(name, DataPrefix))), nil
	case strings.HasPrefix(name, ObjectsPrefix):
		if objectsDir == "" {
			return "", errors.New("backup: the archive holds artifacts: give the objects directory to restore them to")
		}
		return filepath.Join(objectsDir, filepath.FromSlash(strings.TrimPrefix(name, ObjectsPrefix))), nil
	}
	return "", fmt.Errorf("backup: unexpected archive path %s", name)
}

// Conflicts lists the files Install would replace with other content.
func Conflicts(staged string, m Manifest, dataDir, objectsDir string) ([]string, error) {
	var out []string
	for _, f := range m.Files {
		dst, err := target(f.Path, dataDir, objectsDir)
		if err != nil {
			return nil, err
		}
		if dst == "" {
			continue
		}
		have, err := os.ReadFile(dst)
		if errors.Is(err, fs.ErrNotExist) {
			continue
		}
		if err != nil {
			return nil, err
		}
		sum := sha256.Sum256(have)
		if hex.EncodeToString(sum[:]) != f.SHA256 {
			out = append(out, dst)
		}
	}
	sort.Strings(out)
	return out, nil
}

// Install copies the extracted files into place (directories 0700; files
// 0600, or 0644 for those that were world-readable, like certificates),
// each written to a temporary file and renamed.
func Install(staged string, m Manifest, dataDir, objectsDir string) error {
	for _, f := range m.Files {
		dst, err := target(f.Path, dataDir, objectsDir)
		if err != nil {
			return err
		}
		if dst == "" {
			continue
		}
		data, err := os.ReadFile(filepath.Join(staged, filepath.FromSlash(f.Path)))
		if err != nil {
			return err
		}
		mode := os.FileMode(0o600)
		if f.Mode&0o004 != 0 {
			mode = 0o644
		}
		if err := os.MkdirAll(filepath.Dir(dst), 0o700); err != nil {
			return err
		}
		tmp := dst + ".strata-restore"
		if err := os.WriteFile(tmp, data, mode); err != nil {
			return err
		}
		if err := os.Chmod(tmp, mode); err != nil {
			return err
		}
		if err := os.Rename(tmp, dst); err != nil {
			return err
		}
	}
	return nil
}
