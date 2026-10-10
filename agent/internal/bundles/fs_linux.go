package bundles

import (
	"fmt"

	"golang.org/x/sys/unix"
)

// Network file systems the bundle directory must not be on: the workers
// mmap the bundles, and a bundle file changed or lost under a mapping
// (NFS, SMB) crashes them (docs/poc/hyperscan-mmap.md).
var networkFS = map[int64]string{
	0x6969:     "NFS",
	0x517B:     "SMB",
	0xFF534D42: "CIFS",
	0xFE534D42: "SMB2",
}

// statfs is unix.Statfs; tests replace it.
var statfs = unix.Statfs

// CheckLocal refuses a directory on a network file system.
func CheckLocal(dir string) error {
	var st unix.Statfs_t
	if err := statfs(dir, &st); err != nil {
		return fmt.Errorf("bundles: statfs %s: %w", dir, err)
	}
	if name, bad := networkFS[int64(st.Type)]; bad {
		return fmt.Errorf("bundles: %s is on %s; bundles must be on a local file system", dir, name)
	}
	return nil
}
