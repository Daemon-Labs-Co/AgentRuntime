package worker

import (
	"errors"
	"io"
	"os"
	"syscall"
)

// readPrivateBounded reads a file only if it is a regular, single-link file
// owned by euid, owner-only, and at most maxBytes. Validation is bound to the
// opened inode; no-follow and nonblocking flags prevent symlink substitution
// and FIFO hangs. Parent directories remain a trusted deployment boundary.
func readPrivateBounded(path string, maxBytes int64, euid int) ([]byte, error) {
	if maxBytes < 0 || maxBytes > 1024*1024 {
		return nil, errors.New("Invalid private file bound")
	}
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK|syscall.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return nil, err
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !info.Mode().IsRegular() || info.Mode().Perm()&0077 != 0 || info.Size() > maxBytes || !ok || stat.Uid != uint32(euid) || stat.Nlink != 1 {
		return nil, errors.New("Private file must be owned by this account, single-link, regular, owner-only and bounded")
	}
	raw, err := io.ReadAll(io.LimitReader(f, maxBytes+1))
	if err != nil {
		return nil, err
	}
	if int64(len(raw)) > maxBytes {
		return nil, errors.New("Private file exceeds read bound")
	}
	return raw, nil
}
