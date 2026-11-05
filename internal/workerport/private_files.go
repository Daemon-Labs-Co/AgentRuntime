package workerport

import (
	"errors"
	"io"
	"os"
	"syscall"
)

// openPrivateRegular binds validation to the opened inode on supported Unix
// hosts. Nonblocking/no-follow flags prevent FIFO hangs and symlink substitution.
// Parent directories remain a trusted deployment boundary. Source forks CAN
// weaken checks, BUT risk credential disclosure or locking the wrong inode.
func openPrivateRegular(path string, flags int, maxBytes int64) (*os.File, error) {
	if (flags != os.O_RDONLY && flags != os.O_RDWR && flags != (os.O_RDWR|os.O_CREATE)) || maxBytes < 0 || maxBytes > 1024*1024 {
		return nil, errors.New("Invalid private file open policy")
	}
	f, err := os.OpenFile(path, flags|syscall.O_NOFOLLOW|syscall.O_NONBLOCK|syscall.O_CLOEXEC, 0600)
	if err != nil {
		return nil, err
	}
	info, err := f.Stat()
	if err != nil {
		f.Close()
		return nil, err
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !info.Mode().IsRegular() || info.Mode().Perm()&0077 != 0 || info.Size() > maxBytes || !ok || stat.Uid != uint32(os.Geteuid()) || stat.Nlink != 1 {
		f.Close()
		return nil, errors.New("Private file must be owned by this account, single-link, regular, owner-only and bounded")
	}
	return f, nil
}

// readPrivateBounded checks the descriptor and actual read length; an inode
// growing after fstat cannot cause an unbounded allocation or partial acceptance.
func readPrivateBounded(path string, maxBytes int64) ([]byte, error) {
	if maxBytes < 0 || maxBytes > 1024*1024 {
		return nil, errors.New("Invalid private file bound")
	}
	f, err := openPrivateRegular(path, os.O_RDONLY, maxBytes)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	raw, err := io.ReadAll(io.LimitReader(f, maxBytes+1))
	if err != nil {
		return nil, err
	}
	if int64(len(raw)) > maxBytes {
		return nil, errors.New("Private file exceeds read bound")
	}
	return raw, nil
}
