//go:build linux || darwin

// Package toolworkspace defines bounded file primitives for the planned
// credential-free tool container. It is not connected to an execution endpoint.
// Managed model work MUST use the isolated tool container: giving this package a
// host worktree CAN bypass isolation, BUT exposes host files and invalidates the
// security contract. Authentication/audit/permissions belong to the broker.
package toolworkspace

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"path"
	"strings"
	"syscall"
)

const MaxReadBytes = 8 * 1024
const MaxWriteBytes = 64 * 1024

var (
	ErrRefused          = errors.New("workspace file operation refused")
	ErrWriteUnconfirmed = errors.New("workspace write outcome unconfirmed")
)

// Workspace borrows a descriptor-rooted private workspace from trusted setup.
// The owner must keep root open until all operations finish. os.Root prevents
// path/symlink traversal outside that root, not bind mounts/devices/kernel escape.
// Separate verified volumes, dropped privileges and trusted root creation remain
// mandatory. This object never chooses roots from model input or opens a host root.
type Workspace struct{ root *os.Root }

func New(root *os.Root) (*Workspace, error) {
	if root == nil {
		return nil, ErrRefused
	}
	return &Workspace{root}, nil
}

func validPath(name string) bool {
	return name != "" && len(name) <= 4096 && !strings.ContainsAny(name, "\\\x00") && !path.IsAbs(name) && path.Clean(name) == name && name != "." && name != ".." && !strings.HasPrefix(name, "../")
}
func safeFile(info os.FileInfo) bool {
	stat, ok := info.Sys().(*syscall.Stat_t)
	return ok && info.Mode().IsRegular() && stat.Nlink == 1 && stat.Uid == uint32(os.Geteuid()) && info.Mode().Perm()&0022 == 0
}
func active(ctx context.Context) bool { return ctx != nil && ctx.Err() == nil }

// Read opens without following the final link or blocking on a FIFO, validates
// the actual inode and bounds actual bytes as well as stat size. A concurrent
// regular-file writer may change the contents; this is not a snapshot/CAS API.
func (w *Workspace) Read(ctx context.Context, name string) ([]byte, error) {
	if !active(ctx) || !validPath(name) {
		return nil, ErrRefused
	}
	file, err := w.root.OpenFile(name, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, ErrRefused
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil || !safeFile(info) || info.Size() > MaxReadBytes {
		return nil, ErrRefused
	}
	raw, err := io.ReadAll(io.LimitReader(file, MaxReadBytes+1))
	if err != nil || len(raw) > MaxReadBytes || !active(ctx) {
		return nil, ErrRefused
	}
	return raw, nil
}

// Write atomically replaces a regular entry using a private new inode. It never
// truncates an existing inode, so a late hard-link alias cannot redirect the write.
// Only 0777 permission bits are preserved; ownership/ACL/xattrs are not migrated.
// Missing parents and unsafe existing destinations are refused. Rename/sync or
// post-rename identity uncertainty must never trigger an automatic retry.
func (w *Workspace) Write(ctx context.Context, name string, data []byte) error {
	return w.write(ctx, name, data, func(dir *os.File) error { return dir.Sync() })
}
func (w *Workspace) write(ctx context.Context, name string, data []byte, syncDirectory func(*os.File) error) error {
	if !active(ctx) || !validPath(name) || len(data) > MaxWriteBytes {
		return ErrRefused
	}
	parent := path.Dir(name)
	leaf := path.Base(name)
	// Pin the parent so rename, staging cleanup and directory sync cannot be
	// redirected independently by a later ancestor rename/alias replacement.
	parentRoot, err := w.root.OpenRoot(parent)
	if err != nil {
		return ErrRefused
	}
	defer parentRoot.Close()
	dir, err := parentRoot.OpenFile(".", os.O_RDONLY|syscall.O_NONBLOCK, 0)
	if err != nil {
		return ErrRefused
	}
	defer dir.Close()
	parentInfo, err := dir.Stat()
	if err != nil || !parentInfo.IsDir() {
		return ErrRefused
	}
	mode := os.FileMode(0644)
	previous, err := parentRoot.Lstat(leaf)
	if err == nil {
		if !safeFile(previous) {
			return ErrRefused
		}
		mode = previous.Mode().Perm()
	} else if !errors.Is(err, os.ErrNotExist) {
		return ErrRefused
	}
	var nonce [16]byte
	if _, err = rand.Read(nonce[:]); err != nil {
		return ErrRefused
	}
	temporary := ".commonroom-write-" + hex.EncodeToString(nonce[:])
	file, err := parentRoot.OpenFile(temporary, os.O_WRONLY|os.O_CREATE|os.O_EXCL|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0600)
	if err != nil {
		return ErrRefused
	}
	closed := false
	defer func() {
		if !closed {
			file.Close()
		}
		parentRoot.Remove(temporary)
	}()
	if n, err := file.Write(data); err != nil || n != len(data) {
		return ErrRefused
	}
	// Keep staging private while filling it; descriptor chmod does not re-resolve
	// an attacker-replaceable path like Root.Chmod would.
	if file.Chmod(mode) != nil {
		return ErrRefused
	}
	if file.Sync() != nil || !active(ctx) {
		return ErrRefused
	}
	created, err := file.Stat()
	if err != nil || !safeFile(created) {
		return ErrRefused
	}
	if file.Close() != nil {
		return ErrRefused
	}
	closed = true
	if !active(ctx) {
		return ErrRefused
	}
	if parentRoot.Rename(temporary, leaf) != nil {
		return ErrWriteUnconfirmed
	}
	// A competing writer may have replaced our entry: do not claim its content.
	final, err := parentRoot.Lstat(leaf)
	if err != nil || !safeFile(final) || !os.SameFile(created, final) {
		return ErrWriteUnconfirmed
	}
	if syncDirectory(dir) != nil || !active(ctx) {
		return ErrWriteUnconfirmed
	}
	// Do not acknowledge a detached/renamed parent or replaced final entry as the
	// requested name. This is not a lock against arbitrary concurrent code.
	currentParent, err := w.root.Stat(parent)
	if err != nil || !os.SameFile(parentInfo, currentParent) {
		return ErrWriteUnconfirmed
	}
	current, err := w.root.Lstat(name)
	if err != nil || !safeFile(current) || !os.SameFile(created, current) {
		return ErrWriteUnconfirmed
	}
	return nil
}
