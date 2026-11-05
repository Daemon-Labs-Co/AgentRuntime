//go:build linux || darwin

// Package objectcustody stores bounded immutable bytes behind mandatory trusted
// accounting and audit callbacks. It is an internal foundation, not a provider,
// task-output/export endpoint or proof of artifact origin/format. Production
// admission remains blocked until real quota, isolated-source and release
// guards are assembled with the durable controller journal. A source fork CAN supply dishonest callbacks or a host root,
// invalidating storage/accounting/isolation; no supported fallback permits that.
package objectcustody

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"reflect"
	"syscall"
)

// Store borrows a descriptor-pinned, private, quota-backed object root. Trusted
// setup must keep it open and prevent all other writers/mount/device replacement.
// It must never be the engine credential volume or a model-selected/host worktree.
// os.Root is path containment, not kernel/container or physical-quota proof.
type Store struct {
	root          *os.Root
	journal       Journal
	syncFile      func(*os.File) error
	syncDirectory func(*os.File) error
	closeFile     func(*os.File) error
}

func New(root *os.Root, journal Journal) (*Store, error) {
	if root == nil || absent(journal) {
		return nil, ErrRefused
	}
	store := &Store{root: root, journal: journal, syncFile: func(f *os.File) error { return f.Sync() }, syncDirectory: func(f *os.File) error { return f.Sync() }, closeFile: func(f *os.File) error { return f.Close() }}
	dir, err := store.directory()
	if err != nil {
		return nil, err
	}
	if dir.Close() != nil {
		return nil, ErrRefused
	}
	return store, nil
}
func absent(value any) bool {
	if value == nil {
		return true
	}
	v := reflect.ValueOf(value)
	switch v.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		return v.IsNil()
	}
	return false
}
func active(ctx context.Context) bool { return ctx != nil && ctx.Err() == nil }
func safeDirectory(info os.FileInfo) bool {
	stat, ok := info.Sys().(*syscall.Stat_t)
	return ok && info.IsDir() && info.Mode().Perm() == 0700 && info.Mode()&(os.ModeSetuid|os.ModeSetgid|os.ModeSticky) == 0 && stat.Uid == uint32(os.Geteuid())
}
func safeObject(info os.FileInfo) bool {
	stat, ok := info.Sys().(*syscall.Stat_t)
	return ok && info.Mode().IsRegular() && info.Mode().Perm() == 0600 && info.Mode()&(os.ModeSetuid|os.ModeSetgid|os.ModeSticky) == 0 && stat.Nlink == 1 && stat.Uid == uint32(os.Geteuid())
}
func (s *Store) directory() (*os.File, error) {
	if s == nil || s.root == nil || s.journal == nil {
		return nil, ErrRefused
	}
	dir, err := s.root.OpenFile(".", os.O_RDONLY|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, ErrRefused
	}
	info, err := dir.Stat()
	if err != nil || !safeDirectory(info) {
		dir.Close()
		return nil, ErrRefused
	}
	return dir, nil
}
func objectName(id string) string { return "object-" + id + ".blob" }

// Put reads actual bounded bytes only after accounting/admission acknowledgment.
// The source must be a context-aware isolated tool export, never engine output,
// a model path/claim, credentials or an unverified live mutable source. This
// primitive proves stored byte identity only; source quiescence, content/format
// policy and revision attestation remain mandatory caller/journal obligations.
func (s *Store) Put(ctx context.Context, scope Scope, maxBytes int64, source io.Reader) (receipt Receipt, err error) {
	if !active(ctx) || !validScope(scope) || maxBytes < 1 || maxBytes > MaxObjectBytes || absent(source) {
		return Receipt{}, ErrRefused
	}
	dir, err := s.directory()
	if err != nil {
		return Receipt{}, ErrRefused
	}
	defer func() {
		if s.closeFile(dir) != nil || !active(ctx) {
			receipt = Receipt{}
			if err == nil {
				err = ErrUnconfirmed
			}
		}
	}()
	var nonce [16]byte
	if _, err = rand.Read(nonce[:]); err != nil {
		return Receipt{}, ErrRefused
	}
	intent := Intent{ObjectID: hex.EncodeToString(nonce[:]), Scope: scope, MaxBytes: maxBytes}
	if s.journal.Reserve(ctx, intent) != nil || !active(ctx) {
		return Receipt{}, ErrRefused
	}
	// A private unsealed file is never discoverable through the public read path.
	// O_EXCL and random names prevent overwrite; no cleanup/refund is inferred
	// after reservation, even if creation, streaming, sync or acknowledgment fails.
	file, err := s.root.OpenFile(objectName(intent.ObjectID), os.O_RDWR|os.O_CREATE|os.O_EXCL|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0600)
	if err != nil {
		return Receipt{}, ErrUnconfirmed
	}
	closed := false
	defer func() {
		if !closed {
			closed = true
			if s.closeFile(file) != nil || !active(ctx) {
				receipt = Receipt{}
				if err == nil {
					err = ErrUnconfirmed
				}
			}
		}
	}()
	hash := sha256.New()
	buffer := make([]byte, 32*1024)
	total := int64(0)
	emptyReads := 0
	for {
		if !active(ctx) {
			return Receipt{}, ErrUnconfirmed
		}
		available := maxBytes - total + 1
		if available > int64(len(buffer)) {
			available = int64(len(buffer))
		}
		n, readErr := source.Read(buffer[:int(available)])
		if n < 0 || n > int(available) || !active(ctx) {
			return Receipt{}, ErrUnconfirmed
		}
		if n > 0 {
			emptyReads = 0
			if int64(n) > maxBytes-total {
				return Receipt{}, ErrUnconfirmed
			}
			if written, e := file.Write(buffer[:n]); e != nil || written != n {
				return Receipt{}, ErrUnconfirmed
			}
			_, _ = hash.Write(buffer[:n])
			total += int64(n)
		} else if readErr == nil {
			emptyReads++
			if emptyReads >= 16 {
				return Receipt{}, ErrUnconfirmed
			}
		}
		if readErr != nil {
			if !errors.Is(readErr, io.EOF) {
				return Receipt{}, ErrUnconfirmed
			}
			break
		}
	}
	info, err := file.Stat()
	if err != nil || !safeObject(info) || info.Size() != total || s.syncFile(file) != nil || !active(ctx) {
		return Receipt{}, ErrUnconfirmed
	}
	// Verify persisted inode bytes, not merely the buffer passed to Write.
	if _, err = file.Seek(0, io.SeekStart); err != nil {
		return Receipt{}, ErrUnconfirmed
	}
	observed := sha256.New()
	count, err := io.Copy(observed, io.LimitReader(file, total+1))
	if err != nil || count != total || hex.EncodeToString(observed.Sum(nil)) != hex.EncodeToString(hash.Sum(nil)) || !active(ctx) {
		return Receipt{}, ErrUnconfirmed
	}
	// Never retry a close after an uncertain result. Withhold the receipt and
	// retain the reservation; cleanup uncertainty is not disposal/refund evidence.
	closed = true
	if s.closeFile(file) != nil || !active(ctx) {
		return Receipt{}, ErrUnconfirmed
	}
	current, err := s.root.Lstat(objectName(intent.ObjectID))
	if err != nil || !safeObject(current) || !os.SameFile(info, current) || current.Size() != total || s.syncDirectory(dir) != nil || !active(ctx) {
		return Receipt{}, ErrUnconfirmed
	}
	receipt = Receipt{Intent: intent, Bytes: total, Digest: hex.EncodeToString(hash.Sum(nil))}
	if s.journal.Seal(ctx, receipt) != nil || !active(ctx) {
		return Receipt{}, ErrUnconfirmed
	}
	return receipt, nil
}

// Get verifies the actual private inode, size and content BEFORE acknowledging
// release. No raw bytes are returned on any authorization, integrity, cancellation,
// audit or owned-descriptor cleanup failure. It never accepts a model-provided
// filesystem path or URI. Cleanup rechecks cancellation before returning bytes.
func (s *Store) Get(ctx context.Context, scope Scope, receipt Receipt) (raw []byte, err error) {
	if !active(ctx) || !validReceipt(receipt) || scope != receipt.Intent.Scope {
		return nil, ErrRefused
	}
	dir, err := s.directory()
	if err != nil {
		return nil, ErrRefused
	}
	defer func() {
		if s.closeFile(dir) != nil || !active(ctx) {
			clear(raw)
			raw = nil
			err = ErrRefused
		}
	}()
	if s.journal.AuthorizeRead(ctx, scope, receipt) != nil || !active(ctx) {
		return nil, ErrRefused
	}
	file, err := s.root.OpenFile(objectName(receipt.Intent.ObjectID), os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, ErrRefused
	}
	defer func() {
		if s.closeFile(file) != nil || !active(ctx) {
			clear(raw)
			raw = nil
			err = ErrRefused
		}
	}()
	info, err := file.Stat()
	if err != nil || !safeObject(info) || info.Size() != receipt.Bytes {
		return nil, ErrRefused
	}
	raw, err = io.ReadAll(io.LimitReader(file, receipt.Bytes+1))
	if err != nil || int64(len(raw)) != receipt.Bytes || !active(ctx) {
		return nil, ErrRefused
	}
	digest := sha256.Sum256(raw)
	if hex.EncodeToString(digest[:]) != receipt.Digest {
		return nil, ErrRefused
	}
	after, err := file.Stat()
	current, e := s.root.Lstat(objectName(receipt.Intent.ObjectID))
	if err != nil || e != nil || !safeObject(after) || !safeObject(current) || !os.SameFile(info, after) || !os.SameFile(info, current) || after.Size() != receipt.Bytes || current.Size() != receipt.Bytes {
		return nil, ErrRefused
	}
	if s.journal.AcknowledgeRead(ctx, receipt) != nil || !active(ctx) {
		return nil, ErrRefused
	}
	return raw, nil
}
