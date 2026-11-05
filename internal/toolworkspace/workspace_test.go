//go:build linux || darwin

package toolworkspace

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
)

func fixture(t *testing.T) (*Workspace, string) {
	t.Helper()
	dir := t.TempDir()
	root, err := os.OpenRoot(dir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { root.Close() })
	w, err := New(root)
	if err != nil {
		t.Fatal(err)
	}
	return w, dir
}
func TestBoundedReadAndAtomicWrite(t *testing.T) {
	t.Parallel()
	w, dir := fixture(t)
	name := filepath.Join(dir, "file.txt")
	if err := os.WriteFile(name, []byte("old"), 0755); err != nil {
		t.Fatal(err)
	}
	old, err := os.Open(name)
	if err != nil {
		t.Fatal(err)
	}
	defer old.Close()
	if err = w.Write(context.Background(), "file.txt", []byte("new")); err != nil {
		t.Fatal(err)
	}
	raw, err := w.Read(context.Background(), "file.txt")
	if err != nil || string(raw) != "new" {
		t.Fatal("new content not readable")
	}
	oldInfo, _ := old.Stat()
	newInfo, _ := os.Stat(name)
	if os.SameFile(oldInfo, newInfo) || newInfo.Mode().Perm() != 0755 {
		t.Fatal("write reused original inode or changed executable permission")
	}
	if err = w.Write(context.Background(), "created.txt", []byte("synthetic")); err != nil {
		t.Fatal(err)
	}
	entries, _ := os.ReadDir(dir)
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), ".commonroom-write-") {
			t.Fatal("temporary file leaked")
		}
	}
}
func TestRefusedPathsAndEscapingSymlinks(t *testing.T) {
	t.Parallel()
	w, dir := fixture(t)
	outside := t.TempDir()
	target := filepath.Join(outside, "canary")
	os.WriteFile(target, []byte("synthetic canary"), 0600)
	for _, name := range []string{"", ".", "..", "../canary", "/canary", "nested/../canary", "bad\\path", "bad\x00path"} {
		if _, err := w.Read(context.Background(), name); err != ErrRefused {
			t.Fatal("unsafe read path accepted")
		}
		if w.Write(context.Background(), name, []byte("bad")) != ErrRefused {
			t.Fatal("unsafe write path accepted")
		}
	}
	if err := os.Symlink(target, filepath.Join(dir, "link")); err != nil {
		t.Fatal(err)
	}
	if _, err := w.Read(context.Background(), "link"); err != ErrRefused {
		t.Fatal("symlink read accepted")
	}
	if w.Write(context.Background(), "link", []byte("bad")) != ErrRefused {
		t.Fatal("symlink destination accepted")
	}
	if err := os.Symlink(outside, filepath.Join(dir, "escape")); err != nil {
		t.Fatal(err)
	}
	if _, err := w.Read(context.Background(), "escape/canary"); err != ErrRefused {
		t.Fatal("ancestor escape read accepted")
	}
	if w.Write(context.Background(), "escape/new", []byte("bad")) != ErrRefused {
		t.Fatal("ancestor escape write accepted")
	}
	raw, _ := os.ReadFile(target)
	if string(raw) != "synthetic canary" {
		t.Fatal("outside canary changed")
	}
	if _, err := os.Stat(filepath.Join(outside, "new")); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("outside file created")
	}
}
func TestSpecialLinkedWritableAndOversizedFilesRefused(t *testing.T) {
	t.Parallel()
	w, dir := fixture(t)
	ctx := context.Background()
	os.WriteFile(filepath.Join(dir, "linked"), []byte("synthetic"), 0600)
	if err := os.Link(filepath.Join(dir, "linked"), filepath.Join(dir, "alias")); err != nil {
		t.Fatal(err)
	}
	if _, err := w.Read(ctx, "alias"); err != ErrRefused {
		t.Fatal("hard-linked read accepted")
	}
	if w.Write(ctx, "alias", []byte("bad")) != ErrRefused {
		t.Fatal("hard-linked replacement accepted")
	}
	os.WriteFile(filepath.Join(dir, "writable"), []byte("synthetic"), 0600)
	os.Chmod(filepath.Join(dir, "writable"), 0666)
	if _, err := w.Read(ctx, "writable"); err != ErrRefused {
		t.Fatal("shared writable file accepted")
	}
	os.WriteFile(filepath.Join(dir, "large"), []byte(strings.Repeat("x", MaxReadBytes+1)), 0600)
	if _, err := w.Read(ctx, "large"); err != ErrRefused {
		t.Fatal("oversize read accepted")
	}
	if w.Write(ctx, "new", []byte(strings.Repeat("x", MaxWriteBytes+1))) != ErrRefused {
		t.Fatal("oversize write accepted")
	}
	if err := syscall.Mkfifo(filepath.Join(dir, "fifo"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := w.Read(ctx, "fifo"); err != ErrRefused {
		t.Fatal("FIFO accepted")
	}
	if w.Write(ctx, "fifo", []byte("bad")) != ErrRefused {
		t.Fatal("FIFO write accepted")
	}
	if _, err := w.Read(ctx, "missing"); err != ErrRefused {
		t.Fatal("missing file accepted")
	}
	if w.Write(ctx, "missing-parent/file", []byte("bad")) != ErrRefused {
		t.Fatal("missing parent accepted")
	}
}
func TestCancellationAndUnconfirmedDurability(t *testing.T) {
	t.Parallel()
	w, dir := fixture(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if w.Write(ctx, "file", []byte("bad")) != ErrRefused {
		t.Fatal("canceled write accepted")
	}
	if _, err := w.Read(ctx, "file"); err != ErrRefused {
		t.Fatal("canceled read accepted")
	}
	err := w.write(context.Background(), "file", []byte("new"), func(*os.File) error { return errors.New("synthetic directory sync failure") })
	if err != ErrWriteUnconfirmed {
		t.Fatal("failed post-rename durability claimed success")
	}
	raw, _ := os.ReadFile(filepath.Join(dir, "file"))
	if string(raw) != "new" {
		t.Fatal("fixture did not reach ambiguous side effect")
	}
	if _, err := New(nil); err != ErrRefused {
		t.Fatal("nil root accepted")
	}
}

func TestParentReplacementDuringSyncIsNotAcknowledged(t *testing.T) {
	t.Parallel()
	w, dir := fixture(t)
	if err := os.Mkdir(filepath.Join(dir, "nested"), 0700); err != nil {
		t.Fatal(err)
	}
	err := w.write(context.Background(), "nested/file", []byte("new"), func(parent *os.File) error {
		original, err := parent.Stat()
		if err != nil {
			return err
		}
		if err = os.Rename(filepath.Join(dir, "nested"), filepath.Join(dir, "moved")); err != nil {
			return err
		}
		if err = os.Mkdir(filepath.Join(dir, "nested"), 0700); err != nil {
			return err
		}
		replacement, err := os.Stat(filepath.Join(dir, "nested"))
		if err != nil {
			return err
		}
		if os.SameFile(original, replacement) {
			t.Error("fixture parent was not replaced")
		}
		return nil
	})
	if err != ErrWriteUnconfirmed {
		t.Fatal("parent replacement claimed successful named write")
	}
	raw, _ := os.ReadFile(filepath.Join(dir, "moved", "file"))
	if string(raw) != "new" {
		t.Fatal("fixture did not retain pinned-parent write")
	}
	if _, err = os.Stat(filepath.Join(dir, "nested", "file")); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("write was redirected into replacement parent")
	}
}
