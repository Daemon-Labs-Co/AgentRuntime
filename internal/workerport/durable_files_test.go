package workerport

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestPrivateReplacementRequiresDirectorySync(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	path := filepath.Join(dir, "state.json")
	if err := os.WriteFile(path, []byte("old synthetic state"), 0600); err != nil {
		t.Fatal(err)
	}
	failure := errors.New("synthetic directory sync failure")
	called := false
	err := replacePrivateDurably(path, []byte("new synthetic state"), func(got string) error {
		called = true
		if got != path {
			t.Fatal("wrong directory entry synced")
		}
		raw, err := readPrivateBounded(path, 128)
		if err != nil || string(raw) != "new synthetic state" {
			t.Fatal("sync occurred before complete private replacement", err)
		}
		return failure
	})
	if !called || !errors.Is(err, failure) {
		t.Fatal("directory failure was not propagated", err)
	}
	entries, err := os.ReadDir(dir)
	if err != nil || len(entries) != 1 {
		t.Fatal("replacement left temporary files", err)
	}
	if err = replacePrivateDurably(path, []byte("final synthetic state"), syncParentDirectory); err != nil {
		t.Fatal(err)
	}
	raw, err := readPrivateBounded(path, 128)
	if err != nil || string(raw) != "final synthetic state" {
		t.Fatal("durable replacement missing", err)
	}
}

func TestFailedReplacementDoesNotAcknowledgeDirectorySync(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	path := filepath.Join(dir, "occupied")
	if err := os.Mkdir(path, 0700); err != nil {
		t.Fatal(err)
	}
	called := false
	err := replacePrivateDurably(path, []byte("synthetic"), func(string) error { called = true; return nil })
	if err == nil || called {
		t.Fatal("failed rename acknowledged", err)
	}
	entries, err := os.ReadDir(dir)
	if err != nil || len(entries) != 1 {
		t.Fatal("failed replacement leaked temp file", err)
	}
}
