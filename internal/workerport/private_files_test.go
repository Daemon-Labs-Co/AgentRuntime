package workerport

import (
	"bytes"
	"io"
	"os"
	"path/filepath"
	"syscall"
	"testing"
)

func TestPrivateFileRejectsUnsafeTypesAndPermissions(t *testing.T) {
	for _, kind := range []string{"symlink", "hardlink", "public", "directory", "fifo", "oversize"} {
		t.Run(kind, func(t *testing.T) {
			t.Parallel()
			dir := t.TempDir()
			path := filepath.Join(dir, "private")
			target := filepath.Join(dir, "target")
			if err := os.WriteFile(target, []byte("synthetic"), 0600); err != nil {
				t.Fatal(err)
			}
			switch kind {
			case "symlink":
				if err := os.Symlink(target, path); err != nil {
					t.Fatal(err)
				}
			case "hardlink":
				if err := os.Link(target, path); err != nil {
					t.Fatal(err)
				}
			case "public":
				if err := os.WriteFile(path, []byte("synthetic"), 0644); err != nil {
					t.Fatal(err)
				}
			case "directory":
				if err := os.Mkdir(path, 0700); err != nil {
					t.Fatal(err)
				}
			case "fifo":
				if err := syscall.Mkfifo(path, 0600); err != nil {
					t.Fatal(err)
				}
			case "oversize":
				if err := os.WriteFile(path, bytes.Repeat([]byte("x"), 17), 0600); err != nil {
					t.Fatal(err)
				}
			}
			if _, err := readPrivateBounded(path, 16); err == nil {
				t.Fatal("unsafe private file accepted", kind)
			}
		})
	}
}

func TestPrivateDescriptorPinsOpenedInode(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	path := filepath.Join(dir, "private")
	target := filepath.Join(dir, "target")
	if err := os.WriteFile(path, []byte("safe synthetic data"), 0600); err != nil {
		t.Fatal(err)
	}
	f, err := openPrivateRegular(path, os.O_RDONLY, 64)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if err = os.Rename(path, path+".old"); err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(target, []byte("substituted synthetic data"), 0600); err != nil {
		t.Fatal(err)
	}
	if err = os.Symlink(target, path); err != nil {
		t.Fatal(err)
	}
	raw, err := io.ReadAll(f)
	if err != nil || string(raw) != "safe synthetic data" {
		t.Fatal("path substitution changed descriptor", err)
	}
	if _, err = readPrivateBounded(path, 64); err == nil {
		t.Fatal("substituted symlink accepted")
	}
}

func TestPrivateLocksRejectAliasedInodes(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	lease, free, err := workerTryLease(dir, "one.lease")
	if err != nil || !free {
		t.Fatal(err)
	}
	defer lease.Close()
	if err = os.Link(filepath.Join(dir, "one.lease"), filepath.Join(dir, "two.lease")); err != nil {
		t.Fatal(err)
	}
	if other, _, err := workerTryLease(dir, "two.lease"); err == nil {
		other.Close()
		t.Fatal("aliased lock accepted")
	}
	root := filepath.Join(dir, "auth")
	if err = os.Mkdir(root, 0700); err != nil {
		t.Fatal(err)
	}
	if err = os.Symlink(filepath.Join(dir, "one.lease"), filepath.Join(root, ".auth.lock")); err != nil {
		t.Fatal(err)
	}
	if unlock, err := lockWorkerCredential(root); err == nil {
		unlock()
		t.Fatal("credential lock followed symlink")
	}
}

func TestPrivateFileBoundsAndMissingFileSemantics(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "private")
	if _, err := readPrivateBounded(path, 64); !os.IsNotExist(err) {
		t.Fatal("lost bootstrap missing-file semantics", err)
	}
	if err := os.WriteFile(path, bytes.Repeat([]byte("x"), 64), 0600); err != nil {
		t.Fatal(err)
	}
	if raw, err := readPrivateBounded(path, 64); err != nil || len(raw) != 64 {
		t.Fatal("exact bound rejected", err)
	}
	for _, bound := range []int64{-1, 1024*1024 + 1} {
		if _, err := readPrivateBounded(path, bound); err == nil {
			t.Fatal("invalid bound accepted")
		}
	}
}

func TestPrivateCredentialAndRecordRejectLinks(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	source := filepath.Join(dir, "source")
	link := filepath.Join(dir, "link")
	if err := os.WriteFile(source, []byte(`{"synthetic":"value"}`), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(source, link); err != nil {
		t.Fatal(err)
	}
	if credentialPresent(link) {
		t.Fatal("linked credential marked present")
	}
	if err := persistWorkerCredential(filepath.Join(dir, "auth"), "codex", link); err == nil {
		t.Fatal("linked export persisted")
	}
	job := "0123456789abcdef0123456789abcdef"
	if err := os.Symlink(source, filepath.Join(dir, job+".json")); err != nil {
		t.Fatal(err)
	}
	if _, err := readWorkerRecord(dir, job); err == nil {
		t.Fatal("linked worker record accepted")
	}
}

func TestPrivateOpenRejectsDestructiveFlagsBeforeTouchingFile(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "private")
	if err := os.WriteFile(path, []byte("synthetic"), 0600); err != nil {
		t.Fatal(err)
	}
	if f, err := openPrivateRegular(path, os.O_RDWR|os.O_TRUNC, 64); err == nil {
		f.Close()
		t.Fatal("destructive flags accepted")
	}
	raw, err := os.ReadFile(path)
	if err != nil || string(raw) != "synthetic" {
		t.Fatal("rejected open mutated file", err)
	}
}
