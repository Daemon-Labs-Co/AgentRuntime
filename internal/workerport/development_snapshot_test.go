package workerport

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"syscall"
	"testing"
)

func snapshotDigest(raw []byte) string {
	hash := sha256.Sum256(raw)
	return hex.EncodeToString(hash[:])
}

func TestStagedSnapshotSurvivesSourceReplacement(t *testing.T) {
	t.Parallel()
	source := filepath.Join(t.TempDir(), "source.bundle")
	raw := []byte("synthetic approved snapshot")
	if err := os.WriteFile(source, raw, 0600); err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	staged, err := stageDevelopmentBundle(source, snapshotDigest(raw), dir)
	if err != nil {
		t.Fatal(err)
	}
	if staged == source || filepath.Dir(staged) != dir {
		t.Fatal("source path still used for launch")
	}
	if err = os.Remove(source); err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(source, []byte("synthetic unapproved replacement"), 0600); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(staged)
	if err != nil || string(got) != string(raw) {
		t.Fatal("staged snapshot changed with original path", err)
	}
	info, err := os.Stat(staged)
	if err != nil || info.Mode().Perm() != 0444 {
		t.Fatal("staged mount must be read-only", err)
	}
	if _, err = stageDevelopmentBundle(source, snapshotDigest(raw), t.TempDir()); err == nil {
		t.Fatal("replaced source accepted against old approval")
	}
}

func TestUnsafeSnapshotStagingFailsWithoutArtifacts(t *testing.T) {
	t.Parallel()
	for _, kind := range []string{"symlink", "fifo", "public-write", "oversized", "mismatch"} {
		t.Run(kind, func(t *testing.T) {
			t.Parallel()
			dir, output := t.TempDir(), t.TempDir()
			source := filepath.Join(dir, "source.bundle")
			raw := []byte("synthetic snapshot")
			var err error
			switch kind {
			case "symlink":
				target := filepath.Join(dir, "target")
				err = os.WriteFile(target, raw, 0600)
				if err == nil {
					err = os.Symlink(target, source)
				}
			case "fifo":
				err = syscall.Mkfifo(source, 0600)
			default:
				err = os.WriteFile(source, raw, 0600)
				if err == nil && kind == "public-write" {
					err = os.Chmod(source, 0666)
				}
				if err == nil && kind == "oversized" {
					err = os.Truncate(source, maximumDevelopmentBundle+1)
				}
			}
			if err != nil {
				t.Fatal(err)
			}
			digest := snapshotDigest(raw)
			if kind == "mismatch" {
				digest = snapshotDigest([]byte("other synthetic data"))
			}
			if _, err = stageDevelopmentBundle(source, digest, output); err == nil {
				t.Fatal("unsafe snapshot accepted")
			}
			entries, err := os.ReadDir(output)
			if err != nil || len(entries) != 0 {
				t.Fatal("failed staging leaked snapshot", err)
			}
		})
	}
}
