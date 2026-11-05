package workspacebootstrap

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

type fakeGit struct {
	t     *testing.T
	mode  string
	calls []string
}

func (f *fakeGit) Run(ctx context.Context, dir string, args ...string) ([]byte, error) {
	f.calls = append(f.calls, args[0])
	if f.mode == args[0] {
		return nil, errors.New("synthetic private diagnostic")
	}
	commit := strings.Repeat("a", 40)
	switch args[0] {
	case "clone":
		if len(args) != 7 || args[1] != "--no-checkout" || args[2] != "--no-hardlinks" || args[3] != "--template=" || args[4] != "--" {
			f.t.Fatal("unsafe clone")
		}
		if err := os.MkdirAll(filepath.Join(args[6], ".git"), 0700); err != nil {
			f.t.Fatal(err)
		}
	case "rev-parse":
		if f.mode == "foreign-head" && args[2] == "HEAD" {
			commit = strings.Repeat("b", 40)
		}
		return []byte(commit + "\n"), nil
	case "ls-tree":
		if f.mode == "unsafe-tree" {
			return []byte("120000 blob " + commit + " 5\tlink\x00"), nil
		}
		return []byte("100644 blob " + commit + " 5\tfile.txt\x00"), nil
	case "worktree":
		attrs, err := os.ReadFile(filepath.Join(dir, ".git", "info", "attributes"))
		if err != nil || !strings.Contains(string(attrs), "-filter -text -crlf -ident -working-tree-encoding -eol") {
			f.t.Fatal("checkout attributes not controlled")
		}
		if len(args) != 7 || args[1] != "add" || args[2] != "--no-checkout" || args[3] != "-b" || !strings.HasPrefix(args[4], "feature/commonroom-") {
			f.t.Fatal("unsafe worktree")
		}
		if err := os.MkdirAll(args[5], 0700); err != nil {
			f.t.Fatal(err)
		}
	case "reset":
		if len(args) != 4 || args[1] != "--hard" || args[3] != "--" {
			f.t.Fatal("unsafe private worktree reset")
		}
		if err := os.WriteFile(filepath.Join(dir, "file.txt"), []byte("hello"), 0600); err != nil {
			f.t.Fatal(err)
		}
	}
	return nil, nil
}
func TestBootstrapHashBeforeGitAndFreshWorkspace(t *testing.T) {
	t.Parallel()
	for _, mode := range []string{"success", "digest", "nonempty", "clone", "remote", "rev-parse", "ls-tree", "unsafe-tree", "worktree", "reset", "foreign-head", "output"} {
		t.Run(mode, func(t *testing.T) {
			t.Parallel()
			bundle := []byte("synthetic bundle bytes; mocked Git only")
			hash := sha256.Sum256(bundle)
			digest := hex.EncodeToString(hash[:])
			job := strings.Repeat("c", 32)
			dir := t.TempDir()
			f := &fakeGit{t: t, mode: mode}
			var output bytes.Buffer
			if mode == "digest" {
				digest = strings.Repeat("d", 64)
			}
			if mode == "nonempty" {
				if err := os.WriteFile(filepath.Join(dir, "keep"), []byte("synthetic"), 0600); err != nil {
					t.Fatal(err)
				}
			}
			var writer io.Writer = &output
			if mode == "output" {
				writer = shortOutput{}
			}
			err := Run(t.Context(), bytes.NewReader(bundle), writer, dir, job, digest, f)
			if (err == nil) != (mode == "success") {
				t.Fatalf("unexpected result: %v", err)
			}
			if mode == "success" {
				var r Receipt
				if json.Unmarshal(output.Bytes(), &r) != nil || !ValidReceipt(r, job, digest) {
					t.Fatal("unbound receipt")
				}
				if _, err := os.Stat(filepath.Join(dir, ".commonroom-bootstrap.bundle")); !os.IsNotExist(err) {
					t.Fatal("bundle retained after success")
				}
			} else if mode != "output" && output.Len() != 0 {
				t.Fatal("receipt after failed bootstrap")
			}
			if (mode == "digest" || mode == "nonempty") && len(f.calls) != 0 {
				t.Fatal("Git before approved empty snapshot")
			}
			if err := Run(t.Context(), bytes.NewReader(bundle), io.Discard, dir, job, digest, f); err == nil {
				t.Fatal("workspace was reused")
			}
		})
	}
}

type shortOutput struct{}

func (shortOutput) Write(p []byte) (int, error) { return 0, io.ErrShortWrite }
func TestBootstrapTreeLimits(t *testing.T) {
	t.Parallel()
	hash := strings.Repeat("a", 40)
	record := func(mode, size, name string) []byte {
		return []byte(mode + " blob " + hash + " " + size + "\t" + name + "\x00")
	}
	for _, raw := range [][]byte{record("120000", "5", "link"), record("160000", "5", "submodule"), record("100644", "-1", "bad"), record("100644", "268435457", "huge"), record("100644", "1", "../escape"), record("100644", "1", "."), record("100644", "1", "dir/.GiT/config"), record("100644", "1", "/absolute"), []byte("missing terminator"), bytes.Repeat(record("100644", "0", "x"), MaxFiles+1), append(record("100644", "134217729", "a"), record("100644", "134217729", "b")...)} {
		if validTree(raw) {
			t.Fatal("unsafe tree accepted")
		}
	}
	if !validTree(record("100755", "5", "src/check")) || !validTree(nil) {
		t.Fatal("valid tree rejected")
	}
}
func TestBootstrapCancellationAndSymlink(t *testing.T) {
	t.Parallel()
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	f := &fakeGit{t: t}
	if Run(ctx, strings.NewReader("x"), io.Discard, t.TempDir(), strings.Repeat("a", 32), strings.Repeat("a", 64), f) == nil || len(f.calls) != 0 {
		t.Fatal("cancelled bootstrap ran")
	}
	parent := t.TempDir()
	target := t.TempDir()
	link := filepath.Join(parent, "link")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	if Run(t.Context(), strings.NewReader("x"), io.Discard, link, strings.Repeat("a", 32), strings.Repeat("a", 64), f) == nil {
		t.Fatal("symlink root accepted")
	}
	entries, err := os.ReadDir(target)
	if err != nil || len(entries) != 0 {
		t.Fatal("symlink target modified")
	}
}
