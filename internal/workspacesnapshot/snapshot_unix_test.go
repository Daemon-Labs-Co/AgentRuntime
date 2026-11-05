//go:build linux || darwin

package workspacesnapshot

import (
	"commonroom-runtime/internal/objectcustody"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"syscall"
	"testing"
	"time"
)

type syntheticLease struct {
	calls atomic.Int32
	check func(int32) error
}

func (l *syntheticLease) VerifyFrozen(_ context.Context, _ *os.Root, _ Binding) error {
	n := l.calls.Add(1)
	if l.check != nil {
		return l.check(n)
	}
	return nil
}
func binding() Binding {
	return Binding{Execution: objectcustody.ExecutionScope{CompanyID: "company", RoomID: "engineering", TaskID: "task", ExecutionID: strings.Repeat("a", 32), JobID: strings.Repeat("b", 32), RepositoryDigest: strings.Repeat("c", 64), DefinitionDigest: strings.Repeat("d", 64)}, BaseCommit: strings.Repeat("e", 40), VolumeName: "commonroom-tool-work-" + strings.Repeat("b", 32), VolumeNonce: strings.Repeat("f", 32), VolumeCreatedAt: time.Unix(123, 0).UTC().Format(time.RFC3339Nano)}
}
func fixture(t *testing.T) (*os.Root, string, Binding, []Member) {
	t.Helper()
	dir := t.TempDir()
	if os.Chmod(dir, 0700) != nil {
		t.Fatal("root mode")
	}
	if err := os.Mkdir(filepath.Join(dir, "src"), 0755); err != nil {
		t.Fatal(err)
	}
	for name, data := range map[string]string{"src/main.go": "package synthetic\n", "report.txt": "synthetic report\n"} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(data), 0644); err != nil {
			t.Fatal(err)
		}
	}
	root, err := os.OpenRoot(dir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { root.Close() })
	return root, dir, binding(), []Member{{OutputName: "report", Name: "report.txt", MaxBytes: 128}}
}
func capture(t *testing.T) (*Source, string, *syntheticLease) {
	t.Helper()
	root, dir, b, m := fixture(t)
	lease := &syntheticLease{}
	s, err := Capture(t.Context(), root, b, m, lease)
	if err != nil {
		t.Fatal(err)
	}
	return s, dir, lease
}
func scope(s *Source) objectcustody.Scope {
	return objectcustody.Scope{ExecutionScope: s.Snapshot().Scope, OutputName: "report", MemberName: "report.txt"}
}
func receipt(s *Source) objectcustody.Receipt {
	data := []byte("synthetic report\n")
	h := sha256.Sum256(data)
	return objectcustody.Receipt{Intent: objectcustody.Intent{ObjectID: strings.Repeat("1", 32), Scope: scope(s), MaxBytes: 128}, Bytes: int64(len(data)), Digest: hex.EncodeToString(h[:])}
}
func TestCaptureActualSourceRevisionAndImmutableResults(t *testing.T) {
	t.Parallel()
	s, dir, lease := capture(t)
	snapshot := s.Snapshot()
	if snapshot.Version != 1 || len(snapshot.Entries) != 4 || snapshot.Scope.RevisionDigest == "" || snapshot.Digest == snapshot.Scope.RevisionDigest || snapshot.TotalBytes != int64(len("synthetic report\npackage synthetic\n")) {
		t.Fatal("wrong actual source identity", snapshot)
	}
	before := lease.calls.Load()
	r, err := s.Open(t.Context(), scope(s), 128)
	if err != nil || lease.calls.Load() != before {
		t.Fatal("lazy reader observed before custody admission", err)
	}
	got, err := io.ReadAll(r)
	if err != nil || string(got) != "synthetic report\n" {
		t.Fatal("actual bytes wrong", err)
	}
	r.Close()
	if s.VerifyReceipt(t.Context(), receipt(s)) != nil {
		t.Fatal("stored content not linked to source")
	}
	got[0] = 'X'
	snapshot.Entries[1].Digest = "forged"
	snapshot.Members[0].MaxBytes = 999
	snapshot.Scope.JobID = "forged"
	if s.Current(t.Context()) != nil || s.Snapshot().Members[0].MaxBytes != 128 {
		t.Fatal("caller mutated source snapshot")
	}
	if err := os.WriteFile(filepath.Join(dir, "src/main.go"), []byte("changed unrelated source\n"), 0644); err != nil {
		t.Fatal(err)
	}
	if s.Current(t.Context()) == nil || s.VerifyReceipt(t.Context(), receipt(s)) == nil {
		t.Fatal("unrelated source change retained revision authority")
	}
	r, err = s.Open(t.Context(), scope(s), 128)
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	if n, err := r.Read(make([]byte, 128)); n != 0 || err == nil {
		t.Fatal("changed source disclosed cached bytes")
	}
}
func TestCaptureCannotAcceptCallerRevisionOrUnsafeSelection(t *testing.T) {
	for _, mode := range []string{"revision", "job", "volume", "nonce", "created", "base commit", "nil lease", "typed nil lease", "denied lease", "empty members", "absolute", "traversal", "git metadata", "backslash", "nul", "unknown output", "duplicate", "oversized member", "aggregate", "missing member", "directory member"} {
		t.Run(mode, func(t *testing.T) {
			t.Parallel()
			root, _, b, m := fixture(t)
			var lease FrozenLease = &syntheticLease{}
			switch mode {
			case "revision":
				b.Execution.RevisionDigest = strings.Repeat("1", 64)
			case "job":
				b.Execution.JobID = "bad"
			case "volume":
				b.VolumeName = "foreign"
			case "nonce":
				b.VolumeNonce = "bad"
			case "created":
				b.VolumeCreatedAt = "bad"
			case "base commit":
				b.BaseCommit = "bad"
			case "nil lease":
				lease = nil
			case "typed nil lease":
				var absent *syntheticLease
				lease = absent
			case "denied lease":
				lease = &syntheticLease{check: func(int32) error { return errors.New("synthetic frozen-view refusal") }}
			case "empty members":
				m = nil
			case "absolute":
				m[0].Name = "/etc/passwd"
			case "traversal":
				m[0].Name = "../outside"
			case "git metadata":
				m[0].Name = ".git/config"
			case "backslash":
				m[0].Name = "src\\main.go"
			case "nul":
				m[0].Name = "bad\x00name"
			case "unknown output":
				m[0].OutputName = "invalid/name"
			case "duplicate":
				m = append(m, m[0])
			case "oversized member":
				m[0].MaxBytes = MaxFileBytes + 1
			case "aggregate":
				m[0].MaxBytes = MaxSelectedBytes
				m = append(m, Member{OutputName: "other", Name: "src/main.go", MaxBytes: 1})
			case "missing member":
				m[0].Name = "absent.txt"
			case "directory member":
				m[0].Name = "src"
			}
			if s, err := Capture(t.Context(), root, b, m, lease); err == nil || s != nil {
				t.Fatal("unsafe source admitted")
			}
		})
	}
}
func TestCaptureRefusesUnsafeTreeEntries(t *testing.T) {
	for _, mode := range []string{"symlink file", "symlink directory", "hardlink", "fifo", "writable file", "writable directory", "oversized file", "case git", "git symlink", "git file", "depth", "invalid utf8"} {
		t.Run(mode, func(t *testing.T) {
			t.Parallel()
			root, dir, b, m := fixture(t)
			switch mode {
			case "symlink file":
				if err := os.Symlink("report.txt", filepath.Join(dir, "alias")); err != nil {
					t.Fatal(err)
				}
			case "symlink directory":
				if err := os.Symlink("src", filepath.Join(dir, "alias")); err != nil {
					t.Fatal(err)
				}
			case "hardlink":
				if err := os.Link(filepath.Join(dir, "report.txt"), filepath.Join(dir, "alias")); err != nil {
					t.Fatal(err)
				}
			case "fifo":
				if err := syscall.Mkfifo(filepath.Join(dir, "pipe"), 0600); err != nil {
					t.Fatal(err)
				}
			case "writable file":
				if err := os.Chmod(filepath.Join(dir, "report.txt"), 0666); err != nil {
					t.Fatal(err)
				}
			case "writable directory":
				if err := os.Chmod(filepath.Join(dir, "src"), 0777); err != nil {
					t.Fatal(err)
				}
			case "oversized file":
				f, err := os.Create(filepath.Join(dir, "large"))
				if err != nil {
					t.Fatal(err)
				}
				if err = f.Truncate(MaxFileBytes + 1); err != nil {
					t.Fatal(err)
				}
				f.Close()
			case "case git":
				if err := os.Mkdir(filepath.Join(dir, ".GiT"), 0755); err != nil {
					t.Fatal(err)
				}
			case "git symlink":
				if err := os.Symlink("src", filepath.Join(dir, ".git")); err != nil {
					t.Fatal(err)
				}
			case "git file":
				if err := os.WriteFile(filepath.Join(dir, ".git"), []byte("gitdir: foreign"), 0600); err != nil {
					t.Fatal(err)
				}
			case "depth":
				name := filepath.Join(dir, strings.Repeat("d/", MaxDepth+1))
				if err := os.MkdirAll(name, 0755); err != nil {
					t.Fatal(err)
				}
			case "invalid utf8":
				if err := os.WriteFile(filepath.Join(dir, string([]byte{0xff})), []byte("bad"), 0600); err != nil {
					if errors.Is(err, syscall.EILSEQ) && !safeName(string([]byte{0xff})) {
						t.Log("filesystem itself refuses invalid UTF-8 name; validator also refuses")
						return
					}
					t.Fatal(err)
				}
			}
			if s, err := Capture(t.Context(), root, b, m, &syntheticLease{}); err == nil || s != nil {
				t.Fatal("unsafe entry accepted")
			}
		})
	}
}
func TestCaptureExcludesGitInternalsAndBindsSelectionSeparately(t *testing.T) {
	t.Parallel()
	root, dir, b, m := fixture(t)
	if err := os.Mkdir(filepath.Join(dir, ".git"), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, ".git", "config"), []byte("synthetic untrusted Git configuration"), 0600); err != nil {
		t.Fatal(err)
	}
	first, err := Capture(t.Context(), root, b, m, &syntheticLease{})
	if err != nil {
		t.Fatal(err)
	}
	m = append(m, Member{OutputName: "source", Name: "src/main.go", MaxBytes: 128})
	second, err := Capture(t.Context(), root, b, m, &syntheticLease{})
	if err != nil {
		t.Fatal(err)
	}
	if first.Snapshot().Scope.RevisionDigest != second.Snapshot().Scope.RevisionDigest || first.Snapshot().Digest == second.Snapshot().Digest {
		t.Fatal("revision depended on output selection or manifest ignored it")
	}
	for _, e := range first.Snapshot().Entries {
		if strings.Contains(e.Name, ".git") {
			t.Fatal("Git metadata leaked")
		}
	}
}
func TestCaptureMutationAndRevocationWithholdSource(t *testing.T) {
	for _, phase := range []int32{1, 2, 3} {
		t.Run(string(rune('0'+phase)), func(t *testing.T) {
			t.Parallel()
			root, dir, b, m := fixture(t)
			lease := &syntheticLease{check: func(n int32) error {
				if n == phase {
					return errors.New("synthetic revocation")
				}
				return nil
			}}
			if s, err := Capture(t.Context(), root, b, m, lease); err == nil || s != nil {
				t.Fatal("revoked capture returned source")
			}
			lease = &syntheticLease{check: func(n int32) error {
				if n == 2 {
					return os.WriteFile(filepath.Join(dir, "src/main.go"), []byte("mutation\n"), 0644)
				}
				return nil
			}}
			if s, err := Capture(t.Context(), root, b, m, lease); err == nil || s != nil {
				t.Fatal("two-pass mutation not detected")
			}
		})
	}
	s, _, lease := capture(t)
	r, err := s.Open(t.Context(), scope(s), 128)
	if err != nil {
		t.Fatal(err)
	}
	lease.check = func(int32) error { return errors.New("synthetic revocation") }
	if n, err := r.Read(make([]byte, 8)); n != 0 || err == nil {
		t.Fatal("revoked source returned bytes")
	}
	r.Close()
}
func TestSourceRejectsForgedReceiptScopeAndLimit(t *testing.T) {
	t.Parallel()
	s, _, _ := capture(t)
	for _, mode := range []string{"scope", "output", "member", "limit", "digest", "bytes"} {
		t.Run(mode, func(t *testing.T) {
			r := receipt(s)
			switch mode {
			case "scope":
				r.Intent.Scope.ExecutionID = strings.Repeat("2", 32)
			case "output":
				r.Intent.Scope.OutputName = "other"
			case "member":
				r.Intent.Scope.MemberName = "src/main.go"
			case "limit":
				r.Intent.MaxBytes++
			case "digest":
				r.Digest = strings.Repeat("2", 64)
			case "bytes":
				r.Bytes++
			}
			if s.VerifyReceipt(t.Context(), r) == nil {
				t.Fatal("forged stored-source relationship")
			}
			if mode != "digest" && mode != "bytes" {
				if reader, err := s.Open(t.Context(), r.Intent.Scope, r.Intent.MaxBytes); err == nil {
					reader.Close()
					t.Fatal("foreign scope reader")
				}
			}
		})
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if _, err := s.Open(ctx, scope(s), 128); err == nil {
		t.Fatal("cancelled open")
	}
	r, err := s.Open(t.Context(), scope(s), 128)
	if err != nil {
		t.Fatal(err)
	}
	r.Close()
	if n, err := r.Read(make([]byte, 8)); n != 0 || err == nil {
		t.Fatal("closed source reader")
	}
}
func TestCaptureEmptyMemberAndDeclaredByteBoundary(t *testing.T) {
	for _, mode := range []string{"empty", "exact", "over"} {
		t.Run(mode, func(t *testing.T) {
			t.Parallel()
			root, dir, b, m := fixture(t)
			data := "1234"
			m[0].MaxBytes = 4
			if mode == "empty" {
				data = ""
			}
			if mode == "over" {
				data += "5"
			}
			if err := os.WriteFile(filepath.Join(dir, "report.txt"), []byte(data), 0644); err != nil {
				t.Fatal(err)
			}
			s, err := Capture(t.Context(), root, b, m, &syntheticLease{})
			if mode == "over" {
				if err == nil {
					t.Fatal("overlarge member")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			reader, err := s.Open(t.Context(), scope(s), 4)
			if err != nil {
				t.Fatal(err)
			}
			defer reader.Close()
			got, err := io.ReadAll(reader)
			if err != nil || string(got) != data {
				t.Fatal("member mismatch", err)
			}
		})
	}
}
