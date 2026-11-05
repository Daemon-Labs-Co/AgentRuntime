package workspacecapture

import (
	"commonroom-runtime/internal/objectcustody"
	"commonroom-runtime/internal/workspacemount"
	"commonroom-runtime/internal/workspacesnapshot"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

type fixtureContainerView struct {
	dir    string
	proof  workspacemount.Proof
	opened bool
}

func (v *fixtureContainerView) OpenRoot() (*os.Root, error) {
	v.opened = true
	return os.OpenRoot(v.dir)
}
func (v *fixtureContainerView) RootIdentity() (os.FileInfo, error) { return os.Lstat(v.dir) }
func (v *fixtureContainerView) Observe(ctx context.Context, challenge string) (workspacemount.Proof, error) {
	return v.proof, ctx.Err()
}

type fixtureAuthority struct {
	calls int
	check func(context.Context, workspacesnapshot.Binding, workspacemount.Proof) error
}

func (a *fixtureAuthority) AuthorizeFrozenSource(ctx context.Context, b workspacesnapshot.Binding, p workspacemount.Proof) error {
	a.calls++
	if a.check != nil {
		return a.check(ctx, b, p)
	}
	return ctx.Err()
}
func captureFixture(t *testing.T) (*fixtureContainerView, workspacesnapshot.Binding, []workspacesnapshot.Member) {
	t.Helper()
	dir := t.TempDir()
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "result.txt"), []byte("synthetic captured result\n"), 0600); err != nil {
		t.Fatal(err)
	}
	b := workspacesnapshot.Binding{Execution: objectcustody.ExecutionScope{CompanyID: "company", RoomID: "engineering", TaskID: "task", ExecutionID: strings.Repeat("a", 32), JobID: strings.Repeat("b", 32), RepositoryDigest: strings.Repeat("c", 64), DefinitionDigest: strings.Repeat("d", 64)}, BaseCommit: strings.Repeat("e", 40), VolumeName: "commonroom-tool-work-" + strings.Repeat("b", 32), VolumeNonce: strings.Repeat("f", 32), VolumeCreatedAt: time.Unix(123, 0).UTC().Format(time.RFC3339Nano)}
	v := &fixtureContainerView{dir: dir, proof: workspacemount.Proof{Version: 1, Challenge: strings.Repeat("1", 32), MountID: 2, ReadOnly: true, RootReadOnly: true}}
	return v, b, []workspacesnapshot.Member{{OutputName: "result", Name: "result.txt", MaxBytes: 128}}
}
func capturedScope(source *workspacesnapshot.Source) objectcustody.Scope {
	return objectcustody.Scope{ExecutionScope: source.Snapshot().Scope, OutputName: "result", MemberName: "result.txt"}
}
func TestFrozenCaptureActualBytesAndScopeExpiry(t *testing.T) {
	t.Parallel()
	v, b, m := captureFixture(t)
	a := &fixtureAuthority{}
	var escaped *workspacesnapshot.Source
	var reader io.ReadCloser
	err := withFrozenSource(t.Context(), v, b, m, v.proof.Challenge, a, func(source *workspacesnapshot.Source) error {
		escaped = source
		if source.Snapshot().Scope.RevisionDigest == "" {
			t.Fatal("no actual revision")
		}
		var err error
		reader, err = source.Open(t.Context(), capturedScope(source), 128)
		if err != nil {
			return err
		}
		got, err := io.ReadAll(reader)
		if err != nil || string(got) != "synthetic captured result\n" {
			t.Fatal("wrong source", string(got), err)
		}
		return nil
	})
	if err != nil || a.calls < 4 {
		t.Fatal("capture did not reauthorize", err, a.calls)
	}
	defer reader.Close()
	if escaped.Current(t.Context()) == nil {
		t.Fatal("retained source authority revived")
	}
	fresh, err := escaped.Open(t.Context(), capturedScope(escaped), 128)
	if err != nil {
		t.Fatal(err)
	}
	defer fresh.Close()
	if n, err := fresh.Read(make([]byte, 128)); n != 0 || err == nil {
		t.Fatal("new reader revived expired source")
	}

	if n, err := reader.Read(make([]byte, 1)); n != 0 || err == nil {
		t.Fatal("expired reader released bytes")
	}
}
func TestFrozenCaptureRefusesViewAndAuthorityChanges(t *testing.T) {
	t.Parallel()
	for _, mode := range []string{"writable", "root writable", "mount changed", "root changed", "denied", "canceled", "wrong binding", "missing member", "symlink"} {
		t.Run(mode, func(t *testing.T) {
			t.Parallel()
			v, b, m := captureFixture(t)
			a := &fixtureAuthority{}
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			switch mode {
			case "writable":
				v.proof.ReadOnly = false
			case "root writable":
				v.proof.RootReadOnly = false
			case "mount changed":
				a.check = func(context.Context, workspacesnapshot.Binding, workspacemount.Proof) error {
					v.proof.MountID++
					return nil
				}
			case "root changed":
				other := t.TempDir()
				a.check = func(context.Context, workspacesnapshot.Binding, workspacemount.Proof) error {
					v.dir = other
					return nil
				}
			case "denied":
				a.check = func(context.Context, workspacesnapshot.Binding, workspacemount.Proof) error {
					return errors.New("denied")
				}
			case "canceled":
				a.check = func(context.Context, workspacesnapshot.Binding, workspacemount.Proof) error { cancel(); return nil }
			case "wrong binding":
				b.Execution.RevisionDigest = strings.Repeat("9", 64)
			case "missing member":
				m[0].Name = "missing.txt"
			case "symlink":
				if err := os.Symlink("result.txt", filepath.Join(v.dir, "link.txt")); err != nil {
					t.Fatal(err)
				}
			}
			used := false
			if err := withFrozenSource(ctx, v, b, m, strings.Repeat("1", 32), a, func(*workspacesnapshot.Source) error { used = true; return nil }); err == nil || used {
				t.Fatal("unsafe source admitted", err, used)
			}
		})
	}
}
func TestFrozenCaptureRevocationBeforeRead(t *testing.T) {
	t.Parallel()
	v, b, m := captureFixture(t)
	deny := false
	a := &fixtureAuthority{check: func(ctx context.Context, b workspacesnapshot.Binding, p workspacemount.Proof) error {
		if b.VolumeNonce != strings.Repeat("f", 32) || p != v.proof {
			t.Fatal("binding substituted")
		}
		deadline, ok := ctx.Deadline()
		if !ok || time.Until(deadline) > MaxLifetime {
			t.Fatal("capture lifetime unbounded")
		}
		if deny {
			return errors.New("revoked")
		}
		return nil
	}}
	sentinel := errors.New("expected callback exit")
	err := withFrozenSource(t.Context(), v, b, m, v.proof.Challenge, a, func(source *workspacesnapshot.Source) error {
		reader, err := source.Open(t.Context(), capturedScope(source), 128)
		if err != nil {
			return err
		}
		defer reader.Close()
		deny = true
		if n, err := reader.Read(make([]byte, 128)); n != 0 || err == nil {
			t.Fatal("revoked source released bytes")
		}
		return sentinel
	})
	if !errors.Is(err, sentinel) {
		t.Fatal(err)
	}
}
func TestFrozenCaptureMissingAuthorityDoesNotOpenRoot(t *testing.T) {
	t.Parallel()
	v, b, m := captureFixture(t)
	var a *fixtureAuthority
	if withFrozenSource(t.Context(), v, b, m, v.proof.Challenge, a, func(*workspacesnapshot.Source) error { return nil }) == nil || v.opened {
		t.Fatal("opened root without authority")
	}
	// The public API cannot accept the fixture's path or synthetic kernel observer.
	if WithFrozenSource(t.Context(), b, m, v.proof.Challenge, nil, func(*workspacesnapshot.Source) error { return nil }) == nil {
		t.Fatal("public capture without supervisor authority")
	}
}
func TestFrozenCaptureCallbackFailureAndPanicExpireLease(t *testing.T) {
	t.Parallel()
	for _, panicExit := range []bool{false, true} {
		t.Run(fmt.Sprint(panicExit), func(t *testing.T) {
			t.Parallel()
			v, b, m := captureFixture(t)
			var source *workspacesnapshot.Source
			func() {
				defer func() {
					if recovered := recover(); panicExit && recovered == nil {
						t.Error("panic not propagated")
					}
				}()
				err := withFrozenSource(t.Context(), v, b, m, v.proof.Challenge, &fixtureAuthority{}, func(s *workspacesnapshot.Source) error {
					source = s
					if panicExit {
						panic("synthetic")
					}
					return errors.New("synthetic failure")
				})
				if err == nil {
					t.Fatal("callback failure ignored")
				}
			}()
			if source == nil || source.Current(t.Context()) == nil {
				t.Fatal("callback exit left source usable")
			}
		})
	}
}
