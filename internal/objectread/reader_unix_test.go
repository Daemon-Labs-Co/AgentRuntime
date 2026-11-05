//go:build linux || darwin

package objectread

import (
	"commonroom-runtime/internal/objectcustody"
	"commonroom-runtime/internal/workspacemount"
	"context"
	"net"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
)

type seedJournal struct{}

func (seedJournal) Reserve(context.Context, objectcustody.Intent) error { return nil }
func (seedJournal) Seal(context.Context, objectcustody.Receipt) error   { return nil }
func (seedJournal) AuthorizeRead(context.Context, objectcustody.Scope, objectcustody.Receipt) error {
	return objectcustody.ErrRefused
}
func (seedJournal) AcknowledgeRead(context.Context, objectcustody.Receipt) error {
	return objectcustody.ErrRefused
}

type syntheticView struct {
	mu            sync.Mutex
	dir, identity string
	proof         workspacemount.Proof
	calls         int
}

func (v *syntheticView) OpenRoot() (*os.Root, error) { return os.OpenRoot(v.dir) }
func (v *syntheticView) Identity() (os.FileInfo, error) {
	v.mu.Lock()
	defer v.mu.Unlock()
	return os.Lstat(v.identity)
}
func (v *syntheticView) Observe(ctx context.Context, _ string) (workspacemount.Proof, error) {
	v.mu.Lock()
	defer v.mu.Unlock()
	v.calls++
	return v.proof, ctx.Err()
}

type releaseGuard struct {
	auth, acks, stops atomic.Int32
	deny              bool
	onAuth, onAck     func()
}

func (g *releaseGuard) AuthorizeRead(ctx context.Context, _ objectcustody.Scope, _ objectcustody.Receipt) error {
	g.auth.Add(1)
	if g.onAuth != nil {
		g.onAuth()
	}
	if g.deny {
		return objectcustody.ErrRefused
	}
	return ctx.Err()
}
func (g *releaseGuard) AcknowledgeRead(ctx context.Context, _ objectcustody.Receipt) error {
	g.acks.Add(1)
	if g.onAck != nil {
		g.onAck()
	}
	return ctx.Err()
}
func (g *releaseGuard) StopReadAuthority() { g.stops.Add(1) }
func readerFixture(t *testing.T) (Request, *syntheticView) {
	t.Helper()
	dir := t.TempDir()
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	root, err := os.OpenRoot(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	store, err := objectcustody.New(root, seedJournal{})
	if err != nil {
		t.Fatal(err)
	}
	scope := objectcustody.Scope{ExecutionScope: objectcustody.ExecutionScope{CompanyID: "company", RoomID: "room", TaskID: "task", ExecutionID: strings.Repeat("a", 32), JobID: strings.Repeat("b", 32), RepositoryDigest: strings.Repeat("c", 64), RevisionDigest: strings.Repeat("d", 64), DefinitionDigest: strings.Repeat("e", 64)}, OutputName: "report", MemberName: "report.txt"}
	receipt, err := store.Put(t.Context(), scope, 128, strings.NewReader("synthetic immutable object"))
	if err != nil {
		t.Fatal(err)
	}
	challenge := strings.Repeat("f", 32)
	return Request{receipt, challenge}, &syntheticView{dir: dir, identity: dir, proof: workspacemount.Proof{Version: 1, Challenge: challenge, MountID: 2, ReadOnly: true, RootReadOnly: true}}
}
func TestObjectReaderFixedLeaseAndControllerRelay(t *testing.T) {
	t.Parallel()
	for _, mode := range []string{"healthy", "writable mount", "writable root", "wrong challenge", "changed mount", "changed identity", "revoked", "canceled after source ack"} {
		t.Run(mode, func(t *testing.T) {
			t.Parallel()
			q, view := readerFixture(t)
			g := &releaseGuard{}
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			switch mode {
			case "writable mount":
				view.proof.ReadOnly = false
			case "writable root":
				view.proof.RootReadOnly = false
			case "wrong challenge":
				view.proof.Challenge = strings.Repeat("9", 32)
			case "changed mount":
				g.onAuth = func() {
					if g.auth.Load() == 2 {
						view.mu.Lock()
						view.proof.MountID++
						view.mu.Unlock()
					}
				}
			case "changed identity":
				other := t.TempDir()
				g.onAuth = func() {
					if g.auth.Load() == 2 {
						view.mu.Lock()
						view.identity = other
						view.mu.Unlock()
					}
				}
			case "revoked":
				g.onAuth = func() {
					if g.auth.Load() == 2 {
						g.deny = true
					}
				}
			case "canceled after source ack":
				g.onAck = cancel
			}
			left, right := net.Pipe()
			done := make(chan error, 1)
			go func() { done <- serve(ctx, q, right, view) }()
			raw, err := objectcustody.ReadChannel(t.Context(), left, q.Receipt.Intent.Scope, q.Receipt, g)
			serveErr := <-done
			if mode == "healthy" {
				if err != nil || serveErr != nil || string(raw) != "synthetic immutable object" || g.acks.Load() != 2 {
					t.Fatal(err, serveErr, g.acks.Load())
				}
			} else if err == nil || raw != nil || serveErr == nil || g.stops.Load() != 1 {
				t.Fatal("uncertain lease released bytes", mode, err, serveErr)
			}
		})
	}
}
func TestObjectReaderMetadataAndUnsupportedView(t *testing.T) {
	q, _ := readerFixture(t)
	if !ValidRequest(q) {
		t.Fatal("valid request")
	}
	q.Challenge = "bad"
	if ValidRequest(q) {
		t.Fatal("bad challenge")
	}
	if serve(nil, q, nil, nil) == nil {
		t.Fatal("missing dependencies")
	}
}
