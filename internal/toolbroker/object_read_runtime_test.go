package toolbroker

import (
	"commonroom-runtime/internal/objectcustody"
	"commonroom-runtime/internal/objectread"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"net"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

type objectReadRuntimeFixture struct {
	*objectReadPlanRunner
	mode                                                     string
	exists, begun, bound, started, finished, absent, removed bool
	authorizations, acknowledgments, stopped                 int
	process                                                  *mockObjectReadProcess
	exitedChecks                                             int
	cancel                                                   context.CancelFunc
}
type mockObjectReadProcess struct {
	net.Conn
	f         *objectReadRuntimeFixture
	done      chan struct{}
	helperErr error
	closed    atomic.Bool
	waited    atomic.Bool
}

func (p *mockObjectReadProcess) Close() error {
	p.closed.Store(true)
	err := p.Conn.Close()
	<-p.done
	if p.f.mode == "close" {
		return ErrRejected
	}
	return err
}
func (p *mockObjectReadProcess) Read(b []byte) (int, error) {
	n, err := p.Conn.Read(b)
	if err == io.EOF && p.f.mode == "exit-before-wait" {
		p.f.c.State.Status = "exited"
		p.f.c.State.Running = probeBool(false)
	}
	return n, err
}

func (p *mockObjectReadProcess) Wait(ctx context.Context) error {
	if p.closed.Load() {
		return ErrRejected
	}
	select {
	case <-p.done:
		p.waited.Store(true)
		if p.helperErr != nil {
			return p.helperErr
		}
	case <-ctx.Done():
		return ctx.Err()
	}
	p.f.c.State.Status = "exited"
	p.f.c.State.Running = probeBool(false)
	if p.f.mode == "wait" {
		return ErrRejected
	}
	return nil
}
func (f *objectReadRuntimeFixture) BeginObjectRead(ctx context.Context, q objectread.Request, v CaptureObjectVolume, image string) error {
	if q != f.p.request || v != f.p.objects || image != f.p.image {
		f.t.Fatal("unpinned begin")
	}
	if f.mode == "begin" {
		return ErrRejected
	}
	f.begun = true
	return ctx.Err()
}
func (f *objectReadRuntimeFixture) BindObjectRead(ctx context.Context, q objectread.Request, id string) error {
	if !f.begun || q != f.p.request || id != f.c.ID {
		f.t.Fatal("unpinned binding")
	}
	f.bound = true
	if f.mode == "bind" {
		return ErrRejected
	}
	return ctx.Err()
}
func (f *objectReadRuntimeFixture) FinishObjectRead(ctx context.Context, q objectread.Request, id string, absent bool) error {
	if q != f.p.request || id != "" && id != f.c.ID {
		f.t.Fatal("unpinned finish")
	}
	if f.process != nil && !f.process.closed.Load() {
		f.t.Fatal("finish before process joined")
	}
	f.finished = true
	f.absent = absent
	if f.mode == "cancel-finish" {
		f.cancel()
	}
	if f.mode == "finish" {
		return ErrRejected
	}
	return ctx.Err()
}
func (f *objectReadRuntimeFixture) AuthorizeRead(ctx context.Context, s objectcustody.Scope, r objectcustody.Receipt) error {
	f.authorizations++
	if s != f.p.request.Receipt.Intent.Scope || r != f.p.request.Receipt {
		f.t.Fatal("unpinned authorization")
	}
	if f.mode == "callback-policy" && f.authorizations == 3 {
		f.c.HostConfig.NetworkMode = "host"
	}
	if f.mode == "cancel-read" && f.authorizations == 2 {
		f.cancel()
	}
	if f.mode == "authority" {
		return ErrRejected
	}
	return ctx.Err()
}
func (f *objectReadRuntimeFixture) AcknowledgeRead(ctx context.Context, r objectcustody.Receipt) error {
	f.acknowledgments++
	if r != f.p.request.Receipt {
		f.t.Fatal("unpinned acknowledgment")
	}
	if f.mode == "ack" || f.mode == "final-ack" && f.finished {
		return ErrRejected
	}
	if f.acknowledgments == 3 && (!f.finished || !f.absent || !f.removed) {
		f.t.Fatal("final release before cleanup")
	}
	return ctx.Err()
}
func (f *objectReadRuntimeFixture) StopReadAuthority() { f.stopped++ }
func (f *objectReadRuntimeFixture) Run(ctx context.Context, args []string, in []byte, out io.Writer) error {
	if !f.begun {
		f.t.Fatal("daemon before durable authority")
	}
	switch args[0] {
	case "create":
		if !slices.Equal(args, f.p.CreateArgs()) {
			f.t.Fatal("changed launch")
		}
		f.exists = true
		if f.mode == "create" {
			return ErrRejected
		}
		if f.mode == "malformed-id" {
			_, err := io.WriteString(out, "ambiguous")
			return err
		}
		_, err := io.WriteString(out, f.c.ID)
		return err
	case "rm":
		if !slices.Equal(args, []string{"rm", "--force", f.c.ID}) {
			f.t.Fatal("removed foreign identity")
		}
		if f.mode == "cleanup" {
			return ErrRejected
		}
		f.exists = false
		f.removed = true
		if f.mode == "replacement" {
			f.v.CreatedAt = "2000-01-01T00:00:00Z"
		}
		return nil
	case "ps":
		if f.removed && f.mode == "returning-reference" {
			_, err := io.WriteString(out, strings.Repeat("9", 64))
			return err
		}
		if !f.exists {
			return nil
		}
	case "inspect":
		if f.c.State.Status == "exited" {
			f.exitedChecks++
		}
	}
	return f.objectReadPlanRunner.Run(ctx, args, in, out)
}

type relayedSyntheticReader struct {
	journal *objectcustody.ReadJournalChannel
	corrupt bool
}

func (r relayedSyntheticReader) Get(ctx context.Context, s objectcustody.Scope, q objectcustody.Receipt) ([]byte, error) {
	if err := r.journal.AuthorizeRead(ctx, s, q); err != nil {
		return nil, err
	}
	if err := r.journal.AcknowledgeRead(ctx, q); err != nil {
		return nil, err
	}
	if r.corrupt {
		return []byte("bad"), nil
	}
	return []byte("abc"), nil
}
func (f *objectReadRuntimeFixture) StartObjectRead(ctx context.Context, id string) (ObjectReadProcess, error) {
	if !f.bound || id != f.c.ID {
		f.t.Fatal("start before durable exact binding")
	}
	f.started = true
	if f.mode == "start" {
		return nil, ErrRejected
	}
	f.c.State.Status = "running"
	f.c.State.Running = probeBool(true)
	if f.mode == "running-policy" {
		f.c.HostConfig.NetworkMode = "host"
	}
	parent, helper := net.Pipe()
	p := &mockObjectReadProcess{Conn: parent, f: f, done: make(chan struct{})}
	f.process = p
	go func() {
		defer helper.Close()
		j, err := objectcustody.NewReadJournalChannel(ctx, helper, f.p.request.Receipt, func() {})
		if err == nil {
			err = objectcustody.ServeReadChannel(ctx, helper, f.p.request.Receipt.Intent.Scope, f.p.request.Receipt, relayedSyntheticReader{j, f.mode == "corrupt"})
		}
		p.helperErr = err
		close(p.done)
	}()
	if f.mode == "start-stream" {
		return p, ErrRejected
	}
	return p, nil
}
func newObjectReadRuntimeFixture(t *testing.T, mode string) (*ObjectReadRuntime, *objectReadRuntimeFixture) {
	t.Helper()
	old, c, v := objectReadPlanFixture(t)
	q := old.request
	sum := sha256.Sum256([]byte("abc"))
	q.Receipt.Digest = hex.EncodeToString(sum[:])
	p, err := NewObjectReadContainerPlan(q, old.image, old.root, old.objects)
	if err != nil {
		t.Fatal(err)
	}
	c.Config.Cmd = []string{p.encoded}
	c.Config.Labels = p.labels()
	f := &objectReadRuntimeFixture{objectReadPlanRunner: &objectReadPlanRunner{t: t, p: p, c: c, v: v}, mode: mode}
	if mode == "missing-volume" {
		f.v.CreatedAt = "2000-01-01T00:00:00Z"
	}
	if mode == "preexisting" {
		f.exists = true
	}
	r, err := NewObjectReadRuntime(p, f, f, f, f)
	if err != nil {
		t.Fatal(err)
	}
	return r, f
}
func TestObjectReadRuntimeLifecycle(t *testing.T) {
	t.Parallel()
	r, f := newObjectReadRuntimeFixture(t, "")
	raw, err := r.Run(t.Context())
	if err != nil || string(raw) != "abc" {
		t.Fatal("read", err)
	}
	if !f.begun || !f.bound || !f.started || !f.finished || !f.absent || !f.removed || f.authorizations != 3 || f.acknowledgments != 3 || f.stopped != 0 || f.exitedChecks < 2 || !f.process.waited.Load() || !f.process.closed.Load() {
		t.Fatal("incomplete lifecycle", f)
	}
	calls := f.calls
	if raw, err = r.Run(t.Context()); err == nil || raw != nil || f.calls != calls {
		t.Fatal("runtime reused")
	}
}
func TestObjectReadRuntimeFailuresWithholdBytes(t *testing.T) {
	t.Parallel()
	for _, mode := range []string{"begin", "authority", "preexisting", "create", "malformed-id", "bind", "start", "start-stream", "running-policy", "ack", "corrupt", "wait", "close", "cleanup", "replacement", "returning-reference", "finish", "final-ack", "cancel-finish", "cancel-read", "callback-policy", "missing-volume"} {
		t.Run(mode, func(t *testing.T) {
			t.Parallel()
			r, f := newObjectReadRuntimeFixture(t, mode)
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			f.cancel = cancel
			raw, err := r.Run(ctx)
			if err == nil || raw != nil || f.stopped == 0 {
				t.Fatal("released on failure", err)
			}
			if mode != "begin" && (!f.finished || !errors.Is(err, objectcustody.ErrUnconfirmed)) {
				t.Fatal("lost uncertainty", err)
			}
			if mode == "begin" && f.calls != 0 {
				t.Fatal("daemon before begin")
			}
			if (mode == "create" || mode == "malformed-id" || mode == "preexisting" || mode == "missing-volume") && (f.removed || f.absent || f.started) {
				t.Fatal("adopted unknown/preexisting helper")
			}
			if f.process != nil && !f.process.closed.Load() {
				t.Fatal("leaked attached process")
			}
		})
	}
}
func TestObjectReadRuntimeRequiresDependencies(t *testing.T) {
	t.Parallel()
	_, f := newObjectReadRuntimeFixture(t, "")
	var missing *objectReadRuntimeFixture
	for _, makeRuntime := range []func() error{
		func() error { _, e := NewObjectReadRuntime(nil, f, f, f, f); return e },
		func() error { _, e := NewObjectReadRuntime(f.p, missing, f, f, f); return e },
		func() error { _, e := NewObjectReadRuntime(f.p, f, missing, f, f); return e },
		func() error { _, e := NewObjectReadRuntime(f.p, f, f, missing, f); return e },
		func() error { _, e := NewObjectReadRuntime(f.p, f, f, f, missing); return e },
	} {
		if makeRuntime() == nil {
			t.Fatal("missing dependency admitted")
		}
	}
	r, f := newObjectReadRuntimeFixture(t, "")
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if raw, err := r.Run(ctx); err == nil || raw != nil || f.calls != 0 {
		t.Fatal("canceled request touched daemon")
	}
}

func TestObjectReadRuntimeExitAtProtocolEOF(t *testing.T) {
	t.Parallel()
	r, f := newObjectReadRuntimeFixture(t, "exit-before-wait")
	raw, err := r.Run(t.Context())
	if err != nil || string(raw) != "abc" || !f.finished || f.acknowledgments != 3 || !f.absent {
		t.Fatal("successful helper EOF/exit refused", err)
	}
}

// This journal observes the context actually supplied to the persistence boundary.
// Its embedded fixture still checks exact request/ID and process-close ordering.
type objectReadDeadlineJournal struct {
	*objectReadRuntimeFixture
	activeFinish bool
}

func (j *objectReadDeadlineJournal) FinishObjectRead(ctx context.Context, q objectread.Request, id string, absent bool) error {
	deadline, bounded := ctx.Deadline()
	remaining := time.Until(deadline)
	j.activeFinish = ctx.Err() == nil && bounded && remaining > 0 && remaining <= 5*time.Second
	if !j.activeFinish {
		return ctx.Err()
	}
	return j.objectReadRuntimeFixture.FinishObjectRead(ctx, q, id, absent)
}
func TestObjectReadCleanupExhaustionStillJournalsUncertainty(t *testing.T) {
	t.Parallel()
	for _, mode := range []string{"expired", "canceled", "journal-failure"} {
		t.Run(mode, func(t *testing.T) {
			t.Parallel()
			r, f := newObjectReadRuntimeFixture(t, "")
			f.begun = true
			f.exists = true
			j := &objectReadDeadlineJournal{objectReadRuntimeFixture: f}
			r.lifecycle = j
			// Supply the deterministic end state of an exhausted cleanup budget;
			// no sleep, real daemon or permissive production clock seam is needed.
			cleanup, cancel := context.WithDeadline(context.Background(), time.Now().Add(-time.Second))
			defer cancel()
			if mode == "canceled" {
				c, stop := context.WithCancel(context.Background())
				stop()
				cleanup = c
			}
			if mode == "journal-failure" {
				f.mode = "finish"
			}
			err := r.cleanupAndFinish(cleanup, f.c.ID)
			if !errors.Is(err, ErrShutdownUnconfirmed) || !j.activeFinish || !f.finished || f.absent {
				t.Fatal("cleanup exhaustion prevented recording uncertainty", err, j.activeFinish, f.finished, f.absent)
			}
			if f.calls != 0 || f.removed || f.acknowledgments != 0 {
				t.Fatal("expired cleanup removed or released an artifact")
			}
			if mode == "journal-failure" && !errors.Is(err, ErrRejected) {
				t.Fatal("journal failure swallowed", err)
			}
		})
	}
}
