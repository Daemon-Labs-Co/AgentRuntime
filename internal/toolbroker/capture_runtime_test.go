package toolbroker

import (
	"commonroom-runtime/internal/objectcustody"
	"commonroom-runtime/internal/workspacecapture"
	"commonroom-runtime/internal/workspacemount"
	"commonroom-runtime/internal/workspacesnapshot"
	"context"
	"errors"
	"io"
	"net"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

type captureRuntimeFixture struct {
	*captureAdmissionRunner
	mode                                                     string
	exists, begun, bound, started, finished, absent, removed bool
	reserves, seals, observations                            int
	process                                                  *mockCaptureProcess
	exitedChecks                                             atomic.Int32
}
type mockCaptureProcess struct {
	net.Conn
	f          *captureRuntimeFixture
	done       chan error
	closed     atomic.Bool
	waited     atomic.Bool
	earlyClose atomic.Bool
}

func (p *mockCaptureProcess) Wait(ctx context.Context) error {
	if p.closed.Load() {
		return ErrRejected
	}
	p.waited.Store(true)
	select {
	case err := <-p.done:
		if err != nil {
			return err
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
func (f *captureRuntimeFixture) BeginCapture(ctx context.Context, r workspacecapture.Request, o CaptureObjectVolume, image string) error {
	if image != f.p.image {
		f.t.Fatal("creation image not bound to journal")
	}
	f.begun = true
	if f.mode == "begin" {
		return ErrRejected
	}
	return ctx.Err()
}
func (f *captureRuntimeFixture) BindCapture(ctx context.Context, r workspacecapture.Request, id string) error {
	if !f.begun || id != f.c.ID {
		f.t.Fatal("binding out of order")
	}
	f.bound = true
	if f.mode == "bind" {
		return ErrRejected
	}
	return ctx.Err()
}
func (f *captureRuntimeFixture) FinishCapture(ctx context.Context, r workspacecapture.Request, id string, absent bool) error {
	f.finished = true
	f.absent = absent
	if f.mode == "finish" {
		return ErrRejected
	}
	return ctx.Err()
}
func (f *captureRuntimeFixture) AuthorizeFrozenSource(ctx context.Context, b workspacesnapshot.Binding, p workspacemount.Proof) error {
	f.observations++
	if !f.started {
		f.t.Fatal("observation before start")
	}
	if f.mode == "authority" {
		return ErrRejected
	}
	return ctx.Err()
}
func (f *captureRuntimeFixture) Reserve(ctx context.Context, i objectcustody.Intent) error {
	f.reserves++
	if f.mode == "reserve" {
		return ErrRejected
	}
	return ctx.Err()
}
func (f *captureRuntimeFixture) Seal(ctx context.Context, r objectcustody.Receipt) error {
	f.seals++
	if f.mode == "seal" {
		return ErrRejected
	}
	return ctx.Err()
}
func (f *captureRuntimeFixture) AuthorizeRead(context.Context, objectcustody.Scope, objectcustody.Receipt) error {
	f.t.Fatal("read attempted")
	return ErrRejected
}
func (f *captureRuntimeFixture) AcknowledgeRead(context.Context, objectcustody.Receipt) error {
	f.t.Fatal("release attempted")
	return ErrRejected
}
func (f *captureRuntimeFixture) Run(ctx context.Context, args []string, in []byte, out io.Writer) error {
	if !f.begun {
		f.t.Fatal("daemon before begin")
	}
	switch args[0] {
	case "inspect":
		if f.c.State.Status == "exited" {
			f.exitedChecks.Add(1)
		}
	case "create":
		if !slices.Equal(args, f.p.CreateArgs()) {
			f.t.Fatal("launch policy changed")
		}
		f.exists = true
		if f.mode == "create" {
			return errors.New("synthetic lost reply")
		}
		_, e := io.WriteString(out, f.c.ID)
		return e
	case "rm":
		if !slices.Equal(args, []string{"rm", "--force", f.c.ID}) {
			f.t.Fatal("wrong removal")
		}
		if f.mode == "cleanup" {
			return ErrRejected
		}
		f.removed = true
		if f.mode == "replacement" {
			f.obj.CreatedAt = "2000-01-01T00:00:00Z"
		}
		f.exists = false
		return nil
	case "ps":
		if f.removed && f.mode == "returning reference" && slices.Contains(args, "volume="+f.obj.Name) {
			_, e := io.WriteString(out, strings.Repeat("9", 64))
			return e
		}
		if !f.exists {
			return nil
		}
	}
	return f.captureAdmissionRunner.Run(ctx, args, in, out)
}
func (f *captureRuntimeFixture) StartCapture(ctx context.Context, id string) (CaptureProcess, error) {
	if !f.bound || id != f.c.ID {
		f.t.Fatal("start without durable binding")
	}
	f.started = true
	if f.mode == "start" {
		return nil, ErrRejected
	}
	if f.mode == "running-policy" {
		f.c.HostConfig.NetworkMode = "host"
	}
	f.c.State.Status = "running"
	f.c.State.Running = probeBool(true)
	parent, helper := net.Pipe()
	p := &mockCaptureProcess{Conn: parent, f: f, done: make(chan error, 1)}
	f.process = p
	go func() {
		defer helper.Close()
		client, err := workspacecapture.NewCaptureChannel(ctx, helper, f.p.request, func() {})
		if err == nil {
			proof := workspacemount.Proof{Version: 1, Challenge: f.p.request.Challenge, MountID: 2, ReadOnly: true, RootReadOnly: true}
			err = client.AuthorizeFrozenSource(ctx, f.p.request.Binding, proof)
			scope := f.p.request.Binding.Execution
			scope.RevisionDigest = strings.Repeat("7", 64)
			m := f.p.request.Members[0]
			intent := objectcustody.Intent{ObjectID: strings.Repeat("8", 32), Scope: objectcustody.Scope{ExecutionScope: scope, OutputName: m.OutputName, MemberName: m.Name}, MaxBytes: m.MaxBytes}
			receipt := objectcustody.Receipt{Intent: intent, Bytes: 3, Digest: strings.Repeat("9", 64)}
			if err == nil {
				err = client.Reserve(ctx, intent)
			}
			if err == nil {
				err = client.Seal(ctx, receipt)
			}
			if err == nil {
				err = client.Finish(ctx, workspacecapture.CapturedObjects{Snapshot: workspacesnapshot.Snapshot{Scope: scope, Digest: scope.RevisionDigest}, Receipts: []objectcustody.Receipt{receipt}})
			}
		}
		p.done <- err
	}()
	if f.mode == "start-stream" {
		return p, ErrRejected
	}
	return p, nil
}
func newCaptureRuntimeFixture(t *testing.T, mode string) (*CaptureRuntime, *captureRuntimeFixture) {
	t.Helper()
	p, c, s, o := capturePlanFixture(t)
	f := &captureRuntimeFixture{captureAdmissionRunner: &captureAdmissionRunner{t: t, p: p, c: c, src: s, obj: o}, mode: mode}
	if mode == "preexisting" {
		f.exists = true
	}
	r, e := NewCaptureRuntime(p, f, f, f, f, f)
	if e != nil {
		t.Fatal(e)
	}
	return r, f
}
func TestCaptureRuntimeLifecycle(t *testing.T) {
	t.Parallel()
	r, f := newCaptureRuntimeFixture(t, "")
	report, err := r.Run(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if !f.begun || !f.bound || !f.started || !f.finished || !f.absent || !f.removed || f.reserves != 1 || f.seals != 1 || f.observations < 4 || len(report.Receipts) != 1 {
		t.Fatal("incomplete lifecycle", f, report)
	}
	if _, err = r.Run(context.Background()); err == nil {
		t.Fatal("runtime reused")
	}
}
func TestCaptureRuntimeFailureWithholdsReports(t *testing.T) {
	t.Parallel()
	for _, mode := range []string{"begin", "preexisting", "create", "bind", "start", "authority", "reserve", "seal", "wait", "cleanup", "finish", "replacement", "returning reference", "running-policy", "start-stream"} {
		t.Run(mode, func(t *testing.T) {
			t.Parallel()
			r, f := newCaptureRuntimeFixture(t, mode)
			report, err := r.Run(context.Background())
			if err == nil || report.Version != 0 || len(report.Receipts) != 0 {
				t.Fatal("released failed report", err, report)
			}
			if mode == "begin" {
				if f.calls != 0 || f.finished {
					t.Fatal("operation after begin denial")
				}
				return
			}
			if !f.finished || !errors.Is(err, objectcustody.ErrUnconfirmed) {
				t.Fatal("lost uncertain outcome", err)
			}
			if mode == "create" || mode == "preexisting" {
				if f.removed || f.started || f.absent {
					t.Fatal("adopted unknown container")
				}
			}
			if mode == "bind" && f.started {
				t.Fatal("started without durable binding")
			}
			if mode == "cleanup" && f.absent {
				t.Fatal("claimed failed cleanup absent")
			}
			if f.process != nil && !f.process.closed.Load() {
				t.Fatal("failed process stream left open")
			}
			if mode == "seal" && f.reserves != 1 {
				t.Fatal("lost attempted charge")
			}
		})
	}
}

func TestCaptureRuntimeCanceledAndMissingDependencies(t *testing.T) {
	t.Parallel()
	r, f := newCaptureRuntimeFixture(t, "")
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := r.Run(ctx); err == nil || f.begun {
		t.Fatal("canceled runtime admitted")
	}
	var missing *captureRuntimeFixture
	for _, deps := range []struct {
		runner  DockerRunner
		starter CaptureStarter
		life    CaptureLifecycleJournal
		auth    workspacecapture.Authority
		custody objectcustody.Journal
	}{
		{missing, f, f, f, f}, {f, missing, f, f, f}, {f, f, missing, f, f}, {f, f, f, missing, f}, {f, f, f, f, missing},
	} {
		if _, err := NewCaptureRuntime(r.plan, deps.runner, deps.starter, deps.life, deps.auth, deps.custody); err == nil {
			t.Fatal("missing dependency admitted")
		}
	}
}
func TestCaptureRuntimeFailedStreamIsClosed(t *testing.T) {
	t.Parallel()
	r, f := newCaptureRuntimeFixture(t, "start-stream")
	if _, err := r.Run(context.Background()); err == nil {
		t.Fatal("accepted failed starter")
	}
	select {
	case <-f.process.done:
	case <-time.After(time.Second):
		t.Fatal("helper I/O was not interrupted")
	}
}

// Closing the production attached stream cancels its command. Model that behavior
// deterministically: a close before Wait must not count as a successful exit.
func (p *mockCaptureProcess) Close() error {
	if p.closed.Swap(true) {
		return nil
	}
	if !p.waited.Load() || p.f.exitedChecks.Load() < 2 {
		p.earlyClose.Store(true)
	}
	return p.Conn.Close()
}
func TestCaptureRuntimeWaitsAndVerifiesExitBeforeClose(t *testing.T) {
	t.Parallel()
	runtime, fixture := newCaptureRuntimeFixture(t, "")
	report, err := runtime.Run(t.Context())
	if err != nil || len(report.Receipts) != 1 {
		t.Fatal("completed capture discarded", err)
	}
	process := fixture.process
	if !process.waited.Load() || !process.closed.Load() || process.earlyClose.Load() || fixture.exitedChecks.Load() < 2 {
		t.Fatal("process closed before successful wait and exited admission")
	}
}
