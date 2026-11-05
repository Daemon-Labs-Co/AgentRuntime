package toolbroker

import (
	"bytes"
	"commonroom-runtime/internal/workspacebootstrap"
	"context"
	"encoding/json"
	"errors"
	"io"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
)

type bootstrapScenario struct {
	*runtimeScenario
	mode      string
	bootCalls int
	source    string
}

func (f *bootstrapScenario) RunInput(ctx context.Context, args []string, in io.Reader, out io.Writer) error {
	f.bootCalls++
	scope := f.plan.authority.scope
	expected := []string{"exec", "-i", "--user", "1000:1000", "--workdir", "/workspace", f.container.ID, "/opt/commonroom/workspace-bootstrap", scope.JobID, scope.RepositoryDigest}
	if !slices.Equal(args, expected) {
		f.t.Fatal("bootstrap escaped fixed identity")
	}
	raw, err := io.ReadAll(in)
	if err != nil {
		return err
	}
	f.source = string(raw)
	if f.mode == "stream-error" {
		return errors.New("synthetic unavailable")
	}
	receipt := workspacebootstrap.Receipt{Version: 1, Job: scope.JobID, Repository: scope.RepositoryDigest, Commit: strings.Repeat("a", 40), Branch: "feature/commonroom-" + scope.JobID}
	switch f.mode {
	case "job":
		receipt.Job = "foreign"
	case "digest":
		receipt.Repository = strings.Repeat("c", 64)
	case "branch":
		receipt.Branch = "main"
	case "commit":
		receipt.Commit = "unknown"
	case "post-policy":
		f.container.HostConfig.NetworkMode = "host"
	}
	raw, _ = json.Marshal(receipt)
	switch f.mode {
	case "duplicate":
		raw = bytes.Replace(raw, []byte(`"version":1`), []byte(`"version":1,"version":1`), 1)
	case "alias":
		raw = bytes.Replace(raw, []byte(`"version":1`), []byte(`"version":1,"Version":1`), 1)
	case "unknown":
		raw = append(raw[:len(raw)-1], []byte(`,"extra":true}`)...)
	case "missing":
		raw = []byte(`{"version":1}`)
	case "overflow":
		raw = bytes.Repeat([]byte("x"), 1025)
	case "trailing":
		raw = append(raw, []byte(`{}`)...)
	}
	_, err = out.Write(raw)
	return err
}

type trackedInput struct {
	*strings.Reader
	closed atomic.Bool
}

func (r *trackedInput) Close() error { r.closed.Store(true); return nil }
func TestRuntimeBootstrapBindsSnapshotAndGatesTools(t *testing.T) {
	t.Parallel()
	for _, mode := range []string{"success", "stream-error", "job", "digest", "branch", "commit", "duplicate", "alias", "unknown", "missing", "overflow", "trailing", "post-policy"} {
		t.Run(mode, func(t *testing.T) {
			t.Parallel()
			r, base, cancel := runtimeSetup(t, "")
			defer cancel()
			f := &bootstrapScenario{runtimeScenario: base, mode: mode}
			r.executor.runner = f
			id, err := r.Create(t.Context())
			if err != nil {
				t.Fatal(err)
			}
			if err = r.Start(t.Context(), id); err != nil {
				t.Fatal(err)
			}
			before := len(f.calls)
			if r.executor.Execute(t.Context(), f.plan.authority.scope, Action{Operation: "read", Path: "file"}, io.Discard) != ErrRejected || len(f.calls) != before {
				t.Fatal("tools before bootstrap")
			}
			input := &trackedInput{Reader: strings.NewReader("synthetic bounded snapshot")}
			receipt, err := r.Bootstrap(t.Context(), input)
			if (err == nil) != (mode == "success") || !input.closed.Load() || f.bootCalls != 1 {
				t.Fatalf("unexpected bootstrap %v", err)
			}
			if f.plan.workspaceReady() != (mode == "success") {
				t.Fatal("unsafe workspace readiness")
			}
			if mode == "success" && (!workspacebootstrap.ValidReceipt(receipt, f.plan.authority.scope.JobID, f.plan.authority.scope.RepositoryDigest) || f.source != "synthetic bounded snapshot") {
				t.Fatal("snapshot binding lost")
			}
			again := &trackedInput{Reader: strings.NewReader("never replay")}
			if _, err = r.Bootstrap(t.Context(), again); err == nil || f.bootCalls != 1 || !again.closed.Load() {
				t.Fatal("bootstrap replayed or source leaked")
			}
		})
	}
}
func TestRuntimeBootstrapRequiresRunningStreamingAdapter(t *testing.T) {
	t.Parallel()
	for _, mode := range []string{"not-started", "no-stream-adapter", "cancelled"} {
		t.Run(mode, func(t *testing.T) {
			t.Parallel()
			r, base, cancel := runtimeSetup(t, "")
			defer cancel()
			f := &bootstrapScenario{runtimeScenario: base}
			if mode != "no-stream-adapter" {
				r.executor.runner = f
			}
			if mode != "not-started" {
				id, err := r.Create(t.Context())
				if err != nil {
					t.Fatal(err)
				}
				if err = r.Start(t.Context(), id); err != nil {
					t.Fatal(err)
				}
			}
			if mode == "cancelled" {
				cancel()
			}
			input := &trackedInput{Reader: strings.NewReader("unused")}
			if _, err := r.Bootstrap(context.Background(), input); err == nil || !input.closed.Load() || f.bootCalls != 0 {
				t.Fatal("unavailable bootstrap ran")
			}
		})
	}
}

type blockedSnapshot struct {
	entered   chan struct{}
	closed    chan struct{}
	readOnce  sync.Once
	closeOnce sync.Once
}

func (r *blockedSnapshot) Read(p []byte) (int, error) {
	r.readOnce.Do(func() { close(r.entered) })
	<-r.closed
	return 0, io.ErrClosedPipe
}
func (r *blockedSnapshot) Close() error { r.closeOnce.Do(func() { close(r.closed) }); return nil }
func TestRuntimeBootstrapCancellationClosesBlockedSnapshot(t *testing.T) {
	t.Parallel()
	r, base, cancelLifetime := runtimeSetup(t, "")
	defer cancelLifetime()
	f := &bootstrapScenario{runtimeScenario: base}
	r.executor.runner = f
	id, err := r.Create(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if err = r.Start(t.Context(), id); err != nil {
		t.Fatal(err)
	}
	input := &blockedSnapshot{entered: make(chan struct{}), closed: make(chan struct{})}
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	done := make(chan error, 1)
	go func() { _, err := r.Bootstrap(ctx, input); done <- err }()
	<-input.entered
	cancel()
	if err = <-done; err == nil || f.plan.workspaceReady() {
		t.Fatal("blocked cancelled snapshot admitted")
	}
}

func TestBootstrappedExecutorCannotReviveCancelledJob(t *testing.T) {
	t.Parallel()
	r, base, cancel := runtimeSetup(t, "")
	defer cancel()
	f := &bootstrapScenario{runtimeScenario: base}
	r.executor.runner = f
	id, err := r.Create(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if err = r.Start(t.Context(), id); err != nil {
		t.Fatal(err)
	}
	if _, err = r.Bootstrap(t.Context(), io.NopCloser(strings.NewReader("synthetic snapshot"))); err != nil {
		t.Fatal(err)
	}
	cancel()
	calls := len(f.calls)
	if r.executor.Execute(context.Background(), f.plan.authority.scope, Action{Operation: "read", Path: "file"}, io.Discard) != ErrRejected || len(f.calls) != calls {
		t.Fatal("fresh call revived cancelled workspace")
	}
}

func TestExecutorSuppressesSuccessWhenWorkspaceJobEndsDuringAction(t *testing.T) {
	t.Parallel()
	p, c, raw, vol, root, scope, action := executorFixture(t)
	lifetime, endJob := context.WithCancel(t.Context())
	defer endJob()
	p.workspace.Store(&workspaceReadiness{lifetime: lifetime, original: lifetime, containerID: c.ID})
	response := syntheticReadResult(t, "synthetic result")
	runner := runtimeMock(t, raw, vol, func(_ context.Context, _ []string, _ []byte, out io.Writer) error {
		endJob()
		_, err := out.Write(response)
		return err
	}, func(args []string, out io.Writer) error { return nil })
	e := containerExecutor(t, p, runner, root)
	ctx, cancel := context.WithDeadline(t.Context(), scope.Deadline)
	defer cancel()
	var output bytes.Buffer
	if e.Execute(ctx, scope, action, &output) == nil || output.Len() != 0 {
		t.Fatal("success escaped ended workspace lifetime")
	}
}
