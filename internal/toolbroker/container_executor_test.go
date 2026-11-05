package toolbroker

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"slices"
	"strings"
	"testing"
	"time"
)

type mockDocker func(context.Context, []string, []byte, io.Writer) error

func (m mockDocker) Run(c context.Context, a []string, input []byte, w io.Writer) error {
	return m(c, a, input, w)
}
func executorFixture(t *testing.T) (*ToolContainerPlan, toolInspection, []byte, []byte, string, Scope, Action) {
	t.Helper()
	_, c, v, root, _ := inspectionFixture(t)
	a, r := liveFixture(t)
	p, err := NewToolContainerPlan(a, c.Config.Image, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	p.workspace.Store(&workspaceReadiness{lifetime: context.Background(), original: context.Background(), containerID: c.ID}) // Synthetic initialized workspace.
	return p, c, inspectJSON(t, c), inspectJSON(t, v), root, a.scope, Action{Operation: "read", Path: r.Path}
}
func runtimeMock(t *testing.T, c, volume []byte, exec func(context.Context, []string, []byte, io.Writer) error, cleanup func([]string, io.Writer) error) DockerRunner {
	t.Helper()
	return mockDocker(func(ctx context.Context, args []string, input []byte, out io.Writer) error {
		if args[0] == "inspect" {
			if input != nil {
				t.Error("inspection received tool payload")
			}
			_, err := out.Write(c)
			return err
		}
		if args[0] == "volume" {
			if input != nil {
				t.Error("volume inspection received tool payload")
			}
			_, err := out.Write(volume)
			return err
		}
		if args[0] == "exec" {
			return exec(ctx, args, input, out)
		}
		if cleanup != nil {
			return cleanup(args, out)
		}
		t.Errorf("unexpected Docker operation %s", args[0])
		return errors.New("unexpected operation")
	})
}
func containerExecutor(t *testing.T, p *ToolContainerPlan, r DockerRunner, root string) *ContainerExecutor {
	t.Helper()
	e, err := NewContainerExecutor(p, r, root)
	if err != nil {
		t.Fatal(err)
	}
	return e
}

func TestContainerExecutorFixedHelperAndImmutableIdentity(t *testing.T) {
	t.Parallel()
	p, c, raw, vol, root, scope, action := executorFixture(t)
	called := 0
	response := syntheticReadResult(t, "synthetic result")
	runner := runtimeMock(t, raw, vol, func(ctx context.Context, args []string, input []byte, out io.Writer) error {
		called++
		expected := []string{"exec", "-i", "--user", "1000:1000", "--workdir", "/workspace/repository", c.ID, "/usr/local/bin/node", "/opt/commonroom/tool-call.cjs"}
		if !slices.Equal(args, expected) {
			t.Fatal("exec arguments escaped fixed helper/ID")
		}
		var got Action
		if json.Unmarshal(input, &got) != nil || got.Operation != action.Operation || got.Path != action.Path || bytes.Contains(input, []byte("Capability")) {
			t.Fatal("unsafe helper payload")
		}
		_, err := out.Write(response)
		return err
	}, nil)
	e := containerExecutor(t, p, runner, root)
	ctx, cancel := context.WithDeadline(context.Background(), scope.Deadline)
	defer cancel()
	var output bytes.Buffer
	if err := e.Execute(ctx, scope, action, &output); err != nil || !bytes.Equal(output.Bytes(), response) || called != 1 {
		t.Fatal("valid fixed execution failed")
	}
}
func TestContainerExecutorRejectsScopeInputAndContext(t *testing.T) {
	t.Parallel()
	p, _, _, _, root, scope, action := executorFixture(t)
	runner := mockDocker(func(context.Context, []string, []byte, io.Writer) error {
		t.Error("Docker reached for refused input")
		return nil
	})
	e := containerExecutor(t, p, runner, root)
	ctx, cancel := context.WithDeadline(context.Background(), scope.Deadline)
	defer cancel()
	var out bytes.Buffer
	changed := scope
	changed.Room = "other"
	if e.Execute(ctx, changed, action, &out) != ErrRejected {
		t.Fatal("cross-room call accepted")
	}
	bad := action
	bad.Path = "../auth"
	if e.Execute(ctx, scope, bad, &out) != ErrRejected {
		t.Fatal("traversal accepted")
	}
	if e.Execute(context.Background(), scope, action, &out) != ErrRejected {
		t.Fatal("unbounded context accepted")
	}
	later, stop := context.WithDeadline(context.Background(), scope.Deadline.Add(time.Second))
	defer stop()
	if e.Execute(later, scope, action, &out) != ErrRejected {
		t.Fatal("extended deadline accepted")
	}
	if e.Execute(ctx, scope, action, nil) != ErrRejected {
		t.Fatal("missing writer accepted")
	}
}
func TestContainerExecutorRefusesUnsafeOrOversizedInspection(t *testing.T) {
	t.Parallel()
	for _, kind := range []string{"mount", "oversized", "unavailable"} {
		p, c, raw, vol, root, scope, action := executorFixture(t)
		if kind == "mount" {
			c.Mounts[0].Type = "bind"
			raw = inspectJSON(t, c)
		} else if kind == "oversized" {
			raw = []byte(strings.Repeat("x", MaxInspectionBytes+1))
		}
		calls := 0
		runner := runtimeMock(t, raw, vol, func(context.Context, []string, []byte, io.Writer) error { calls++; return nil }, nil)
		if kind == "unavailable" {
			runner = mockDocker(func(context.Context, []string, []byte, io.Writer) error { return errors.New("synthetic-private-error") })
		}
		e := containerExecutor(t, p, runner, root)
		ctx, cancel := context.WithDeadline(context.Background(), scope.Deadline)
		var out bytes.Buffer
		if err := e.Execute(ctx, scope, action, &out); err != ErrRejected || calls != 0 || out.Len() != 0 {
			t.Fatal("unsafe inspection reached execution")
		}
		cancel()
		if _, err := p.RunArgs(time.Now()); err != ErrRejected {
			t.Fatal("inspection failure did not fence job")
		}
	}
}
func TestContainerExecutorFailureRequiresAbsenceProof(t *testing.T) {
	t.Parallel()
	for _, kind := range []string{"confirmed", "still-present", "daemon-error", "unexpected-id", "remove-error", "already-absent", "overflow"} {
		p, c, raw, vol, root, scope, action := executorFixture(t)
		ps := 0
		removed := 0
		runner := runtimeMock(t, raw, vol, func(ctx context.Context, _ []string, _ []byte, out io.Writer) error {
			if kind == "overflow" {
				io.WriteString(out, strings.Repeat("x", MaxOutputBytes+1))
				return nil
			}
			return errors.New("synthetic internal failure")
		}, func(args []string, out io.Writer) error {
			if args[0] == "ps" {
				ps++
				if !slices.Contains(args, "id="+c.ID) || !slices.Contains(args, "--no-trunc") {
					t.Error("inventory not exact immutable ID")
				}
				if kind == "daemon-error" {
					return errors.New("unavailable")
				}
				if kind == "unexpected-id" {
					io.WriteString(out, strings.Repeat("e", 64))
					return nil
				}
				if kind == "already-absent" || ps > 1 && kind != "still-present" {
					return nil
				}
				io.WriteString(out, c.ID)
				return nil
			}
			if args[0] == "rm" {
				removed++
				if !slices.Equal(args, []string{"rm", "--force", c.ID}) {
					t.Error("cleanup targeted a name/other identity")
				}
				if kind == "remove-error" {
					return errors.New("failed removal")
				}
				return nil
			}
			t.Error("unexpected cleanup")
			return errors.New("unexpected")
		})
		e := containerExecutor(t, p, runner, root)
		ctx, cancel := context.WithDeadline(context.Background(), scope.Deadline)
		var output bytes.Buffer
		err := e.Execute(ctx, scope, action, &output)
		cancel()
		expected := ErrShutdownUnconfirmed
		if kind == "confirmed" || kind == "already-absent" {
			expected = ErrExecution
		}
		if kind == "overflow" {
			expected = ErrOutputLimit
		}
		if err != expected || output.Len() != 0 {
			t.Fatalf("%s: wrong failure/partial output: %v", kind, err)
		}
		if kind == "already-absent" && removed != 0 || kind == "unexpected-id" && removed != 0 {
			t.Fatal("cleanup broadened scope")
		}
	}
}
func TestContainerExecutorCanceledWorkUsesIndependentCleanup(t *testing.T) {
	t.Parallel()
	p, c, raw, vol, root, scope, action := executorFixture(t)
	ctx, cancel := context.WithDeadline(context.Background(), scope.Deadline)
	defer cancel()
	ps := 0
	runner := runtimeMock(t, raw, vol, func(runCtx context.Context, _ []string, _ []byte, _ io.Writer) error {
		cancel()
		<-runCtx.Done()
		return runCtx.Err()
	}, func(args []string, out io.Writer) error {
		if args[0] == "ps" {
			ps++
			if ps == 1 {
				io.WriteString(out, c.ID)
			}
			return nil
		}
		if args[0] == "rm" {
			return nil
		}
		t.Fatal("unknown cleanup")
		return nil
	})
	checked := mockDocker(func(runCtx context.Context, args []string, input []byte, out io.Writer) error {
		if args[0] == "ps" || args[0] == "rm" {
			if runCtx.Err() != nil {
				t.Error("cleanup inherited canceled execution")
			}
			deadline, ok := runCtx.Deadline()
			if !ok || time.Until(deadline) > 10*time.Second {
				t.Error("cleanup unbounded")
			}
		}
		return runner.Run(runCtx, args, input, out)
	})
	e := containerExecutor(t, p, checked, root)
	var output bytes.Buffer
	if e.Execute(ctx, scope, action, &output) != ErrExecution || ps != 2 {
		t.Fatal("canceled work not confirmed absent")
	}
}

func TestContainerExecutorRevocationCancelsRunner(t *testing.T) {
	t.Parallel()
	p, c, raw, vol, root, scope, action := executorFixture(t)
	started := make(chan struct{})
	result := make(chan error, 1)
	ps := 0
	runner := runtimeMock(t, raw, vol, func(ctx context.Context, _ []string, _ []byte, _ io.Writer) error {
		close(started)
		<-ctx.Done()
		return ctx.Err()
	}, func(args []string, out io.Writer) error {
		if args[0] == "ps" {
			ps++
			if ps == 1 {
				io.WriteString(out, c.ID)
			}
		}
		return nil
	})
	e := containerExecutor(t, p, runner, root)
	ctx, cancel := context.WithDeadline(context.Background(), scope.Deadline)
	defer cancel()
	go func() { var out bytes.Buffer; result <- e.Execute(ctx, scope, action, &out) }()
	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("runner not started")
	}
	p.authority.Revoke()
	select {
	case err := <-result:
		if err != ErrExecution || ps != 2 {
			t.Fatal("revoked work did not verify cleanup")
		}
	case <-time.After(time.Second):
		t.Fatal("revocation not propagated")
	}
}
func TestDispatcherUsesContainerExecutorAfterAudit(t *testing.T) {
	t.Parallel()
	p, c, raw, vol, root, scope, _ := executorFixture(t)
	stage := 0
	response := syntheticReadResult(t, "ok")
	runner := runtimeMock(t, raw, vol, func(_ context.Context, _ []string, _ []byte, out io.Writer) error {
		if stage != 1 {
			t.Error("tool execution before audit intent")
		}
		stage = 2
		_, err := out.Write(response)
		return err
	}, nil)
	audit := mockAudit{intent: func(context.Context, Intent) error { stage = 1; return nil }, outcome: func(_ context.Context, _ Intent, o Outcome) error {
		if stage != 2 || o.Status != "succeeded" {
			t.Error("outcome before execution")
		}
		stage = 3
		return nil
	}}
	// Minting the token and this authority is trusted setup, not imported history.
	a, token, err := New(scope, []string{"read"}, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	p, err = NewToolContainerPlan(a, p.image, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	p.workspace.Store(&workspaceReadiness{lifetime: context.Background(), original: context.Background(), containerID: c.ID}) // Synthetic completed bootstrap.
	e := containerExecutor(t, p, runner, root)
	d := dispatcher(t, a, audit, e)
	r := Request{Scope: scope, Capability: token, CallID: "call", Operation: "read", Path: "file.go"}
	output, err := d.Dispatch(context.Background(), r)
	if err != nil || !bytes.Equal(output, response) || stage != 3 {
		t.Fatal("audited container adapter flow failed")
	}
}

func TestExecutorPinsOriginalBootstrapIdentity(t *testing.T) {
	t.Parallel()
	p, c, _, vol, root, scope, action := executorFixture(t)
	original := c.ID
	c.ID = strings.Repeat("e", 64) // Identical policy, different container.
	raw := inspectJSON(t, c)
	runner := mockDocker(func(ctx context.Context, args []string, _ []byte, out io.Writer) error {
		if args[0] == "inspect" {
			if args[len(args)-1] != original {
				t.Fatal("inspection used a mutable/replacement identity")
			}
			_, err := out.Write(raw)
			return err
		}
		if args[0] == "volume" {
			_, err := out.Write(vol)
			return err
		}
		t.Fatal("replacement reached execution or cleanup")
		return ErrRejected
	})
	e := containerExecutor(t, p, runner, root)
	ctx, cancel := context.WithDeadline(t.Context(), scope.Deadline)
	defer cancel()
	if e.Execute(ctx, scope, action, io.Discard) != ErrRejected {
		t.Fatal("replacement container accepted")
	}
}
