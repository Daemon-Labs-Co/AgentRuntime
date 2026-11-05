package toolbroker

import (
	"context"
	"errors"
	"io"
	"slices"
	"strings"
	"testing"
	"time"
)

type runtimeScenario struct {
	t               *testing.T
	plan            *ToolContainerPlan
	container       toolInspection
	volume          toolVolumeInspection
	mode            string
	calls           []string
	creates, starts int
	volumeExists    bool
	volumeCreates   int
}

func (f *runtimeScenario) Run(ctx context.Context, args []string, in []byte, out io.Writer) error {
	f.calls = append(f.calls, args[0])
	if len(in) != 0 {
		f.t.Fatal("payload unexpectedly sent to Docker lifecycle")
	}
	var raw []byte
	switch args[0] {
	case "ps":
		if f.mode == "inventory-error" {
			return errors.New("synthetic unavailable")
		}
		if f.mode == "collision" {
			raw = []byte(f.container.ID)
		}
	case "volume":
		switch args[1] {
		case "ls":
			if f.mode == "volume-inventory-error" {
				return errors.New("synthetic unavailable")
			}
			if f.volumeExists {
				raw = []byte(f.volume.Name)
			}
		case "create":
			f.volumeCreates++
			if f.mode == "volume-create-error" {
				return errors.New("unknown volume create")
			}
			f.volumeExists = true
			f.volume.Labels = map[string]string{}
			for i, arg := range args {
				if arg == "--label" {
					key, value, _ := strings.Cut(args[i+1], "=")
					f.volume.Labels[key] = value
				}
			}
			f.volume.CreatedAt = time.Now().UTC().Format(time.RFC3339Nano)
			raw = []byte(f.volume.Name)
			if f.mode == "volume-create-reply" {
				raw = []byte("foreign")
			}
		case "inspect":
			if f.mode == "missing-volume" || !f.volumeExists {
				return errors.New("not found")
			}
			v := f.volume
			if f.mode == "volume-bind" {
				v.Options = map[string]string{"device": "/synthetic/host", "o": "bind"}
			}
			if f.mode == "volume-time" {
				v.CreatedAt = "invalid"
			}
			if f.mode == "volume-replaced" {
				v.CreatedAt = time.Now().Add(time.Hour).UTC().Format(time.RFC3339Nano)
			}
			if f.mode == "volume-nonce" {
				v.Labels = map[string]string{}
				for k, value := range f.volume.Labels {
					v.Labels[k] = value
				}
				v.Labels["commonroom.workspace.nonce"] = strings.Repeat("e", 32)
			}
			raw = inspectJSON(f.t, v)
		default:
			f.t.Fatalf("unexpected volume operation %v", args)
		}
	case "create":
		f.creates++
		expected, err := f.plan.CreateArgs(f.plan.authority.issued)
		if err != nil || !slices.Equal(args, expected) {
			f.t.Fatal("creation escaped fixed plan")
		}
		if f.mode == "create-error" {
			return errors.New("unknown create outcome")
		}
		if f.mode == "invalid-id" {
			raw = []byte("short-id")
		} else {
			raw = []byte(f.container.ID)
		}
	case "inspect":
		if args[len(args)-1] != f.container.ID {
			f.t.Fatal("inspection by mutable identity")
		}
		c := f.container
		if f.mode == "foreign-id" {
			c.ID = strings.Repeat("e", 64)
		}
		if f.mode == "unsafe-policy" {
			c.HostConfig.NetworkMode = "host"
		}
		if f.mode == "already-exited" {
			c.State.Status = "exited"
		}
		raw = inspectJSON(f.t, c)
	case "start":
		f.starts++
		if !slices.Equal(args, []string{"start", f.container.ID}) {
			f.t.Fatal("startup escaped immutable identity")
		}
		if f.mode == "start-error" {
			return errors.New("unknown start outcome")
		}
		if f.mode == "wrong-start-id" {
			raw = []byte(strings.Repeat("f", 64))
		} else {
			raw = []byte(f.container.ID)
		}
		if f.mode != "did-not-start" {
			f.container.State.Running = boolValue(true)
			f.container.State.Status = "running"
		}
	default:
		f.t.Fatalf("unexpected operation %v", args)
	}
	_, err := out.Write(raw)
	return err
}
func unpreparedRuntimeSetup(t *testing.T, mode string) (*ToolContainerRuntime, *runtimeScenario, context.CancelFunc) {
	t.Helper()
	p, c, v, root, _ := inspectionFixture(t)
	a, _ := liveFixture(t)
	p.authority = a
	c.State.Running = boolValue(false)
	c.State.Status = "created"
	fake := &runtimeScenario{t: t, plan: p, container: c, volume: v, mode: mode}
	ctx, cancel := context.WithCancel(t.Context())
	r, err := NewToolContainerRuntime(ctx, p, fake, root)
	if err != nil {
		cancel()
		t.Fatal(err)
	}
	return r, fake, cancel
}
func runtimeSetup(t *testing.T, mode string) (*ToolContainerRuntime, *runtimeScenario, context.CancelFunc) {
	t.Helper()
	r, f, cancel := unpreparedRuntimeSetup(t, "")
	intent, err := f.plan.WorkspaceIntent(time.Now())
	if err != nil {
		cancel()
		t.Fatal(err)
	}
	if _, err = r.PrepareVolume(t.Context(), intent); err != nil {
		cancel()
		t.Fatal(err)
	}
	f.mode = mode
	return r, f, cancel
}
func TestToolRuntimeCreateInspectStart(t *testing.T) {
	t.Parallel()
	r, f, cancel := runtimeSetup(t, "")
	defer cancel()
	id, err := r.Create(t.Context())
	if err != nil || id != f.container.ID || f.starts != 0 {
		t.Fatalf("create started process or lost identity: %v", err)
	}
	if _, err = r.Inspect(t.Context(), id); err != nil {
		t.Fatal(err)
	}
	if err = r.Start(t.Context(), id); err != nil || f.starts != 1 {
		t.Fatalf("start: %v", err)
	}
	before := len(f.calls)
	if _, err = r.Create(t.Context()); err == nil {
		t.Fatal("creation replayed")
	}
	if err = r.Start(t.Context(), id); err == nil || len(f.calls) != before {
		t.Fatal("startup replayed")
	}
}
func TestToolRuntimeRefusesUncertainCreation(t *testing.T) {
	t.Parallel()
	for _, mode := range []string{"inventory-error", "collision", "missing-volume", "volume-bind", "create-error", "invalid-id", "foreign-id", "unsafe-policy", "already-exited"} {
		t.Run(mode, func(t *testing.T) {
			t.Parallel()
			r, f, cancel := runtimeSetup(t, mode)
			defer cancel()
			if _, err := r.Create(t.Context()); err == nil {
				t.Fatal("unsafe creation accepted")
			}
			calls := len(f.calls)
			if _, err := r.Create(t.Context()); err == nil {
				t.Fatal("uncertain creation retried")
			}
			if err := r.Start(t.Context(), f.container.ID); err == nil || f.starts != 0 || len(f.calls) != calls {
				t.Fatal("failed creation acquired start authority")
			}
			if slices.Contains([]string{"missing-volume", "volume-bind", "inventory-error", "collision"}, mode) && f.creates != 0 {
				t.Fatal("create ran without verified prerequisite")
			}
		})
	}
}
func TestToolRuntimeRevalidatesBeforeStart(t *testing.T) {
	t.Parallel()
	for _, mode := range []string{"unsafe-policy", "volume-bind", "start-error", "wrong-start-id", "did-not-start"} {
		t.Run(mode, func(t *testing.T) {
			t.Parallel()
			r, f, cancel := runtimeSetup(t, "")
			defer cancel()
			id, err := r.Create(t.Context())
			if err != nil {
				t.Fatal(err)
			}
			f.mode = mode
			if err = r.Start(t.Context(), id); err == nil {
				t.Fatal("unsafe or uncertain start accepted")
			}
			calls := len(f.calls)
			if err = r.Start(t.Context(), id); err == nil || len(f.calls) != calls {
				t.Fatal("uncertain start retried")
			}
			if (mode == "unsafe-policy" || mode == "volume-bind") && f.starts != 0 {
				t.Fatal("started before policy checks")
			}
		})
	}
}
func TestToolRuntimeJobLifetimeAndIdentity(t *testing.T) {
	t.Parallel()
	for _, mode := range []string{"cancelled-job", "revoked", "foreign-id"} {
		t.Run(mode, func(t *testing.T) {
			t.Parallel()
			r, f, cancel := runtimeSetup(t, "")
			defer cancel()
			id, err := r.Create(t.Context())
			if err != nil {
				t.Fatal(err)
			}
			switch mode {
			case "cancelled-job":
				cancel()
			case "revoked":
				f.plan.authority.Revoke()
			case "foreign-id":
				id = strings.Repeat("e", 64)
			}
			calls := len(f.calls)
			if err = r.Start(context.Background(), id); err == nil || len(f.calls) != calls {
				t.Fatal("new call context revived authority or changed identity")
			}
		})
	}
}
func TestToolCreateArgsAndCreatedState(t *testing.T) {
	t.Parallel()
	p, c, v, root, now := inspectionFixture(t)
	args, err := p.CreateArgs(now)
	if err != nil || args[0] != "create" || slices.Contains(args, "-d") || slices.Contains(args, "--rm") {
		t.Fatal("create implicitly runs/removes")
	}
	if err = p.VerifyCreatedInspection(inspectJSON(t, c), inspectJSON(t, v), root, now); err == nil {
		t.Fatal("running container accepted as created")
	}
	c.State.Running = boolValue(false)
	c.State.Status = "created"
	if err = p.VerifyCreatedInspection(inspectJSON(t, c), inspectJSON(t, v), root, now); err != nil {
		t.Fatal(err)
	}
	if err = p.VerifyInspection(inspectJSON(t, c), inspectJSON(t, v), root, now); err == nil {
		t.Fatal("stopped container accepted as running")
	}
	p.authority.Revoke()
	if _, err = p.CreateArgs(now); err == nil {
		t.Fatal("revoked creation plan accepted")
	}
}

func TestToolRuntimeOriginalCancellationPrecedesDerivedPropagation(t *testing.T) {
	t.Parallel()
	plan, container, raw, volume, root, scope, action := executorFixture(t)
	calls := 0
	response := syntheticReadResult(t, "synthetic")
	base := runtimeMock(t, raw, volume, func(_ context.Context, _ []string, _ []byte, out io.Writer) error {
		_, err := out.Write(response)
		return err
	}, func([]string, io.Writer) error { return nil })
	runner := mockDocker(func(ctx context.Context, args []string, in []byte, out io.Writer) error {
		calls++
		return base.Run(ctx, args, in, out)
	})
	runtime, err := NewToolContainerRuntime(context.Background(), plan, runner, root)
	if err != nil {
		t.Fatal(err)
	}
	original, cancel := context.WithCancel(t.Context())
	runtime.original = original
	cancel()
	if _, err = runtime.WorkspaceIntent(context.Background()); err != ErrRejected {
		t.Fatal("uncancelled child revived workspace intent")
	}
	plan.workspace.Store(&workspaceReadiness{lifetime: context.Background(), original: original, containerID: container.ID})
	callCtx, done := context.WithDeadline(context.Background(), scope.Deadline)
	defer done()
	if err = runtime.executor.Execute(callCtx, scope, action, io.Discard); err != ErrRejected || calls != 0 {
		t.Fatal("uncancelled child revived tool dispatch", err, calls)
	}
}
