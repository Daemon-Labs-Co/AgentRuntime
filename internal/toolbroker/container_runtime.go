package toolbroker

import (
	"context"
	"strings"
	"sync"
	"time"
)

// ToolContainerRuntime is the constrained tool half of the paired launcher.
// Only the trusted isolated worker may construct it after journalled admission.
// PrepareVolume allocates a fresh local workspace after a durable intent;
// Bootstrap initializes it after idle startup. This module never mounts host
// files or accepts Docker flags from a model.
// Pair lifecycle MUST bind both IDs and inspect aggregate policy before Start.
// A source fork CAN bypass those steps, BUT loses crash/containment guarantees.
// No production pair endpoint currently calls this module.
type ToolContainerRuntime struct {
	mu                 sync.Mutex
	lifetime           context.Context
	original           context.Context
	executor           *ContainerExecutor
	id                 string
	attempted, started bool
	verified           bool
	running            bool
	bootstrapAttempted bool
	volumeAttempted    bool
	volumePrepared     bool
}

func NewToolContainerRuntime(lifetime context.Context, plan *ToolContainerPlan, runner DockerRunner, dockerRoot string) (*ToolContainerRuntime, error) {
	if lifetime == nil || lifetime.Err() != nil {
		return nil, ErrRejected
	}
	executor, err := NewContainerExecutor(plan, runner, dockerRoot)
	if err != nil {
		return nil, err
	}
	if _, err = plan.CreateArgs(time.Now()); err != nil {
		return nil, err
	}
	return &ToolContainerRuntime{lifetime: lifetime, original: lifetime, executor: executor}, nil
}

func (r *ToolContainerRuntime) context(ctx context.Context) (context.Context, func(), error) {
	if ctx == nil || ctx.Err() != nil || r.lifetime.Err() != nil || r.original.Err() != nil {
		return nil, nil, ErrRejected
	}
	child, cancel := r.executor.plan.authority.executionContext(ctx)
	stop := context.AfterFunc(r.lifetime, cancel)
	if r.lifetime.Err() != nil || r.original.Err() != nil || child.Err() != nil {
		stop()
		cancel()
		return nil, nil, ErrRejected
	}
	return child, func() { stop(); cancel() }, nil
}

// Create issues only Docker create, verifies the returned immutable ID and the
// full stopped-container/volume policy, and retains uncertainty on any failure.
// The caller owns the durable creation intent before invoking this method.
func (r *ToolContainerRuntime) Create(ctx context.Context) (string, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.attempted || !r.volumePrepared {
		return "", ErrRejected
	}
	child, cancel, err := r.context(ctx)
	if err != nil {
		return "", err
	}
	defer cancel()
	r.attempted = true
	p := r.executor.plan
	// Never adopt an existing named container, even if its labels match.
	observed, err := r.executor.capture(child, []string{"ps", "-a", "--no-trunc", "--filter", "name=^/" + p.ContainerName() + "$", "--format", "{{.ID}}"}, 8192)
	if err != nil || strings.TrimSpace(string(observed)) != "" {
		return "", ErrRejected
	}
	// Require the separately prepared volume to exist and match its complete
	// local-only policy before create: Docker must not implicitly create one.
	volume, err := r.executor.capture(child, []string{"volume", "inspect", "--format", "{{json .}}", p.WorkspaceVolume()}, MaxInspectionBytes)
	var v toolVolumeInspection
	if err != nil || decodeInspection(volume, &v) != nil || p.verifyVolume(v, r.executor.dockerRoot) != nil {
		return "", ErrRejected
	}
	args, err := p.CreateArgs(time.Now())
	if err != nil {
		return "", err
	}
	raw, err := r.executor.capture(child, args, 8192)
	id := strings.TrimSpace(string(raw))
	if err != nil || !digest(id, 32) {
		return "", ErrExecution
	}
	r.id = id // Never forget an observed identity after inspection failure.
	if err = r.verify(child, id, false); err != nil {
		return "", err
	}
	r.verified = true
	return id, nil
}

func (r *ToolContainerRuntime) inspection(ctx context.Context, id string) ([]byte, []byte, error) {
	raw, err := r.executor.capture(ctx, []string{"inspect", "--type", "container", "--format", "{{json .}}", id}, MaxInspectionBytes)
	if err != nil {
		return nil, nil, ErrRejected
	}
	volume, err := r.executor.capture(ctx, []string{"volume", "inspect", "--format", "{{json .}}", r.executor.plan.WorkspaceVolume()}, MaxInspectionBytes)
	if err != nil {
		return nil, nil, ErrRejected
	}
	var c toolInspection
	if decodeInspection(raw, &c) != nil || c.ID != id {
		return nil, nil, ErrRejected
	}
	return raw, volume, nil
}
func (r *ToolContainerRuntime) verify(ctx context.Context, id string, running bool) error {
	raw, volume, err := r.inspection(ctx, id)
	if err != nil {
		return err
	}
	return r.executor.plan.verifyInspection(raw, volume, r.executor.dockerRoot, time.Now(), running)
}

// Inspect supplies fresh ID-bound metadata for the supervisor's aggregate gate.
func (r *ToolContainerRuntime) Inspect(ctx context.Context, id string) ([]byte, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	child, cancel, err := r.context(ctx)
	if err != nil {
		return nil, err
	}
	defer cancel()
	if r.id == "" || id != r.id {
		return nil, ErrRejected
	}
	raw, _, err := r.inspection(child, id)
	return raw, err
}

// Start rechecks full stopped policy before starting by immutable ID, then checks
// running policy. It never retries an uncertain start and never claims pair proof.
func (r *ToolContainerRuntime) Start(ctx context.Context, id string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	child, cancel, err := r.context(ctx)
	if err != nil {
		return err
	}
	defer cancel()
	if r.id == "" || id != r.id || !r.verified || r.started {
		return ErrRejected
	}
	r.started = true
	if err = r.verify(child, id, false); err != nil {
		return err
	}
	raw, err := r.executor.capture(child, []string{"start", id}, 8192)
	if err != nil || strings.TrimSpace(string(raw)) != id {
		return ErrExecution
	}
	if err = r.verify(child, id, true); err != nil {
		return err
	}
	r.running = true
	return nil
}
