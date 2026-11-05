package toolbroker

import (
	"commonroom-runtime/internal/toolcommand"
	"context"
	"encoding/json"
	"errors"
	"io"
	"path"
	"time"
)

var ErrShutdownUnconfirmed = errors.New("tool container shutdown could not be confirmed")

// DockerRunner is a trusted isolated-worker dependency. It must invoke only the
// approved local rootless Docker daemon without shell parsing, inherited provider
// credentials or context overrides; stdout/stderr must honor writer errors and
// cancellation. Tests inject mocks. No real runner or automatic fallback exists.
// A source fork CAN supply a host/shell runner, BUT breaks the execution boundary.
type DockerRunner interface {
	Run(context.Context, []string, []byte, io.Writer) error
}

// ContainerExecutor adapts audited broker actions to a fixed container-side
// file helper or fixed terminal Go profile. It starts no container and requires a separately initialized tool pair.
// Use only through Dispatcher: this executor is not an audit/authentication API.
type ContainerExecutor struct {
	plan       *ToolContainerPlan
	runner     DockerRunner
	dockerRoot string
}

// NewContainerExecutor binds trusted policy, daemon data root and explicit runner.
// The future supervisor must verify the rootless daemon and never source these
// dependencies from a model/plugin request. There is no default Docker context.
func NewContainerExecutor(plan *ToolContainerPlan, runner DockerRunner, dockerRoot string) (*ContainerExecutor, error) {
	if plan == nil || runner == nil || len(dockerRoot) > 4096 || !path.IsAbs(dockerRoot) || path.Clean(dockerRoot) != dockerRoot || dockerRoot == "/" {
		return nil, ErrRejected
	}
	return &ContainerExecutor{plan, runner, dockerRoot}, nil
}

// Execute verifies reported runtime/volume policy before invoking the fixed Node
// helper via immutable container ID. Action JSON contains no capability or Docker
// launch options. Failed/ambiguous work fences authority and requires tool-container
// absence proof; the future supervisor must additionally stop/verify the engine.
func (e *ContainerExecutor) Execute(ctx context.Context, scope Scope, action Action, out io.Writer) error {
	if ctx == nil || ctx.Err() != nil || out == nil || !e.plan.workspaceReady() {
		return ErrRejected
	}
	// A terminal command consumes the container; later helper calls are forbidden.
	if e.plan.commandUsed.Load() {
		return ErrRejected
	}
	command := action.Operation == "command"
	if command && (!e.plan.commandsEnabled || !toolcommand.Valid(action.Command)) {
		return ErrRejected
	}
	if !command && action.Operation != "read" && action.Operation != "write" {
		return ErrRejected
	}
	scope.Deadline = scope.Deadline.UTC().Round(0)
	deadline, ok := ctx.Deadline()
	if !ok || deadline.After(e.plan.authority.scope.Deadline) || !e.plan.authority.permitsAction(scope, action, time.Now()) {
		return ErrRejected
	}
	if command && !e.plan.commandUsed.CompareAndSwap(false, true) {
		return ErrRejected
	}
	action.Command = append([]string(nil), action.Command...)
	ctx, cancelAuthority := e.plan.authority.executionContext(ctx)
	defer cancelAuthority()
	ready := e.plan.workspace.Load()
	stop := context.AfterFunc(ready.lifetime, cancelAuthority)
	defer stop()
	if !ready.active() || ctx.Err() != nil {
		return ErrRejected
	}

	input, err := json.Marshal(action)
	if err != nil || len(input) > MaxRequestBytes {
		return ErrRejected
	}
	if _, err = e.plan.RunArgs(time.Now()); err != nil {
		return err
	}
	container, err := e.capture(ctx, []string{"inspect", "--type", "container", "--format", "{{json .}}", ready.containerID}, MaxInspectionBytes)
	if err != nil {
		e.plan.authority.Revoke()
		return ErrRejected
	}
	volume, err := e.capture(ctx, []string{"volume", "inspect", "--format", "{{json .}}", e.plan.WorkspaceVolume()}, MaxInspectionBytes)
	if err != nil || e.plan.VerifyInspection(container, volume, e.dockerRoot, time.Now()) != nil {
		e.plan.authority.Revoke()
		return ErrRejected
	}
	var inspected toolInspection
	if decodeInspection(container, &inspected) != nil || inspected.ID != ready.containerID {
		e.plan.authority.Revoke()
		return ErrRejected
	}
	// Inspection and dispatch stay pinned to the original bootstrap identity.
	id := inspected.ID
	if _, err = e.plan.RunArgs(time.Now()); err != nil {
		return err
	}
	if command {
		return e.executeCommand(ctx, id, action, out)
	}
	execCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	output := &boundedOutput{cancel: cancel}
	args := []string{"exec", "-i", "--user", "1000:1000", "--workdir", "/workspace/repository", id, "/usr/local/bin/node", "/opt/commonroom/tool-call.cjs"}
	if execCtx.Err() != nil || !ready.active() {
		return e.failed(id, false)
	}
	runErr := e.runner.Run(execCtx, args, input, output)
	raw, overflow := output.snapshot()
	if runErr != nil || execCtx.Err() != nil || !ready.active() || overflow {
		return e.failed(id, overflow)
	}
	if !validHelperResult(raw, action) {
		return e.failed(id, false)
	}
	if _, err = e.plan.RunArgs(time.Now()); err != nil {
		return e.failed(id, false)
	}
	if n, err := out.Write(raw); err != nil || n != len(raw) {
		return e.failed(id, false)
	}
	return nil
}

func (e *ContainerExecutor) capture(ctx context.Context, args []string, limit int) ([]byte, error) {
	child, cancel := context.WithCancel(ctx)
	defer cancel()
	output := &boundedOutput{cancel: cancel, maxBytes: limit}
	err := e.runner.Run(child, args, nil, output)
	raw, overflow := output.snapshot()
	if overflow {
		return nil, ErrOutputLimit
	}
	if err != nil || child.Err() != nil {
		return nil, ErrExecution
	}
	return raw, nil
}

// failed never retries the tool action. Cleanup gets a separate bounded context
// because shutdown must still be attempted after the execution deadline expires.
func (e *ContainerExecutor) failed(id string, overflow bool) error {
	e.plan.authority.Revoke()
	cleanup, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if e.stopAndConfirm(cleanup, id) != nil {
		return ErrShutdownUnconfirmed
	}
	if overflow {
		return ErrOutputLimit
	}
	return ErrExecution
}

func (e *ContainerExecutor) stopAndConfirm(ctx context.Context, id string) error {
	return StopContainer(ctx, e.runner, id, nil)
}
