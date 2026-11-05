package toolbroker

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"time"

	"commonroom-runtime/internal/toolcommand"
)

// DockerCommandRunner captures combined command stdout/stderr and the observed
// Docker CLI exit status. Zero indicates successful exec completion; nonzero may
// be a command failure OR a client/daemon error and MUST remain unconfirmed.
// It runs only approved rootless Docker, never a host compiler/shell/provider.
// No model may supply this adapter. Source replacement violates isolation.
type DockerCommandRunner interface {
	DockerRunner
	RunCommand(context.Context, []string, io.Writer) (int, error)
}

type isolatedCommandAdapter struct {
	runner DockerCommandRunner
	id     string
}

func (a isolatedCommandAdapter) Run(ctx context.Context, spec toolcommand.Spec, out io.Writer) (int, error) {
	// A fresh tool volume has no previous executable commands. Cache setup happens
	// before the first untrusted process and selects only these fixed directories.
	prepare := []string{"exec", "--user", "1000:1000", "--workdir", "/workspace", a.id, "/bin/mkdir", "-p", "/workspace/.commonroom-command/cache", "/workspace/.commonroom-command/tmp", "/workspace/.commonroom-command/modules"}
	if err := a.runner.Run(ctx, prepare, nil, io.Discard); err != nil {
		return -1, ErrExecution
	}
	args := []string{"exec", "--user", "1000:1000", "--workdir", spec.Dir}
	for _, entry := range spec.Env {
		args = append(args, "--env", entry)
	}
	args = append(args, a.id, spec.Program)
	args = append(args, spec.Args...)
	return a.runner.RunCommand(ctx, args, out)
}

// executeCommand observes the receipt in trusted worker memory, not a process
// alongside untrusted tests. It always consumes the tool container: no result is
// released before verified exact-ID absence, including escaped/background child
// processes. The supervisor must still reconcile both roles and retain source.
func (e *ContainerExecutor) executeCommand(ctx context.Context, id string, action Action, out io.Writer) error {
	runner, ok := e.runner.(DockerCommandRunner)
	if !ok {
		return e.failed(id, false)
	}
	receipt, err := toolcommand.Run(ctx, action.Command, isolatedCommandAdapter{runner, id})
	if err != nil {
		return e.failed(id, errors.Is(err, toolcommand.ErrOutputLimit))
	}
	raw, err := json.Marshal(receipt)
	if err != nil || !validCommandReceipt(raw, action) {
		return e.failed(id, false)
	}
	cleanup, done := context.WithTimeout(context.Background(), 10*time.Second)
	stopErr := e.stopAndConfirm(cleanup, id)
	done()
	if stopErr != nil {
		e.plan.authority.Revoke()
		return ErrShutdownUnconfirmed
	}
	if ctx.Err() != nil {
		return ErrExecution
	}
	if _, err = e.plan.RunArgs(time.Now()); err != nil {
		return err
	}
	n, err := out.Write(raw)
	if err != nil || n != len(raw) {
		return e.failed(id, false)
	}
	return nil
}
