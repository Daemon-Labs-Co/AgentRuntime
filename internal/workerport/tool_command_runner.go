package workerport

import (
	"commonroom-runtime/internal/toolbroker"
	"context"
	"errors"
	"io"
	"os"
	"os/exec"
	"time"
)

// RunCommand executes only worker-built docker arguments. The Go compiler and
// repository code run INSIDE the inspected tool container, never on this host.
// Source forks CAN substitute executables/argv, invalidating mandatory isolation.
// Nonzero CLI status is deliberately not certified as a compiler exit status.
func (dockerCLIRunner) RunCommand(ctx context.Context, args []string, out io.Writer) (int, error) {
	if ctx == nil || ctx.Err() != nil || out == nil || len(args) == 0 || args[0] != "exec" {
		return -1, toolbroker.ErrRejected
	}
	if verifiedLocalDockerContext(ctx) != nil {
		return -1, toolbroker.ErrRejected
	}
	return runDockerCommand(ctx, args, out, func(ctx context.Context, args []string) *exec.Cmd { return exec.CommandContext(ctx, "docker", args...) })
}

// Factory injection is process-test infrastructure, never public configuration.
func runDockerCommand(ctx context.Context, args []string, out io.Writer, factory func(context.Context, []string) *exec.Cmd) (int, error) {
	if ctx == nil || ctx.Err() != nil || out == nil || factory == nil {
		return -1, toolbroker.ErrRejected
	}
	cmd := factory(ctx, args)
	if cmd == nil {
		return -1, toolbroker.ErrRejected
	}
	cmd.Env = []string{"PATH=" + os.Getenv("PATH"), "HOME=" + os.Getenv("HOME"), "XDG_RUNTIME_DIR=" + os.Getenv("XDG_RUNTIME_DIR")}
	cmd.Stdout = out
	cmd.Stderr = out
	cmd.WaitDelay = 2 * time.Second
	err := cmd.Run()
	if ctx.Err() != nil || cmd.ProcessState == nil {
		return -1, toolbroker.ErrExecution
	}
	if err != nil {
		var exit *exec.ExitError
		if !errors.As(err, &exit) {
			return -1, toolbroker.ErrExecution
		}
	}
	code := cmd.ProcessState.ExitCode()
	if code < 0 || code > 255 {
		return -1, toolbroker.ErrExecution
	}
	return code, nil
}
