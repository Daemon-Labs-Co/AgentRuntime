package workerport

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"os/exec"
	"time"
)

type dockerCLIRunner struct{}

// Run verifies the same local-only, resource-enforcing Docker context required
// of the main agent container path (verifiedLocalDockerContext, isolation.go)
// before every invocation — this runner is called several times per tool
// action (inspect, inspect, exec, and on failure ps/rm/ps), and each one is a
// point where a tampered or remote Docker context must still be caught, not
// just the first. Checks are never cached as permission for a later call.
func (dockerCLIRunner) Run(ctx context.Context, args []string, stdin []byte, out io.Writer) error {
	var input io.Reader
	if len(stdin) > 0 {
		input = bytes.NewReader(stdin)
	}
	return (dockerCLIRunner{}).RunInput(ctx, args, input, out)
}

// RunInput streams only worker-approved snapshot input; it applies the same
// per-invocation rootless checks and fixed environment as bounded tool actions.
func (dockerCLIRunner) RunInput(ctx context.Context, args []string, input io.Reader, out io.Writer) error {
	if ctx == nil || ctx.Err() != nil || out == nil || len(args) == 0 {
		return errors.New("docker runner requires a live context, arguments and an output sink")
	}
	if err := verifiedLocalDockerContext(ctx); err != nil {
		return err
	}
	cmd := exec.CommandContext(ctx, "docker", args...)
	// Only Docker selection and minimum platform variables, never provider keys
	// or ambient environment — same allowlist as isolatedRunArgs' caller.
	cmd.Env = []string{"PATH=" + os.Getenv("PATH"), "HOME=" + os.Getenv("HOME"), "XDG_RUNTIME_DIR=" + os.Getenv("XDG_RUNTIME_DIR")}
	cmd.WaitDelay = 2 * time.Second
	cmd.Stdin = input
	// out is already bounded by the broker's own boundedOutput writer
	// (internal/toolbroker); write straight through rather than buffering
	// again here.
	cmd.Stdout = out
	var stderr limitedAgentOutput
	cmd.Stderr = &stderr
	return cmd.Run()
}
