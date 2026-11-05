package workerport

import (
	"commonroom-runtime/internal/toolbroker"
	"context"
	"os"
	"os/exec"
)

// StartCapture starts only a durably bound, independently inspected capture ID.
// The caller MUST use CaptureRuntime, hold creator ownership and enforce physical
// quotas/current authority. Rootless daemon selection is checked per invocation.
// This is the fixed reviewed helper's private stream, never a provider/model pipe.
// No shell, host execution, alternative executable, SSH or automatic fallback is
// accepted. Source forks that replace this adapter invalidate isolation guarantees.
func (dockerCLIRunner) StartCapture(ctx context.Context, id string) (toolbroker.CaptureProcess, error) {
	if ctx == nil || ctx.Err() != nil || !repositoryDigestPattern.MatchString(id) {
		return nil, toolbroker.ErrRejected
	}
	if verifiedLocalDockerContext(ctx) != nil {
		return nil, toolbroker.ErrRejected
	}
	return openCaptureCommand(ctx, func(child context.Context) *exec.Cmd { return captureStartCommand(child, id) })
}

func captureStartCommand(ctx context.Context, id string) *exec.Cmd {
	cmd := exec.CommandContext(ctx, "docker", "start", "--attach", "--interactive", id)
	cmd.Env = []string{"PATH=" + os.Getenv("PATH"), "HOME=" + os.Getenv("HOME"), "XDG_RUNTIME_DIR=" + os.Getenv("XDG_RUNTIME_DIR")}
	return cmd
}

// Factory injection is private to synthetic process tests. Production always uses
// captureStartCommand after rootless validation; no request may supply a factory.
func openCaptureCommand(ctx context.Context, factory func(context.Context) *exec.Cmd) (toolbroker.CaptureProcess, error) {
	stream, err := openEngineCommand(ctx, factory)
	if err != nil {
		return nil, err
	}
	return stream.(*engineCommandStream), nil
}
