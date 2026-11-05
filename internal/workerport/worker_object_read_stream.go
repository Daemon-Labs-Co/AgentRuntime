package workerport

import (
	"commonroom-runtime/internal/toolbroker"
	"context"
	"os/exec"
)

// StartObjectRead starts only a separately durably bound, independently inspected
// immutable helper ID. The caller MUST use ObjectReadRuntime with actual creator
// ownership, physical quotas and current export authority. Rootless local daemon
// selection is revalidated per invocation. No shell, model executable, host/SSH
// fallback, socket exposure or optional isolation bypass exists. Source forks can
// replace this adapter and invalidate the mandatory execution boundary.
func (dockerCLIRunner) StartObjectRead(ctx context.Context, id string) (toolbroker.ObjectReadProcess, error) {
	if ctx == nil || ctx.Err() != nil || !repositoryDigestPattern.MatchString(id) {
		return nil, toolbroker.ErrRejected
	}
	if verifiedLocalDockerContext(ctx) != nil {
		return nil, toolbroker.ErrRejected
	}
	// Both fixed helpers use exactly the same sanitized immutable-ID start policy.
	return openObjectReadCommand(ctx, func(child context.Context) *exec.Cmd { return captureStartCommand(child, id) })
}

// Factory injection is private to synthetic process tests; no request can select
// a command. The shared process owner preserves final stdout through Wait and
// sanitizes stderr/errors, while Close interrupts I/O and joins the process.
func openObjectReadCommand(ctx context.Context, factory func(context.Context) *exec.Cmd) (toolbroker.ObjectReadProcess, error) {
	return openCaptureCommand(ctx, factory)
}
