package toolbroker

import (
	"context"
	"strings"
)

// StopContainer removes only an immutable container identity and requires a
// successful exact-ID absence observation. verify, when supplied, validates
// ownership before removal. This proves neither pair shutdown nor creator lease
// release; callers retain their stronger reconciliation checks. The trusted
// runner must enforce the approved local rootless daemon on every invocation.
// A source fork CAN replace that adapter, BUT invalidates containment proof.
func StopContainer(ctx context.Context, runner DockerRunner, id string, verify func(context.Context, string) error) error {
	if ctx == nil || ctx.Err() != nil || runner == nil || !digest(id, 32) {
		return ErrShutdownUnconfirmed
	}
	capture := func(args []string) (string, error) {
		child, cancel := context.WithCancel(ctx)
		defer cancel()
		out := &boundedOutput{cancel: cancel, maxBytes: 8192}
		err := runner.Run(child, args, nil, out)
		raw, overflow := out.snapshot()
		if err != nil || child.Err() != nil || overflow {
			return "", ErrShutdownUnconfirmed
		}
		return strings.TrimSpace(string(raw)), nil
	}
	absent := func() (bool, error) {
		raw, err := capture([]string{"ps", "-a", "--no-trunc", "--filter", "id=" + id, "--format", "{{.ID}}"})
		if err != nil || raw != "" && raw != id {
			return false, ErrShutdownUnconfirmed
		}
		return raw == "", nil
	}
	gone, err := absent()
	if err != nil {
		return ErrShutdownUnconfirmed
	}
	if gone {
		return nil
	}
	if verify != nil && verify(ctx, id) != nil {
		return ErrShutdownUnconfirmed
	}
	if _, err = capture([]string{"rm", "--force", id}); err != nil {
		return ErrShutdownUnconfirmed
	}
	gone, err = absent()
	if err != nil || !gone {
		return ErrShutdownUnconfirmed
	}
	return nil
}
