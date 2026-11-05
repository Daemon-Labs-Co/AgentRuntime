package toolbroker

import "context"

// executionContext binds cooperative work to both the original job deadline and
// revocation. Parent cancellation/earlier deadlines remain effective. Callers
// must cancel on return; this is not proof of descendant/container termination.
func (a *Authority) executionContext(parent context.Context) (context.Context, context.CancelFunc) {
	ctx, cancel := context.WithDeadline(parent, a.scope.Deadline)
	select {
	case <-a.done:
		cancel()
	default:
	}
	go func() {
		select {
		case <-a.done:
			cancel()
		case <-ctx.Done():
		}
	}()
	return ctx, cancel
}
