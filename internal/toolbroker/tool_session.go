package toolbroker

import (
	"context"
	"io"
	"sync"
	"time"
)

// ToolSession assembles one authority, plan, runtime and audited dispatcher.
// Runtime bootstrap opens readiness on the exact plan used by Dispatcher;
// callers cannot accidentally bootstrap one plan and execute through another.
// These are trusted worker objects, never serialized as model configuration.
// Close revokes access and closes audit I/O, NOT proof of container/volume stop.
// The paired supervisor must retain ownership through all calls and fence after
// failure. A source fork CAN substitute an unaudited runner/link, BUT invalidates
// isolation and durable audit guarantees. No host fallback is provided.
type ToolSession struct {
	audit      *AuditClient
	Runtime    *ToolContainerRuntime
	Dispatcher *Dispatcher
	close      func()
	scope      Scope
	commands   bool
}

// Scope returns immutable nonsecret registration metadata, never the capability.
func (s *ToolSession) Scope() Scope {
	if s == nil {
		return Scope{}
	}
	return s.scope
}

func (s *ToolSession) Close() {
	if s != nil && s.close != nil {
		s.close()
	}
}

// NewToolSession requires a worker-authenticated private audit channel separated
// from engine stdout, a registered immutable scope and an approved local runner.
// It does not authenticate peers or grant controller/owner authority. The caller
// supplies operator-reviewed image/root policy, never model-provided Docker data.
// After accepting basic inputs, construction owns/closes the channel on failure.
// The raw capability is returned once for private engine delivery, never history.
func NewToolSession(ctx context.Context, scope Scope, allowed []string, image, dockerRoot string, now time.Time, channel io.ReadWriteCloser, runner DockerRunner) (*ToolSession, string, error) {
	return NewToolSessionWithCommands(ctx, scope, allowed, image, dockerRoot, now, channel, runner, false)
}

// NewToolSessionWithCommands requires both the worker feature setting and a
// separately admitted command grant. Enabled is trusted policy, never model data.
func NewToolSessionWithCommands(ctx context.Context, scope Scope, allowed []string, image, dockerRoot string, now time.Time, channel io.ReadWriteCloser, runner DockerRunner, enabled bool) (*ToolSession, string, error) {
	commandGrant := false
	for _, op := range allowed {
		if op == "command" {
			commandGrant = true
		}
	}
	if commandGrant && !enabled {
		return nil, "", ErrRejected
	}
	if ctx == nil || ctx.Err() != nil || channel == nil || runner == nil {
		return nil, "", ErrRejected
	}
	scope.Deadline = scope.Deadline.UTC().Round(0)
	lifetime, cancel := context.WithDeadline(ctx, scope.Deadline)
	var authority *Authority
	failed := true
	defer func() {
		if failed {
			cancel()
			if authority != nil {
				authority.Revoke()
			}
			_ = channel.Close()
		}
	}()
	authority, token, err := New(scope, allowed, now)
	if err != nil {
		return nil, "", err
	}
	plan, err := NewToolContainerPlanWithCommands(authority, image, now, enabled)
	if err != nil {
		return nil, "", err
	}
	runtime, err := NewToolContainerRuntime(lifetime, plan, runner, dockerRoot)
	if err != nil {
		return nil, "", err
	}
	// Retain the original caller context as well as the deadline child: parent
	// Done closes before cancellation necessarily reaches all derived contexts.
	runtime.original = ctx
	audit, err := NewAuditClient(channel, scope)
	if err != nil {
		return nil, "", err
	}
	dispatcher, err := NewDispatcher(authority, audit, runtime.executor)
	if err != nil {
		return nil, "", err
	}
	var once sync.Once
	closeLink := func() { once.Do(func() { authority.Revoke(); _ = channel.Close() }) }
	stop := context.AfterFunc(lifetime, closeLink)
	cleanup := func() { stop(); closeLink(); cancel() }
	if lifetime.Err() != nil {
		cleanup()
		return nil, "", ErrRejected
	}
	failed = false
	return &ToolSession{audit: audit, Runtime: runtime, Dispatcher: dispatcher, close: cleanup, scope: scope, commands: enabled && commandGrant}, token, nil
}

// WorkspaceIntent is a lifetime-bound request for the supervisor to journal.
// It creates no Docker object and never becomes permission to skip that journal.
func (r *ToolContainerRuntime) WorkspaceIntent(ctx context.Context) (WorkspaceVolumeIdentity, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	child, cancel, err := r.context(ctx)
	if err != nil {
		return WorkspaceVolumeIdentity{}, err
	}
	defer cancel()
	if child.Err() != nil || r.volumeAttempted || r.attempted {
		return WorkspaceVolumeIdentity{}, ErrRejected
	}
	return r.executor.plan.WorkspaceIntent(time.Now())
}

// VerifyCreated repeats full stopped policy for the supervisor's durable bind.
func (r *ToolContainerRuntime) VerifyCreated(ctx context.Context, id string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	child, cancel, err := r.context(ctx)
	if err != nil {
		return err
	}
	defer cancel()
	if !r.verified || r.id != id || r.started {
		return ErrRejected
	}
	return r.verify(child, id, false)
}

// CommandsEnabled reports only an explicitly configured, separately granted capability.
func (s *ToolSession) CommandsEnabled() bool { return s != nil && s.commands }
