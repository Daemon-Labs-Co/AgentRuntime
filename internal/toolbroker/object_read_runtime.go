package toolbroker

import (
	"commonroom-runtime/internal/objectcustody"
	"commonroom-runtime/internal/objectread"
	"context"
	"errors"
	"io"
	"strings"
	"sync/atomic"
	"time"
)

// ObjectReadLifecycleJournal is trusted current-authority infrastructure. Begin
// MUST authenticate the creator/worker, fence writers, enforce actual physical
// quotas/export policy and durably reserve capacity before any daemon operation.
// Bind journals the exact created ID before start. Finish records observed absence
// or uncertainty under current authority; failure must latch integrity. No default
// exists. Neither successful cleanup nor release acknowledges user acceptance.
type ObjectReadLifecycleJournal interface {
	BeginObjectRead(context.Context, objectread.Request, CaptureObjectVolume, string) error
	BindObjectRead(context.Context, objectread.Request, string) error
	FinishObjectRead(context.Context, objectread.Request, string, bool) error
}

// ObjectReadProcess owns only non-TTY private helper stdin/stdout. Wait must join
// pumps and verify successful exit without closing the stream prematurely. Close
// promptly interrupts I/O and joins pumps on every path. Never use model pipes.
type ObjectReadProcess interface {
	io.ReadWriteCloser
	Wait(context.Context) error
}

// ObjectReadStarter starts ONLY this durably bound ID on the same authenticated
// rootless daemon as the runner. It must not create/replace/exec or adopt a name.
// Any process returned on failure is still owned and closed by the runtime.
type ObjectReadStarter interface {
	StartObjectRead(context.Context, string) (ObjectReadProcess, error)
}

// ObjectReadRuntime is one-shot isolated helper orchestration, not a download or
// host launcher. All dependencies are mandatory trusted infrastructure. A source
// fork CAN fake runners/journals, invalidating isolation. Production must supply
// verified same-daemon dependencies; no permissive journal, host/SSH fallback or
// isolation toggle is supplied.
type ObjectReadRuntime struct {
	physical  *objectReadInspector
	starter   ObjectReadStarter
	lifecycle ObjectReadLifecycleJournal
	guard     objectcustody.ReadReleaseGuard
	attempted atomic.Bool
}

func NewObjectReadRuntime(p *ObjectReadContainerPlan, r DockerRunner, s ObjectReadStarter, l ObjectReadLifecycleJournal, g objectcustody.ReadReleaseGuard) (*ObjectReadRuntime, error) {
	if p == nil || missingProbeDependency(r) || missingProbeDependency(s) || missingProbeDependency(l) || missingProbeDependency(g) {
		return nil, ErrRejected
	}
	return &ObjectReadRuntime{physical: &objectReadInspector{p, r}, starter: s, lifecycle: l, guard: g}, nil
}

// Run withholds bytes until successful exit, exited policy, joined process,
// exact-ID cleanup, repeated absence checks, durable lifecycle finish and a final
// current release acknowledgment. Any uncertainty returns nil, stops this read
// authority and retains charges/objects. There is no automatic retry or adoption.
func (r *ObjectReadRuntime) Run(ctx context.Context) (raw []byte, err error) {
	if r == nil || ctx == nil || ctx.Err() != nil || !r.attempted.CompareAndSwap(false, true) {
		return nil, ErrRejected
	}
	child, cancel := context.WithTimeout(ctx, 35*time.Second)
	defer cancel()
	defer func() {
		if err != nil {
			raw = nil
			r.guard.StopReadAuthority()
		}
	}()
	p := r.physical.plan
	if err = r.lifecycle.BeginObjectRead(child, p.request, p.objects, p.image); err != nil {
		return nil, err
	}
	id := ""
	var process ObjectReadProcess
	defer func() {
		if !missingProbeDependency(process) {
			err = errors.Join(err, process.Close())
		}
		cleanup, stop := context.WithTimeout(context.Background(), 5*time.Second)
		defer stop()
		err = errors.Join(err, r.cleanupAndFinish(cleanup, id), ctx.Err(), child.Err())
		if err == nil {
			err = r.guard.AcknowledgeRead(child, p.request.Receipt)
		}
		err = errors.Join(err, ctx.Err(), child.Err())
		if err != nil {
			err = errors.Join(err, objectcustody.ErrUnconfirmed)
		}
	}()
	if err = r.guard.AuthorizeRead(child, p.request.Receipt.Intent.Scope, p.request.Receipt); err != nil {
		return nil, err
	}
	if err = p.VerifyNoReferences(child, r.physical.runner); err != nil {
		return nil, err
	}
	created, e := r.physical.capture(child, p.CreateArgs()...)
	candidate := strings.TrimSpace(string(created))
	if e != nil || !digest(candidate, 32) {
		return nil, ErrRejected
	}
	id = candidate
	if err = r.lifecycle.BindObjectRead(child, p.request, id); err != nil {
		return nil, err
	}
	if err = p.VerifyAdmission(child, r.physical.runner, id, "created"); err != nil {
		return nil, err
	}
	process, err = r.starter.StartObjectRead(child, id)
	if err != nil || missingProbeDependency(process) {
		return nil, errors.Join(err, ErrRejected)
	}
	if err = p.VerifyAdmission(child, r.physical.runner, id, "running"); err != nil {
		return nil, err
	}
	raw, err = objectcustody.ReadSupervisedChannel(child, process, p.request.Receipt.Intent.Scope, p.request.Receipt, objectReadRunningGuard{r, id})
	if err != nil {
		return nil, err
	}
	if err = process.Wait(child); err != nil {
		return nil, err
	}
	if err = p.VerifyAdmission(child, r.physical.runner, id, "exited"); err != nil {
		return nil, err
	}
	return raw, nil
}

// cleanupAndFinish keeps observed cleanup uncertainty distinct from journal
// persistence failure. No cleanup result grants release or refunds storage.
func (r *ObjectReadRuntime) cleanupAndFinish(cleanup context.Context, id string) error {
	removal := error(ErrShutdownUnconfirmed)
	if id != "" {
		removal = StopContainer(cleanup, r.physical.runner, id, r.physical.owned)
		if removal == nil {
			removal = r.physical.absent(cleanup, id)
		}
	}
	// Cleanup may have consumed its entire deadline. Recording that uncertainty
	// must get its own bounded opportunity, even if the caller was canceled.
	finishCtx, stop := context.WithTimeout(context.Background(), 5*time.Second)
	defer stop()
	finish := r.lifecycle.FinishObjectRead(finishCtx, r.physical.plan.request, id, removal == nil)
	return errors.Join(removal, finish)
}

type objectReadRunningGuard struct {
	runtime *ObjectReadRuntime
	id      string
}

func (g objectReadRunningGuard) AuthorizeRead(ctx context.Context, s objectcustody.Scope, r objectcustody.Receipt) error {
	if g.runtime.physical.plan.VerifyAdmission(ctx, g.runtime.physical.runner, g.id, "running") != nil {
		return ErrRejected
	}
	if err := g.runtime.guard.AuthorizeRead(ctx, s, r); err != nil {
		return err
	}
	return g.runtime.physical.plan.VerifyAdmission(ctx, g.runtime.physical.runner, g.id, "running")
}
func (g objectReadRunningGuard) acknowledgeAdmission(ctx context.Context) error {
	// EOF can race actual successful helper exit. Both phases require the same
	// exact policy; no failed exit, missing container or changed identity is allowed.
	if g.runtime.physical.plan.VerifyAdmission(ctx, g.runtime.physical.runner, g.id, "running") == nil {
		return nil
	}
	return g.runtime.physical.plan.VerifyAdmission(ctx, g.runtime.physical.runner, g.id, "exited")
}
func (g objectReadRunningGuard) AcknowledgeRead(ctx context.Context, r objectcustody.Receipt) error {
	if err := g.acknowledgeAdmission(ctx); err != nil {
		return err
	}
	if err := g.runtime.guard.AcknowledgeRead(ctx, r); err != nil {
		return err
	}
	return g.acknowledgeAdmission(ctx)
}
func (g objectReadRunningGuard) StopReadAuthority() { g.runtime.guard.StopReadAuthority() }
