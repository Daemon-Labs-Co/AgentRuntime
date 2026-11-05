package toolbroker

import (
	"commonroom-runtime/internal/objectcustody"
	"commonroom-runtime/internal/workspacecapture"
	"commonroom-runtime/internal/workspacemount"
	"commonroom-runtime/internal/workspacesnapshot"
	"context"
	"errors"
	"io"
	"slices"
	"strings"
	"sync/atomic"
	"time"
)

// CaptureLifecycleJournal is trusted current-authority infrastructure. Begin MUST
// hold creator ownership, fence writers, establish physical quotas and durably
// reserve a container slot before creation. Bound MUST journal the exact ID before
// start. Finish rechecks authority and records actual absence/uncertainty before
// report release. Failed/unknown work retains storage and charges. No default exists.
type CaptureLifecycleJournal interface {
	BeginCapture(context.Context, workspacecapture.Request, CaptureObjectVolume, string) error
	BindCapture(context.Context, workspacecapture.Request, string) error
	FinishCapture(context.Context, workspacecapture.Request, string, bool) error
}

// CaptureProcess owns only the reviewed helper's non-TTY private stdin/stdout.
// Wait must observe actual exit success, respect cancellation and join all pumps;
// Close must promptly interrupt I/O and join pumps, including on failure.
// Implementations MUST NOT use model/provider pipes.
type CaptureProcess interface {
	io.ReadWriteCloser
	Wait(context.Context) error
}

// CaptureStarter starts ONLY the supplied durably bound container ID on the same
// approved rootless daemon as DockerRunner, returning an exclusively owned stream.
// StartCapture must not create/replace/exec commands, adopt names or return a model
// stream. On failure any returned process is still owned/closed by the runtime.
// Source forks CAN fake these dependencies, invalidating isolation guarantees.
type CaptureStarter interface {
	StartCapture(context.Context, string) (CaptureProcess, error)
}

// CaptureRuntime is a one-shot lifecycle, never a host launcher or authorization
// API. All dependencies are mandatory trusted infrastructure. No real daemon/peer
// assembly, physical quota provisioner, fallback or boundary toggle is supplied.
type CaptureRuntime struct {
	*captureInspector
	starter   CaptureStarter
	lifecycle CaptureLifecycleJournal
	authority workspacecapture.Authority
	custody   objectcustody.Journal
	attempted atomic.Bool
}

func NewCaptureRuntime(p *CaptureContainerPlan, r DockerRunner, s CaptureStarter, l CaptureLifecycleJournal, a workspacecapture.Authority, j objectcustody.Journal) (*CaptureRuntime, error) {
	if p == nil || missingProbeDependency(r) || missingProbeDependency(s) || missingProbeDependency(l) || missingProbeDependency(a) || missingProbeDependency(j) {
		return nil, ErrRejected
	}
	return &CaptureRuntime{captureInspector: &captureInspector{plan: p, runner: r}, starter: s, lifecycle: l, authority: a, custody: j}, nil
}
func (r *CaptureRuntime) request() workspacecapture.Request {
	q := r.plan.request
	q.Members = slices.Clone(q.Members)
	return q
}

// Run withholds its report until successful exit, exact-ID removal, repeated absence
// checks and final durable current-authority acknowledgment. Any failure returns a
// zero report and uncertainty; there is no automatic retry, refund or volume delete.
func (r *CaptureRuntime) Run(ctx context.Context) (report workspacecapture.Report, err error) {
	if r == nil || ctx == nil || ctx.Err() != nil || !r.attempted.CompareAndSwap(false, true) {
		return report, ErrRejected
	}
	child, cancel := context.WithTimeout(ctx, 35*time.Second)
	defer cancel()
	if err = r.lifecycle.BeginCapture(child, r.request(), r.plan.objects, r.plan.image); err != nil {
		return report, err
	}
	id := ""
	var process CaptureProcess
	defer func() {
		if !missingProbeDependency(process) {
			err = errors.Join(err, process.Close())
		}
		cleanup, stop := context.WithTimeout(context.Background(), 5*time.Second)
		defer stop()
		removal := error(ErrShutdownUnconfirmed)
		if id != "" {
			removal = StopContainer(cleanup, r.runner, id, r.owned)
			if removal == nil {
				removal = r.absent(cleanup, id)
			}
		}
		finish := r.lifecycle.FinishCapture(cleanup, r.request(), id, removal == nil)
		err = errors.Join(err, removal, finish, ctx.Err(), child.Err())
		if err != nil {
			report = workspacecapture.Report{}
			err = errors.Join(err, objectcustody.ErrUnconfirmed)
		}
	}()
	raw, e := r.capture(child, "ps", "-a", "--no-trunc", "--filter", "name=^/"+r.plan.name()+"$", "--format", "{{.ID}}")
	if e != nil || strings.TrimSpace(string(raw)) != "" {
		return report, ErrRejected
	}
	raw, e = r.capture(child, r.plan.CreateArgs()...)
	candidate := strings.TrimSpace(string(raw))
	if e != nil || !digest(candidate, 32) {
		return report, ErrRejected
	}
	id = candidate
	if err = r.plan.VerifyAdmission(child, r.runner, id, "created"); err != nil {
		return report, err
	}
	if err = r.lifecycle.BindCapture(child, r.request(), id); err != nil {
		return report, err
	}
	process, err = r.starter.StartCapture(child, id)
	if err != nil || missingProbeDependency(process) {
		return report, errors.Join(err, ErrRejected)
	}
	if err = r.plan.VerifyAdmission(child, r.runner, id, "running"); err != nil {
		return report, err
	}
	report, err = workspacecapture.ServeSupervisedCaptureChannel(child, process, r.request(), captureRunningAuthority{r, id}, r.custody)
	if err != nil {
		return report, err
	}
	if err = process.Wait(child); err != nil {
		return report, err
	}
	if err = r.plan.VerifyAdmission(child, r.runner, id, "exited"); err != nil {
		return report, err
	}
	return report, nil
}

type captureRunningAuthority struct {
	runtime *CaptureRuntime
	id      string
}

func (a captureRunningAuthority) AuthorizeFrozenSource(ctx context.Context, b workspacesnapshot.Binding, p workspacemount.Proof) error {
	if a.runtime.plan.VerifyAdmission(ctx, a.runtime.runner, a.id, "running") != nil {
		return ErrRejected
	}
	return a.runtime.authority.AuthorizeFrozenSource(ctx, b, p)
}
