package toolbroker

import (
	"commonroom-runtime/internal/objectcustody"
	"commonroom-runtime/internal/workspacecapture"
	"context"
	"errors"
	"slices"
	"sync/atomic"
	"time"
)

// CaptureRecoveryJournal MUST authenticate current cleanup authority against a
// durable interrupted capture record, its exact bound ID/request/image/volumes,
// and exclusive creator ownership. Begin never reserves new creation or exports
// bytes. Finish durably records observed absence/uncertainty under current policy;
// failed persistence must trip integrity stop. Storage charges/objects remain.
// No model-facing, permissive or production default implementation exists.
type CaptureRecoveryJournal interface {
	BeginCaptureRecovery(context.Context, workspacecapture.Request, CaptureObjectVolume, string, string) error
	FinishCaptureRecovery(context.Context, workspacecapture.Request, string, bool) error
}

// CaptureRecovery reconciles a durably known helper ID only. It has no starter,
// source reader, object-store writer, release, adoption or volume deletion API.
// Source forks may fake trusted evidence, invalidating containment guarantees.
// Mandatory isolation has no toggle or host/SSH fallback here.
type CaptureRecovery struct {
	physical  *captureInspector
	journal   CaptureRecoveryJournal
	attempted atomic.Bool
}

func NewCaptureRecovery(plan *CaptureContainerPlan, runner DockerRunner, journal CaptureRecoveryJournal) (*CaptureRecovery, error) {
	if plan == nil || missingProbeDependency(runner) || missingProbeDependency(journal) {
		return nil, ErrRejected
	}
	return &CaptureRecovery{physical: &captureInspector{plan, runner}, journal: journal}, nil
}
func (r *CaptureRecovery) request() workspacecapture.Request {
	q := r.physical.plan.request
	q.Members = slices.Clone(q.Members)
	return q
}

// Reconcile authorizes before any daemon call, refuses unknown/replaced/conflicting
// identities, and records uncertainty on failure. A nil result proves only observed
// exact helper absence and a successful durable acknowledgment, not released quota,
// source validity, complete objects or a recovered/publishable capture report.
func (r *CaptureRecovery) Reconcile(ctx context.Context, id string) (err error) {
	if r == nil || ctx == nil || ctx.Err() != nil || !digest(id, 32) || !r.attempted.CompareAndSwap(false, true) {
		return ErrRejected
	}
	child, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	if err = r.journal.BeginCaptureRecovery(child, r.request(), r.physical.plan.objects, r.physical.plan.image, id); err != nil {
		return err
	}
	confirmed := false
	defer func() {
		finishCtx, stop := context.WithTimeout(context.Background(), 5*time.Second)
		defer stop()
		finish := r.journal.FinishCaptureRecovery(finishCtx, r.request(), id, confirmed)
		err = errors.Join(err, finish, ctx.Err(), child.Err())
		if err != nil {
			err = errors.Join(err, objectcustody.ErrUnconfirmed)
		}
	}()
	absent, err := r.physical.known(child, id)
	if err != nil {
		return err
	}
	if !absent {
		if err = StopContainer(child, r.physical.runner, id, r.physical.owned); err != nil {
			return err
		}
	}
	if err = r.physical.absent(child, id); err != nil {
		return err
	}
	confirmed = true
	return nil
}
