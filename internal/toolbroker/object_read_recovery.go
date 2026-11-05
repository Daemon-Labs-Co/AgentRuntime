package toolbroker

import (
	"commonroom-runtime/internal/objectcustody"
	"commonroom-runtime/internal/objectread"
	"context"
	"errors"
	"sync/atomic"
	"time"
)

// ObjectReadRecoveryJournal MUST authenticate cleanup authority from a durable
// interrupted record pinning request, worker, image, volume and exact created ID.
// Begin authorizes no creation/read. Finish durably records absence/uncertainty;
// persistence failure must stop integrity. Storage charges and objects remain.
type ObjectReadRecoveryJournal interface {
	BeginObjectReadRecovery(context.Context, objectread.Request, CaptureObjectVolume, string, string) error
	FinishObjectReadRecovery(context.Context, objectread.Request, string, bool) error
}

// ObjectReadRecovery reconciles one recorded ID. It has no starter, release guard,
// reader, volume deletion, quota refund or name-adoption capability. There is no
// host fallback; source substitution of trusted dependencies invalidates isolation.
type ObjectReadRecovery struct {
	physical  *objectReadInspector
	journal   ObjectReadRecoveryJournal
	attempted atomic.Bool
}

func NewObjectReadRecovery(p *ObjectReadContainerPlan, r DockerRunner, j ObjectReadRecoveryJournal) (*ObjectReadRecovery, error) {
	if p == nil || missingProbeDependency(r) || missingProbeDependency(j) {
		return nil, ErrRejected
	}
	return &ObjectReadRecovery{physical: &objectReadInspector{p, r}, journal: j}, nil
}
func (r *ObjectReadRecovery) Reconcile(ctx context.Context, id string) (err error) {
	if r == nil || ctx == nil || ctx.Err() != nil || !digest(id, 32) || !r.attempted.CompareAndSwap(false, true) {
		return ErrRejected
	}
	child, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	p := r.physical.plan
	if err = r.journal.BeginObjectReadRecovery(child, p.request, p.objects, p.image, id); err != nil {
		return err
	}
	confirmed := false
	defer func() {
		finishCtx, stop := context.WithTimeout(context.Background(), 5*time.Second)
		defer stop()
		err = errors.Join(err, r.journal.FinishObjectReadRecovery(finishCtx, p.request, id, confirmed), ctx.Err(), child.Err())
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
