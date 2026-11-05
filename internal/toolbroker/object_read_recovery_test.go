package toolbroker

import (
	"commonroom-runtime/internal/objectcustody"
	"commonroom-runtime/internal/objectread"
	"context"
	"errors"
	"strings"
	"testing"
)

type objectReadRecoveryFixture struct {
	*objectReadRuntimeFixture
	deny, failFinish bool
}

func (f *objectReadRecoveryFixture) BeginObjectReadRecovery(ctx context.Context, q objectread.Request, v CaptureObjectVolume, image, id string) error {
	if f.deny || q != f.p.request || v != f.p.objects || image != f.p.image || id != f.c.ID {
		return ErrRejected
	}
	f.begun = true
	return ctx.Err()
}
func (f *objectReadRecoveryFixture) FinishObjectReadRecovery(ctx context.Context, q objectread.Request, id string, absent bool) error {
	if q != f.p.request || id != f.c.ID {
		f.t.Fatal("unpinned recovery finish")
	}
	f.finished = true
	f.absent = absent
	if f.failFinish {
		return ErrRejected
	}
	return ctx.Err()
}
func newObjectReadRecoveryFixture(t *testing.T) (*ObjectReadRecovery, *objectReadRecoveryFixture) {
	t.Helper()
	_, base := newObjectReadRuntimeFixture(t, "")
	f := &objectReadRecoveryFixture{objectReadRuntimeFixture: base}
	r, err := NewObjectReadRecovery(f.p, f, f)
	if err != nil {
		t.Fatal(err)
	}
	return r, f
}
func TestObjectReadRecoveryKnownIdentity(t *testing.T) {
	t.Parallel()
	for _, mode := range []string{"running", "absent", "policy-drift"} {
		t.Run(mode, func(t *testing.T) {
			t.Parallel()
			r, f := newObjectReadRecoveryFixture(t)
			f.exists = mode != "absent"
			f.c.State.Status = "running"
			f.c.State.Running = probeBool(true)
			if mode == "policy-drift" {
				f.c.HostConfig.NetworkMode = "host"
			}
			if err := r.Reconcile(t.Context(), f.c.ID); err != nil {
				t.Fatal(err)
			}
			if !f.finished || !f.absent || f.started || f.bound || f.authorizations != 0 || f.acknowledgments != 0 || f.removed != (mode != "absent") {
				t.Fatal("unsafe recovery", f)
			}
			if r.Reconcile(t.Context(), f.c.ID) == nil {
				t.Fatal("recovery reused")
			}
		})
	}
}
func TestObjectReadRecoveryRefusesConflicts(t *testing.T) {
	t.Parallel()
	for _, mode := range []string{"foreign-image", "foreign-labels", "volume-replaced", "extra-reference", "extra-catalog", "cleanup", "returning-reference", "finish"} {
		t.Run(mode, func(t *testing.T) {
			t.Parallel()
			r, f := newObjectReadRecoveryFixture(t)
			f.exists = true
			switch mode {
			case "foreign-image":
				f.c.Image = "sha256:" + strings.Repeat("9", 64)
			case "foreign-labels":
				f.c.Config.Labels["commonroom.read"] = "other"
			case "volume-replaced":
				f.v.CreatedAt = "2000-01-01T00:00:00Z"
			case "extra-reference":
				f.objectReadPlanRunner.mode = "extra reference"
			case "extra-catalog":
				f.objectReadPlanRunner.mode = "extra catalog"

			case "cleanup", "returning-reference":
				f.mode = mode
			case "finish":
				f.failFinish = true
			}
			err := r.Reconcile(t.Context(), f.c.ID)
			if err == nil || !errors.Is(err, objectcustody.ErrUnconfirmed) || !f.finished {
				t.Fatal("lost uncertainty", err)
			}
			if mode != "finish" && f.absent {
				t.Fatal("false absence")
			}
			if mode != "finish" && mode != "cleanup" && mode != "returning-reference" && f.removed {
				t.Fatal("removed foreign/conflicting identity")
			}
			if f.started || f.authorizations != 0 || f.acknowledgments != 0 {
				t.Fatal("recovery released bytes")
			}
		})
	}
}
func TestObjectReadRecoveryAuthorizesBeforeDaemon(t *testing.T) {
	t.Parallel()
	for _, mode := range []string{"denied", "wrong-id", "missing-id", "canceled", "nil-context"} {
		t.Run(mode, func(t *testing.T) {
			t.Parallel()
			r, f := newObjectReadRecoveryFixture(t)
			id := f.c.ID
			ctx := t.Context()
			switch mode {
			case "denied":
				f.deny = true
			case "wrong-id":
				id = strings.Repeat("9", 64)
			case "missing-id":
				id = ""
			case "canceled":
				c, cancel := context.WithCancel(ctx)
				cancel()
				ctx = c
			case "nil-context":
				ctx = nil
			}
			if r.Reconcile(ctx, id) == nil || f.calls != 0 || f.finished || f.removed {
				t.Fatal("daemon before authority")
			}
		})
	}
	_, f := newObjectReadRecoveryFixture(t)
	var missing *objectReadRecoveryFixture
	if _, err := NewObjectReadRecovery(f.p, missing, f); err == nil {
		t.Fatal("nil runner")
	}
	if _, err := NewObjectReadRecovery(f.p, f, missing); err == nil {
		t.Fatal("nil journal")
	}
	if _, err := NewObjectReadRecovery(nil, f, f); err == nil {
		t.Fatal("nil plan")
	}
}
