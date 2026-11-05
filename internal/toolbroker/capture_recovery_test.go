package toolbroker

import (
	"commonroom-runtime/internal/objectcustody"
	"commonroom-runtime/internal/workspacecapture"
	"context"
	"errors"
	"strings"
	"testing"
)

type captureRecoveryFixture struct {
	*captureRuntimeFixture
	denied, finishDenied bool
	expectedImage        string
}

func (f *captureRecoveryFixture) BeginCaptureRecovery(ctx context.Context, q workspacecapture.Request, o CaptureObjectVolume, image, id string) error {
	if id != f.c.ID || image != f.expectedImage || o != f.p.objects {
		return ErrRejected
	}
	expected, _ := workspacecapture.RequestDigest(f.p.request)
	actual, _ := workspacecapture.RequestDigest(q)
	if actual != expected {
		return ErrRejected
	}
	if f.denied {
		return ErrRejected
	}
	f.begun = true
	return ctx.Err()
}
func (f *captureRecoveryFixture) FinishCaptureRecovery(ctx context.Context, q workspacecapture.Request, id string, absent bool) error {
	f.finished = true
	f.absent = absent
	if f.finishDenied {
		return ErrRejected
	}
	return ctx.Err()
}
func newCaptureRecoveryFixture(t *testing.T) (*CaptureRecovery, *captureRecoveryFixture) {
	t.Helper()
	_, base := newCaptureRuntimeFixture(t, "")
	f := &captureRecoveryFixture{captureRuntimeFixture: base, expectedImage: base.p.image}
	r, err := NewCaptureRecovery(base.p, f, f)
	if err != nil {
		t.Fatal(err)
	}
	return r, f
}
func TestCaptureRecoveryKnownPresentAndAbsent(t *testing.T) {
	t.Parallel()
	for _, mode := range []string{"running", "absent", "policy drift"} {
		t.Run(mode, func(t *testing.T) {
			t.Parallel()
			r, f := newCaptureRecoveryFixture(t)
			f.exists = mode != "absent"
			f.c.State.Status = "running"
			f.c.State.Running = probeBool(true)
			if mode == "policy drift" {
				f.c.HostConfig.NetworkMode = "host"
			}
			if err := r.Reconcile(t.Context(), f.c.ID); err != nil {
				t.Fatal(err)
			}
			if !f.begun || !f.finished || !f.absent || f.started || f.reserves != 0 || f.seals != 0 || f.removed != (mode != "absent") {
				t.Fatal("unsafe recovery result", f)
			}
			if r.Reconcile(t.Context(), f.c.ID) == nil {
				t.Fatal("recovery reused")
			}
		})
	}
}
func TestCaptureRecoveryRefusesConflictAndRetainsUncertainty(t *testing.T) {
	t.Parallel()
	for _, mode := range []string{"foreign image", "foreign labels", "source replacement", "object replacement", "extra source reference", "extra custody reference", "extra volume", "cleanup", "returning reference", "finish"} {
		t.Run(mode, func(t *testing.T) {
			t.Parallel()
			r, f := newCaptureRecoveryFixture(t)
			f.exists = true
			switch mode {
			case "foreign image":
				f.c.Image = "sha256:" + strings.Repeat("9", 64)
			case "foreign labels":
				f.c.Config.Labels["commonroom.capture"] = "other"
			case "source replacement":
				f.src.CreatedAt = "2000-01-01T00:00:00Z"
			case "object replacement":
				f.obj.CreatedAt = "2000-01-01T00:00:00Z"
			case "extra source reference":
				f.captureAdmissionRunner.mode = "volume=" + f.src.Name
			case "extra custody reference":
				f.captureAdmissionRunner.mode = "volume=" + f.obj.Name
			case "extra volume":
				f.captureAdmissionRunner.mode = "extra volume"
			case "cleanup", "returning reference":
				f.mode = mode
			case "finish":
				f.finishDenied = true
			}
			err := r.Reconcile(t.Context(), f.c.ID)
			if err == nil || !errors.Is(err, objectcustody.ErrUnconfirmed) || !f.finished {
				t.Fatal("lost recovery uncertainty", err)
			}
			if mode != "finish" && f.absent {
				t.Fatal("false absence")
			}
			if mode != "cleanup" && mode != "returning reference" && mode != "finish" && f.removed {
				t.Fatal("removed before conflict resolved")
			}
			if f.started || f.reserves != 0 || f.seals != 0 {
				t.Fatal("recovery performed capture")
			}
		})
	}
}
func TestCaptureRecoveryRequiresDurableAuthorityBeforeDaemon(t *testing.T) {
	t.Parallel()
	for _, mode := range []string{"denied", "wrong ID", "wrong recorded image", "canceled", "missing ID"} {
		t.Run(mode, func(t *testing.T) {
			t.Parallel()
			r, f := newCaptureRecoveryFixture(t)
			id := f.c.ID
			ctx := t.Context()
			switch mode {
			case "denied":
				f.denied = true
			case "wrong ID":
				id = strings.Repeat("9", 64)
			case "wrong recorded image":
				f.expectedImage = "sha256:" + strings.Repeat("9", 64)
			case "canceled":
				c, cancel := context.WithCancel(ctx)
				cancel()
				ctx = c
			case "missing ID":
				id = ""
			}
			if r.Reconcile(ctx, id) == nil {
				t.Fatal("unauthorized recovery")
			}
			if f.calls != 0 || f.finished || f.removed {
				t.Fatal("daemon/mutation before authorization")
			}
		})
	}
	p, _, _, _ := capturePlanFixture(t)
	var missing *captureRecoveryFixture
	if _, err := NewCaptureRecovery(p, missing, missing); err == nil {
		t.Fatal("typed nil admitted")
	}
}
