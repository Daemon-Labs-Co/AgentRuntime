package toolbroker

import (
	"context"
	"strings"
	"testing"
	"time"
)

func TestWorkspaceVolumePrepareAndIdentity(t *testing.T) {
	t.Parallel()
	r, f, cancel := unpreparedRuntimeSetup(t, "")
	defer cancel()
	if _, err := r.Create(t.Context()); err == nil {
		t.Fatal("container created before fresh volume")
	}
	intent, err := f.plan.WorkspaceIntent(time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if !ValidWorkspaceVolume(f.plan.authority.scope.JobID, intent, false) {
		t.Fatal("invalid minted intent")
	}
	again, err := f.plan.WorkspaceIntent(time.Now())
	if err != nil || again != intent {
		t.Fatal("intent changed before creation")
	}
	identity, err := r.PrepareVolume(t.Context(), intent)
	if err != nil || !ValidWorkspaceVolume(f.plan.authority.scope.JobID, identity, true) || f.volumeCreates != 1 {
		t.Fatalf("prepare failed %v", err)
	}
	calls := len(f.calls)
	if _, err = r.PrepareVolume(t.Context(), intent); err == nil || len(f.calls) != calls {
		t.Fatal("volume recreated")
	}
	if _, err = f.plan.WorkspaceIntent(time.Now()); err == nil {
		t.Fatal("prepared intent reminted")
	}
	if _, err = r.Create(t.Context()); err != nil {
		t.Fatal(err)
	}
	f.mode = "volume-replaced"
	if err = r.Start(t.Context(), f.container.ID); err == nil || f.starts != 0 {
		t.Fatal("replacement volume accepted")
	}
}
func TestWorkspaceVolumeRefusesAdoptionAndUncertainty(t *testing.T) {
	t.Parallel()
	for _, mode := range []string{"existing", "volume-inventory-error", "volume-create-error", "volume-create-reply", "missing-volume", "volume-bind", "volume-nonce", "volume-time"} {
		t.Run(mode, func(t *testing.T) {
			t.Parallel()
			r, f, cancel := unpreparedRuntimeSetup(t, mode)
			defer cancel()
			if mode == "existing" {
				f.volumeExists = true
			}
			intent, err := f.plan.WorkspaceIntent(time.Now())
			if err != nil {
				t.Fatal(err)
			}
			if _, err = r.PrepareVolume(t.Context(), intent); err == nil {
				t.Fatal("unsafe volume preparation accepted")
			}
			calls := len(f.calls)
			if _, err = r.PrepareVolume(t.Context(), intent); err == nil || len(f.calls) != calls {
				t.Fatal("uncertain volume retried")
			}
			if _, err = r.Create(t.Context()); err == nil || f.creates != 0 {
				t.Fatal("container after failed volume preparation")
			}
			if (mode == "existing" || mode == "volume-inventory-error") && f.volumeCreates != 0 {
				t.Fatal("create after existing/unavailable inventory")
			}
		})
	}
}
func TestWorkspaceVolumeIntentCannotBeChangedOrRevived(t *testing.T) {
	t.Parallel()
	for _, mode := range []string{"name", "nonce", "created", "cancelled"} {
		t.Run(mode, func(t *testing.T) {
			t.Parallel()
			r, f, cancel := unpreparedRuntimeSetup(t, "")
			defer cancel()
			intent, err := f.plan.WorkspaceIntent(time.Now())
			if err != nil {
				t.Fatal(err)
			}
			switch mode {
			case "name":
				intent.Name = "foreign"
			case "nonce":
				intent.Nonce = strings.Repeat("d", 32)
			case "created":
				intent.CreatedAt = time.Now().UTC().Format(time.RFC3339)
			case "cancelled":
				cancel()
			}
			if _, err = r.PrepareVolume(context.Background(), intent); err == nil || len(f.calls) != 0 {
				t.Fatal("foreign/cancelled intent reached Docker")
			}
		})
	}
}
