package toolbroker

import (
	"context"
	"strings"
	"testing"
)

func TestObjectReadInspectRecordedObservesOnly(t *testing.T) {
	t.Parallel()
	for _, mode := range []string{"present", "absent", "owned policy drift", "foreign image", "foreign label", "replacement", "extra reference", "extra catalog", "missing id", "canceled"} {
		t.Run(mode, func(t *testing.T) {
			t.Parallel()
			_, f := newObjectReadRuntimeFixture(t, "")
			f.begun = true
			f.exists = mode != "absent"
			id := f.c.ID
			ctx := t.Context()
			switch mode {
			case "owned policy drift":
				f.c.HostConfig.NetworkMode = "host"
			case "foreign image":
				f.c.Image = "sha256:" + strings.Repeat("9", 64)
			case "foreign label":
				f.c.Config.Labels["commonroom.read"] = "foreign"
			case "replacement":
				f.v.CreatedAt = "2000-01-01T00:00:00Z"
			case "extra reference":
				f.objectReadPlanRunner.mode = "extra reference"
			case "extra catalog":
				f.objectReadPlanRunner.mode = "extra catalog"
			case "missing id":
				id = ""
			case "canceled":
				var cancel context.CancelFunc
				ctx, cancel = context.WithCancel(ctx)
				cancel()
			}
			absent, err := f.p.InspectRecorded(ctx, f, id)
			healthy := mode == "present" || mode == "absent" || mode == "owned policy drift"
			if (err == nil) != healthy || absent != (mode == "absent") {
				t.Fatal(mode, absent, err)
			}
			if f.started || f.bound || f.finished || f.removed || f.authorizations != 0 || f.acknowledgments != 0 {
				t.Fatal("observer performed lifecycle or released bytes")
			}
		})
	}
}
