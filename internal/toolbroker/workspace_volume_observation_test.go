package toolbroker

import (
	"context"
	"path"
	"strings"
	"testing"
	"time"
)

func TestRetainedWorkspaceObservationRequiresExactUnattachedVolume(t *testing.T) {
	t.Parallel()
	for _, mode := range []string{"healthy", "missing", "nonce", "time", "options", "mount", "driver", "scope", "label", "referenced", "daemon", "replace-before-remove", "extra", "bad-name", "bad-root", "cancelled", "nil-context", "nil-runner", "typed-nil-runner", "uncreated", "bad-repository"} {
		t.Run(mode, func(t *testing.T) {
			t.Parallel()
			job, repository, root := strings.Repeat("a", 32), strings.Repeat("b", 64), "/home/synthetic/.local/share/docker"
			id := WorkspaceVolumeIdentity{1, "commonroom-tool-work-" + job, strings.Repeat("c", 32), time.Now().UTC().Format(time.RFC3339Nano)}
			v := toolVolumeInspection{Name: id.Name, Driver: "local", Scope: "local", Mountpoint: path.Join(root, "volumes", id.Name, "_data"), CreatedAt: id.CreatedAt, Labels: map[string]string{"commonroom.managed": "true", "commonroom.execution": "separated-tool-v1", "commonroom.job": job, "commonroom.repository": repository, "commonroom.workspace.nonce": id.Nonce}}
			f := &cleanupVolumeDocker{t: t, volume: &v, name: id.Name, mode: mode}
			var runner DockerRunner = f
			ctx := t.Context()
			switch mode {
			case "cancelled":
				child, cancel := context.WithCancel(ctx)
				cancel()
				ctx = child
			case "nil-context":
				ctx = nil
			case "nil-runner":
				runner = nil
			case "typed-nil-runner":
				var missing *cleanupVolumeDocker
				runner = missing
			case "uncreated":
				id.CreatedAt = ""
			case "bad-repository":
				repository = "foreign"
			case "missing":
				f.volume = nil
			case "nonce":
				v.Labels["commonroom.workspace.nonce"] = strings.Repeat("d", 32)
			case "time":
				v.CreatedAt = time.Now().Add(time.Hour).UTC().Format(time.RFC3339Nano)
			case "options":
				v.Options = map[string]string{"o": "bind"}
			case "mount":
				v.Mountpoint = "/foreign"
			case "driver":
				v.Driver = "foreign"
			case "scope":
				v.Scope = "global"
			case "label":
				v.Labels["unexpected"] = "true"
			case "bad-name":
				id.Name = "foreign"
			case "bad-root":
				root = "/"
			}
			err := VerifyRetainedWorkspace(ctx, runner, job, repository, root, id)
			if (err == nil) != (mode == "healthy") {
				t.Fatalf("unexpected observation result %v", err)
			}
			if f.removed != 0 {
				t.Fatal("observation deleted data")
			}
			if mode == "healthy" && f.inspectCalls != 2 {
				t.Fatal("identity was not rechecked")
			}
		})
	}
}
