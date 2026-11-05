package toolbroker

import (
	"context"
	"errors"
	"io"
	"path"
	"strings"
	"testing"
	"time"
)

type cleanupVolumeDocker struct {
	t                     *testing.T
	volume                *toolVolumeInspection
	name                  string
	mode                  string
	inspectCalls, removed int
}

func (f *cleanupVolumeDocker) Run(ctx context.Context, args []string, _ []byte, out io.Writer) error {
	if ctx.Err() != nil {
		return ctx.Err()
	}
	if f.mode == "daemon" {
		return errors.New("synthetic daemon unavailable")
	}
	var raw []byte
	switch args[0] + "/" + args[1] {
	case "volume/ls":
		if f.volume != nil {
			raw = []byte(f.name)
		}
		if f.mode == "extra" && strings.HasPrefix(args[3], "label=") {
			raw = []byte("unknown-workspace")
		}
	case "volume/inspect":
		if f.volume == nil {
			return errors.New("missing")
		}
		f.inspectCalls++
		raw = inspectJSON(f.t, *f.volume)
		if f.mode == "replace-before-remove" && f.inspectCalls == 1 {
			f.volume.CreatedAt = time.Now().Add(time.Hour).UTC().Format(time.RFC3339Nano)
		}
	case "volume/rm":
		if args[len(args)-1] != f.name {
			f.t.Fatal("cleanup escaped bound name")
		}
		if f.mode == "remove-error" {
			return errors.New("synthetic unavailable")
		}
		f.removed++
		raw = []byte(f.name)
		if f.mode != "replacement" {
			f.volume = nil
		}
	case "ps/-a":
		if f.mode == "referenced" {
			raw = []byte(strings.Repeat("d", 64))
		}
	default:
		f.t.Fatalf("unexpected cleanup operation %v", args)
	}
	_, err := out.Write(raw)
	return err
}
func TestWorkspaceVolumeRemovalProof(t *testing.T) {
	t.Parallel()
	for _, mode := range []string{"success", "absent", "pending-intent", "unknown", "nonce", "time", "bind", "referenced", "daemon", "remove-error", "replacement", "replace-before-remove", "extra", "retain"} {
		t.Run(mode, func(t *testing.T) {
			t.Parallel()
			job, repository, root := strings.Repeat("a", 32), strings.Repeat("b", 64), "/home/synthetic/.local/share/docker"
			identity := WorkspaceVolumeIdentity{1, "commonroom-tool-work-" + job, strings.Repeat("c", 32), time.Now().UTC().Format(time.RFC3339Nano)}
			v := toolVolumeInspection{Name: identity.Name, Driver: "local", Scope: "local", Mountpoint: path.Join(root, "volumes", identity.Name, "_data"), CreatedAt: identity.CreatedAt, Labels: map[string]string{"commonroom.managed": "true", "commonroom.execution": "separated-tool-v1", "commonroom.job": job, "commonroom.repository": repository, "commonroom.workspace.nonce": identity.Nonce}}
			f := &cleanupVolumeDocker{t: t, volume: &v, name: identity.Name, mode: mode}
			bound := &identity
			switch mode {
			case "absent":
				f.volume = nil
			case "pending-intent":
				identity.CreatedAt = ""
			case "unknown":
				bound = nil
			case "nonce":
				v.Labels["commonroom.workspace.nonce"] = strings.Repeat("d", 32)
			case "time":
				v.CreatedAt = time.Now().Add(time.Hour).UTC().Format(time.RFC3339Nano)
			case "bind":
				v.Options = map[string]string{"o": "bind"}
			}
			observed, err := RemoveWorkspaceVolume(t.Context(), f, job, repository, root, bound, mode != "retain")
			success := mode == "success" || mode == "absent" || mode == "pending-intent"
			if (err == nil) != success {
				t.Fatalf("unexpected cleanup proof %v", err)
			}
			if mode == "pending-intent" && (observed == nil || observed.CreatedAt == "") {
				t.Fatal("lost discovery evidence")
			}
			if !success && mode != "replacement" && mode != "extra" && f.removed != 0 {
				t.Fatal("unsafe volume removal")
			}
			if mode == "success" && (f.inspectCalls != 2 || f.removed != 1) {
				t.Fatal("missing identity revalidation/removal")
			}
		})
	}
}
func TestWorkspaceVolumeCleanupRejectsInvalidBinding(t *testing.T) {
	t.Parallel()
	f := &cleanupVolumeDocker{t: t, mode: "daemon"}
	for _, root := range []string{"/", "relative", "/tmp/../other"} {
		if _, err := RemoveWorkspaceVolume(context.Background(), f, strings.Repeat("a", 32), strings.Repeat("b", 64), root, nil, true); err == nil {
			t.Fatal("invalid root accepted")
		}
	}
}
