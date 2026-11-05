package toolbroker

import (
	"context"
	"path"
	"reflect"
	"strings"
)

// VerifyRetainedWorkspace observes an exact retained volume with no container
// references. The caller MUST hold its creator job lease and prevent all managed
// writers for the entire observation/use interval. runner MUST enforce the same
// approved rootless daemon on every call. Daemon administrators remain trusted.
// This is NOT a read-only mount attestation, source root or FrozenLease. It never
// mounts, executes, adopts, deletes or refunds data. Source forks CAN omit these
// checks, BUT then cannot claim managed writer fencing. No host fallback exists.
func VerifyRetainedWorkspace(ctx context.Context, runner DockerRunner, job, repository, dockerRoot string, identity WorkspaceVolumeIdentity) error {
	if ctx == nil || ctx.Err() != nil || absentWorkspaceRunner(runner) || !digest(job, 16) || !digest(repository, 32) || !ValidWorkspaceVolume(job, identity, true) || !path.IsAbs(dockerRoot) || path.Clean(dockerRoot) != dockerRoot || dockerRoot == "/" {
		return ErrRejected
	}
	e := &ContainerExecutor{runner: runner}
	capture := func(args ...string) (string, error) {
		raw, err := e.capture(ctx, args, MaxInspectionBytes)
		if err != nil || ctx.Err() != nil {
			return "", ErrRejected
		}
		return strings.TrimSpace(string(raw)), nil
	}
	for pass := 0; pass < 2; pass++ {
		found, err := capture("volume", "ls", "--filter", "label=commonroom.job="+job, "--filter", "label=commonroom.execution=separated-tool-v1", "--format", "{{.Name}}")
		if err != nil || found != identity.Name {
			return ErrRejected
		}
		raw, err := capture("volume", "inspect", "--format", "{{json .}}", identity.Name)
		var v toolVolumeInspection
		if err != nil || decodeInspection([]byte(raw), &v) != nil || !validObservedWorkspaceVolume(v, job, repository, dockerRoot, identity) {
			return ErrRejected
		}

		refs, err := capture("ps", "-a", "--no-trunc", "--filter", "volume="+identity.Name, "--format", "{{.ID}}")
		if err != nil || refs != "" {
			return ErrRejected
		}
	}
	return nil
}

func absentWorkspaceRunner(runner DockerRunner) bool {
	if runner == nil {
		return true
	}
	r := reflect.ValueOf(runner)
	switch r.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		return r.IsNil()
	}
	return false
}

// Shared with disposal: observation and removal must bind the same immutable
// creator metadata even though only disposal may authorize deletion.
func validObservedWorkspaceVolume(v toolVolumeInspection, job, repository, dockerRoot string, identity WorkspaceVolumeIdentity) bool {
	labels := map[string]string{"commonroom.managed": "true", "commonroom.execution": "separated-tool-v1", "commonroom.job": job, "commonroom.repository": repository, "commonroom.workspace.nonce": identity.Nonce}
	return ValidWorkspaceVolume(job, identity, true) && v.Name == identity.Name && v.Driver == "local" && v.Scope == "local" && v.Mountpoint == path.Join(dockerRoot, "volumes", identity.Name, "_data") && v.CreatedAt == identity.CreatedAt && len(v.Options) == 0 && sameMap(v.Labels, labels)
}
