package toolbroker

import (
	"context"
	"path"
	"strings"
)

// RemoveWorkspaceVolume is explicit ephemeral-workspace teardown, not retention
// policy or audit deletion. The caller MUST hold the original creator lease and
// prevent other managed creation until this returns. Only an exact owner-approved
// disposal workflow may set discard; ordinary cancellation retains data.
// Docker supplies no immutable volume-removal ID: creation nonce/time distinguish
// replacements, but an administrator with daemon access can still race the name.
// Such administrators and the daemon remain trusted. Models get neither access.
// Source changes CAN skip this contract, BUT invalidate safe cleanup claims.
func RemoveWorkspaceVolume(ctx context.Context, runner DockerRunner, job, repository, dockerRoot string, identity *WorkspaceVolumeIdentity, discard bool) (*WorkspaceVolumeIdentity, error) {
	if ctx == nil || ctx.Err() != nil || runner == nil || !digest(job, 16) || !digest(repository, 32) || !path.IsAbs(dockerRoot) || path.Clean(dockerRoot) != dockerRoot || dockerRoot == "/" {
		return identity, ErrShutdownUnconfirmed
	}
	e := &ContainerExecutor{runner: runner}
	capture := func(args ...string) (string, error) {
		raw, err := e.capture(ctx, args, MaxInspectionBytes)
		if err != nil {
			return "", ErrShutdownUnconfirmed
		}
		return strings.TrimSpace(string(raw)), nil
	}
	name := "commonroom-tool-work-" + job
	inventory := func() (string, error) {
		return capture("volume", "ls", "--filter", "name=^"+name+"$", "--format", "{{.Name}}")
	}
	observed, err := inventory()
	if err != nil || observed != "" && observed != name {
		return identity, ErrShutdownUnconfirmed
	}
	var bound WorkspaceVolumeIdentity
	if identity != nil {
		bound = *identity
		if !ValidWorkspaceVolume(job, bound, bound.CreatedAt != "") {
			return identity, ErrShutdownUnconfirmed
		}
	}
	verify := func() (WorkspaceVolumeIdentity, error) {
		raw, err := capture("volume", "inspect", "--format", "{{json .}}", name)
		var v toolVolumeInspection
		if err != nil || decodeInspection([]byte(raw), &v) != nil {
			return bound, ErrShutdownUnconfirmed
		}
		candidate := bound
		if candidate.CreatedAt == "" {
			candidate.CreatedAt = v.CreatedAt
		}
		if !validObservedWorkspaceVolume(v, job, repository, dockerRoot, candidate) {
			return bound, ErrShutdownUnconfirmed
		}

		return candidate, nil
	}
	if observed != "" {
		if identity == nil {
			return identity, ErrShutdownUnconfirmed
		} // Never adopt unknown data.
		bound, err = verify()
		if err != nil {
			return identity, err
		}
		identity = &bound
		refs, err := capture("ps", "-a", "--no-trunc", "--filter", "volume="+name, "--format", "{{.ID}}")
		if err != nil || refs != "" {
			return identity, ErrShutdownUnconfirmed
		}
		if _, err = verify(); err != nil {
			return identity, err
		}
		if !discard {
			return identity, ErrShutdownUnconfirmed
		}
		removed, err := capture("volume", "rm", name)
		if err != nil || removed != name {
			return identity, ErrShutdownUnconfirmed
		}
	}
	if remaining, err := inventory(); err != nil || remaining != "" {
		return identity, ErrShutdownUnconfirmed
	}
	// Unknown workspace volumes carrying this job remain unresolved, never erased.
	remaining, err := capture("volume", "ls", "--filter", "label=commonroom.job="+job, "--filter", "label=commonroom.execution=separated-tool-v1", "--format", "{{.Name}}")
	if err != nil || remaining != "" || ctx.Err() != nil {
		return identity, ErrShutdownUnconfirmed
	}
	return identity, nil
}
