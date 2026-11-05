package workerport

import (
	"commonroom-runtime/internal/toolbroker"
	"context"
	"errors"
	"path/filepath"
)

// workerCleanupOwnershipKey is set only after acquiring the creator job lease.
// Killing a creator's containers while its lease is held does not authorize
// erasing its workspace or confirming completed cleanup.
type workerCleanupOwnershipKey struct{}

type workerWorkspaceDiscardKey struct{}

func stopWorkerWorkspace(ctx context.Context, v workerJobRecord, runner toolbroker.DockerRunner) (workerJobRecord, error) {
	owned, _ := ctx.Value(workerCleanupOwnershipKey{}).(bool)
	if !owned {
		return v, nil
	}
	root, err := pairCapture(ctx, runner, []string{"info", "--format", "{{.DockerRootDir}}"})
	if err != nil || !filepath.IsAbs(root) || filepath.Clean(root) != root || root == "/" {
		return v, errors.New("workspace daemon root unverified")
	}
	var identity *toolbroker.WorkspaceVolumeIdentity
	if v.Pair.Workspace != nil {
		copy := v.Pair.Workspace.Identity
		identity = &copy
	}
	expected, _ := ctx.Value(workerWorkspaceDiscardKey{}).(*toolbroker.WorkspaceVolumeIdentity)
	discard := expected != nil
	if discard && (identity == nil || *expected != *identity || !toolbroker.ValidWorkspaceVolume(v.JobID, *expected, true)) {
		return v, errors.New("workspace disposal binding changed")
	}
	observed, err := toolbroker.RemoveWorkspaceVolume(ctx, runner, v.JobID, v.Pair.Repository, root, identity, discard)
	if v.Pair.Workspace != nil {
		copy := *v.Pair.Workspace
		if observed != nil {
			copy.Identity = *observed
		}
		copy.Removed = err == nil
		v.Pair.Workspace = &copy
	}
	if err != nil {
		return v, errors.New("workspace cleanup unverified")
	}
	return v, nil
}

func sameWorkspaceEvidence(before, after workerJobRecord) bool {
	if before.Pair == nil || after.Pair == nil {
		return before.Pair == nil && after.Pair == nil
	}
	a, b := before.Pair.Workspace, after.Pair.Workspace
	if a == nil || b == nil {
		return a == nil && b == nil
	}
	return a.CreationStarted == b.CreationStarted && a.Identity.Version == b.Identity.Version && a.Identity.Name == b.Identity.Name && a.Identity.Nonce == b.Identity.Nonce && (a.Identity.CreatedAt == "" || a.Identity.CreatedAt == b.Identity.CreatedAt) && (!a.Removed || b.Removed)
}
