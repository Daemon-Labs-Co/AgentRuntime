package toolbroker

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"strings"
	"time"
)

// WorkspaceVolumeIdentity is non-secret creation evidence, not authority. Named
// Docker volumes have no immutable deletion ID; nonce and daemon creation time
// detect replacement, while the worker's exclusive creator lease prevents other
// managed code from replacing the name during verification/removal.
type WorkspaceVolumeIdentity struct {
	Version   int    `json:"version"`
	Name      string `json:"name"`
	Nonce     string `json:"nonce"`
	CreatedAt string `json:"createdAt,omitempty"`
}

func ValidWorkspaceVolume(job string, v WorkspaceVolumeIdentity, created bool) bool {
	if !digest(job, 16) || v.Version != 1 || v.Name != "commonroom-tool-work-"+job || !digest(v.Nonce, 16) {
		return false
	}
	if !created {
		return v.CreatedAt == ""
	}
	timestamp, err := time.Parse(time.RFC3339Nano, v.CreatedAt)
	return err == nil && !timestamp.IsZero() && len(v.CreatedAt) <= 64
}

// WorkspaceIntent mints the identity that MUST be durably journalled before
// PrepareVolume. It accepts no model names, paths, mounts, labels or driver flags.
func (p *ToolContainerPlan) WorkspaceIntent(now time.Time) (WorkspaceVolumeIdentity, error) {
	if _, err := p.RunArgs(now); err != nil {
		return WorkspaceVolumeIdentity{}, err
	}
	if existing := p.volume.Load(); existing != nil {
		if existing.CreatedAt != "" {
			return WorkspaceVolumeIdentity{}, ErrRejected
		}
		return *existing, nil
	}
	var nonce [16]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return WorkspaceVolumeIdentity{}, ErrRejected
	}
	intent := WorkspaceVolumeIdentity{Version: 1, Name: p.WorkspaceVolume(), Nonce: hex.EncodeToString(nonce[:])}
	if !p.volume.CompareAndSwap(nil, &intent) {
		return p.WorkspaceIntent(now)
	}
	return intent, nil
}
func (p *ToolContainerPlan) volumeLabels(identity WorkspaceVolumeIdentity) map[string]string {
	labels := p.labels()
	labels["commonroom.workspace.nonce"] = identity.Nonce
	return labels
}
func (p *ToolContainerPlan) verifyVolumeIdentity(v toolVolumeInspection, identity WorkspaceVolumeIdentity, root string) error {
	if !ValidWorkspaceVolume(p.authority.scope.JobID, identity, true) || v.CreatedAt != identity.CreatedAt {
		return ErrRejected
	}
	if p.verifyVolumeShape(v, root, p.volumeLabels(identity)) != nil {
		return ErrRejected
	}
	return nil
}

// PrepareVolume refuses existing volumes and attempts creation once. The worker
// must hold creator/admission ownership and journal intent before entering here.
// Any daemon/receipt/inspection failure is uncertain; it never adopts, deletes or
// retries the name. No automatic reconciliation or host directory mount exists.
func (r *ToolContainerRuntime) PrepareVolume(ctx context.Context, intent WorkspaceVolumeIdentity) (WorkspaceVolumeIdentity, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.volumeAttempted || r.attempted {
		return WorkspaceVolumeIdentity{}, ErrRejected
	}
	child, cancel, err := r.context(ctx)
	if err != nil {
		return WorkspaceVolumeIdentity{}, err
	}
	defer cancel()
	p := r.executor.plan
	bound := p.volume.Load()
	if bound == nil || *bound != intent || !ValidWorkspaceVolume(p.authority.scope.JobID, intent, false) {
		return WorkspaceVolumeIdentity{}, ErrRejected
	}
	r.volumeAttempted = true
	raw, err := r.executor.capture(child, []string{"volume", "ls", "--filter", "name=^" + intent.Name + "$", "--format", "{{.Name}}"}, 8192)
	if err != nil || strings.TrimSpace(string(raw)) != "" {
		return WorkspaceVolumeIdentity{}, ErrRejected
	}
	args, err := p.VolumeCreateArgs(time.Now())
	if err != nil {
		return WorkspaceVolumeIdentity{}, err
	}
	raw, err = r.executor.capture(child, args, 8192)
	if err != nil || strings.TrimSpace(string(raw)) != intent.Name {
		return WorkspaceVolumeIdentity{}, ErrExecution
	}
	raw, err = r.executor.capture(child, []string{"volume", "inspect", "--format", "{{json .}}", intent.Name}, MaxInspectionBytes)
	var observed toolVolumeInspection
	if err != nil || decodeInspection(raw, &observed) != nil {
		return WorkspaceVolumeIdentity{}, ErrRejected
	}
	identity := intent
	identity.CreatedAt = observed.CreatedAt
	if p.verifyVolumeIdentity(observed, identity, r.executor.dockerRoot) != nil {
		return WorkspaceVolumeIdentity{}, ErrRejected
	}
	if child.Err() != nil || r.lifetime.Err() != nil {
		return WorkspaceVolumeIdentity{}, ErrRejected
	}
	p.volume.Store(&identity)
	r.volumePrepared = true
	return identity, nil
}
