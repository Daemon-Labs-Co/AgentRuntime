package workerport

import (
	"commonroom-runtime/internal/toolbroker"
	"context"
	"errors"
	"io"
	"strings"
)

const workerPairVersion = 1

const workerPairLifecycleVersion = 3

const workerPairExecution = "separated-pair-v1"

const workerWorkspaceLifecycleVersion = 4

const workerWorkspaceExecution = "separated-pair-workspace-v1"

func pairedLifecycleVersion(version int) bool {
	return version == workerPairLifecycleVersion || version == workerWorkspaceLifecycleVersion
}

func pairExecution(version int) string {
	if version == workerWorkspaceLifecycleVersion {
		return workerWorkspaceExecution
	}
	return workerPairExecution
}

// workerPairRecord is additive, explicitly versioned lifecycle evidence, not an
// execution capability. Both roles share one job lease and the old logical-job
// admission slot. Actual engine/tool resource policy still needs launch verification.
// No provider, token, command or host path belongs here.
// A source fork CAN skip creation journalling, BUT invalidates crash recovery.
type workerPairRecord struct {
	Version    int                  `json:"version"`
	Repository string               `json:"repository"`
	Engine     workerPairContainer  `json:"engine"`
	Tool       workerPairContainer  `json:"tool"`
	Workspace  *workerPairWorkspace `json:"workspace,omitempty"`
}

type workerPairWorkspace struct {
	CreationStarted bool                               `json:"creationStarted"`
	Identity        toolbroker.WorkspaceVolumeIdentity `json:"identity"`
	Removed         bool                               `json:"removed"`
}

type workerPairContainer struct {
	CreationStarted bool   `json:"creationStarted"`
	ID              string `json:"id,omitempty"`
	Absent          bool   `json:"absent"`
}

func pairContainerName(job, role string) string { return "commonroom-" + role + "-" + job }

func validPairContainerID(id string) bool {
	return len(id) == 64 && repositoryDigestPattern.MatchString(id)
}

func validWorkerPair(v workerJobRecord) bool {
	if v.Execution == "" {
		return v.Pair == nil && !pairedLifecycleVersion(v.Version)
	}
	if !pairedLifecycleVersion(v.Version) || v.Execution != pairExecution(v.Version) || v.Pair == nil {
		return false
	}
	p := v.Pair
	if p.Version != workerPairVersion || !repositoryDigestPattern.MatchString(p.Repository) {
		return false
	}
	if v.Version == workerPairLifecycleVersion && p.Workspace != nil {
		return false
	}
	if workspace := p.Workspace; workspace != nil {
		if !workspace.CreationStarted || !toolbroker.ValidWorkspaceVolume(v.JobID, workspace.Identity, workspace.Identity.CreatedAt != "") {
			return false
		}
		if workspace.Removed && !workspace.CreationStarted {
			return false
		}
	}
	if v.Version == workerWorkspaceLifecycleVersion && v.Status == "running" && (p.Workspace == nil || p.Workspace.Identity.CreatedAt == "" || p.Workspace.Removed) {
		return false
	}
	if v.ShutdownConfirmed && p.Workspace != nil && !p.Workspace.Removed {
		return false
	}
	for _, c := range []workerPairContainer{p.Engine, p.Tool} {
		if c.ID != "" && (!c.CreationStarted || !validPairContainerID(c.ID)) {
			return false
		}
		if c.Absent && !c.CreationStarted {
			return false
		}
	}
	if p.Engine.ID != "" && p.Engine.ID == p.Tool.ID {
		return false
	}
	if v.Status == "running" && (p.Engine.ID == "" || p.Tool.ID == "" || p.Engine.Absent || p.Tool.Absent) {
		return false
	}
	if v.ShutdownConfirmed && (!pairRoleSettled(p.Engine) || !pairRoleSettled(p.Tool)) {
		return false
	}
	return true
}

func pairRoleSettled(c workerPairContainer) bool { return !c.CreationStarted || c.Absent }

// pairCapture never interprets shell input, inherits credentials or returns raw
// diagnostics. The production runner revalidates the approved rootless daemon.
func pairCapture(ctx context.Context, runner toolbroker.DockerRunner, args []string) (string, error) {
	if ctx == nil || ctx.Err() != nil || runner == nil {
		return "", errors.New("pair runtime unavailable")
	}
	child, cancel := context.WithCancel(ctx)
	defer cancel()
	out := &workerPairOutput{cancel: cancel}
	err := runner.Run(child, args, nil, out)
	if err != nil || child.Err() != nil || out.overflow {
		return "", errors.New("pair runtime observation failed")
	}
	return strings.TrimSpace(out.data.String()), nil
}

type workerPairOutput struct {
	data     strings.Builder
	cancel   context.CancelFunc
	overflow bool
}

func (w *workerPairOutput) Write(p []byte) (int, error) {
	if w.data.Len()+len(p) > 8192 {
		w.overflow = true
		w.cancel()
		return 0, io.ErrShortBuffer
	}
	return w.data.Write(p)
}

func pairInventory(ctx context.Context, runner toolbroker.DockerRunner, filter string) (string, error) {
	raw, err := pairCapture(ctx, runner, []string{"ps", "-a", "--no-trunc", "--filter", filter, "--format", "{{.ID}}"})
	if err != nil {
		return "", err
	}
	if raw != "" && !validPairContainerID(raw) {
		return "", errors.New("ambiguous pair inventory")
	}
	return raw, nil
}

func inspectPairIdentity(ctx context.Context, runner toolbroker.DockerRunner, v workerJobRecord, role, id string) error {
	format := `{{.Id}}|{{.Name}}|{{index .Config.Labels "commonroom.managed"}}|{{index .Config.Labels "commonroom.job"}}|{{index .Config.Labels "commonroom.execution"}}|{{index .Config.Labels "commonroom.repository"}}`
	got, err := pairCapture(ctx, runner, []string{"inspect", "--type", "container", "--format", format, id})
	expected := id + "|/" + pairContainerName(v.JobID, role) + "|true|" + v.JobID + "|separated-" + role + "-v1|" + v.Pair.Repository
	if err != nil || got != expected {
		return errors.New("pair container binding unverified")
	}
	return nil
}

// stopWorkerPair attempts both roles even if one fails. Docker errors/EOF are
// never absence proof. Missing IDs from a create/journal crash are discovered by
// fixed name, inspected for exact role/job/digest, then removed by immutable ID.
// Callers must also wait for the supervisor lease; this function alone cannot
// prove a still-running creator won't launch later. It grants no restart authority.
func stopWorkerPair(ctx context.Context, v workerJobRecord, runner toolbroker.DockerRunner) (workerJobRecord, error) {
	if v.Pair == nil || !validWorkerPair(v) || !validWorkerJobID(v.JobID) {
		return v, errors.New("invalid pair shutdown binding")
	}
	pair := *v.Pair
	v.Pair = &pair
	var failed bool
	for _, role := range []string{"engine", "tool"} {
		current := &pair.Engine
		if role == "tool" {
			current = &pair.Tool
		}
		// Check fixed-name collisions even for a role whose creation never began.
		byName, err := pairInventory(ctx, runner, "name=^/"+pairContainerName(v.JobID, role)+"$")
		if err != nil {
			failed = true
			continue
		}
		id := current.ID
		if byName != "" {
			if id != "" && id != byName {
				failed = true
				continue
			}
			if !current.CreationStarted || inspectPairIdentity(ctx, runner, v, role, byName) != nil {
				failed = true
				continue
			}
			id = byName
			current.ID = id
		}
		if id != "" {
			if err := toolbroker.StopContainer(ctx, runner, id, func(ctx context.Context, id string) error {
				return inspectPairIdentity(ctx, runner, v, role, id)
			}); err != nil {
				failed = true
				continue
			}
		}
		// Name reuse must not be converted into absence of this role.
		if remaining, err := pairInventory(ctx, runner, "name=^/"+pairContainerName(v.JobID, role)+"$"); err != nil || remaining != "" {
			failed = true
			continue
		}
		if current.CreationStarted {
			current.Absent = true
		}
	}
	// No extra managed container with this job label may survive unnoticed.
	if remaining, err := pairCapture(ctx, runner, []string{"ps", "-a", "--no-trunc", "--filter", "label=commonroom.job=" + v.JobID, "--format", "{{.ID}}"}); err != nil || remaining != "" {
		failed = true
	}
	if failed {
		return v, errors.New("pair shutdown unverified")
	}
	if v.Version == workerWorkspaceLifecycleVersion {
		return stopWorkerWorkspace(ctx, v, runner)
	}
	return v, nil
}

// Pair acknowledgements bind execution kind and repository as well as scope.
// Version-2 replies cannot settle a version-3 cancellation request.
type workerFenceAck struct {
	DiscardedWorkspace    *toolbroker.WorkspaceVolumeIdentity `json:"discardedWorkspace,omitempty"`
	Version               int                                 `json:"version"`
	JobID                 string                              `json:"jobId"`
	Scope                 string                              `json:"scope"`
	Stopped               bool                                `json:"stopped"`
	CancellationRequested bool                                `json:"cancellationRequested"`
	Execution             string                              `json:"execution,omitempty"`
	Repository            string                              `json:"repository,omitempty"`
	WorkspaceRemoved      bool                                `json:"workspaceRemoved,omitempty"`
}

func workerFenceAcknowledgement(request workerFenceRequest, record workerJobRecord) workerFenceAck {
	ack := workerFenceAck{Version: request.Version, JobID: record.JobID, Scope: record.Scope, Stopped: record.ShutdownConfirmed, CancellationRequested: true, Execution: record.Execution}
	if record.Pair != nil {
		ack.Repository = record.Pair.Repository
	}
	if request.Version == workerWorkspaceLifecycleVersion {
		ack.WorkspaceRemoved = record.ShutdownConfirmed && record.Pair != nil && (record.Pair.Workspace == nil || record.Pair.Workspace.Removed)
	}
	if request.DiscardWorkspace && ack.WorkspaceRemoved && matchesWorkspaceDisposal(request, record) {
		copy := record.Pair.Workspace.Identity
		ack.DiscardedWorkspace = &copy
	}
	return ack
}

// Versions 3/4 cannot be interpreted as a version-2 single job; version 4
// additionally prevents old container-only readers ignoring workspace cleanup.
// Reuse common scalar validation only after checking the actual pair evidence.
func validWorkerRecord(v workerJobRecord) bool {
	if v.Version == workerLifecycleVersion {
		return validV2WorkerRecord(v)
	}
	if !pairedLifecycleVersion(v.Version) || v.Pair == nil || !validWorkerPair(v) {
		return false
	}
	base := v
	base.Version = workerLifecycleVersion
	base.Pair = nil
	base.Execution = ""
	return validV2WorkerRecord(base)
}
