package toolbroker

import (
	"commonroom-runtime/internal/workspacecapture"
	"context"
	"encoding/base64"
	"encoding/json"
	"path"
	"slices"
	"strings"
	"time"
)

const captureExecutable = "/opt/commonroom/workspace-capture"

// CaptureObjectVolume is retained creation metadata, not storage authorization.
// A trusted supervisor MUST independently prove physical quotas, exclusive creator
// ownership and current custody authorization. Docker labels cannot prove those.
type CaptureObjectVolume struct{ Name, Nonce, CreatedAt string }

// CaptureContainerPlan admits only the reviewed, credential-free capture helper.
// It does not launch containers or confer authority. A future runtime MUST journal
// creation and exact IDs, authenticate its private stream, fence other writers,
// enforce physical storage quotas, and verify exit/cleanup before report release.
// Source forks CAN fake inspection/provenance, BUT invalidate isolation guarantees.
// No host/SSH execution or mount fallback exists and this boundary has no toggle.
type CaptureContainerPlan struct {
	request                       workspacecapture.Request
	image, root, encoded, binding string
	source                        WorkspaceVolumeIdentity
	objects                       CaptureObjectVolume
}

// ValidCaptureMetadata checks finite identities only, never daemon/root provenance,
// physical quotas or execution authority. Durable journal replay uses this without
// inventing an observed Docker data root.
func ValidCaptureMetadata(request workspacecapture.Request, image string, objects CaptureObjectVolume) bool {
	_, _, err := captureMetadata(request, image, objects)
	return err == nil
}
func captureMetadata(request workspacecapture.Request, image string, objects CaptureObjectVolume) (string, []byte, error) {
	binding, err := workspacecapture.RequestDigest(request)
	if err != nil {
		return "", nil, ErrRejected
	}
	job := request.Binding.Execution.JobID
	source := WorkspaceVolumeIdentity{Version: 1, Name: request.Binding.VolumeName, Nonce: request.Binding.VolumeNonce, CreatedAt: request.Binding.VolumeCreatedAt}
	created, timeErr := time.Parse(time.RFC3339Nano, objects.CreatedAt)
	raw, marshalErr := json.Marshal(request)
	if marshalErr != nil || len(raw) > 48*1024 || !ValidWorkspaceVolume(job, source, true) || !strings.HasPrefix(image, "sha256:") || !digest(strings.TrimPrefix(image, "sha256:"), 32) || objects.Name != "commonroom-custody-"+job || !digest(objects.Nonce, 16) || timeErr != nil || created.IsZero() || len(objects.CreatedAt) > 64 {
		return "", nil, ErrRejected
	}
	return binding, raw, nil
}
func NewCaptureContainerPlan(request workspacecapture.Request, image, root string, objects CaptureObjectVolume) (*CaptureContainerPlan, error) {
	binding, raw, err := captureMetadata(request, image, objects)
	if err != nil || !path.IsAbs(root) || path.Clean(root) != root || root == "/" || len(root) > 4096 {
		return nil, ErrRejected
	}
	source := WorkspaceVolumeIdentity{Version: 1, Name: request.Binding.VolumeName, Nonce: request.Binding.VolumeNonce, CreatedAt: request.Binding.VolumeCreatedAt}
	request.Members = slices.Clone(request.Members)
	return &CaptureContainerPlan{request: request, image: image, root: root, encoded: base64.RawURLEncoding.EncodeToString(raw), binding: binding, source: source, objects: objects}, nil
}
func (p *CaptureContainerPlan) name() string {
	return "commonroom-capture-" + p.request.Binding.Execution.JobID + "-" + p.request.Challenge
}
func (p *CaptureContainerPlan) labels() map[string]string {
	return map[string]string{"commonroom.managed": "true", "commonroom.execution": "workspace-capture-v1", "commonroom.job": p.request.Binding.Execution.JobID, "commonroom.repository": p.request.Binding.Execution.RepositoryDigest, "commonroom.capture": p.binding}
}
func (p *CaptureContainerPlan) objectLabels() map[string]string {
	return map[string]string{"commonroom.managed": "true", "commonroom.execution": "object-custody-v1", "commonroom.job": p.request.Binding.Execution.JobID, "commonroom.repository": p.request.Binding.Execution.RepositoryDigest, "commonroom.custody.nonce": p.objects.Nonce}
}

// CreateArgs describes fixed policy only; it MUST NOT be launched without the
// durable supervised lifecycle described on CaptureContainerPlan.
func (p *CaptureContainerPlan) CreateArgs() []string {
	if p == nil {
		return nil
	}
	args := []string{"create", "--pull=never", "--name", p.name(), "--interactive", "--init", "--no-healthcheck", "--ipc=private", "--cgroupns=private", "--network=none", "--read-only", "--user", "1000:1000", "--env", "PATH=/", "--cap-drop=ALL", "--security-opt=no-new-privileges:true", "--pids-limit=16", "--memory=64m", "--memory-swap=64m", "--cpus=0.25", "--ulimit", "nofile=64:64", "--log-driver=none", "--restart=no", "--workdir", "/workspace", "--mount", "type=volume,src=" + p.source.Name + ",dst=/workspace,readonly,volume-nocopy", "--mount", "type=volume,src=" + p.objects.Name + ",dst=/objects,volume-nocopy", "--entrypoint", captureExecutable}
	for _, key := range []string{"commonroom.managed", "commonroom.execution", "commonroom.job", "commonroom.repository", "commonroom.capture"} {
		args = append(args, "--label", key+"="+p.labels()[key])
	}
	return append(args, p.image, p.encoded)
}

// VerifyInspection checks directly fetched, bounded Docker metadata for a durably
// recorded exact ID. phase is created, running or exited; unknown phases fail.
// Repeated physical inventory/current-authority checks are still mandatory: this
// pure validator cannot exclude other mounts or races by daemon administrators.
func (p *CaptureContainerPlan) VerifyInspection(id, phase string, container, source, objects []byte) error {
	if p == nil || !digest(id, 32) || phase != "created" && phase != "running" && phase != "exited" {
		return ErrRejected
	}
	var c toolInspection
	var src, obj toolVolumeInspection
	if decodeInspection(container, &c) != nil || decodeInspection(source, &src) != nil || decodeInspection(objects, &obj) != nil {
		return ErrRejected
	}
	if _, _, err := p.verifyVolumes(source, objects); err != nil {
		return err
	}

	if c.ID != id || c.Name != "/"+p.name() || c.Image != p.image || c.Config.Image != p.image || !sameMap(c.Config.Labels, p.labels()) || c.RestartCount != 0 || c.State.Status != phase || !isBool(c.State.Running, phase == "running") || !isBool(c.State.Paused, false) || !isBool(c.State.Restarting, false) || !isBool(c.State.Dead, false) || !isBool(c.State.OOMKilled, false) || !isInt(c.State.ExitCode, 0) || c.State.Error != "" {
		return ErrRejected
	}
	if c.Config.User != "1000:1000" || c.Config.WorkingDir != "/workspace" || !isBool(c.Config.Tty, false) || !isBool(c.Config.OpenStdin, true) || !isBool(c.Config.StdinOnce, false) || !slices.Equal(c.Config.Env, []string{"PATH=/"}) || !slices.Equal(c.Config.Entrypoint, []string{captureExecutable}) || !slices.Equal(c.Config.Cmd, []string{p.encoded}) || !slices.Equal(c.Config.Healthcheck.Test, []string{"NONE"}) {
		return ErrRejected
	}
	if !privateHelperHost(c) || len(c.Mounts) != 2 {
		return ErrRejected
	}
	seen := map[string]bool{}
	for _, m := range c.Mounts {
		v := src
		writable := false
		if m.Destination == "/objects" {
			v = obj
			writable = true
		} else if m.Destination != "/workspace" {
			return ErrRejected
		}
		if seen[m.Destination] || m.Type != "volume" || m.Name != v.Name || m.Source != v.Mountpoint || m.Driver != "local" || !isBool(m.RW, writable) || m.Propagation != "" && m.Propagation != "rprivate" {
			return ErrRejected
		}
		seen[m.Destination] = true
	}
	return nil
}

// VerifyAdmission fetches independent metadata and reference inventories twice.
// The trusted caller MUST hold exclusive creator ownership throughout, authenticate
// the approved rootless runner, and independently enforce quota/current policy.
// No creation, execution, adoption, removal or storage release occurs here.
func (p *CaptureContainerPlan) VerifyAdmission(ctx context.Context, runner DockerRunner, id, phase string) error {
	if p == nil || ctx == nil || ctx.Err() != nil || missingProbeDependency(runner) || !digest(id, 32) || phase != "created" && phase != "running" && phase != "exited" {
		return ErrRejected
	}
	child, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	capture := func(args ...string) ([]byte, error) {
		return (&ContainerExecutor{runner: runner}).capture(child, args, MaxInspectionBytes)
	}
	for pass := 0; pass < 2; pass++ {
		c, err := capture("inspect", "--type", "container", "--format", "{{json .}}", id)
		if err != nil {
			return ErrRejected
		}
		src, err := capture("volume", "inspect", "--format", "{{json .}}", p.source.Name)
		if err != nil {
			return ErrRejected
		}
		obj, err := capture("volume", "inspect", "--format", "{{json .}}", p.objects.Name)
		if err != nil || p.VerifyInspection(id, phase, c, src, obj) != nil {
			return ErrRejected
		}
		for _, filter := range []string{"volume=" + p.source.Name, "volume=" + p.objects.Name, "label=commonroom.job=" + p.request.Binding.Execution.JobID, "name=^/" + p.name() + "$"} {
			raw, err := capture("ps", "-a", "--no-trunc", "--filter", filter, "--format", "{{.ID}}")
			if err != nil || strings.TrimSpace(string(raw)) != id {
				return ErrRejected
			}
		}
		for execution, name := range map[string]string{"separated-tool-v1": p.source.Name, "object-custody-v1": p.objects.Name} {
			raw, err := capture("volume", "ls", "--filter", "label=commonroom.job="+p.request.Binding.Execution.JobID, "--filter", "label=commonroom.execution="+execution, "--format", "{{.Name}}")
			if err != nil || strings.TrimSpace(string(raw)) != name {
				return ErrRejected
			}
		}
	}
	return child.Err()
}

func (p *CaptureContainerPlan) verifyVolumes(source, objects []byte) (src, obj toolVolumeInspection, err error) {
	if decodeInspection(source, &src) != nil || decodeInspection(objects, &obj) != nil {
		return src, obj, ErrRejected
	}
	if !validObservedWorkspaceVolume(src, p.request.Binding.Execution.JobID, p.request.Binding.Execution.RepositoryDigest, p.root, p.source) || obj.Name != p.objects.Name || obj.Driver != "local" || obj.Scope != "local" || obj.CreatedAt != p.objects.CreatedAt || obj.Mountpoint != path.Join(p.root, "volumes", p.objects.Name, "_data") || len(obj.Options) != 0 || !sameMap(obj.Labels, p.objectLabels()) {
		return src, obj, ErrRejected
	}
	return src, obj, nil
}

// privateHelperHost verifies common credential-free helper limits, not image, mounts or authority.
func privateHelperHost(c toolInspection) bool {
	h := c.HostConfig
	if !isBool(h.Privileged, false) || !isBool(h.ReadonlyRootfs, true) || !isBool(h.Init, true) || !isBool(h.AutoRemove, false) || h.RestartPolicy.Name != "no" || h.NetworkMode != "none" || h.PidMode != "" || h.IpcMode != "private" || h.CgroupnsMode != "private" || h.UsernsMode != "" || !isInt(h.Memory, probeMemory) || !isInt(h.MemorySwap, probeMemory) || !isInt(h.NanoCpus, 250000000) || !isInt(h.PidsLimit, 16) || !slices.Equal(h.CapDrop, []string{"ALL"}) || len(h.CapAdd) != 0 || !slices.Equal(h.SecurityOpt, []string{"no-new-privileges:true"}) {
		return false
	}
	if len(h.Binds) != 0 || len(h.VolumesFrom) != 0 || len(h.Devices) != 0 || len(h.DeviceRequests) != 0 || len(h.PortBindings) != 0 || len(h.Tmpfs) != 0 || h.LogConfig.Type != "none" || len(h.LogConfig.Config) != 0 || len(h.Ulimits) != 1 || h.Ulimits[0].Name != "nofile" || h.Ulimits[0].Soft != 64 || h.Ulimits[0].Hard != 64 {
		return false
	}

	return true
}
