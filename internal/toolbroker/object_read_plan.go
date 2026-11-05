package toolbroker

import (
	"commonroom-runtime/internal/objectread"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"path"
	"slices"
	"strings"
	"time"
)

const objectReadExecutable = "/opt/commonroom/object-read"

// ObjectReadContainerPlan describes only the fixed credential-free reader. It
// supplies no lifecycle/capacity/release rights. The supervisor MUST authenticate
// the rootless worker/creator, durably reserve a helper slot and exact ID, fence
// writers, enforce physical quota and current export policy, and confirm exit/
// cleanup before downstream release. Source forks CAN falsify observations; no
// host/SSH execution fallback or optional isolation toggle exists.
type ObjectReadContainerPlan struct {
	request                       objectread.Request
	image, root, encoded, binding string
	objects                       CaptureObjectVolume
}

// ObjectReadIntent is finite immutable journal metadata, not permission to
// execute, read, release storage or bypass mandatory isolated admission.
type ObjectReadIntent struct {
	Request objectread.Request  `json:"request"`
	Image   string              `json:"image"`
	Objects CaptureObjectVolume `json:"objects"`
}

// ValidObjectReadMetadata validates finite identities without inventing a daemon
// root observation. Actual worker, image, quota and release proof remain mandatory.
func ValidObjectReadMetadata(q objectread.Request, image string, objects CaptureObjectVolume) bool {
	created, err := time.Parse(time.RFC3339Nano, objects.CreatedAt)
	raw, marshalErr := json.Marshal(q)
	return objectread.ValidRequest(q) && marshalErr == nil && len(raw) <= 6144 && strings.HasPrefix(image, "sha256:") && digest(strings.TrimPrefix(image, "sha256:"), 32) && objects.Name == "commonroom-custody-"+q.Receipt.Intent.Scope.JobID && digest(objects.Nonce, 16) && err == nil && !created.IsZero() && len(objects.CreatedAt) <= 64
}

func NewObjectReadContainerPlan(q objectread.Request, image, root string, objects CaptureObjectVolume) (*ObjectReadContainerPlan, error) {
	if !ValidObjectReadMetadata(q, image, objects) || !path.IsAbs(root) || path.Clean(root) != root || root == "/" || len(root) > 4096 {
		return nil, ErrRejected
	}
	raw, _ := json.Marshal(q)
	sum := sha256.Sum256(raw)
	return &ObjectReadContainerPlan{request: q, image: image, root: root, encoded: base64.RawURLEncoding.EncodeToString(raw), binding: hex.EncodeToString(sum[:]), objects: objects}, nil
}
func (p *ObjectReadContainerPlan) name() string {
	return "commonroom-read-" + p.request.Receipt.Intent.Scope.JobID + "-" + p.request.Challenge
}
func (p *ObjectReadContainerPlan) labels() map[string]string {
	s := p.request.Receipt.Intent.Scope
	return map[string]string{"commonroom.managed": "true", "commonroom.execution": "object-read-v1", "commonroom.job": s.JobID, "commonroom.repository": s.RepositoryDigest, "commonroom.read": p.binding}
}
func (p *ObjectReadContainerPlan) objectLabels() map[string]string {
	s := p.request.Receipt.Intent.Scope
	return map[string]string{"commonroom.managed": "true", "commonroom.execution": "object-custody-v1", "commonroom.job": s.JobID, "commonroom.repository": s.RepositoryDigest, "commonroom.custody.nonce": p.objects.Nonce}
}

// CreateArgs is fixed policy metadata, never permission to launch a reader.
func (p *ObjectReadContainerPlan) CreateArgs() []string {
	if p == nil {
		return nil
	}
	args := []string{"create", "--pull=never", "--name", p.name(), "--interactive", "--init", "--no-healthcheck", "--ipc=private", "--cgroupns=private", "--network=none", "--read-only", "--user", "1000:1000", "--env", "PATH=/", "--cap-drop=ALL", "--security-opt=no-new-privileges:true", "--pids-limit=16", "--memory=64m", "--memory-swap=64m", "--cpus=0.25", "--ulimit", "nofile=64:64", "--log-driver=none", "--restart=no", "--workdir", "/objects", "--mount", "type=volume,src=" + p.objects.Name + ",dst=/objects,readonly,volume-nocopy", "--entrypoint", objectReadExecutable}
	for _, key := range []string{"commonroom.managed", "commonroom.execution", "commonroom.job", "commonroom.repository", "commonroom.read"} {
		args = append(args, "--label", key+"="+p.labels()[key])
	}
	return append(args, p.image, p.encoded)
}
func (p *ObjectReadContainerPlan) verifyVolume(raw []byte) (toolVolumeInspection, error) {
	var v toolVolumeInspection
	if p == nil || decodeInspection(raw, &v) != nil || v.Name != p.objects.Name || v.Driver != "local" || v.Scope != "local" || v.CreatedAt != p.objects.CreatedAt || v.Mountpoint != path.Join(p.root, "volumes", p.objects.Name, "_data") || len(v.Options) != 0 || !sameMap(v.Labels, p.objectLabels()) {
		return toolVolumeInspection{}, ErrRejected
	}
	return v, nil
}

// VerifyInspection validates actual bounded observations for a durably known exact
// ID. It neither discovers/adopts IDs nor proves quota or current release rights.
func (p *ObjectReadContainerPlan) VerifyInspection(id, phase string, container, objects []byte) error {
	if p == nil || !digest(id, 32) || phase != "created" && phase != "running" && phase != "exited" {
		return ErrRejected
	}
	var c toolInspection
	v, err := p.verifyVolume(objects)
	if err != nil || decodeInspection(container, &c) != nil {
		return ErrRejected
	}
	if c.ID != id || c.Name != "/"+p.name() || c.Image != p.image || c.Config.Image != p.image || !sameMap(c.Config.Labels, p.labels()) || c.RestartCount != 0 || c.State.Status != phase || !isBool(c.State.Running, phase == "running") || !isBool(c.State.Paused, false) || !isBool(c.State.Restarting, false) || !isBool(c.State.Dead, false) || !isBool(c.State.OOMKilled, false) || !isInt(c.State.ExitCode, 0) || c.State.Error != "" {
		return ErrRejected
	}
	if c.Config.User != "1000:1000" || c.Config.WorkingDir != "/objects" || !isBool(c.Config.Tty, false) || !isBool(c.Config.OpenStdin, true) || !isBool(c.Config.StdinOnce, false) || !slices.Equal(c.Config.Env, []string{"PATH=/"}) || !slices.Equal(c.Config.Entrypoint, []string{objectReadExecutable}) || !slices.Equal(c.Config.Cmd, []string{p.encoded}) || !slices.Equal(c.Config.Healthcheck.Test, []string{"NONE"}) || !privateHelperHost(c) || len(c.Mounts) != 1 {
		return ErrRejected
	}
	m := c.Mounts[0]
	if m.Type != "volume" || m.Name != v.Name || m.Source != v.Mountpoint || m.Destination != "/objects" || m.Driver != "local" || !isBool(m.RW, false) || m.Propagation != "" && m.Propagation != "rprivate" {
		return ErrRejected
	}
	return nil
}

// VerifyAdmission performs two independent metadata/reference/catalog passes. Only
// read-only queries are issued; the caller must independently fence writers and
// hold actual creator/account authority throughout. Daemon admins remain trusted.
func (p *ObjectReadContainerPlan) VerifyAdmission(ctx context.Context, runner DockerRunner, id, phase string) error {
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
		v, err := capture("volume", "inspect", "--format", "{{json .}}", p.objects.Name)
		if err != nil || p.VerifyInspection(id, phase, c, v) != nil {
			return ErrRejected
		}
		for _, filter := range []string{"volume=" + p.objects.Name, "label=commonroom.job=" + p.request.Receipt.Intent.Scope.JobID, "name=^/" + p.name() + "$"} {
			raw, err := capture("ps", "-a", "--no-trunc", "--filter", filter, "--format", "{{.ID}}")
			if err != nil || strings.TrimSpace(string(raw)) != id {
				return ErrRejected
			}
		}
		raw, err := capture("volume", "ls", "--filter", "label=commonroom.job="+p.request.Receipt.Intent.Scope.JobID, "--filter", "label=commonroom.execution=object-custody-v1", "--format", "{{.Name}}")
		if err != nil || strings.TrimSpace(string(raw)) != p.objects.Name {
			return ErrRejected
		}
	}
	return child.Err()
}
