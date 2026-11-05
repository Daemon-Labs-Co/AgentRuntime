package toolbroker

import (
	"bytes"
	"commonroom-runtime/internal/workspacemount"
	"context"
	"encoding/json"
	"errors"
	"path"
	"reflect"
	"slices"
	"strings"
	"sync/atomic"
	"time"
)

const probeExecutable = "/opt/commonroom/workspace-mount-probe"
const probeMemory int64 = 64 * 1024 * 1024

// WorkspaceProbeIntent is trusted worker metadata, never model launch input.
// The challenge is a fresh non-secret per-observation nonce, not a capability.
type WorkspaceProbeIntent struct {
	JobID, Repository, Image, Challenge string
	Volume                              WorkspaceVolumeIdentity
}

// WorkspaceProbeJournal MUST authenticate current authority, hold creator
// ownership and reserve a physical container slot plus durable creation intent
// before Begin succeeds. Bound journals the exact ID before execution. Finish
// durably records observed absence/uncertainty and rechecks current authority
// before proof release. Failure must trip controller integrity stop as required.
// Finish receives an empty ID and absent=false when creation identity is unknown.
// No production journal/authority assembly or default implementation exists.
type WorkspaceProbeJournal interface {
	Begin(context.Context, WorkspaceProbeIntent) error
	Bound(context.Context, WorkspaceProbeIntent, string) error
	Finish(context.Context, WorkspaceProbeIntent, string, bool) error
}

// WorkspaceMountProbe is a one-shot isolated metadata observer, not a source
// exporter or FrozenLease. Only the reviewed credential-free scratch image may
// be supplied. runner MUST target the approved rootless daemon on every call.
// Source forks CAN provide dishonest runners/journals, BUT invalidate isolation.
// There is no host execution or mount fallback, and no source bytes are read.
type WorkspaceMountProbe struct {
	intent    WorkspaceProbeIntent
	runner    DockerRunner
	journal   WorkspaceProbeJournal
	root      string
	attempted atomic.Bool
}

func NewWorkspaceMountProbe(intent WorkspaceProbeIntent, runner DockerRunner, journal WorkspaceProbeJournal, dockerRoot string) (*WorkspaceMountProbe, error) {
	if !digest(intent.JobID, 16) || !digest(intent.Repository, 32) || !strings.HasPrefix(intent.Image, "sha256:") || !digest(strings.TrimPrefix(intent.Image, "sha256:"), 32) || !workspacemount.ValidChallenge(intent.Challenge) || !ValidWorkspaceVolume(intent.JobID, intent.Volume, true) || missingProbeDependency(runner) || missingProbeDependency(journal) || !path.IsAbs(dockerRoot) || path.Clean(dockerRoot) != dockerRoot || dockerRoot == "/" || len(dockerRoot) > 4096 {
		return nil, ErrRejected
	}
	return &WorkspaceMountProbe{intent: intent, runner: runner, journal: journal, root: dockerRoot}, nil
}
func missingProbeDependency(v any) bool {
	if v == nil {
		return true
	}
	r := reflect.ValueOf(v)
	switch r.Kind() {
	case reflect.Pointer, reflect.Map, reflect.Func, reflect.Chan, reflect.Interface, reflect.Slice:
		return r.IsNil()
	}
	return false
}
func (p *WorkspaceMountProbe) name() string {
	return "commonroom-export-" + p.intent.JobID + "-" + p.intent.Challenge
}
func (p *WorkspaceMountProbe) labels() map[string]string {
	return map[string]string{"commonroom.managed": "true", "commonroom.execution": "workspace-mount-probe-v1", "commonroom.job": p.intent.JobID, "commonroom.repository": p.intent.Repository, "commonroom.probe": p.intent.Challenge}
}
func (p *WorkspaceMountProbe) createArgs() []string {
	args := []string{"create", "--pull=never", "--name", p.name(), "--init", "--no-healthcheck", "--ipc=private", "--cgroupns=private", "--network=none", "--read-only", "--user", "1000:1000", "--env", "PATH=/", "--cap-drop=ALL", "--security-opt=no-new-privileges:true", "--pids-limit=16", "--memory=64m", "--memory-swap=64m", "--cpus=0.25", "--ulimit", "nofile=64:64", "--log-driver=none", "--restart=no", "--workdir", "/workspace", "--mount", "type=volume,src=" + p.intent.Volume.Name + ",dst=/workspace,readonly,volume-nocopy", "--entrypoint", probeExecutable}
	for _, key := range []string{"commonroom.managed", "commonroom.execution", "commonroom.job", "commonroom.repository", "commonroom.probe"} {
		args = append(args, "--label", key+"="+p.labels()[key])
	}
	return append(args, p.intent.Image, p.intent.Challenge)
}
func (p *WorkspaceMountProbe) capture(ctx context.Context, args []string, max int) ([]byte, error) {
	return (&ContainerExecutor{runner: p.runner}).capture(ctx, args, max)
}
func (p *WorkspaceMountProbe) inspect(ctx context.Context, id string) (toolInspection, error) {
	raw, err := p.capture(ctx, []string{"inspect", "--type", "container", "--format", "{{json .}}", id}, MaxInspectionBytes)
	var c toolInspection
	if err != nil || decodeInspection(raw, &c) != nil || c.ID != id || c.Name != "/"+p.name() || c.Config.Image != p.intent.Image || c.Image != p.intent.Image || !sameMap(c.Config.Labels, p.labels()) {
		return c, ErrRejected
	}
	return c, nil
}
func (p *WorkspaceMountProbe) verify(ctx context.Context, id string, exited bool) error {
	c, err := p.inspect(ctx, id)
	if err != nil {
		return err
	}
	raw, err := p.capture(ctx, []string{"volume", "inspect", "--format", "{{json .}}", p.intent.Volume.Name}, MaxInspectionBytes)
	var v toolVolumeInspection
	if err != nil || decodeInspection(raw, &v) != nil || !validObservedWorkspaceVolume(v, p.intent.JobID, p.intent.Repository, p.root, p.intent.Volume) {
		return ErrRejected
	}
	status := "created"
	if exited {
		status = "exited"
	}
	if c.State.Status != status || !isBool(c.State.Running, false) || !isBool(c.State.Paused, false) || !isBool(c.State.Restarting, false) || !isBool(c.State.Dead, false) || !isBool(c.State.OOMKilled, false) || !isInt(c.State.ExitCode, 0) || c.State.Error != "" || c.RestartCount != 0 {
		return ErrRejected
	}
	if c.Config.User != "1000:1000" || c.Config.WorkingDir != "/workspace" || !isBool(c.Config.Tty, false) || !isBool(c.Config.OpenStdin, false) || !isBool(c.Config.StdinOnce, false) || !slices.Equal(c.Config.Env, []string{"PATH=/"}) || !slices.Equal(c.Config.Entrypoint, []string{probeExecutable}) || !slices.Equal(c.Config.Cmd, []string{p.intent.Challenge}) || !slices.Equal(c.Config.Healthcheck.Test, []string{"NONE"}) {
		return ErrRejected
	}
	h := c.HostConfig
	if !isBool(h.Privileged, false) || !isBool(h.ReadonlyRootfs, true) || !isBool(h.Init, true) || !isBool(h.AutoRemove, false) || h.RestartPolicy.Name != "no" || h.NetworkMode != "none" || h.PidMode != "" || h.IpcMode != "private" || h.CgroupnsMode != "private" || h.UsernsMode != "" || !isInt(h.Memory, probeMemory) || !isInt(h.MemorySwap, probeMemory) || !isInt(h.NanoCpus, 250000000) || !isInt(h.PidsLimit, 16) || !slices.Equal(h.CapDrop, []string{"ALL"}) || len(h.CapAdd) != 0 || !slices.Equal(h.SecurityOpt, []string{"no-new-privileges:true"}) {
		return ErrRejected
	}
	if len(h.Binds) != 0 || len(h.VolumesFrom) != 0 || len(h.Devices) != 0 || len(h.DeviceRequests) != 0 || len(h.PortBindings) != 0 || len(h.Tmpfs) != 0 || h.LogConfig.Type != "none" || len(h.LogConfig.Config) != 0 || len(h.Ulimits) != 1 || h.Ulimits[0].Name != "nofile" || h.Ulimits[0].Soft != 64 || h.Ulimits[0].Hard != 64 || len(c.Mounts) != 1 {
		return ErrRejected
	}
	m := c.Mounts[0]
	if m.Type != "volume" || m.Name != p.intent.Volume.Name || m.Source != v.Mountpoint || m.Destination != "/workspace" || m.Driver != "local" || !isBool(m.RW, false) || (m.Propagation != "" && m.Propagation != "rprivate") {
		return ErrRejected
	}
	return nil
}

// Run withholds reports until the helper exits successfully, its exact ID is
// removed/observed absent, and final durable journal/current-authority checks pass.
// Lost create replies retain uncertainty; names are never adopted or retried.
// Cleanup uses a fresh bounded context while the caller must keep creator
// ownership held. This returns no live mount/root or enduring frozen capability.
func (p *WorkspaceMountProbe) Run(ctx context.Context) (proof workspacemount.Proof, err error) {
	if p == nil || ctx == nil || ctx.Err() != nil || !p.attempted.CompareAndSwap(false, true) {
		return proof, ErrRejected
	}
	child, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	if err = p.journal.Begin(child, p.intent); err != nil {
		return proof, err
	}
	id := ""
	defer func() {
		cleanup, cancelCleanup := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancelCleanup()
		// An empty ID retains uncertainty; never adopt or remove by name.
		removal := error(ErrShutdownUnconfirmed)
		if id != "" {
			removal = StopContainer(cleanup, p.runner, id, func(c context.Context, actual string) error { _, e := p.inspect(c, actual); return e })
		}
		finish := p.journal.Finish(cleanup, p.intent, id, removal == nil)
		err = errors.Join(err, removal, finish, ctx.Err(), child.Err())
		if err != nil {
			proof = workspacemount.Proof{}
		}
	}()
	inventory, e := p.capture(child, []string{"ps", "-a", "--no-trunc", "--filter", "name=^/" + p.name() + "$", "--format", "{{.ID}}"}, 8192)
	if e != nil || len(bytes.TrimSpace(inventory)) != 0 {
		return proof, ErrRejected
	}
	raw, e := p.capture(child, p.createArgs(), 8192)
	createdID := strings.TrimSpace(string(raw))
	if e != nil || !digest(createdID, 32) {
		return proof, ErrRejected
	}

	id = createdID
	if err = p.verify(child, id, false); err != nil {
		return proof, err
	}
	if err = p.journal.Bound(child, p.intent, id); err != nil {
		return proof, err
	}
	raw, err = p.capture(child, []string{"start", "--attach", id}, 4096)
	if err != nil {
		return proof, err
	}
	if decodeInspection(raw, &proof) != nil {
		return workspacemount.Proof{}, ErrRejected
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&proof) != nil || !workspacemount.ValidProof(proof, p.intent.Challenge) {
		return workspacemount.Proof{}, ErrRejected
	}
	if err = p.verify(child, id, true); err != nil {
		return workspacemount.Proof{}, err
	}
	return proof, nil
}

// VerifyAdmission verifies the exact stopped probe and retained-volume references
// while the caller holds creator ownership. It never authorizes other attached
// containers, running processes, source reads or an enduring FrozenLease.
// The approved daemon/image remain trusted; administrators can race names.
func (p *WorkspaceMountProbe) VerifyAdmission(ctx context.Context, id string) error {
	if p == nil || ctx == nil || ctx.Err() != nil || !digest(id, 32) {
		return ErrRejected
	}
	for pass := 0; pass < 2; pass++ {
		c, err := p.inspect(ctx, id)
		if err != nil || c.State.Status != "created" && c.State.Status != "exited" {
			return ErrRejected
		}
		if p.verify(ctx, id, c.State.Status == "exited") != nil {
			return ErrRejected
		}
		raw, err := p.capture(ctx, []string{"volume", "ls", "--filter", "label=commonroom.job=" + p.intent.JobID, "--filter", "label=commonroom.execution=separated-tool-v1", "--format", "{{.Name}}"}, MaxInspectionBytes)
		if err != nil || strings.TrimSpace(string(raw)) != p.intent.Volume.Name {
			return ErrRejected
		}
		for _, filter := range []string{"volume=" + p.intent.Volume.Name, "label=commonroom.job=" + p.intent.JobID, "name=^/" + p.name() + "$"} {
			raw, err = p.capture(ctx, []string{"ps", "-a", "--no-trunc", "--filter", filter, "--format", "{{.ID}}"}, MaxInspectionBytes)
			if err != nil || strings.TrimSpace(string(raw)) != id {
				return ErrRejected
			}
		}
	}
	return ctx.Err()
}

// InspectRecovery admits only a durably known probe ID, present with exact
// ownership or already absent, and no other workspace/job/name references.
// Recovery may STOP an owned running or policy-drifted helper; it never starts
// it or authorizes bytes. The trusted caller MUST hold creator ownership and
// obtain durable current cleanup authorization before removal. No name adoption.
func (p *WorkspaceMountProbe) InspectRecovery(ctx context.Context, id string) (bool, error) {
	if p == nil || ctx == nil || ctx.Err() != nil || !digest(id, 32) {
		return false, ErrRejected
	}
	absent := false
	for pass := 0; pass < 2; pass++ {
		raw, err := p.capture(ctx, []string{"ps", "-a", "--no-trunc", "--filter", "id=" + id, "--format", "{{.ID}}"}, MaxInspectionBytes)
		found := strings.TrimSpace(string(raw))
		if err != nil || found != "" && found != id {
			return false, ErrRejected
		}
		if pass > 0 && absent != (found == "") {
			return false, ErrRejected
		}
		absent = found == ""
		if !absent {
			if _, err := p.inspect(ctx, id); err != nil {
				return false, err
			}
		}
		raw, err = p.capture(ctx, []string{"volume", "ls", "--filter", "label=commonroom.job=" + p.intent.JobID, "--filter", "label=commonroom.execution=separated-tool-v1", "--format", "{{.Name}}"}, MaxInspectionBytes)
		if err != nil || strings.TrimSpace(string(raw)) != p.intent.Volume.Name {
			return false, ErrRejected
		}
		raw, err = p.capture(ctx, []string{"volume", "inspect", "--format", "{{json .}}", p.intent.Volume.Name}, MaxInspectionBytes)
		var v toolVolumeInspection
		if err != nil || decodeInspection(raw, &v) != nil || !validObservedWorkspaceVolume(v, p.intent.JobID, p.intent.Repository, p.root, p.intent.Volume) {
			return false, ErrRejected
		}
		for _, filter := range []string{"volume=" + p.intent.Volume.Name, "label=commonroom.job=" + p.intent.JobID, "name=^/" + p.name() + "$"} {
			raw, err = p.capture(ctx, []string{"ps", "-a", "--no-trunc", "--filter", filter, "--format", "{{.ID}}"}, MaxInspectionBytes)
			if err != nil || strings.TrimSpace(string(raw)) != found {
				return false, ErrRejected
			}
		}
	}
	if ctx.Err() != nil {
		return false, ErrRejected
	}
	return absent, nil
}

// RemoveRecorded performs only exact-ID reconciliation, never create/start or
// volume deletion. Callers must durably authorize recovery first. Absence is
// reobserved with exact retained volume/reference checks before success.
func (p *WorkspaceMountProbe) RemoveRecorded(ctx context.Context, id string) error {
	if _, err := p.InspectRecovery(ctx, id); err != nil {
		return err
	}
	if err := StopContainer(ctx, p.runner, id, func(ctx context.Context, id string) error { _, err := p.inspect(ctx, id); return err }); err != nil {
		return err
	}
	absent, err := p.InspectRecovery(ctx, id)
	if err != nil || !absent {
		return ErrShutdownUnconfirmed
	}
	return nil
}
