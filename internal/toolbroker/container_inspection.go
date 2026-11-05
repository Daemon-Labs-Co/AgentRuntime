package toolbroker

import (
	"bytes"
	"encoding/json"
	"io"
	"path"
	"slices"
	"strings"
	"time"
)

const MaxInspectionBytes = 64 * 1024
const toolScratchOptions = "rw,nosuid,nodev,noexec,size=64m,mode=1777"
const toolIdleProgram = "setInterval(() => {}, 2147483647)"

// toolEnvironment is fixed supervisor policy, not model input. Unknown inherited
// image environment is refused by inspection; image provenance remains separate.
func toolEnvironment() map[string]string {
	return map[string]string{
		"HOME": "/tmp/tool-home", "PATH": "/usr/local/go/bin:/usr/local/bin:/usr/bin:/bin",
		"HTTP_PROXY": "", "HTTPS_PROXY": "", "ALL_PROXY": "", "NO_PROXY": "",
		"NODE_OPTIONS": "", "NODE_USE_ENV_PROXY": "0", "NODE_VERSION": "", "YARN_VERSION": "",
	}
}
func (p *ToolContainerPlan) labels() map[string]string {
	return map[string]string{
		"commonroom.managed": "true", "commonroom.execution": "separated-tool-v1",
		"commonroom.job": p.authority.scope.JobID, "commonroom.repository": p.authority.scope.RepositoryDigest,
	}
}

// VolumeCreateArgs generates only a plain local named volume. The future fenced
// supervisor must refuse existing volumes first, initialize its approved snapshot
// without credentials, and verify inspection before using it. This is not a launch.
func (p *ToolContainerPlan) VolumeCreateArgs(now time.Time) ([]string, error) {
	if _, err := p.RunArgs(now); err != nil {
		return nil, err
	}
	args := []string{"volume", "create", "--driver", "local"}
	labels := p.labels()
	for _, key := range []string{"commonroom.managed", "commonroom.execution", "commonroom.job", "commonroom.repository"} {
		args = append(args, "--label", key+"="+labels[key])
	}
	if identity := p.volume.Load(); identity != nil {
		args = append(args, "--label", "commonroom.workspace.nonce="+identity.Nonce)
	}
	return append(args, p.WorkspaceVolume()), nil
}

type toolInspection struct {
	ID           string `json:"Id"`
	Name         string
	Image        string
	RestartCount int
	State        struct {
		Running, Paused, Restarting, Dead *bool
		OOMKilled                         *bool
		ExitCode                          *int64
		Error                             string
		Status                            string
	}
	Config struct {
		Image, User, WorkingDir   string
		Tty, OpenStdin, StdinOnce *bool
		Env, Entrypoint, Cmd      []string
		Labels                    map[string]string
		Healthcheck               struct{ Test []string }
	}
	HostConfig struct {
		Privileged, ReadonlyRootfs, Init                        *bool
		AutoRemove                                              *bool
		RestartPolicy                                           struct{ Name string }
		NetworkMode, PidMode, IpcMode, CgroupnsMode, UsernsMode string
		Memory, MemorySwap, NanoCpus, PidsLimit                 *int64
		CapDrop, CapAdd, SecurityOpt, Binds, VolumesFrom        []string
		Devices, DeviceRequests                                 []json.RawMessage
		PortBindings                                            map[string]json.RawMessage
		Tmpfs                                                   map[string]string
		LogConfig                                               struct {
			Type   string
			Config map[string]string
		}
		Ulimits []struct {
			Name       string
			Soft, Hard int64
		}
	}
	Mounts []struct {
		Type, Name, Source, Destination, Driver, Propagation string
		RW                                                   *bool
	}
}
type toolVolumeInspection struct {
	Name, Driver, Scope, Mountpoint, CreatedAt string
	Options, Labels                            map[string]string
}

func isBool(p *bool, value bool) bool  { return p != nil && *p == value }
func isInt(p *int64, value int64) bool { return p != nil && *p == value }
func sameMap(a, b map[string]string) bool {
	if len(a) != len(b) {
		return false
	}
	for k, v := range b {
		value, ok := a[k]
		if !ok || value != v {
			return false
		}
	}
	return true
}

// VerifyInspection consumes bounded single-object Docker inspection metadata
// fetched directly by the trusted worker, never supplied by a model or plugin.
// dockerRoot must be the approved rootless daemon's canonical data root. Unknown
// descriptive Docker fields are ignored, but duplicate/case-alias fields refused.
// This verifies selected reported policy only: it cannot prove a trusted daemon,
// image contents, fresh volume history, atomic execution, or real shutdown.
func (p *ToolContainerPlan) VerifyInspection(container, volume []byte, dockerRoot string, now time.Time) error {
	return p.verifyInspection(container, volume, dockerRoot, now, true)
}

// VerifyCreatedInspection checks the same policy before any process may start.
// A stopped existing container is not automatically fresh; creation ownership
// must be established by the worker lifecycle and ToolContainerRuntime.
func (p *ToolContainerPlan) VerifyCreatedInspection(container, volume []byte, dockerRoot string, now time.Time) error {
	return p.verifyInspection(container, volume, dockerRoot, now, false)
}

func (p *ToolContainerPlan) verifyInspection(container, volume []byte, dockerRoot string, now time.Time, running bool) error {
	if _, err := p.RunArgs(now); err != nil {
		return err
	}
	if len(dockerRoot) > 4096 || !path.IsAbs(dockerRoot) || path.Clean(dockerRoot) != dockerRoot || dockerRoot == "/" {
		return ErrRejected
	}
	var c toolInspection
	var v toolVolumeInspection
	if decodeInspection(container, &c) != nil || decodeInspection(volume, &v) != nil {
		return ErrRejected
	}
	if !digest(c.ID, 32) || c.Name != "/"+p.ContainerName() || c.Config.Image != p.image || !strings.HasPrefix(c.Image, "sha256:") || !digest(strings.TrimPrefix(c.Image, "sha256:"), 32) || c.RestartCount != 0 {
		return ErrRejected
	}
	if strings.HasPrefix(p.image, "sha256:") && c.Image != p.image {
		return ErrRejected
	}
	if !running && c.State.Status != "created" {
		return ErrRejected
	}
	if !isBool(c.State.Running, running) || !isBool(c.State.Paused, false) || !isBool(c.State.Restarting, false) || !isBool(c.State.Dead, false) || c.State.Error != "" {
		return ErrRejected
	}
	if c.Config.User != "1000:1000" || c.Config.WorkingDir != "/workspace" || !slices.Equal(c.Config.Entrypoint, []string{"/usr/local/bin/node"}) || !slices.Equal(c.Config.Cmd, []string{"-e", toolIdleProgram}) || !sameMap(c.Config.Labels, p.labels()) || !slices.Equal(c.Config.Healthcheck.Test, []string{"NONE"}) {
		return ErrRejected
	}
	env := map[string]string{}
	for _, entry := range c.Config.Env {
		key, value, ok := strings.Cut(entry, "=")
		if !ok {
			return ErrRejected
		}
		if _, exists := env[key]; exists {
			return ErrRejected
		}
		env[key] = value
	}
	if !sameMap(env, toolEnvironment()) {
		return ErrRejected
	}
	h := c.HostConfig
	if !isBool(h.Privileged, false) || !isBool(h.ReadonlyRootfs, true) || !isBool(h.Init, true) || h.NetworkMode != "none" || h.PidMode != "" || h.IpcMode != "private" || h.CgroupnsMode != "private" || h.UsernsMode != "" {
		return ErrRejected
	}
	if !isInt(h.Memory, ToolMemoryBytes) || !isInt(h.MemorySwap, ToolMemoryBytes) || !isInt(h.NanoCpus, 500000000) || !isInt(h.PidsLimit, ToolProcessLimit) || !slices.Equal(h.CapDrop, []string{"ALL"}) || len(h.CapAdd) != 0 || !slices.Equal(h.SecurityOpt, []string{"no-new-privileges:true"}) {
		return ErrRejected
	}
	if len(h.Binds) != 0 || len(h.VolumesFrom) != 0 || len(h.Devices) != 0 || len(h.DeviceRequests) != 0 || len(h.PortBindings) != 0 || h.LogConfig.Type != "none" || len(h.LogConfig.Config) != 0 || !sameMap(h.Tmpfs, map[string]string{"/tmp": toolScratchOptions}) {
		return ErrRejected
	}
	if len(h.Ulimits) != 1 || h.Ulimits[0].Name != "nofile" || h.Ulimits[0].Soft != 512 || h.Ulimits[0].Hard != 512 {
		return ErrRejected
	}
	if p.verifyVolume(v, dockerRoot) != nil {
		return ErrRejected
	}
	workspaces := 0
	scratch := 0
	for _, mount := range c.Mounts {
		if mount.Type == "volume" && mount.Name == v.Name && mount.Source == v.Mountpoint && mount.Destination == "/workspace" && mount.Driver == "local" && isBool(mount.RW, true) && (mount.Propagation == "" || mount.Propagation == "rprivate") {
			workspaces++
			continue
		}
		// Docker versions may report the configured tmpfs separately from volumes.
		if mount.Type == "tmpfs" && mount.Name == "" && mount.Source == "" && mount.Destination == "/tmp" && mount.Driver == "" && isBool(mount.RW, true) && mount.Propagation == "" {
			scratch++
			continue
		}
		return ErrRejected
	}
	if workspaces != 1 || scratch > 1 {
		return ErrRejected
	}
	return nil
}

func decodeInspection(raw []byte, target any) error {
	if len(raw) == 0 || len(raw) > MaxInspectionBytes {
		return ErrRejected
	}
	trimmed := bytes.TrimSpace(raw)
	if len(trimmed) == 0 || trimmed[0] != '{' {
		return ErrRejected
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	if inspectionValue(d, 0) != nil {
		return ErrRejected
	}
	if _, err := d.Token(); err != io.EOF {
		return ErrRejected
	}
	if json.Unmarshal(raw, target) != nil {
		return ErrRejected
	}
	return nil
}

// inspectionValue rejects ambiguous object members before Go's case-insensitive
// struct decoder. Null optional Docker fields are permitted; depth is bounded.
func inspectionValue(d *json.Decoder, depth int) error {
	if depth > 32 {
		return ErrRejected
	}
	token, err := d.Token()
	if err != nil {
		return ErrRejected
	}
	delim, ok := token.(json.Delim)
	if !ok {
		return nil
	}
	switch delim {
	case '{':
		seen := map[string]bool{}
		for d.More() {
			key, err := d.Token()
			s, ok := key.(string)
			if err != nil || !ok {
				return ErrRejected
			}
			s = strings.ToLower(s)
			if seen[s] {
				return ErrRejected
			}
			seen[s] = true
			if inspectionValue(d, depth+1) != nil {
				return ErrRejected
			}
		}
	case '[':
		for d.More() {
			if inspectionValue(d, depth+1) != nil {
				return ErrRejected
			}
		}
	default:
		return ErrRejected
	}
	if _, err = d.Token(); err != nil {
		return ErrRejected
	}
	return nil
}

// verifyVolume rejects Docker local-driver options that could hide host binds.
func (p *ToolContainerPlan) verifyVolume(v toolVolumeInspection, dockerRoot string) error {
	if identity := p.volume.Load(); identity != nil {
		return p.verifyVolumeIdentity(v, *identity, dockerRoot)
	}
	return p.verifyVolumeShape(v, dockerRoot, p.labels())
}
func (p *ToolContainerPlan) verifyVolumeShape(v toolVolumeInspection, dockerRoot string, labels map[string]string) error {
	expectedSource := path.Join(dockerRoot, "volumes", p.WorkspaceVolume(), "_data")
	if v.Name != p.WorkspaceVolume() || v.Driver != "local" || v.Scope != "local" || v.Mountpoint != expectedSource || len(v.Options) != 0 || !sameMap(v.Labels, labels) {
		return ErrRejected
	}
	return nil
}
