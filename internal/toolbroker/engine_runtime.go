package toolbroker

import (
	"context"
	"encoding/json"
	"path"
	"slices"
	"sort"
	"strings"
	"sync"
	"time"
)

// EngineContainerRuntime creates only a fresh reviewed Codex engine, never a
// provider on the host. The gateway socket path is private worker policy, NOT
// model input. The worker must operate its approved private provider gateway before
// constructing this. Credentials enter only through the owned protocol stdin.
// A source fork CAN substitute image/runner/paths, BUT violates credential
// separation. No automatic image, provider, network or uncontained fallback exists.
type EngineContainerRuntime struct {
	mu                                    sync.Mutex
	ctx                                   context.Context
	original                              context.Context
	cancel                                context.CancelFunc
	scope                                 Scope
	image, gateway, imageID, id           string
	runner                                DockerRunner
	attempted, verified, started, running bool
	attached                              bool
	credentialExported                    bool
}

func NewEngineContainerRuntime(ctx context.Context, scope Scope, image, gateway string, runner DockerRunner) (*EngineContainerRuntime, error) {
	validPath := func(v string) bool {
		return len(v) <= 4096 && path.IsAbs(v) && path.Clean(v) == v && v != "/" && !strings.ContainsAny(v, ",:\x00\n\r")
	}
	if ctx == nil || ctx.Err() != nil || scope.Provider != "codex" || !ValidAuditScope(scope, time.Now()) || !validToolImage(image) || !validPath(gateway) || runner == nil {
		return nil, ErrRejected
	}
	lifetime, cancel := context.WithDeadline(ctx, scope.Deadline)
	return &EngineContainerRuntime{ctx: lifetime, original: ctx, cancel: cancel, scope: scope, image: image, gateway: gateway, runner: runner}, nil
}

// Close only cancels execution. It never proves container absence or discards data.
func (r *EngineContainerRuntime) Close()       { r.cancel() }
func (r *EngineContainerRuntime) name() string { return "commonroom-engine-" + r.scope.JobID }
func (r *EngineContainerRuntime) labels() map[string]string {
	return map[string]string{"commonroom.managed": "true", "commonroom.execution": "separated-engine-v1", "commonroom.job": r.scope.JobID, "commonroom.repository": r.scope.RepositoryDigest}
}
func engineEnvironment() map[string]string {
	return map[string]string{"HOME": "/tmp", "CODEX_HOME": "", "PATH": "/opt/commonroom/bin:/usr/local/bin:/usr/bin:/bin", "HTTP_PROXY": "", "HTTPS_PROXY": "", "ALL_PROXY": "", "NO_PROXY": "", "NODE_OPTIONS": "", "NODE_USE_ENV_PROXY": "0", "NODE_VERSION": "", "YARN_VERSION": ""}
}
func (r *EngineContainerRuntime) createArgs() []string {
	args := []string{"create", "-i", "--pull=never", "--name", r.name(), "--init", "--no-healthcheck", "--ipc=private", "--cgroupns=private", "--network=none", "--read-only", "--user", "1000:1000", "--cap-drop=ALL", "--security-opt=no-new-privileges:true", "--pids-limit=64", "--memory=512m", "--memory-swap=512m", "--cpus=0.5", "--ulimit", "nofile=512:512", "--log-driver=none", "--tmpfs", "/tmp:" + toolScratchOptions, "--workdir", "/tmp", "--mount", "type=bind,src=" + r.gateway + ",dst=/run/provider.sock,readonly"}
	labels := r.labels()
	keys := []string{}
	for key := range labels {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		args = append(args, "--label", key+"="+labels[key])
	}
	env := engineEnvironment()
	keys = keys[:0]
	for key := range env {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		args = append(args, "--env", key+"="+env[key])
	}
	return append(args, "--entrypoint", "/usr/local/bin/node", r.image, "/opt/commonroom/engine-entrypoint.cjs")
}
func (r *EngineContainerRuntime) context(ctx context.Context) (context.Context, func(), error) {
	if ctx == nil || ctx.Err() != nil || r.ctx.Err() != nil || r.original.Err() != nil {
		return nil, nil, ErrRejected
	}
	child, cancel := context.WithDeadline(ctx, r.scope.Deadline)
	stop := context.AfterFunc(r.ctx, cancel)
	return child, func() { stop(); cancel() }, nil
}
func (r *EngineContainerRuntime) capture(ctx context.Context, args []string) ([]byte, error) {
	child, cancel := context.WithCancel(ctx)
	defer cancel()
	output := &boundedOutput{cancel: cancel, maxBytes: MaxInspectionBytes}
	err := r.runner.Run(child, args, nil, output)
	raw, overflow := output.snapshot()
	if err != nil || overflow || child.Err() != nil {
		return nil, ErrExecution
	}
	return raw, nil
}
func (r *EngineContainerRuntime) verifyImage(raw []byte) error {
	var image struct {
		ID          string   `json:"Id"`
		RepoDigests []string `json:"RepoDigests"`
		Config      struct {
			Env, Entrypoint, Cmd, OnBuild []string
			User, WorkingDir              string
			Volumes                       map[string]json.RawMessage
		}
	}
	if decodeInspection(raw, &image) != nil || !strings.HasPrefix(image.ID, "sha256:") || !digest(strings.TrimPrefix(image.ID, "sha256:"), 32) || (strings.HasPrefix(r.image, "sha256:") && r.image != image.ID) {
		return ErrRejected
	}
	// A repository manifest digest is distinct from Docker's config image ID.
	// Bind the staged metadata to the exact reviewed repository/digest as well as
	// retaining the image ID for stopped/running container verification. A trusted
	// daemon/runner can lie about both; source forks cannot remove this check and
	// retain the mandatory isolation/approved-image claim.
	if !strings.HasPrefix(r.image, "sha256:") && !slices.Contains(image.RepoDigests, r.image) {
		return ErrRejected
	}
	c := image.Config
	if c.User != "1000:1000" || c.WorkingDir != "/tmp" || !slices.Equal(c.Entrypoint, []string{"/usr/local/bin/node", "/opt/commonroom/engine-entrypoint.cjs"}) || len(c.Cmd) != 0 || len(c.OnBuild) != 0 || len(c.Volumes) != 0 {
		return ErrRejected
	}
	allowed := engineEnvironment()
	seen := map[string]bool{}
	for _, entry := range c.Env {
		key, _, ok := strings.Cut(entry, "=")
		if _, known := allowed[key]; !ok || !known || seen[key] {
			return ErrRejected
		}
		seen[key] = true
	}
	r.imageID = image.ID
	return nil
}
func (r *EngineContainerRuntime) verify(raw []byte, running bool) error {
	var c toolInspection
	if decodeInspection(raw, &c) != nil || c.ID != r.id || !digest(c.ID, 32) || c.Image != r.imageID || c.Config.Image != r.image || c.Name != "/"+r.name() || c.RestartCount != 0 {
		return ErrRejected
	}
	if !isBool(c.State.Running, running) || !isBool(c.State.Paused, false) || !isBool(c.State.Restarting, false) || !isBool(c.State.Dead, false) || c.State.Error != "" || (!running && c.State.Status != "created") || (running && c.State.Status != "running") {
		return ErrRejected
	}
	config := c.Config
	if config.User != "1000:1000" || config.WorkingDir != "/tmp" || !slices.Equal(config.Entrypoint, []string{"/usr/local/bin/node"}) || !slices.Equal(config.Cmd, []string{"/opt/commonroom/engine-entrypoint.cjs"}) || !sameMap(config.Labels, r.labels()) || !slices.Equal(config.Healthcheck.Test, []string{"NONE"}) || !isBool(config.Tty, false) || !isBool(config.OpenStdin, true) || !isBool(config.StdinOnce, false) {
		return ErrRejected
	}
	env := map[string]string{}
	for _, entry := range config.Env {
		key, value, ok := strings.Cut(entry, "=")
		if !ok {
			return ErrRejected
		}
		if _, duplicate := env[key]; duplicate {
			return ErrRejected
		}
		env[key] = value
	}
	if !sameMap(env, engineEnvironment()) {
		return ErrRejected
	}
	h := c.HostConfig
	if !isBool(h.Privileged, false) || !isBool(h.ReadonlyRootfs, true) || !isBool(h.Init, true) || !isBool(h.AutoRemove, false) || h.RestartPolicy.Name != "no" || h.NetworkMode != "none" || h.PidMode != "" || h.IpcMode != "private" || h.CgroupnsMode != "private" || h.UsernsMode != "" {
		return ErrRejected
	}
	if !isInt(h.Memory, ToolMemoryBytes) || !isInt(h.MemorySwap, ToolMemoryBytes) || !isInt(h.NanoCpus, 500000000) || !isInt(h.PidsLimit, ToolProcessLimit) || !slices.Equal(h.CapDrop, []string{"ALL"}) || len(h.CapAdd) != 0 || !slices.Equal(h.SecurityOpt, []string{"no-new-privileges:true"}) {
		return ErrRejected
	}
	if len(h.Binds) != 0 || len(h.VolumesFrom) != 0 || len(h.Devices) != 0 || len(h.DeviceRequests) != 0 || len(h.PortBindings) != 0 || h.LogConfig.Type != "none" || len(h.LogConfig.Config) != 0 || !sameMap(h.Tmpfs, map[string]string{"/tmp": toolScratchOptions}) || len(h.Ulimits) != 1 || h.Ulimits[0].Name != "nofile" || h.Ulimits[0].Soft != 512 || h.Ulimits[0].Hard != 512 {
		return ErrRejected
	}
	gateway, scratch := 0, 0
	for _, mount := range c.Mounts {
		if mount.Type == "bind" && mount.Name == "" && mount.Driver == "" && isBool(mount.RW, false) && mount.Propagation == "rprivate" {
			if mount.Source == r.gateway && mount.Destination == "/run/provider.sock" {
				gateway++
				continue
			}
		}
		if mount.Type == "tmpfs" && mount.Source == "" && mount.Name == "" && mount.Driver == "" && mount.Destination == "/tmp" && isBool(mount.RW, true) && mount.Propagation == "" {
			scratch++
			continue
		}
		return ErrRejected
	}
	if gateway != 1 || scratch > 1 {
		return ErrRejected
	}
	return nil
}
func (r *EngineContainerRuntime) inspect(ctx context.Context) ([]byte, error) {
	return r.capture(ctx, []string{"inspect", "--type", "container", "--format", "{{json .}}", r.id})
}
func (r *EngineContainerRuntime) Create(ctx context.Context) (string, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.attempted {
		return "", ErrRejected
	}
	child, done, err := r.context(ctx)
	if err != nil {
		return "", ErrRejected
	}
	defer done()
	r.attempted = true
	inventory, err := r.capture(child, []string{"ps", "-a", "--no-trunc", "--filter", "name=^/" + r.name() + "$", "--format", "{{.ID}}"})
	if err != nil || strings.TrimSpace(string(inventory)) != "" {
		return "", ErrRejected
	}
	image, err := r.capture(child, []string{"image", "inspect", "--format", "{{json .}}", r.image})
	if err != nil || r.verifyImage(image) != nil {
		return "", ErrRejected
	}
	raw, err := r.capture(child, r.createArgs())
	id := strings.TrimSpace(string(raw))
	if err != nil || !digest(id, 32) {
		return "", ErrExecution
	}
	r.id = id
	inspected, err := r.inspect(child)
	if err != nil || r.verify(inspected, false) != nil {
		return "", ErrRejected
	}
	r.verified = true
	return id, nil
}
func (r *EngineContainerRuntime) VerifyCreated(ctx context.Context, id string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	child, done, err := r.context(ctx)
	if err != nil {
		return err
	}
	defer done()
	if id != r.id || !r.verified || r.started {
		return ErrRejected
	}
	raw, err := r.inspect(child)
	if err != nil {
		return err
	}
	return r.verify(raw, false)
}
func (r *EngineContainerRuntime) Inspect(ctx context.Context, id string) ([]byte, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	child, done, err := r.context(ctx)
	if err != nil {
		return nil, err
	}
	defer done()
	if id != r.id || !r.verified {
		return nil, ErrRejected
	}
	raw, err := r.inspect(child)
	if err != nil || r.verify(raw, r.running) != nil {
		return nil, ErrRejected
	}
	return raw, nil
}
func (r *EngineContainerRuntime) Start(ctx context.Context, id string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	child, done, err := r.context(ctx)
	if err != nil {
		return err
	}
	defer done()
	if id != r.id || !r.verified || r.started {
		return ErrRejected
	}
	r.started = true
	raw, err := r.inspect(child)
	if err != nil || r.verify(raw, false) != nil {
		return ErrRejected
	}
	reply, err := r.capture(child, []string{"start", r.id})
	if err != nil || strings.TrimSpace(string(reply)) != r.id {
		return ErrExecution
	}
	raw, err = r.inspect(child)
	if err != nil || r.verify(raw, true) != nil {
		return ErrRejected
	}
	r.running = true
	return nil
}
