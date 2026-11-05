package toolbroker

import (
	"context"
	"regexp"
	"strings"
	"sync/atomic"
	"time"
)

// The planned pair must share the old logical-job ceiling, not silently double
// it. Tools reserve half; the future engine receives at most the other half.
// Aggregate admission and pinned-runtime verification remain unwired.
const (
	ToolMemoryBytes  = 512 * 1024 * 1024
	ToolProcessLimit = 64
	ToolCPU          = "0.5"
)

var toolImageRepository = regexp.MustCompile(`^[a-z0-9][a-z0-9./:_-]{0,254}$`)

// ToolContainerPlan is trusted-supervisor policy, never a model request. It
// derives identities from the scoped job and exposes no caller-supplied mounts,
// network, environment, container names or Docker flags. It only generates
// arguments; there is no Docker launch, filesystem executor or host fallback.
// A source fork CAN add engine/host mounts, BUT invalidates credential separation.
type ToolContainerPlan struct {
	authority       *Authority
	image           string
	workspace       atomic.Pointer[workspaceReadiness]
	volume          atomic.Pointer[WorkspaceVolumeIdentity]
	commandsEnabled bool
	commandUsed     atomic.Bool
}

// NewToolContainerPlan requires an approved immutable image from private worker
// configuration. Pinning verifies spelling, not provenance or image contents:
// the operator must separately review/sign/scan the tool-only image. No provider
// credentials may be baked into it. There is no implicit image or tag fallback.
func NewToolContainerPlan(authority *Authority, image string, now time.Time) (*ToolContainerPlan, error) {
	return NewToolContainerPlanWithCommands(authority, image, now, false)
}

// Commands are explicit trusted worker policy; this never grants authority.
func NewToolContainerPlanWithCommands(authority *Authority, image string, now time.Time, enabled bool) (*ToolContainerPlan, error) {
	if authority == nil || !validToolImage(image) {
		return nil, ErrRejected
	}
	authority.mu.Lock()
	defer authority.mu.Unlock()
	if authority.revoked || now.Before(authority.issued) || !validScope(authority.scope, now) {
		return nil, ErrRejected
	}
	return &ToolContainerPlan{authority: authority, image: image, commandsEnabled: enabled}, nil
}
func validToolImage(image string) bool {
	if len(image) > 327 {
		return false
	}
	if strings.HasPrefix(image, "sha256:") {
		return digest(strings.TrimPrefix(image, "sha256:"), 32)
	}
	parts := strings.Split(image, "@sha256:")
	return len(parts) == 2 && toolImageRepository.MatchString(parts[0]) && digest(parts[1], 32)
}

// ContainerName and WorkspaceVolume are unique job identities, not reusable
// connection homes. Before creation the future supervisor must prove the job is
// fresh and refuse pre-existing/unresolved containers or volumes.
func (p *ToolContainerPlan) ContainerName() string {
	return "commonroom-tool-" + p.authority.scope.JobID
}
func (p *ToolContainerPlan) WorkspaceVolume() string {
	return "commonroom-tool-work-" + p.authority.scope.JobID
}

// RunArgs checks revocation/lifetime and returns a fresh slice. Planning is not
// an atomic Docker launch; the future fenced supervisor must revalidate authority.
// The idle container uses /workspace so the named volume stays empty until
// credential-free Bootstrap initializes its repository before engine startup. No host bundle/auth/socket is mounted.
// The fixed tool-only image must provide Node at the declared entrypoint; holding
// the process alive does not authorize any tool execution or establish readiness.
func (p *ToolContainerPlan) RunArgs(now time.Time) ([]string, error) {
	p.authority.mu.Lock()
	defer p.authority.mu.Unlock()
	if p.authority.revoked || now.Before(p.authority.issued) || !now.Before(p.authority.scope.Deadline) {
		return nil, ErrRejected
	}
	return []string{
		"run", "-d", "--rm", "--pull=never", "--name", p.ContainerName(),
		"--label", "commonroom.managed=true", "--label", "commonroom.execution=separated-tool-v1",
		"--label", "commonroom.job=" + p.authority.scope.JobID,
		"--label", "commonroom.repository=" + p.authority.scope.RepositoryDigest,
		"--init", "--no-healthcheck", "--ipc=private", "--cgroupns=private", "--network=none", "--read-only", "--user", "1000:1000",
		"--cap-drop=ALL", "--security-opt=no-new-privileges:true",
		"--pids-limit=64", "--memory=512m", "--memory-swap=512m", "--cpus=0.5",
		"--ulimit", "nofile=512:512", "--log-driver=none",
		"--tmpfs", "/tmp:" + toolScratchOptions,
		"--mount", "type=volume,src=" + p.WorkspaceVolume() + ",dst=/workspace",
		"--workdir", "/workspace",
		"--env", "HOME=/tmp/tool-home", "--env", "HTTP_PROXY=", "--env", "HTTPS_PROXY=",
		"--env", "ALL_PROXY=", "--env", "NO_PROXY=", "--env", "NODE_OPTIONS=",
		"--env", "NODE_USE_ENV_PROXY=0",
		"--env", "PATH=/usr/local/go/bin:/usr/local/bin:/usr/bin:/bin",
		"--env", "NODE_VERSION=", "--env", "YARN_VERSION=",
		"--entrypoint", "/usr/local/bin/node", p.image,
		"-e", toolIdleProgram,
	}, nil
}

// RemoveArgs is scoped cleanup, not proof of shutdown. The future supervisor must
// inspect absence and release both-container leases before settling a pair.
func (p *ToolContainerPlan) RemoveArgs() []string {
	return []string{"rm", "--force", p.ContainerName()}
}

// CreateArgs generates a stopped container with the same mandatory policy.
// Explicit immutable-ID cleanup replaces automatic removal so crash evidence is
// retained. Callers must not start it until inspection and pair journalling pass.
func (p *ToolContainerPlan) CreateArgs(now time.Time) ([]string, error) {
	args, err := p.RunArgs(now)
	if err != nil {
		return nil, err
	}
	out := []string{"create"}
	for _, arg := range args[1:] {
		if arg != "-d" && arg != "--rm" {
			out = append(out, arg)
		}
	}
	return out, nil
}

// Readiness is issued only by successful bootstrap and retains its original job.
// A fresh per-call context must never revive a cancelled workspace authority.
type workspaceReadiness struct {
	lifetime    context.Context
	original    context.Context
	containerID string
}

func (p *ToolContainerPlan) workspaceReady() bool {
	ready := p.workspace.Load()
	return ready.active() && digest(ready.containerID, 32)
}

func (ready *workspaceReadiness) active() bool {
	return ready != nil && ready.lifetime != nil && ready.original != nil && ready.lifetime.Err() == nil && ready.original.Err() == nil
}
