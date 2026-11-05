package toolbroker

import (
	"slices"
	"strings"
	"testing"
	"time"
)

func TestToolPlanFixedCredentialFreeBoundary(t *testing.T) {
	t.Parallel()
	a, r, now := fixture(t)
	image := "registry.example/tool-only@sha256:" + strings.Repeat("c", 64)
	p, err := NewToolContainerPlan(a, image, now)
	if err != nil {
		t.Fatal(err)
	}
	args, err := p.RunArgs(now)
	if err != nil {
		t.Fatal(err)
	}
	for _, required := range []string{"--network=none", "--read-only", "--cap-drop=ALL", "--security-opt=no-new-privileges:true", "--user", "1000:1000", "--pull=never", "--pids-limit=64", "--memory=512m", "--memory-swap=512m", "--cpus=0.5", "nofile=512:512", "--log-driver=none"} {
		if !slices.Contains(args, required) {
			t.Fatalf("missing %s", required)
		}
	}
	mounts := 0
	for i, arg := range args {
		if arg == "--mount" {
			mounts++
			if i+1 >= len(args) || args[i+1] != "type=volume,src="+p.WorkspaceVolume()+",dst=/workspace" {
				t.Fatal("unexpected mount")
			}
		}
		if strings.Contains(arg, "type=bind") || strings.Contains(arg, "provider-auth") || strings.Contains(arg, "provider.sock") || strings.Contains(arg, "/home/agent") || strings.Contains(arg, "docker.sock") || strings.Contains(arg, "--privileged") || strings.Contains(arg, "--pid=host") {
			t.Fatalf("unsafe tool argument %q", arg)
		}
	}
	if mounts != 1 || p.ContainerName() != "commonroom-tool-"+r.Scope.JobID || p.WorkspaceVolume() != "commonroom-tool-work-"+r.Scope.JobID {
		t.Fatal("unexpected identity/mount count")
	}
	if !slices.Equal(p.RemoveArgs(), []string{"rm", "--force", p.ContainerName()}) {
		t.Fatal("cleanup escapes job")
	}
	args[0] = "mutated"
	again, _ := p.RunArgs(now)
	if again[0] != "run" {
		t.Fatal("caller mutated stored policy")
	}
}
func TestToolPlanRefusesUnsafeImagesAndScope(t *testing.T) {
	t.Parallel()
	a, r, now := fixture(t)
	for _, image := range []string{"", "tool:latest", "--privileged", "tool@sha256:abc", "Tool@sha256:" + strings.Repeat("c", 64), "tool\n--network=host@sha256:" + strings.Repeat("c", 64), "tool@sha256:" + strings.Repeat("C", 64)} {
		if _, err := NewToolContainerPlan(a, image, now); err != ErrRejected {
			t.Fatalf("unsafe image accepted %q", image)
		}
	}
	for _, job := range []string{"../host", "--name=other", strings.Repeat("a", 31), strings.Repeat("A", 32)} {
		changed := r.Scope
		changed.JobID = job
		corrupt := &Authority{scope: changed, issued: now}
		if _, err := NewToolContainerPlan(corrupt, "sha256:"+strings.Repeat("c", 64), now); err != ErrRejected {
			t.Fatal("unsafe job accepted")
		}
	}
	a.scope.Version = 2
	if _, err := NewToolContainerPlan(a, "sha256:"+strings.Repeat("c", 64), now); err != ErrRejected {
		t.Fatal("unknown protocol accepted")
	}
}
func TestToolPlanOriginalLifetimeAndJobVolumeIsolation(t *testing.T) {
	t.Parallel()
	a, r, now := fixture(t)
	image := "sha256:" + strings.Repeat("c", 64)
	p, err := NewToolContainerPlan(a, image, now)
	if err != nil {
		t.Fatal(err)
	}
	for _, when := range []time.Time{now.Add(-time.Second), r.Scope.Deadline, r.Scope.Deadline.Add(time.Second)} {
		if _, err = p.RunArgs(when); err != ErrRejected {
			t.Fatal("launch outside original authority")
		}
	}
	r.Scope.JobID = strings.Repeat("d", 32)
	otherAuthority, _, err := New(r.Scope, []string{"read"}, now)
	if err != nil {
		t.Fatal(err)
	}
	other, err := NewToolContainerPlan(otherAuthority, image, now)
	if err != nil {
		t.Fatal(err)
	}
	if p.ContainerName() == other.ContainerName() || p.WorkspaceVolume() == other.WorkspaceVolume() {
		t.Fatal("jobs share execution identity")
	}
	if ToolMemoryBytes != 512*1024*1024 || ToolProcessLimit != 64 || ToolCPU != "0.5" {
		t.Fatal("aggregate pair allocation changed without review")
	}
}

func TestToolPlanRevocation(t *testing.T) {
	t.Parallel()
	a, _, now := fixture(t)
	image := "sha256:" + strings.Repeat("c", 64)
	p, err := NewToolContainerPlan(a, image, now)
	if err != nil {
		t.Fatal(err)
	}
	a.Revoke()
	if _, err = p.RunArgs(now); err != ErrRejected {
		t.Fatal("revoked plan remained available")
	}
	if _, err = NewToolContainerPlan(a, image, now); err != ErrRejected {
		t.Fatal("revoked authority minted a plan")
	}
	if _, err = NewToolContainerPlan(nil, image, now); err != ErrRejected {
		t.Fatal("missing authority accepted")
	}
}
