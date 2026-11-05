package toolbroker

import (
	"encoding/json"
	"path"
	"slices"
	"strings"
	"testing"
	"time"
)

func boolValue(v bool) *bool  { return &v }
func intValue(v int64) *int64 { return &v }
func inspectionFixture(t *testing.T) (*ToolContainerPlan, toolInspection, toolVolumeInspection, string, time.Time) {
	t.Helper()
	a, _, now := fixture(t)
	p, err := NewToolContainerPlan(a, "sha256:"+strings.Repeat("c", 64), now)
	if err != nil {
		t.Fatal(err)
	}
	root := "/home/synthetic/.local/share/docker"
	var c toolInspection
	c.ID = strings.Repeat("d", 64)
	c.Name = "/" + p.ContainerName()
	c.Image = p.image
	c.State.Running = boolValue(true)
	c.State.Paused = boolValue(false)
	c.State.Restarting = boolValue(false)
	c.State.Dead = boolValue(false)
	c.Config.Image = p.image
	c.Config.User = "1000:1000"
	c.Config.WorkingDir = "/workspace"
	c.Config.Entrypoint = []string{"/usr/local/bin/node"}
	c.Config.Cmd = []string{"-e", toolIdleProgram}
	c.Config.Healthcheck.Test = []string{"NONE"}
	c.Config.Labels = p.labels()
	for key, value := range toolEnvironment() {
		c.Config.Env = append(c.Config.Env, key+"="+value)
	}
	h := &c.HostConfig
	h.Privileged = boolValue(false)
	h.ReadonlyRootfs = boolValue(true)
	h.Init = boolValue(true)
	h.NetworkMode = "none"
	h.IpcMode = "private"
	h.CgroupnsMode = "private"
	h.Memory = intValue(ToolMemoryBytes)
	h.MemorySwap = intValue(ToolMemoryBytes)
	h.NanoCpus = intValue(500000000)
	h.PidsLimit = intValue(ToolProcessLimit)
	h.CapDrop = []string{"ALL"}
	h.SecurityOpt = []string{"no-new-privileges:true"}
	h.Tmpfs = map[string]string{"/tmp": toolScratchOptions}
	h.LogConfig.Type = "none"
	h.Ulimits = append(h.Ulimits, struct {
		Name       string
		Soft, Hard int64
	}{"nofile", 512, 512})
	var v toolVolumeInspection
	v.Name = p.WorkspaceVolume()
	v.Driver = "local"
	v.Scope = "local"
	v.Mountpoint = path.Join(root, "volumes", v.Name, "_data")
	v.Labels = p.labels()
	c.Mounts = append(c.Mounts, struct {
		Type, Name, Source, Destination, Driver, Propagation string
		RW                                                   *bool
	}{"volume", v.Name, v.Mountpoint, "/workspace", "local", "", boolValue(true)})
	return p, c, v, root, now
}
func inspectJSON(t *testing.T, v any) []byte {
	t.Helper()
	raw, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}
func TestToolInspectionAcceptsDeclaredPolicy(t *testing.T) {
	t.Parallel()
	p, c, v, root, now := inspectionFixture(t)
	if err := p.VerifyInspection(inspectJSON(t, c), inspectJSON(t, v), root, now); err != nil {
		t.Fatal(err)
	}
	// Some Docker versions include configured tmpfs in Mounts as well.
	scratch := c.Mounts[0]
	scratch.Type = "tmpfs"
	scratch.Name = ""
	scratch.Source = ""
	scratch.Destination = "/tmp"
	scratch.Driver = ""
	c.Mounts = append(c.Mounts, scratch)
	if err := p.VerifyInspection(inspectJSON(t, c), inspectJSON(t, v), root, now); err != nil {
		t.Fatal(err)
	}
	args, err := p.VolumeCreateArgs(now)
	if err != nil || !slices.Contains(args, "local") || args[len(args)-1] != v.Name {
		t.Fatal("volume identity not fixed")
	}
}
func TestToolInspectionRejectsContainerBoundaryChanges(t *testing.T) {
	t.Parallel()
	changes := []func(*toolInspection){
		func(c *toolInspection) { c.Name = "/other" }, func(c *toolInspection) { c.Config.Image = "mutable:latest" }, func(c *toolInspection) { c.Image = "sha256:" + strings.Repeat("e", 64) }, func(c *toolInspection) { c.Config.User = "0:0" },
		func(c *toolInspection) { c.Config.Env = append(c.Config.Env, "PROVIDER_TOKEN=synthetic") }, func(c *toolInspection) { c.Config.Env = append(c.Config.Env, "HOME=/other") }, func(c *toolInspection) { c.Config.Entrypoint = []string{"sh"} }, func(c *toolInspection) { c.Config.Cmd = []string{"-e", "other"} }, func(c *toolInspection) { c.Config.Labels["commonroom.job"] = "other" }, func(c *toolInspection) { c.Config.Healthcheck.Test = []string{"CMD", "other"} },
		func(c *toolInspection) { c.State.Running = boolValue(false) }, func(c *toolInspection) { c.State.Running = nil }, func(c *toolInspection) { c.State.Paused = boolValue(true) }, func(c *toolInspection) { c.RestartCount = 1 },
		func(c *toolInspection) { c.HostConfig.Privileged = boolValue(true) }, func(c *toolInspection) { c.HostConfig.Privileged = nil }, func(c *toolInspection) { c.HostConfig.ReadonlyRootfs = boolValue(false) }, func(c *toolInspection) { c.HostConfig.Init = boolValue(false) }, func(c *toolInspection) { c.HostConfig.NetworkMode = "host" }, func(c *toolInspection) { c.HostConfig.PidMode = "host" }, func(c *toolInspection) { c.HostConfig.IpcMode = "host" }, func(c *toolInspection) { c.HostConfig.CgroupnsMode = "host" }, func(c *toolInspection) { c.HostConfig.UsernsMode = "host" },
		func(c *toolInspection) { c.HostConfig.Memory = intValue(0) }, func(c *toolInspection) { c.HostConfig.MemorySwap = intValue(-1) }, func(c *toolInspection) { c.HostConfig.NanoCpus = intValue(0) }, func(c *toolInspection) { c.HostConfig.PidsLimit = intValue(-1) }, func(c *toolInspection) { c.HostConfig.CapAdd = []string{"SYS_ADMIN"} }, func(c *toolInspection) { c.HostConfig.CapDrop = nil }, func(c *toolInspection) {
			c.HostConfig.SecurityOpt = append(c.HostConfig.SecurityOpt, "seccomp=unconfined")
		},
		func(c *toolInspection) { c.HostConfig.Binds = []string{"/synthetic/auth:/auth"} }, func(c *toolInspection) { c.HostConfig.VolumesFrom = []string{"engine"} }, func(c *toolInspection) { c.HostConfig.Devices = []json.RawMessage{json.RawMessage(`{}`)} }, func(c *toolInspection) { c.HostConfig.DeviceRequests = []json.RawMessage{json.RawMessage(`{}`)} }, func(c *toolInspection) {
			c.HostConfig.PortBindings = map[string]json.RawMessage{"443/tcp": json.RawMessage(`[]`)}
		}, func(c *toolInspection) { c.HostConfig.LogConfig.Type = "json-file" }, func(c *toolInspection) { c.HostConfig.Tmpfs["/tmp"] = "rw,size=1g" }, func(c *toolInspection) { c.HostConfig.Ulimits[0].Hard = 4096 },
		func(c *toolInspection) { c.Mounts[0].Type = "bind" }, func(c *toolInspection) { c.Mounts[0].Name = "provider-home" }, func(c *toolInspection) { c.Mounts[0].Source = "/synthetic/auth" }, func(c *toolInspection) { c.Mounts = append(c.Mounts, c.Mounts[0]) }, func(c *toolInspection) { c.Mounts[0].Propagation = "shared" }, func(c *toolInspection) { c.Mounts = nil },
	}
	for i, change := range changes {
		p, c, v, root, now := inspectionFixture(t)
		change(&c)
		if p.VerifyInspection(inspectJSON(t, c), inspectJSON(t, v), root, now) != ErrRejected {
			t.Fatalf("accepted boundary mutation %d", i)
		}
	}
}
func TestToolInspectionRejectsRedirectedVolume(t *testing.T) {
	t.Parallel()
	changes := []func(*toolVolumeInspection){func(v *toolVolumeInspection) {
		v.Options = map[string]string{"type": "none", "o": "bind", "device": "/synthetic/auth"}
	}, func(v *toolVolumeInspection) { v.Driver = "remote" }, func(v *toolVolumeInspection) { v.Scope = "global" }, func(v *toolVolumeInspection) { v.Mountpoint = "/synthetic/auth" }, func(v *toolVolumeInspection) { v.Labels["commonroom.repository"] = "other" }, func(v *toolVolumeInspection) { v.Name = "other" }}
	for _, change := range changes {
		p, c, v, root, now := inspectionFixture(t)
		change(&v)
		if p.VerifyInspection(inspectJSON(t, c), inspectJSON(t, v), root, now) != ErrRejected {
			t.Fatal("redirected volume accepted")
		}
	}
}
func TestToolInspectionMalformedAndRevoked(t *testing.T) {
	t.Parallel()
	p, c, v, root, now := inspectionFixture(t)
	raw := inspectJSON(t, c)
	vol := inspectJSON(t, v)
	for _, bad := range [][]byte{nil, []byte("   "), []byte("[]"), append(append([]byte(nil), raw...), []byte(" {}")...), []byte(strings.Repeat(" ", MaxInspectionBytes+1)), []byte(strings.Replace(string(raw), `"Privileged":false`, `"Privileged":false,"privileged":false`, 1))} {
		if p.VerifyInspection(bad, vol, root, now) != ErrRejected {
			t.Fatal("malformed inspection accepted")
		}
	}
	for _, badRoot := range []string{"/", "relative", "/home/../other"} {
		if p.VerifyInspection(raw, vol, badRoot, now) != ErrRejected {
			t.Fatal("unsafe daemon root accepted")
		}
	}
	p.authority.Revoke()
	if p.VerifyInspection(raw, vol, root, now) != ErrRejected {
		t.Fatal("revoked policy accepted")
	}
	if _, err := p.VolumeCreateArgs(now); err != ErrRejected {
		t.Fatal("revoked volume creation available")
	}
}

func TestToolPlanMatchesInspectionEnvironment(t *testing.T) {
	t.Parallel()
	p, _, _, _, now := inspectionFixture(t)
	args, err := p.RunArgs(now)
	if err != nil {
		t.Fatal(err)
	}
	env := map[string]string{}
	labels := map[string]string{}
	for i, arg := range args {
		if arg != "--env" && arg != "--label" {
			continue
		}
		if i+1 >= len(args) {
			t.Fatal("missing argument")
		}
		key, value, ok := strings.Cut(args[i+1], "=")
		if !ok {
			t.Fatal("invalid argument")
		}
		target := env
		if arg == "--label" {
			target = labels
		}
		if _, exists := target[key]; exists {
			t.Fatal("duplicated policy key")
		}
		target[key] = value
	}
	if !sameMap(env, toolEnvironment()) || !sameMap(labels, p.labels()) {
		t.Fatal("launch/inspection policy mismatch")
	}
	for _, flag := range []string{"--no-healthcheck", "--ipc=private", "--cgroupns=private"} {
		if !slices.Contains(args, flag) {
			t.Fatalf("missing %s", flag)
		}
	}
}
