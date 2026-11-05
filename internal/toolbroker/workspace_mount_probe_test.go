package toolbroker

import (
	"commonroom-runtime/internal/workspacemount"
	"context"
	"encoding/json"
	"errors"
	"io"
	"path"
	"slices"
	"strings"
	"testing"
)

type probeScenario struct {
	t                                        *testing.T
	p                                        *WorkspaceMountProbe
	c                                        toolInspection
	v                                        toolVolumeInspection
	mode                                     string
	events                                   []string
	exists, started, removed, finishedAbsent bool
	cancel                                   context.CancelFunc
}

func (f *probeScenario) Begin(context.Context, WorkspaceProbeIntent) error {
	f.events = append(f.events, "begin")
	if f.mode == "begin" {
		return errors.New("synthetic journal unavailable")
	}
	return nil
}
func (f *probeScenario) Bound(_ context.Context, _ WorkspaceProbeIntent, id string) error {
	f.events = append(f.events, "bound")
	if id != f.c.ID {
		f.t.Fatal("wrong durable ID")
	}
	if f.mode == "bound" {
		return errors.New("synthetic journal unavailable")
	}
	return nil
}
func (f *probeScenario) Finish(ctx context.Context, _ WorkspaceProbeIntent, id string, absent bool) error {
	f.events = append(f.events, "finish")
	f.finishedAbsent = absent
	if ctx.Err() != nil || (id != f.c.ID && id != "") {
		f.t.Fatal("invalid cleanup journal context or ID")
	}
	if f.mode == "finish" {
		return errors.New("synthetic journal unavailable")
	}
	if f.mode == "cancel-at-finish" {
		f.cancel()
	}
	return nil
}
func (f *probeScenario) Run(ctx context.Context, args []string, in []byte, out io.Writer) error {
	if ctx.Err() != nil {
		return ctx.Err()
	}
	if len(in) != 0 {
		f.t.Fatal("unexpected input")
	}
	f.events = append(f.events, args[0])
	var raw []byte
	switch args[0] {
	case "ps":
		filter := args[4]
		if strings.HasPrefix(filter, "name=") {
			if f.mode == "collision" {
				raw = []byte(f.c.ID)
			}
		} else if filter != "id="+f.c.ID {
			f.t.Fatal("mutable identity used")
		} else if f.exists {
			raw = []byte(f.c.ID)
		}
	case "create":
		if !slices.Equal(args, f.p.createArgs()) {
			f.t.Fatal("unexpected launch args")
		}
		f.exists = true
		if f.mode == "malformed-create" {
			return outError(out, "short-id")
		}
		if f.mode == "lost-create" {
			return errors.New("unknown create outcome")
		}
		raw = []byte(f.c.ID)
	case "inspect":
		if args[len(args)-1] != f.c.ID {
			f.t.Fatal("incorrect inspect ID")
		}
		// Clone before mutation so post-start drift does not poison cleanup ownership.
		b, _ := json.Marshal(f.c)
		var c toolInspection
		_ = json.Unmarshal(b, &c)
		if f.started {
			c.State.Status = "exited"
		}
		if !f.started || f.mode == "post-start-writable" {
			switch f.mode {
			case "writable", "post-start-writable":
				c.Mounts[0].RW = probeBool(true)
			case "network":
				c.HostConfig.NetworkMode = "host"
			case "environment":
				c.Config.Env = append(c.Config.Env, "SYNTHETIC_TOKEN=fixture")
			case "memory":
				c.HostConfig.Memory = probeInt(0)
			case "image":
				c.Image = "sha256:" + strings.Repeat("f", 64)
			case "oom":
				c.State.OOMKilled = probeBool(true)
			}
		}
		raw = inspectJSON(f.t, c)
	case "volume":
		if args[1] != "inspect" || args[len(args)-1] != f.v.Name {
			f.t.Fatal("workspace mutation attempted")
		}
		v := f.v
		if f.mode == "volume" {
			v.CreatedAt = "2000-01-01T00:00:00Z"
		}
		raw = inspectJSON(f.t, v)
	case "start":
		if !slices.Equal(args, []string{"start", "--attach", f.c.ID}) || !slices.Contains(f.events, "bound") {
			f.t.Fatal("execution before durable binding")
		}
		f.started = true
		proof := workspacemount.Proof{Version: 1, Challenge: f.p.intent.Challenge, MountID: 2, ReadOnly: true, RootReadOnly: true}
		if f.mode == "proof" {
			proof.Challenge = strings.Repeat("f", 32)
		}
		raw = inspectJSON(f.t, proof)
		switch f.mode {
		case "unknown-proof":
			raw = []byte(strings.Replace(string(raw), "{", "{\"extra\":true,", 1))
		case "duplicate-proof":
			raw = []byte(strings.Replace(string(raw), "{", "{\"version\":1,", 1))
		case "oversize":
			raw = []byte(strings.Repeat("x", 4097))
		case "cancel":
			f.cancel()
			return ctx.Err()
		}
	case "rm":
		if !slices.Equal(args, []string{"rm", "--force", f.c.ID}) {
			f.t.Fatal("removed wrong ID")
		}
		if f.mode == "cleanup" {
			return errors.New("synthetic removal unavailable")
		}
		f.removed = true
		if f.mode != "absence" {
			f.exists = false
		}
	default:
		f.t.Fatalf("unexpected operation %v", args)
	}
	_, err := out.Write(raw)
	return err
}
func probeBool(v bool) *bool  { return &v }
func probeInt(v int64) *int64 { return &v }
func newProbeScenario(t *testing.T, mode string) *probeScenario {
	t.Helper()
	root := "/home/synthetic/.local/share/docker"
	intent := WorkspaceProbeIntent{JobID: strings.Repeat("a", 32), Repository: strings.Repeat("b", 64), Image: "sha256:" + strings.Repeat("d", 64), Challenge: strings.Repeat("e", 32)}
	intent.Volume = WorkspaceVolumeIdentity{1, "commonroom-tool-work-" + intent.JobID, strings.Repeat("c", 32), "2026-10-25T00:00:00Z"}
	f := &probeScenario{t: t, mode: mode}
	p, err := NewWorkspaceMountProbe(intent, f, f, root)
	if err != nil {
		t.Fatal(err)
	}
	f.p = p
	f.v = toolVolumeInspection{Name: intent.Volume.Name, Driver: "local", Scope: "local", Mountpoint: path.Join(root, "volumes", intent.Volume.Name, "_data"), CreatedAt: intent.Volume.CreatedAt, Labels: map[string]string{"commonroom.managed": "true", "commonroom.execution": "separated-tool-v1", "commonroom.job": intent.JobID, "commonroom.repository": intent.Repository, "commonroom.workspace.nonce": intent.Volume.Nonce}}
	c := &f.c
	c.ID = strings.Repeat("1", 64)
	c.Name = "/" + p.name()
	c.Image = intent.Image
	c.State.Status = "created"
	c.State.Running = probeBool(false)
	c.State.Paused = probeBool(false)
	c.State.Restarting = probeBool(false)
	c.State.Dead = probeBool(false)
	c.State.OOMKilled = probeBool(false)
	c.State.ExitCode = probeInt(0)
	c.Config.Image = intent.Image
	c.Config.User = "1000:1000"
	c.Config.WorkingDir = "/workspace"
	c.Config.Tty = probeBool(false)
	c.Config.OpenStdin = probeBool(false)
	c.Config.StdinOnce = probeBool(false)
	c.Config.Env = []string{"PATH=/"}
	c.Config.Entrypoint = []string{probeExecutable}
	c.Config.Cmd = []string{intent.Challenge}
	c.Config.Labels = p.labels()
	c.Config.Healthcheck.Test = []string{"NONE"}
	h := &c.HostConfig
	h.Privileged = probeBool(false)
	h.ReadonlyRootfs = probeBool(true)
	h.Init = probeBool(true)
	h.AutoRemove = probeBool(false)
	h.RestartPolicy.Name = "no"
	h.NetworkMode = "none"
	h.IpcMode = "private"
	h.CgroupnsMode = "private"
	h.Memory = probeInt(probeMemory)
	h.MemorySwap = probeInt(probeMemory)
	h.NanoCpus = probeInt(250000000)
	h.PidsLimit = probeInt(16)
	h.CapDrop = []string{"ALL"}
	h.SecurityOpt = []string{"no-new-privileges:true"}
	h.LogConfig.Type = "none"
	h.Ulimits = append(h.Ulimits, struct {
		Name       string
		Soft, Hard int64
	}{"nofile", 64, 64})
	c.Mounts = append(c.Mounts, struct {
		Type, Name, Source, Destination, Driver, Propagation string
		RW                                                   *bool
	}{"volume", intent.Volume.Name, f.v.Mountpoint, "/workspace", "local", "", probeBool(false)})
	return f
}
func TestWorkspaceMountProbeLifecycle(t *testing.T) {
	t.Parallel()
	for _, mode := range []string{"healthy", "begin", "bound", "finish", "collision", "lost-create", "malformed-create", "writable", "post-start-writable", "network", "environment", "memory", "image", "oom", "volume", "proof", "unknown-proof", "duplicate-proof", "oversize", "cleanup", "absence", "cancel", "cancel-at-finish"} {
		t.Run(mode, func(t *testing.T) {
			t.Parallel()
			f := newProbeScenario(t, mode)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			f.cancel = cancel
			proof, err := f.p.Run(ctx)
			if mode == "healthy" {
				if err != nil || !workspacemount.ValidProof(proof, f.p.intent.Challenge) || !f.removed || !f.finishedAbsent {
					t.Fatalf("healthy observation failed: %v events=%v", err, f.events)
				}
			} else if err == nil || proof != (workspacemount.Proof{}) {
				t.Fatalf("unsafe report released: %+v %v", proof, err)
			}
			if (mode == "begin" || mode == "bound" || mode == "collision" || mode == "lost-create") && f.started {
				t.Fatal("unauthorized execution")
			}
			if mode == "begin" && len(f.events) != 1 {
				t.Fatal("Docker before durable intent")
			}
			if mode == "cleanup" || mode == "absence" {
				if f.finishedAbsent {
					t.Fatal("manufactured cleanup acknowledgment")
				}
			}
			if mode == "lost-create" && slices.Contains(f.events, "rm") {
				t.Fatal("adopted lost create reply")
			}

			if mode != "begin" && !slices.Contains(f.events, "finish") {
				t.Fatal("begun attempt lacks outcome acknowledgment")
			}
			if mode == "lost-create" || mode == "malformed-create" || mode == "collision" {
				if f.finishedAbsent || slices.Contains(f.events, "rm") {
					t.Fatal("unknown identity treated as removed")
				}
			}
			before := len(f.events)
			if _, e := f.p.Run(context.Background()); e == nil || len(f.events) != before {
				t.Fatal("one-shot probe retried")
			}
		})
	}
}
func TestProbeCreateIsReadOnlyNoCopy(t *testing.T) {
	t.Parallel()
	f := newProbeScenario(t, "healthy")
	args := f.p.createArgs()
	for _, required := range []string{"--pull=never", "--network=none", "--read-only", "type=volume,src=" + f.v.Name + ",dst=/workspace,readonly,volume-nocopy"} {
		if !slices.Contains(args, required) {
			t.Fatalf("missing %s", required)
		}
	}
}
func TestProbeRequiresTrustedDependencies(t *testing.T) {
	t.Parallel()
	f := newProbeScenario(t, "healthy")
	var missing *probeScenario
	for _, d := range []struct {
		r DockerRunner
		j WorkspaceProbeJournal
	}{{nil, f}, {f, nil}, {missing, f}, {f, missing}} {
		if _, e := NewWorkspaceMountProbe(f.p.intent, d.r, d.j, f.p.root); e == nil {
			t.Fatal("missing dependency accepted")
		}
	}
}

func TestProbeRejectsInspectedPolicyDrift(t *testing.T) {
	t.Parallel()
	cases := map[string]func(*probeScenario){
		"root writable":     func(f *probeScenario) { f.c.HostConfig.ReadonlyRootfs = probeBool(false) },
		"privileged":        func(f *probeScenario) { f.c.HostConfig.Privileged = probeBool(true) },
		"stdin":             func(f *probeScenario) { f.c.Config.OpenStdin = probeBool(true) },
		"user":              func(f *probeScenario) { f.c.Config.User = "0:0" },
		"entrypoint":        func(f *probeScenario) { f.c.Config.Entrypoint = []string{"/bin/sh"} },
		"argument":          func(f *probeScenario) { f.c.Config.Cmd = []string{"foreign"} },
		"capabilities":      func(f *probeScenario) { f.c.HostConfig.CapAdd = []string{"SYS_ADMIN"} },
		"security option":   func(f *probeScenario) { f.c.HostConfig.SecurityOpt = nil },
		"host bind":         func(f *probeScenario) { f.c.HostConfig.Binds = []string{"/synthetic:/host:ro"} },
		"tmpfs":             func(f *probeScenario) { f.c.HostConfig.Tmpfs = map[string]string{"/tmp": "rw"} },
		"mount identity":    func(f *probeScenario) { f.c.Mounts[0].Name = "foreign" },
		"mount source":      func(f *probeScenario) { f.c.Mounts[0].Source = "/foreign" },
		"mount propagation": func(f *probeScenario) { f.c.Mounts[0].Propagation = "shared" },
		"extra mount":       func(f *probeScenario) { f.c.Mounts = append(f.c.Mounts, f.c.Mounts[0]) },
		"process bound":     func(f *probeScenario) { f.c.HostConfig.PidsLimit = nil },
		"cpu bound":         func(f *probeScenario) { f.c.HostConfig.NanoCpus = probeInt(0) },
		"logging":           func(f *probeScenario) { f.c.HostConfig.LogConfig.Type = "json-file" },
		"restart":           func(f *probeScenario) { f.c.HostConfig.RestartPolicy.Name = "always" },
		"namespace":         func(f *probeScenario) { f.c.HostConfig.PidMode = "host" },
		"healthcheck":       func(f *probeScenario) { f.c.Config.Healthcheck.Test = []string{"CMD", "foreign"} },
		"exit code":         func(f *probeScenario) { f.c.State.ExitCode = probeInt(1) },
		"volume options":    func(f *probeScenario) { f.v.Options = map[string]string{"o": "bind"} },
		"volume nonce":      func(f *probeScenario) { f.v.Labels["commonroom.workspace.nonce"] = strings.Repeat("f", 32) },
	}
	for name, change := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			f := newProbeScenario(t, "healthy")
			change(f)
			p, err := f.p.Run(context.Background())
			if err == nil || p != (workspacemount.Proof{}) || f.started {
				t.Fatalf("policy drift accepted: %v %v", p, err)
			}
			if !f.removed || !f.finishedAbsent {
				t.Fatal("known owned container left without cleanup")
			}
		})
	}
}

func outError(out io.Writer, s string) error { _, err := io.WriteString(out, s); return err }

type probeAdmissionDocker struct {
	f              *probeScenario
	extra, replace bool
	inspections    int
}

func (d *probeAdmissionDocker) Run(ctx context.Context, args []string, in []byte, out io.Writer) error {
	if args[0] == "ps" {
		raw := d.f.c.ID
		if d.extra {
			raw += "\n" + strings.Repeat("9", 64)
		}
		_, err := io.WriteString(out, raw)
		return err
	}
	if args[0] == "volume" && args[1] == "ls" {
		_, err := io.WriteString(out, d.f.v.Name)
		return err
	}
	if args[0] == "volume" && args[1] == "inspect" {
		d.inspections++
		if d.replace && d.inspections > 1 {
			d.f.v.CreatedAt = "2000-01-01T00:00:00Z"
		}
	}
	return d.f.Run(ctx, args, in, out)
}
func TestWorkspaceProbeAdmissionAllowsOnlyExactStoppedReadOnlyHelper(t *testing.T) {
	t.Parallel()
	for _, mode := range []string{"created", "exited", "running", "extra", "writable", "replacement"} {
		t.Run(mode, func(t *testing.T) {
			t.Parallel()
			f := newProbeScenario(t, "healthy")
			d := &probeAdmissionDocker{f: f, extra: mode == "extra", replace: mode == "replacement"}
			p, e := NewWorkspaceMountProbe(f.p.intent, d, f, f.p.root)
			if e != nil {
				t.Fatal(e)
			}
			f.p = p
			switch mode {
			case "exited":
				f.started = true
			case "running":
				f.c.State.Status = "running"
			case "writable":
				f.c.Mounts[0].RW = probeBool(true)
			}
			err := p.VerifyAdmission(t.Context(), f.c.ID)
			good := mode == "created" || mode == "exited"
			if (err == nil) != good {
				t.Fatalf("admission=%v", err)
			}
			if good && VerifyRetainedWorkspace(t.Context(), d, p.intent.JobID, p.intent.Repository, p.root, p.intent.Volume) == nil {
				t.Fatal("ordinary unattached-volume admission weakened")
			}
		})
	}
}
