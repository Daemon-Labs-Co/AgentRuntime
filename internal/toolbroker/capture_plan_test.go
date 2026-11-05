package toolbroker

import (
	"commonroom-runtime/internal/objectcustody"
	"commonroom-runtime/internal/workspacecapture"
	"commonroom-runtime/internal/workspacesnapshot"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"path"
	"slices"
	"strings"
	"testing"
)

func capturePlanFixture(t *testing.T) (*CaptureContainerPlan, toolInspection, toolVolumeInspection, toolVolumeInspection) {
	t.Helper()
	f := newProbeScenario(t, "") // Metadata only: no Docker runner calls.
	req := workspacecapture.Request{Binding: workspacesnapshot.Binding{Execution: objectcustody.ExecutionScope{CompanyID: "company", RoomID: "room", TaskID: "task", ExecutionID: strings.Repeat("2", 32), JobID: f.p.intent.JobID, RepositoryDigest: f.p.intent.Repository, DefinitionDigest: strings.Repeat("3", 64)}, BaseCommit: strings.Repeat("4", 40), VolumeName: f.v.Name, VolumeNonce: f.p.intent.Volume.Nonce, VolumeCreatedAt: f.v.CreatedAt}, Members: []workspacesnapshot.Member{{OutputName: "patch", Name: "change.patch", MaxBytes: 1024}}, Challenge: f.p.intent.Challenge}
	objects := CaptureObjectVolume{"commonroom-custody-" + req.Binding.Execution.JobID, strings.Repeat("5", 32), f.v.CreatedAt}
	p, err := NewCaptureContainerPlan(req, f.p.intent.Image, f.p.root, objects)
	if err != nil {
		t.Fatal(err)
	}
	c := f.c
	c.Name = "/" + p.name()
	c.Config.OpenStdin = probeBool(true)
	c.Config.Entrypoint = []string{captureExecutable}
	c.Config.Cmd = []string{p.encoded}
	c.Config.Labels = p.labels()
	obj := toolVolumeInspection{Name: objects.Name, Driver: "local", Scope: "local", CreatedAt: objects.CreatedAt, Mountpoint: path.Join(p.root, "volumes", objects.Name, "_data"), Labels: p.objectLabels()}
	m := c.Mounts[0]
	m.Name = obj.Name
	m.Source = obj.Mountpoint
	m.Destination = "/objects"
	m.RW = probeBool(true)
	c.Mounts = append(c.Mounts, m)
	return p, c, f.v, obj
}
func TestCapturePlanFixedArgumentsAndPhases(t *testing.T) {
	t.Parallel()
	p, c, src, obj := capturePlanFixture(t)
	args := p.CreateArgs()
	for _, required := range []string{"--interactive", "--pull=never", "--read-only", "--network=none", "--cap-drop=ALL", "type=volume,src=" + src.Name + ",dst=/workspace,readonly,volume-nocopy", "type=volume,src=" + obj.Name + ",dst=/objects,volume-nocopy", captureExecutable} {
		if !slices.Contains(args, required) {
			t.Fatal("missing policy", required)
		}
	}
	raw, err := base64.RawURLEncoding.DecodeString(args[len(args)-1])
	if err != nil {
		t.Fatal(err)
	}
	var req workspacecapture.Request
	if json.Unmarshal(raw, &req) != nil {
		t.Fatal("request not encoded")
	}
	d, _ := workspacecapture.RequestDigest(req)
	if d != p.binding {
		t.Fatal("changed binding")
	}
	for _, phase := range []string{"created", "running", "exited"} {
		c.State.Status = phase
		c.State.Running = probeBool(phase == "running")
		if p.VerifyInspection(c.ID, phase, inspectJSON(t, c), inspectJSON(t, src), inspectJSON(t, obj)) != nil {
			t.Fatal("refused", phase)
		}
	}

}
func TestCapturePlanRejectsPolicyDrift(t *testing.T) {
	t.Parallel()
	cases := map[string]func(*toolInspection, *toolVolumeInspection, *toolVolumeInspection){
		"source writable":     func(c *toolInspection, _, _ *toolVolumeInspection) { c.Mounts[0].RW = probeBool(true) },
		"objects readonly":    func(c *toolInspection, _, _ *toolVolumeInspection) { c.Mounts[1].RW = probeBool(false) },
		"objects replacement": func(_ *toolInspection, _, o *toolVolumeInspection) { o.CreatedAt = "2000-01-01T00:00:00Z" },
		"object bind driver": func(_ *toolInspection, _, o *toolVolumeInspection) {
			o.Options = map[string]string{"device": "/private", "type": "none", "o": "bind"}
		},
		"source replacement": func(_ *toolInspection, s, _ *toolVolumeInspection) {
			s.Labels["commonroom.workspace.nonce"] = strings.Repeat("9", 32)
		},
		"objects nonce": func(_ *toolInspection, _, o *toolVolumeInspection) {
			o.Labels["commonroom.custody.nonce"] = strings.Repeat("9", 32)
		},
		"extra mount":           func(c *toolInspection, _, _ *toolVolumeInspection) { c.Mounts = append(c.Mounts, c.Mounts[0]) },
		"duplicate destination": func(c *toolInspection, _, _ *toolVolumeInspection) { c.Mounts[1] = c.Mounts[0] },
		"host mount":            func(c *toolInspection, _, _ *toolVolumeInspection) { c.Mounts[1].Type = "bind" },
		"socket": func(c *toolInspection, _, _ *toolVolumeInspection) {
			c.HostConfig.Binds = []string{"/var/run/docker.sock:/socket"}
		},
		"network":             func(c *toolInspection, _, _ *toolVolumeInspection) { c.HostConfig.NetworkMode = "host" },
		"privilege":           func(c *toolInspection, _, _ *toolVolumeInspection) { c.HostConfig.Privileged = probeBool(true) },
		"root writable":       func(c *toolInspection, _, _ *toolVolumeInspection) { c.HostConfig.ReadonlyRootfs = probeBool(false) },
		"interactive missing": func(c *toolInspection, _, _ *toolVolumeInspection) { c.Config.OpenStdin = nil },
		"tty":                 func(c *toolInspection, _, _ *toolVolumeInspection) { c.Config.Tty = probeBool(true) },
		"command":             func(c *toolInspection, _, _ *toolVolumeInspection) { c.Config.Cmd = []string{"model-input"} },
		"image":               func(c *toolInspection, _, _ *toolVolumeInspection) { c.Image = "sha256:" + strings.Repeat("9", 64) },
		"environment": func(c *toolInspection, _, _ *toolVolumeInspection) {
			c.Config.Env = append(c.Config.Env, "TOKEN=synthetic")
		},
		"executable":       func(c *toolInspection, _, _ *toolVolumeInspection) { c.Config.Entrypoint = []string{"/bin/sh"} },
		"oom":              func(c *toolInspection, _, _ *toolVolumeInspection) { c.State.OOMKilled = probeBool(true) },
		"failure":          func(c *toolInspection, _, _ *toolVolumeInspection) { c.State.ExitCode = probeInt(1) },
		"unlimited memory": func(c *toolInspection, _, _ *toolVolumeInspection) { c.HostConfig.Memory = probeInt(0) },
		"auto removal":     func(c *toolInspection, _, _ *toolVolumeInspection) { c.HostConfig.AutoRemove = probeBool(true) },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			p, c, s, o := capturePlanFixture(t)
			mutate(&c, &s, &o)
			if p.VerifyInspection(c.ID, "created", inspectJSON(t, c), inspectJSON(t, s), inspectJSON(t, o)) == nil {
				t.Fatal("accepted policy drift")
			}
		})
	}
}
func TestCapturePlanRefusesUntrustedInputs(t *testing.T) {
	t.Parallel()
	p, c, s, o := capturePlanFixture(t)
	for _, phase := range []string{"", "paused", "dead"} {
		if p.VerifyInspection(c.ID, phase, inspectJSON(t, c), inspectJSON(t, s), inspectJSON(t, o)) == nil {
			t.Fatal("phase admitted")
		}
	}
	if p.VerifyInspection(strings.Repeat("0", 64), "created", inspectJSON(t, c), inspectJSON(t, s), inspectJSON(t, o)) == nil {
		t.Fatal("ID substitution")
	}
	raw := inspectJSON(t, c)
	raw = append([]byte(`{"Id":"bad",`), raw[1:]...)
	if p.VerifyInspection(c.ID, "created", raw, inspectJSON(t, s), inspectJSON(t, o)) == nil {
		t.Fatal("duplicate field")
	}
	for _, change := range []func(*workspacecapture.Request, *string, *string, *CaptureObjectVolume){
		func(r *workspacecapture.Request, _, _ *string, _ *CaptureObjectVolume) {
			r.Binding.Execution.RevisionDigest = strings.Repeat("1", 64)
		},
		func(_ *workspacecapture.Request, i, _ *string, _ *CaptureObjectVolume) { *i = "latest" },
		func(_ *workspacecapture.Request, _, r *string, _ *CaptureObjectVolume) { *r = "/" },
		func(_ *workspacecapture.Request, _, _ *string, o *CaptureObjectVolume) { o.Name = "arbitrary" },
		func(_ *workspacecapture.Request, _, _ *string, o *CaptureObjectVolume) { o.Nonce = "" },
		func(_ *workspacecapture.Request, _, _ *string, o *CaptureObjectVolume) { o.CreatedAt = "" },
	} {
		r, i, root, objects := p.request, p.image, p.root, p.objects
		change(&r, &i, &root, &objects)
		if _, err := NewCaptureContainerPlan(r, i, root, objects); err == nil {
			t.Fatal("invalid plan admitted")
		}
	}
}

type captureAdmissionRunner struct {
	t           *testing.T
	p           *CaptureContainerPlan
	c           toolInspection
	src, obj    toolVolumeInspection
	mode        string
	inspections int
	calls       int
	cancel      context.CancelFunc
}

func (f *captureAdmissionRunner) Run(ctx context.Context, args []string, in []byte, out io.Writer) error {
	f.calls++
	if len(in) != 0 || ctx.Err() != nil {
		return ErrRejected
	}
	if _, ok := ctx.Deadline(); !ok {
		f.t.Fatal("missing bounded context")
	}
	var raw []byte
	switch args[0] {
	case "inspect":
		if args[len(args)-1] != f.c.ID {
			f.t.Fatal("wrong ID")
		}
		f.inspections++
		if f.mode == "second-pass writer" && f.inspections == 2 {
			f.c.Mounts[0].RW = probeBool(true)
		}
		raw = inspectJSON(f.t, f.c)
	case "volume":
		if args[1] == "inspect" {
			switch args[len(args)-1] {
			case f.src.Name:
				raw = inspectJSON(f.t, f.src)
			case f.obj.Name:
				raw = inspectJSON(f.t, f.obj)
			default:
				f.t.Fatal("wrong volume")
			}
		} else if args[1] == "ls" {
			raw = []byte(f.src.Name)
			if slices.Contains(args, "label=commonroom.execution=object-custody-v1") {
				raw = []byte(f.obj.Name)
			}
			if f.mode == "extra volume" {
				raw = append(raw, []byte("\nunexpected-volume")...)
			}
		} else {
			f.t.Fatal("volume mutation")
		}
	case "ps":
		raw = []byte(f.c.ID)
		for _, filter := range []string{"volume=" + f.src.Name, "volume=" + f.obj.Name, "label=commonroom.job=" + f.p.request.Binding.Execution.JobID, "name=^/" + f.p.name() + "$"} {
			if f.mode == filter && slices.Contains(args, filter) {
				raw = append(raw, []byte("\n"+strings.Repeat("9", 64))...)
			}
		}
	default:
		f.t.Fatal("mutation attempted", args)
	}
	if f.mode == "unavailable" {
		return errors.New("synthetic daemon unavailable")
	}
	if f.cancel != nil {
		f.cancel()
	}
	_, err := out.Write(raw)
	return err
}
func TestCaptureAdmissionInventoriesAndRechecks(t *testing.T) {
	t.Parallel()
	p, _, s, o := capturePlanFixture(t)
	modes := []string{"", "second-pass writer", "extra volume", "unavailable", "volume=" + s.Name, "volume=" + o.Name, "label=commonroom.job=" + p.request.Binding.Execution.JobID, "name=^/" + p.name() + "$", "cancel"}
	for _, mode := range modes {
		t.Run(mode, func(t *testing.T) {
			t.Parallel()
			plan, c, src, obj := capturePlanFixture(t)
			f := &captureAdmissionRunner{t: t, p: plan, c: c, src: src, obj: obj, mode: mode}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			if mode == "cancel" {
				f.cancel = cancel
			}
			err := plan.VerifyAdmission(ctx, f, c.ID, "created")
			if (err == nil) != (mode == "") {
				t.Fatal("unexpected admission", err)
			}
			if mode == "" && f.inspections != 2 {
				t.Fatal("not rechecked")
			}
		})
	}
}
func TestCaptureAdmissionRefusesBeforeDaemon(t *testing.T) {
	t.Parallel()
	p, c, s, o := capturePlanFixture(t)
	f := &captureAdmissionRunner{t: t, p: p, c: c, src: s, obj: o}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if p.VerifyAdmission(ctx, f, c.ID, "created") == nil || p.VerifyAdmission(context.Background(), f, c.ID, "paused") == nil || p.VerifyAdmission(context.Background(), f, "name", "created") == nil {
		t.Fatal("invalid admission")
	}
	if f.calls != 0 {
		t.Fatal("daemon called before validation")
	}
	var missing *captureAdmissionRunner
	if p.VerifyAdmission(context.Background(), missing, c.ID, "created") == nil {
		t.Fatal("typed nil accepted")
	}
}
