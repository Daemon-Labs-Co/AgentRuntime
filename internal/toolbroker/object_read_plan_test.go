package toolbroker

import (
	"commonroom-runtime/internal/objectcustody"
	"commonroom-runtime/internal/objectread"
	"context"
	"encoding/base64"
	"encoding/json"
	"io"
	"slices"
	"strings"
	"testing"
)

func objectReadPlanFixture(t *testing.T) (*ObjectReadContainerPlan, toolInspection, toolVolumeInspection) {
	t.Helper()
	capture, c, _, v := capturePlanFixture(t)
	scope := objectcustody.Scope{ExecutionScope: capture.request.Binding.Execution, OutputName: "patch", MemberName: "change.patch"}
	scope.RevisionDigest = strings.Repeat("6", 64)
	q := objectread.Request{Receipt: objectcustody.Receipt{Intent: objectcustody.Intent{ObjectID: strings.Repeat("7", 32), Scope: scope, MaxBytes: 128}, Bytes: 3, Digest: strings.Repeat("8", 64)}, Challenge: capture.request.Challenge}
	p, err := NewObjectReadContainerPlan(q, capture.image, capture.root, capture.objects)
	if err != nil {
		t.Fatal(err)
	}
	c.Name = "/" + p.name()
	c.Config.Labels = p.labels()
	c.Config.WorkingDir = "/objects"
	c.Config.Entrypoint = []string{objectReadExecutable}
	c.Config.Cmd = []string{p.encoded}
	c.Mounts = c.Mounts[1:]
	c.Mounts[0].RW = probeBool(false)
	return p, c, v
}
func TestObjectReadPlanFixedPolicyAndPhases(t *testing.T) {
	t.Parallel()
	p, c, v := objectReadPlanFixture(t)
	args := p.CreateArgs()
	for _, want := range []string{"--pull=never", "--interactive", "--read-only", "--network=none", "--log-driver=none", "--cap-drop=ALL", objectReadExecutable, "type=volume,src=" + v.Name + ",dst=/objects,readonly,volume-nocopy"} {
		if !slices.Contains(args, want) {
			t.Fatal("missing restriction", want)
		}
	}
	mounts := 0
	for _, arg := range args {
		if arg == "--mount" {
			mounts++
		}
		if strings.Contains(arg, "/workspace") || strings.Contains(arg, "docker.sock") {
			t.Fatal("unexpected exposed mount", arg)
		}
	}
	if mounts != 1 {
		t.Fatal("reader has extra mount")
	}
	raw, err := base64.RawURLEncoding.DecodeString(args[len(args)-1])
	var q objectread.Request
	if err != nil || json.Unmarshal(raw, &q) != nil || q != p.request {
		t.Fatal("changed finite request")
	}
	for _, phase := range []string{"created", "running", "exited"} {
		c.State.Status = phase
		c.State.Running = probeBool(phase == "running")
		if err = p.VerifyInspection(c.ID, phase, inspectJSON(t, c), inspectJSON(t, v)); err != nil {
			t.Fatal(phase, err)
		}
	}
}
func TestObjectReadPlanRejectsPolicyDrift(t *testing.T) {
	t.Parallel()
	cases := map[string]func(*toolInspection, *toolVolumeInspection){
		"writable objects":        func(c *toolInspection, _ *toolVolumeInspection) { c.Mounts[0].RW = probeBool(true) },
		"extra source mount":      func(c *toolInspection, _ *toolVolumeInspection) { c.Mounts = append(c.Mounts, c.Mounts[0]) },
		"host bind":               func(c *toolInspection, _ *toolVolumeInspection) { c.Mounts[0].Type = "bind" },
		"credential path":         func(c *toolInspection, _ *toolVolumeInspection) { c.Mounts[0].Destination = "/credentials" },
		"wrong source inode path": func(c *toolInspection, _ *toolVolumeInspection) { c.Mounts[0].Source += "/other" },
		"unreviewed image":        func(c *toolInspection, _ *toolVolumeInspection) { c.Image = "sha256:" + strings.Repeat("9", 64) },
		"entrypoint":              func(c *toolInspection, _ *toolVolumeInspection) { c.Config.Entrypoint = []string{"/bin/sh"} },
		"environment": func(c *toolInspection, _ *toolVolumeInspection) {
			c.Config.Env = append(c.Config.Env, "TOKEN=synthetic")
		},
		"privileged":    func(c *toolInspection, _ *toolVolumeInspection) { c.HostConfig.Privileged = probeBool(true) },
		"writable root": func(c *toolInspection, _ *toolVolumeInspection) { c.HostConfig.ReadonlyRootfs = probeBool(false) },
		"network":       func(c *toolInspection, _ *toolVolumeInspection) { c.HostConfig.NetworkMode = "host" },
		"tty":           func(c *toolInspection, _ *toolVolumeInspection) { c.Config.Tty = probeBool(true) },
		"restart":       func(c *toolInspection, _ *toolVolumeInspection) { c.RestartCount = 1 },
		"exit":          func(c *toolInspection, _ *toolVolumeInspection) { c.State.ExitCode = probeInt(1) },
		"volume nonce": func(_ *toolInspection, v *toolVolumeInspection) {
			v.Labels["commonroom.custody.nonce"] = strings.Repeat("9", 32)
		},
		"volume replacement": func(_ *toolInspection, v *toolVolumeInspection) { v.CreatedAt = "2000-01-01T00:00:00Z" },
		"bind-backed volume": func(_ *toolInspection, v *toolVolumeInspection) { v.Options = map[string]string{"device": "/private"} },
	}
	for name, change := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			p, c, v := objectReadPlanFixture(t)
			change(&c, &v)
			if p.VerifyInspection(c.ID, "created", inspectJSON(t, c), inspectJSON(t, v)) == nil {
				t.Fatal("drift admitted")
			}
		})
	}
}

type objectReadPlanRunner struct {
	t        *testing.T
	p        *ObjectReadContainerPlan
	c        toolInspection
	v        toolVolumeInspection
	mode     string
	inspects int
	calls    int
}

func (f *objectReadPlanRunner) Run(ctx context.Context, args []string, in []byte, out io.Writer) error {
	f.calls++
	if ctx.Err() != nil || len(in) != 0 {
		return ErrRejected
	}
	switch args[0] {
	case "inspect":
		if args[len(args)-1] != f.c.ID {
			return ErrRejected
		}
		f.inspects++
		c := f.c
		if f.mode == "second pass drift" && f.inspects > 1 {
			c.Config.User = "0"
		}
		_, err := out.Write(inspectJSON(f.t, c))
		return err
	case "ps":
		raw := f.c.ID
		if f.mode == "extra reference" {
			raw += "\n" + strings.Repeat("9", 64)
		}
		_, err := io.WriteString(out, raw)
		return err
	case "volume":
		if args[1] == "inspect" {
			if args[len(args)-1] != f.v.Name {
				return ErrRejected
			}
			_, err := out.Write(inspectJSON(f.t, f.v))
			return err
		}
		if args[1] == "ls" {
			raw := f.v.Name
			if f.mode == "extra catalog" {
				raw += "\nother"
			}
			_, err := io.WriteString(out, raw)
			return err
		}
	}
	f.t.Error("non-observation command", args)
	return ErrRejected
}
func TestObjectReadAdmissionIndependentPasses(t *testing.T) {
	t.Parallel()
	for _, mode := range []string{"healthy", "extra reference", "extra catalog", "second pass drift"} {
		t.Run(mode, func(t *testing.T) {
			t.Parallel()
			p, c, v := objectReadPlanFixture(t)
			runner := &objectReadPlanRunner{t: t, p: p, c: c, v: v, mode: mode}
			err := p.VerifyAdmission(t.Context(), runner, c.ID, "created")
			if (err == nil) != (mode == "healthy") {
				t.Fatal(mode, err)
			}
			if mode == "healthy" && (runner.inspects != 2 || runner.calls != 12) {
				t.Fatal("missing independent observations", runner.inspects, runner.calls)
			}
		})
	}
}
func TestObjectReadMetadataRefusesUnboundedOrUnpinnedPlan(t *testing.T) {
	t.Parallel()
	p, _, _ := objectReadPlanFixture(t)
	for _, mode := range []string{"image", "root", "volume", "nonce", "created", "receipt"} {
		q := p.request
		image, root, objects := p.image, p.root, p.objects
		switch mode {
		case "image":
			image = "latest"
		case "root":
			root = "/"
		case "volume":
			objects.Name = "unrelated"
		case "nonce":
			objects.Nonce = "bad"
		case "created":
			objects.CreatedAt = "bad"
		case "receipt":
			q.Receipt.Intent.MaxBytes = objectcustody.MaxObjectBytes + 1
		}
		if _, err := NewObjectReadContainerPlan(q, image, root, objects); err == nil {
			t.Fatal("invalid metadata admitted", mode)
		}
	}
}
