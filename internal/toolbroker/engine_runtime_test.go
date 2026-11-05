package toolbroker

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"strings"
	"testing"
	"time"
)

type engineDockerFake struct {
	runtime                        *EngineContainerRuntime
	calls                          [][]string
	existing, failedStart, running bool
	mutation                       func(map[string]any)
	imageMutation                  func(map[string]any)
}

func (f *engineDockerFake) Run(ctx context.Context, args []string, _ []byte, out io.Writer) error {
	if ctx.Err() != nil {
		return ctx.Err()
	}
	f.calls = append(f.calls, append([]string(nil), args...))
	switch args[0] {
	case "ps":
		if f.existing {
			io.WriteString(out, strings.Repeat("f", 64))
		}
		return nil
	case "image":
		raw := map[string]any{"Id": "sha256:" + strings.Repeat("c", 64), "RepoDigests": []string{f.runtime.image}, "Config": map[string]any{"User": "1000:1000", "WorkingDir": "/tmp", "Env": []string{"PATH=/usr/local/bin"}, "Entrypoint": []string{"/usr/local/bin/node", "/opt/commonroom/engine-entrypoint.cjs"}, "Cmd": []string{}}}
		if f.imageMutation != nil {
			f.imageMutation(raw)
		}
		return json.NewEncoder(out).Encode(raw)
	case "create":
		_, err := io.WriteString(out, strings.Repeat("d", 64))
		return err
	case "inspect":
		raw := engineInspectionFixture(f.runtime, f.running)
		if f.mutation != nil {
			f.mutation(raw)
		}
		return json.NewEncoder(out).Encode(raw)
	case "start":
		if f.failedStart {
			return errors.New("synthetic daemon failure")
		}
		f.running = true
		_, err := io.WriteString(out, args[1])
		return err
	}
	return errors.New("unexpected synthetic operation")
}
func engineInspectionFixture(r *EngineContainerRuntime, running bool) map[string]any {
	env := []string{}
	for key, value := range engineEnvironment() {
		env = append(env, key+"="+value)
	}
	status := "created"
	if running {
		status = "running"
	}
	return map[string]any{"Id": strings.Repeat("d", 64), "Name": "/" + r.name(), "Image": "sha256:" + strings.Repeat("c", 64), "RestartCount": 0,
		"State":      map[string]any{"Running": running, "Paused": false, "Restarting": false, "Dead": false, "Error": "", "Status": status},
		"Config":     map[string]any{"Image": r.image, "User": "1000:1000", "WorkingDir": "/tmp", "Entrypoint": []string{"/usr/local/bin/node"}, "Cmd": []string{"/opt/commonroom/engine-entrypoint.cjs"}, "Env": env, "Labels": r.labels(), "Healthcheck": map[string]any{"Test": []string{"NONE"}}, "Tty": false, "OpenStdin": true, "StdinOnce": false},
		"HostConfig": map[string]any{"Privileged": false, "ReadonlyRootfs": true, "Init": true, "AutoRemove": false, "RestartPolicy": map[string]string{"Name": "no"}, "NetworkMode": "none", "PidMode": "", "IpcMode": "private", "CgroupnsMode": "private", "UsernsMode": "", "Memory": ToolMemoryBytes, "MemorySwap": ToolMemoryBytes, "NanoCpus": 500000000, "PidsLimit": ToolProcessLimit, "CapDrop": []string{"ALL"}, "SecurityOpt": []string{"no-new-privileges:true"}, "LogConfig": map[string]any{"Type": "none", "Config": map[string]string{}}, "Tmpfs": map[string]string{"/tmp": toolScratchOptions}, "Ulimits": []any{map[string]any{"Name": "nofile", "Soft": 512, "Hard": 512}}},
		"Mounts":     []any{map[string]any{"Type": "bind", "Source": r.gateway, "Destination": "/run/provider.sock", "RW": false, "Propagation": "rprivate"}}}
}
func engineFixture(t *testing.T) (*EngineContainerRuntime, *engineDockerFake) {
	t.Helper()
	scope := Scope{Version: 1, JobID: strings.Repeat("a", 32), Room: "room", Participant: "agent", Connection: "connection", Provider: "codex", RepositoryDigest: strings.Repeat("b", 64), Deadline: time.Now().UTC().Add(time.Minute)}
	fake := &engineDockerFake{}
	runtime, err := NewEngineContainerRuntime(t.Context(), scope, "ghcr.io/example/engine@sha256:"+strings.Repeat("a", 64), "/private/worker/gateway.sock", fake)
	if err != nil {
		t.Fatal(err)
	}
	fake.runtime = runtime
	t.Cleanup(runtime.Close)
	return runtime, fake
}
func TestEngineRuntimeCreatesFreshStoppedAndStartsByImmutableID(t *testing.T) {
	t.Parallel()
	runtime, fake := engineFixture(t)
	id, err := runtime.Create(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if fake.running {
		t.Fatal("create launched process")
	}
	if runtime.VerifyCreated(t.Context(), id) != nil {
		t.Fatal("stopped verification refused")
	}
	if err = runtime.Start(t.Context(), id); err != nil {
		t.Fatal(err)
	}
	if _, err = runtime.Inspect(t.Context(), id); err != nil {
		t.Fatal(err)
	}
	before := len(fake.calls)
	if runtime.Start(t.Context(), id) == nil {
		t.Fatal("used engine restarted")
	}
	if _, err = runtime.Create(t.Context()); err == nil {
		t.Fatal("engine recreated")
	}
	if len(fake.calls) != before {
		t.Fatal("replay reached daemon")
	}
	for _, call := range fake.calls {
		if call[0] == "create" {
			joined := strings.Join(call, " ")
			if strings.Contains(joined, "/workspace") || strings.Contains(joined, "--network=host") || strings.Contains(joined, "--rm") || !strings.Contains(joined, "--pull=never") {
				t.Fatal("uncontained engine arguments", call)
			}
		}
		if call[0] == "start" && call[1] != id {
			t.Fatal("mutable start")
		}
	}
}
func TestEngineRuntimeRejectsUnsafeReportedPolicyBeforeStart(t *testing.T) {
	t.Parallel()
	for _, mode := range []string{"gateway writable", "extra repository mount", "network", "privileged", "resource", "image", "environment", "auto remove", "restart", "tty", "identity", "reused state"} {
		t.Run(mode, func(t *testing.T) {
			runtime, fake := engineFixture(t)
			fake.mutation = func(raw map[string]any) {
				h := raw["HostConfig"].(map[string]any)
				c := raw["Config"].(map[string]any)
				switch mode {
				case "gateway writable":
					raw["Mounts"].([]any)[0].(map[string]any)["RW"] = true
				case "extra repository mount":
					raw["Mounts"] = append(raw["Mounts"].([]any), map[string]any{"Type": "volume", "Destination": "/workspace", "RW": true})
				case "network":
					h["NetworkMode"] = "host"
				case "privileged":
					h["Privileged"] = true
				case "resource":
					h["Memory"] = 0
				case "image":
					raw["Image"] = "sha256:" + strings.Repeat("f", 64)
				case "environment":
					c["Env"] = append(c["Env"].([]string), "OPENAI_API_KEY=synthetic")
				case "auto remove":
					h["AutoRemove"] = true
				case "restart":
					h["RestartPolicy"] = map[string]string{"Name": "always"}
				case "tty":
					c["Tty"] = true
				case "identity":
					raw["Id"] = strings.Repeat("f", 64)
				case "reused state":
					raw["State"].(map[string]any)["Status"] = "exited"
				}
			}
			if _, err := runtime.Create(t.Context()); err == nil {
				t.Fatal("unsafe policy accepted", mode)
			}
			if fake.running {
				t.Fatal("unsafe engine started")
			}
		})
	}
}
func TestEngineRuntimeImagePreflightRefusesImplicitVolumesAndCodeInjection(t *testing.T) {
	t.Parallel()
	for _, mode := range []string{"volume", "injected environment", "entrypoint", "mutable existing"} {
		t.Run(mode, func(t *testing.T) {
			runtime, fake := engineFixture(t)
			if mode == "mutable existing" {
				fake.existing = true
			} else {
				fake.imageMutation = func(raw map[string]any) {
					c := raw["Config"].(map[string]any)
					switch mode {
					case "volume":
						c["Volumes"] = map[string]any{"/workspace": map[string]any{}}
					case "injected environment":
						c["Env"] = []string{"NODE_OPTIONS=--require /injected", "LD_PRELOAD=/injected"}
					case "entrypoint":
						c["Entrypoint"] = []string{"sh", "-c"}
					}
				}
			}
			if _, err := runtime.Create(t.Context()); err == nil {
				t.Fatal("unsafe image/container admitted")
			}
			for _, call := range fake.calls {
				if call[0] == "create" {
					t.Fatal("unsafe preflight reached creation")
				}
			}
		})
	}
}
func TestEngineRuntimeCancelledLifetimeAndUncertainStartCannotRevive(t *testing.T) {
	t.Parallel()
	runtime, fake := engineFixture(t)
	id, err := runtime.Create(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	fake.failedStart = true
	if runtime.Start(t.Context(), id) == nil {
		t.Fatal("uncertain start succeeded")
	}
	before := len(fake.calls)
	fake.failedStart = false
	if runtime.Start(context.Background(), id) == nil || len(fake.calls) != before {
		t.Fatal("uncertain start retried")
	}
	runtime.Close()
	if _, err = runtime.Inspect(context.Background(), id); err == nil {
		t.Fatal("cancelled engine revived")
	}
}

func TestEngineRuntimeRechecksPolicyImmediatelyBeforeAndAfterStart(t *testing.T) {
	t.Parallel()
	for _, phase := range []string{"before", "after"} {
		t.Run(phase, func(t *testing.T) {
			runtime, fake := engineFixture(t)
			id, err := runtime.Create(t.Context())
			if err != nil {
				t.Fatal(err)
			}
			fake.mutation = func(raw map[string]any) {
				if phase == "before" || fake.running {
					raw["HostConfig"].(map[string]any)["NetworkMode"] = "host"
				}
			}
			if runtime.Start(t.Context(), id) == nil {
				t.Fatal("policy drift accepted", phase)
			}
			if phase == "before" && fake.running {
				t.Fatal("unsafe stopped container started")
			}
			if phase == "after" && !fake.running {
				t.Fatal("post-start observation not exercised")
			}
			before := len(fake.calls)
			if runtime.Start(t.Context(), id) == nil || len(fake.calls) != before {
				t.Fatal("uncertain start retried")
			}
		})
	}
}

func TestEngineRuntimeOriginalCancellationPrecedesDerivedPropagation(t *testing.T) {
	t.Parallel()
	runtime, fake := engineFixture(t)
	original, cancel := context.WithCancel(t.Context())
	runtime.original = original
	runtime.ctx = context.Background() // Simulate an uncancelled deadline child during propagation.
	cancel()
	if _, err := runtime.Create(context.Background()); err != ErrRejected || len(fake.calls) != 0 {
		t.Fatal("derived context revived cancelled original")
	}
}

func TestEngineRuntimeRefusesUnboundRepositoryDigestBeforeCreation(t *testing.T) {
	t.Parallel()
	for _, mode := range []string{"missing", "different digest", "different repository", "tag only", "malformed"} {
		t.Run(mode, func(t *testing.T) {
			t.Parallel()
			runtime, fake := engineFixture(t)
			fake.imageMutation = func(raw map[string]any) {
				switch mode {
				case "missing":
					delete(raw, "RepoDigests")
				case "different digest":
					raw["RepoDigests"] = []string{"ghcr.io/example/engine@sha256:" + strings.Repeat("f", 64)}
				case "different repository":
					raw["RepoDigests"] = []string{"ghcr.io/untrusted/engine@sha256:" + strings.Repeat("a", 64)}
				case "tag only":
					raw["RepoDigests"] = []string{"ghcr.io/example/engine:latest"}
				case "malformed":
					raw["RepoDigests"] = "not-a-list"
				}
			}
			if _, err := runtime.Create(t.Context()); err == nil {
				t.Fatal("unbound image digest accepted")
			}
			for _, call := range fake.calls {
				if call[0] == "create" || call[0] == "start" {
					t.Fatal("digest mismatch reached container mutation", call)
				}
			}
		})
	}
}

func TestEngineRuntimeDistinguishesManifestDigestFromLocalImageID(t *testing.T) {
	t.Parallel()
	for _, mode := range []string{"repository aliases", "direct image id", "wrong direct image id"} {
		t.Run(mode, func(t *testing.T) {
			t.Parallel()
			runtime, fake := engineFixture(t)
			if mode != "repository aliases" {
				runtime.image = "sha256:" + strings.Repeat("c", 64)
			}
			fake.imageMutation = func(raw map[string]any) {
				if mode == "repository aliases" {
					raw["RepoDigests"] = []string{"registry.example/alias@sha256:" + strings.Repeat("f", 64), runtime.image}
				}
				if mode == "direct image id" {
					delete(raw, "RepoDigests")
				}
				if mode == "wrong direct image id" {
					raw["Id"] = "sha256:" + strings.Repeat("f", 64)
				}
			}
			_, err := runtime.Create(t.Context())
			if (err != nil) != (mode == "wrong direct image id") {
				t.Fatal("wrong image identity outcome", err)
			}
		})
	}
}
