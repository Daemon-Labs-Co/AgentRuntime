package worker

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"commonroom-runtime/protocol"
)

const goodImage = "registry.example/agent@sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

const digestHex = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

func tooManyRepositories() string {
	var entries []string
	for i := 0; i < 65; i++ {
		entries = append(entries, fmt.Sprintf(`"room%d":{"bundle":"/b/x","sha256":%q}`, i, digestHex))
	}
	return fmt.Sprintf(`{"image":%q,"authDir":"/tmp/a","developmentRepositories":{%s}}`, goodImage, strings.Join(entries, ","))
}

const rootlessInfo = `{"SecurityOptions":["name=seccomp,profile=builtin","name=rootless"],"MemoryLimit":true,"SwapLimit":true,"PidsLimit":true,"CpuCfsQuota":true}`

type fixture struct {
	Deps Deps
	Home string
	Auth string
}

type options struct {
	config     string // replaces the generated config when non-empty
	configMode os.FileMode
	infoJSON   string
	imageExit  int
	goos       string
	noDocker   bool
	codexMode  os.FileMode
	skipClaude bool
	skipCodex  bool
}

// newFixture builds a private home, credential directory and fake docker
// script inside t.TempDir(). No real container engine is ever invoked.
func newFixture(t *testing.T, o options) fixture {
	t.Helper()
	root := t.TempDir()
	home := filepath.Join(root, "home")
	auth := filepath.Join(root, "auth")
	must := func(err error) {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
	}
	must(os.MkdirAll(filepath.Join(home, ".config/commonroom-worker"), 0o700))
	config := o.config
	if config == "" {
		config = fmt.Sprintf(`{"image":%q,"authDir":%q}`, goodImage, auth)
	}
	mode := o.configMode
	if mode == 0 {
		mode = 0o600
	}
	configPath := filepath.Join(home, ".config/commonroom-worker/config.json")
	must(os.WriteFile(configPath, []byte(config), mode))
	must(os.Chmod(configPath, mode))

	for provider, file := range protocol.CredentialFiles {
		if (provider == "codex" && o.skipCodex) || (provider == "claude" && o.skipClaude) {
			continue
		}
		dir := filepath.Join(auth, provider)
		must(os.MkdirAll(dir, 0o700))
		credMode := os.FileMode(0o600)
		if provider == "codex" && o.codexMode != 0 {
			credMode = o.codexMode
		}
		path := filepath.Join(dir, file)
		must(os.WriteFile(path, []byte(`{"synthetic":"fixture"}`), 0o600))
		must(os.Chmod(path, credMode))
	}

	info := o.infoJSON
	if info == "" {
		info = rootlessInfo
	}
	docker := filepath.Join(root, "docker")
	script := fmt.Sprintf("#!/bin/sh\ncase \"$1\" in\n info) cat <<'EOF'\n%s\nEOF\n ;;\n image) exit %d ;;\n *) exit 2 ;;\nesac\n", info, o.imageExit)
	must(os.WriteFile(docker, []byte(script), 0o755))
	if o.noDocker {
		docker = filepath.Join(root, "missing-docker")
	}
	goos := o.goos
	if goos == "" {
		goos = "linux"
	}
	return fixture{Deps: Deps{Home: home, GOOS: goos, Docker: docker, Euid: os.Geteuid()}, Home: home, Auth: auth}
}

func run(d Deps, args ...string) (int, string, string) {
	var out, diag bytes.Buffer
	code := Run(d, args, strings.NewReader(""), &out, &diag)
	return code, out.String(), diag.String()
}

func TestReadyReportsConfiguredRuntimeAndCredentials(t *testing.T) {
	t.Parallel()
	f := newFixture(t, options{})
	code, out, diag := run(f.Deps, protocol.ActionReady)
	if code != 0 || diag != "" {
		t.Fatalf("code=%d diag=%q", code, diag)
	}
	var got protocol.Ready
	decoder := json.NewDecoder(strings.NewReader(out))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&got); err != nil {
		t.Fatal(err)
	}
	if got.Version != 1 || got.LifecycleVersion != 2 || !got.Configured || !got.RuntimeReady {
		t.Fatalf("unexpected result %+v", got)
	}
	if !got.Credentials["codex"] || !got.Credentials["claude"] || len(got.Credentials) != 2 {
		t.Fatalf("credentials %+v", got.Credentials)
	}
}

func TestReadyWireKeysMatchController(t *testing.T) {
	t.Parallel()
	f := newFixture(t, options{})
	_, out, _ := run(f.Deps, protocol.ActionReady)
	var raw map[string]any
	if err := json.Unmarshal([]byte(out), &raw); err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{"version", "lifecycleVersion", "configured", "runtimeReady", "credentials"} {
		if _, ok := raw[key]; !ok {
			t.Fatalf("missing key %q in %s", key, out)
		}
	}
	if len(raw) != 5 {
		t.Fatalf("unexpected keys in %s", out)
	}
}

func TestReadyReportsUnsafeOrMissingCredentialsWithoutFailing(t *testing.T) {
	t.Parallel()
	f := newFixture(t, options{codexMode: 0o644, skipClaude: true})
	code, out, _ := run(f.Deps, protocol.ActionReady)
	if code != 0 {
		t.Fatalf("code=%d", code)
	}
	var got protocol.Ready
	if err := json.Unmarshal([]byte(out), &got); err != nil {
		t.Fatal(err)
	}
	if got.Credentials["codex"] || got.Credentials["claude"] {
		t.Fatalf("group-readable and missing credentials must report false: %+v", got.Credentials)
	}
}

func TestReadyRefusals(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name string
		o    options
		want string
	}{
		{"missing config file", options{config: " ", configMode: 0o600}, "owner-only, bounded"},
		{"group-readable config", options{configMode: 0o640}, "owner-only"},
		{"unpinned image tag", options{config: `{"image":"registry.example/agent:latest","authDir":"/tmp/a"}`}, "digest-pinned"},
		{"relative auth directory", options{config: fmt.Sprintf(`{"image":%q,"authDir":"relative"}`, goodImage)}, "absolute authDir"},
		{"unknown config field", options{config: fmt.Sprintf(`{"image":%q,"authDir":"/tmp/a","extra":1}`, goodImage)}, "digest-pinned"},
		{"registry entry without digest", options{config: fmt.Sprintf(`{"image":%q,"authDir":"/tmp/a","developmentRepositories":{"r":{"bundle":"/b/x"}}}`, goodImage)}, "Invalid approved development bundle"},
		{"registry relative bundle", options{config: fmt.Sprintf(`{"image":%q,"authDir":"/tmp/a","developmentRepositories":{"r":{"bundle":"b/x","sha256":%q}}}`, goodImage, digestHex)}, "Invalid approved development bundle"},
		{"registry bundle with comma", options{config: fmt.Sprintf(`{"image":%q,"authDir":"/tmp/a","developmentRepositories":{"r":{"bundle":"/b/x,y","sha256":%q}}}`, goodImage, digestHex)}, "Invalid approved development bundle"},
		{"registry bad room name", options{config: fmt.Sprintf(`{"image":%q,"authDir":"/tmp/a","developmentRepositories":{"-bad":{"bundle":"/b/x","sha256":%q}}}`, goodImage, digestHex)}, "Invalid approved development bundle"},
		{"registry unknown nested field", options{config: fmt.Sprintf(`{"image":%q,"authDir":"/tmp/a","developmentRepositories":{"r":{"bundle":"/b/x","sha256":%q,"extra":1}}}`, goodImage, digestHex)}, "digest-pinned"},
		{"registry too large", options{config: tooManyRepositories()}, "Too many development repositories"},
		{"not linux", options{goos: "darwin"}, "Linux worker"},
		{"docker missing", options{noDocker: true}, "Rootless Docker is required"},
		{"daemon not rootless", options{infoJSON: `{"SecurityOptions":["name=seccomp"],"MemoryLimit":true,"SwapLimit":true,"PidsLimit":true,"CpuCfsQuota":true}`}, "limits unavailable"},
		{"daemon without seccomp", options{infoJSON: `{"SecurityOptions":["name=rootless"],"MemoryLimit":true,"SwapLimit":true,"PidsLimit":true,"CpuCfsQuota":true}`}, "limits unavailable"},
		{"swap limit false", options{infoJSON: `{"SecurityOptions":["name=seccomp","name=rootless"],"MemoryLimit":true,"SwapLimit":false,"PidsLimit":true,"CpuCfsQuota":true}`}, "limits unavailable"},
		{"missing pids limit", options{infoJSON: `{"SecurityOptions":["name=seccomp","name=rootless"],"MemoryLimit":true,"SwapLimit":true,"CpuCfsQuota":true}`}, "limits unavailable"},
		{"malformed daemon info", options{infoJSON: `not json`}, "limits unavailable"},
		{"image unavailable", options{imageExit: 1}, "image is unavailable"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			f := newFixture(t, tc.o)
			if tc.o.config == " " {
				os.Remove(filepath.Join(f.Home, ".config/commonroom-worker/config.json"))
			}
			code, out, diag := run(f.Deps, protocol.ActionReady)
			if code == 0 || out != "" {
				t.Fatalf("expected refusal, code=%d out=%q", code, out)
			}
			if !strings.Contains(diag, tc.want) {
				t.Fatalf("diagnostic %q does not mention %q", diag, tc.want)
			}
		})
	}
}

func TestEveryOtherActionIsRefused(t *testing.T) {
	t.Parallel()
	f := newFixture(t, options{})
	for _, action := range protocol.Actions {
		if action == protocol.ActionReady {
			continue
		}
		for _, args := range [][]string{{action}, {action, "value"}} {
			code, out, diag := run(f.Deps, args...)
			if code == 0 || out != "" || !strings.Contains(diag, "Unsupported worker action") {
				t.Fatalf("%v: code=%d out=%q diag=%q", args, code, out, diag)
			}
		}
	}
}

func TestMalformedInvocationsAreRefused(t *testing.T) {
	t.Parallel()
	f := newFixture(t, options{})
	for _, args := range [][]string{{}, {"unknown-v9"}, {protocol.ActionReady, "extra"}, {"--agent-worker", protocol.ActionReady}} {
		code, out, diag := run(f.Deps, args...)
		if code == 0 || out != "" || diag == "" {
			t.Fatalf("%v: code=%d out=%q diag=%q", args, code, out, diag)
		}
	}
}

func TestDiagnosticsNeverEchoCredentialContents(t *testing.T) {
	t.Parallel()
	f := newFixture(t, options{imageExit: 1})
	_, out, diag := run(f.Deps, protocol.ActionReady)
	if strings.Contains(out+diag, "synthetic") {
		t.Fatalf("credential content leaked: %q %q", out, diag)
	}
}

func TestReadPrivateBoundedRejectsUnsafeFiles(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	euid := os.Geteuid()
	write := func(name string, mode os.FileMode, data string) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte(data), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(p, mode); err != nil {
			t.Fatal(err)
		}
		return p
	}
	if _, err := readPrivateBounded(write("ok", 0o600, "x"), 8, euid); err != nil {
		t.Fatalf("owner-only file refused: %v", err)
	}
	if _, err := readPrivateBounded(write("open", 0o644, "x"), 8, euid); err == nil {
		t.Fatal("world-readable file accepted")
	}
	if _, err := readPrivateBounded(write("big", 0o600, "123456789"), 8, euid); err == nil {
		t.Fatal("oversized file accepted")
	}
	if _, err := readPrivateBounded(write("wrongowner", 0o600, "x"), 8, euid+1); err == nil {
		t.Fatal("file owned by another user accepted")
	}
	link := filepath.Join(dir, "link")
	if err := os.Symlink(filepath.Join(dir, "ok"), link); err != nil {
		t.Fatal(err)
	}
	if _, err := readPrivateBounded(link, 8, euid); err == nil {
		t.Fatal("symlink accepted")
	}
	hard := filepath.Join(dir, "hard")
	if err := os.Link(filepath.Join(dir, "ok"), hard); err != nil {
		t.Fatal(err)
	}
	if _, err := readPrivateBounded(hard, 8, euid); err == nil {
		t.Fatal("multi-link file accepted")
	}
}

// controllerReadyProbe mirrors the controller's ready-v1 acceptance rule
// (cmd/server/connection_diagnostics.go in the application repository). If the
// controller's rule changes, this contract test and the protocol version change
// together.
func controllerAcceptsReady(raw []byte) bool {
	var ready struct {
		Version          int  `json:"version"`
		Configured       bool `json:"configured"`
		RuntimeReady     bool `json:"runtimeReady"`
		LifecycleVersion int  `json:"lifecycleVersion"`
	}
	return json.Unmarshal(raw, &ready) == nil && ready.Version == 1 && ready.LifecycleVersion == 2 && ready.Configured && ready.RuntimeReady
}

func TestReadyOutputIsAcceptedByTheControllerProbe(t *testing.T) {
	t.Parallel()
	f := newFixture(t, options{})
	code, out, _ := run(f.Deps, protocol.ActionReady)
	if code != 0 || !controllerAcceptsReady([]byte(out)) {
		t.Fatalf("controller would reject %q (code %d)", out, code)
	}
	for _, rejected := range []string{`{}`, `{"version":1,"lifecycleVersion":2,"configured":true}`, `{"version":2,"lifecycleVersion":2,"configured":true,"runtimeReady":true}`} {
		if controllerAcceptsReady([]byte(rejected)) {
			t.Fatalf("contract helper accepted %s", rejected)
		}
	}
}

func TestReadyAcceptsAValidDevelopmentRegistryWithoutUsingIt(t *testing.T) {
	t.Parallel()
	for _, extra := range []string{
		`"developmentEnabled":true`,
		fmt.Sprintf(`"developmentEnabled":true,"developmentRepositories":{"room-1":{"bundle":"/srv/bundles/a.bundle","sha256":%q}}`, digestHex),
		`"developmentRepositories":{}`,
	} {
		f := newFixture(t, options{})
		config := fmt.Sprintf(`{"image":%q,"authDir":%q,%s}`, goodImage, f.Auth, extra)
		path := filepath.Join(f.Home, ".config/commonroom-worker/config.json")
		if err := os.WriteFile(path, []byte(config), 0o600); err != nil {
			t.Fatal(err)
		}
		code, out, diag := run(f.Deps, protocol.ActionReady)
		if code != 0 || !controllerAcceptsReady([]byte(out)) {
			t.Fatalf("%s: code=%d out=%q diag=%q", extra, code, out, diag)
		}
	}
}
