package workerport

import (
	"encoding/base64"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestConnectionAuthProtocol(t *testing.T) {
	t.Parallel()
	v := workerAuthRequest{1, "connection-a", "codex"}
	encoded, err := encodeWorkerAuth(v)
	if err != nil {
		t.Fatal(err)
	}
	got, err := decodeWorkerAuth(encoded)
	if err != nil || got != v {
		t.Fatal(got, err)
	}
	for _, raw := range []string{`{"version":1,"connection":"../escape","provider":"codex"}`, `{"version":1,"connection":"a","provider":"shell"}`, `{"version":2,"connection":"a","provider":"claude"}`, `{"version":1,"connection":"a","provider":"codex","command":"sh"}`, `{"version":1,"connection":"a","provider":"codex"}{}`} {
		if _, err = decodeWorkerAuth(base64.RawURLEncoding.EncodeToString([]byte(raw))); err == nil {
			t.Fatal("accepted invalid request", raw)
		}
	}
	if _, err = decodeWorkerAuth(strings.Repeat("a", 1025)); err == nil {
		t.Fatal("unbounded input")
	}
}

func TestConnectionCredentialScope(t *testing.T) {
	t.Parallel()
	a, err := executionConnectionID("room/member/connection-a/ssh://worker")
	if err != nil || a != "connection-a" {
		t.Fatal(a, err)
	}
	b, _ := executionConnectionID("other/member2/connection-a/ssh://worker")
	if connectionAuthKey(a) != connectionAuthKey(b) || connectionAuthKey(a) == connectionAuthKey("connection-b") {
		t.Fatal("incorrect connection scope")
	}
	for _, key := range []string{"", "key", "r/p/../endpoint", "r/p/a;sh/endpoint"} {
		if _, err = executionConnectionID(key); err == nil {
			t.Fatal("unsafe identity accepted")
		}
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "auth.json")
	os.WriteFile(path, []byte(`{"fixture":true}`), 0600)
	if !credentialPresent(path) {
		t.Fatal("private fixture rejected")
	}
	os.Chmod(path, 0644)
	if credentialPresent(path) {
		t.Fatal("public credentials accepted")
	}
	os.Chmod(path, 0600)
	os.WriteFile(path, []byte("invalid"), 0600)
	if credentialPresent(path) {
		t.Fatal("invalid JSON accepted")
	}
	os.Remove(path)
	os.Symlink(filepath.Join(dir, "missing"), path)
	if credentialPresent(path) {
		t.Fatal("symlink accepted")
	}
}

func TestPersistWorkerCredential(t *testing.T) {
	t.Parallel()
	for _, provider := range []string{"codex", "claude"} {
		t.Run(provider, func(t *testing.T) {
			t.Parallel()
			dir := t.TempDir()
			source := filepath.Join(dir, "export.json")
			root := filepath.Join(dir, "connection", provider)
			raw := []byte(`{"fixture":"first"}`)
			if err := os.WriteFile(source, raw, 0600); err != nil {
				t.Fatal(err)
			}
			if err := persistWorkerCredential(root, provider, source); err != nil {
				t.Fatal(err)
			}
			target := filepath.Join(root, providerCredentialName(provider))
			info, err := os.Stat(target)
			if err != nil || info.Mode().Perm() != 0600 || !credentialPresent(target) {
				t.Fatal("private login not saved", err)
			}
			for _, invalid := range []string{"{}", "not-json", strings.Repeat("x", 65537)} {
				os.WriteFile(source, []byte(invalid), 0600)
				if err := persistWorkerCredential(root, provider, source); err == nil {
					t.Fatal("invalid export accepted")
				}
				got, err := os.ReadFile(target)
				if err != nil || string(got) != string(raw) {
					t.Fatal("previous login replaced", err)
				}
			}
			os.Remove(source)
			os.Symlink(target, source)
			if persistWorkerCredential(root, provider, source) == nil {
				t.Fatal("symlink export accepted")
			}
			os.Remove(source)
			if persistWorkerCredential(root, provider, source) == nil {
				t.Fatal("missing export accepted")
			}
			os.WriteFile(source, []byte(`{"fixture":"second"}`), 0600)
			if err := persistWorkerCredential(root, provider, source); err != nil {
				t.Fatal(err)
			}
			got, _ := os.ReadFile(target)
			if string(got) != `{"fixture":"second"}` {
				t.Fatal("replacement not saved")
			}
			files, _ := filepath.Glob(filepath.Join(root, ".login-*"))
			if len(files) != 0 {
				t.Fatal("temporary credential leaked")
			}
		})
	}
}

func TestWorkerCredentialExportPolicy(t *testing.T) {
	t.Parallel()
	for _, provider := range []string{"codex", "claude"} {
		args, err := workerCredentialExportArgs("sha256:trusted", "private-login-volume", provider)
		if err != nil {
			t.Fatal(err)
		}
		joined := strings.Join(args, " ")
		for _, required := range []string{"--network=none", "--read-only", "1000:1000", "--cap-drop=ALL", "no-new-privileges:true", "--log-driver=none", "type=volume,src=private-login-volume,dst=/home/agent,readonly", "O_NOFOLLOW", "65537", "JSON.parse"} {
			if !strings.Contains(joined, required) {
				t.Fatalf("missing export boundary %s", required)
			}
		}
		for _, forbidden := range []string{"type=bind", "provider.sock", "docker.sock", "HTTP_PROXY", "auth-login", "--privileged"} {
			if strings.Contains(joined, forbidden) {
				t.Fatalf("unexpected export capability %s", forbidden)
			}
		}
		mounts := 0
		for _, arg := range args {
			if arg == "--mount" {
				mounts++
			}
		}
		if mounts != 1 {
			t.Fatal("export must mount only the login volume")
		}
		expected := "/home/agent/.codex/auth.json"
		if provider == "claude" {
			expected = "/home/agent/.claude/.credentials.json"
		}
		if args[len(args)-1] != expected {
			t.Fatal("wrong credential file")
		}
	}
	if _, err := workerCredentialExportArgs("image", "volume", "shell"); err == nil {
		t.Fatal("unsupported provider accepted")
	}
}

func TestCredentialExportOutputLimit(t *testing.T) {
	t.Parallel()
	var output credentialExportOutput
	if n, err := output.Write([]byte(strings.Repeat("x", 65536))); err != nil || n != 65536 {
		t.Fatal(n, err)
	}
	if n, err := output.Write([]byte("x")); err == nil || n != 0 || output.Len() != 65536 {
		t.Fatal("overflow must fail without retaining extra bytes")
	}
}

func TestClearWorkerCredentialScopeAndLock(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	first := filepath.Join(root, "connection-a", "claude")
	other := filepath.Join(root, "connection-b", "claude")
	os.MkdirAll(first, 0700)
	os.MkdirAll(other, 0700)
	for _, dir := range []string{first, other} {
		if err := os.WriteFile(filepath.Join(dir, ".credentials.json"), []byte(`{"fixture":true}`), 0600); err != nil {
			t.Fatal(err)
		}
	}
	unlock, err := lockWorkerCredential(first)
	if err != nil {
		t.Fatal(err)
	}
	if second, e := lockWorkerCredential(first); e == nil {
		second()
		t.Fatal("concurrent sign-in/out accepted")
	}
	unlock()
	if err := clearWorkerCredential(first, "claude"); err != nil {
		t.Fatal(err)
	}
	if credentialPresent(filepath.Join(first, ".credentials.json")) {
		t.Fatal("credentials remain")
	}
	if !credentialPresent(filepath.Join(other, ".credentials.json")) {
		t.Fatal("other connection cleared")
	}
	if err := clearWorkerCredential(first, "claude"); err != nil {
		t.Fatal("idempotent logout", err)
	}
	unlock, err = lockWorkerCredential(first)
	if err != nil {
		t.Fatal("lock not released", err)
	}
	unlock()
}

func TestCodexDeviceLoginUsesHeadlessContainerAttachment(t *testing.T) {
	t.Parallel()
	launch := isolatedRunArgs("sha256:"+strings.Repeat("a", 64), "login-fixture", "volume-fixture", "/temporary/provider.sock", "/unused", "codex", []string{"auth-login"})
	codex := workerLoginContainerArgs(launch, "codex")
	if codex[0] != "create" {
		t.Fatal(codex)
	}
	for _, arg := range codex {
		if arg == "-t" || arg == "-i" || arg == "--rm" || strings.Contains(arg, "/run/provider-auth.json") {
			t.Fatal("device login retained interactive attachment or existing credential mount", arg)
		}
	}
	joined := strings.Join(codex, " ")
	for _, boundary := range []string{"--network=none", "--read-only", "--cap-drop=ALL", "--security-opt=no-new-privileges:true", "--pids-limit=128", "--memory=1g", "/run/provider.sock"} {
		if !strings.Contains(joined, boundary) {
			t.Fatal("lost isolation boundary", boundary)
		}
	}
	claude := strings.Join(workerLoginContainerArgs(launch, "claude"), " ")
	if !strings.Contains(claude, "-t") || !strings.Contains(claude, "-i") {
		t.Fatal("interactive provider changed")
	}
}
