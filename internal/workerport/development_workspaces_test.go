package workerport

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestDevelopmentWorkerIndependentAuthorizationAndIntegrity(t *testing.T) {
	t.Parallel()
	dir, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	file := filepath.Join(dir, "repo.bundle")
	raw := []byte("synthetic bundle fixture; no live repository")
	if err := os.WriteFile(file, raw, 0644); err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(raw)
	digest := hex.EncodeToString(sum[:])
	registry, _ := json.Marshal(map[string]developmentRepository{"engineering": {Bundle: file, SHA256: digest}})
	for _, c := range []struct {
		key, digest, flag string
		ok                bool
	}{
		{"engineering/agent/connection/ssh://worker", digest, "true", true},
		{"engineering/agent/connection/ssh://worker", digest, "false", false},
		{"other/agent/connection/ssh://worker", digest, "true", false},
		{"engineering/agent/connection/ssh://worker", strings.Repeat("b", 64), "true", false},
	} {
		_, err := workerDevelopmentBundle(c.key, c.digest, c.flag, string(registry))
		if (err == nil) != c.ok {
			t.Fatal(c, err)
		}
	}
	if err := os.Chmod(file, 0666); err != nil {
		t.Fatal(err)
	}
	if _, err := workerDevelopmentBundle("engineering/a/c/w", digest, "true", string(registry)); err == nil {
		t.Fatal("world writable source allowed")
	}
	os.Chmod(file, 0644)
	os.WriteFile(file, []byte("tampered"), 0644)
	if _, err := workerDevelopmentBundle("engineering/a/c/w", digest, "true", string(registry)); err == nil {
		t.Fatal("tampered source allowed")
	}
	link := filepath.Join(dir, "link.bundle")
	os.Symlink(file, link)
	registry, _ = json.Marshal(map[string]developmentRepository{"engineering": {Bundle: link, SHA256: digest}})
	if _, err := workerDevelopmentBundle("engineering/a/c/w", digest, "true", string(registry)); err == nil {
		t.Fatal("symlink source allowed")
	}
}

func TestDevelopmentMountPreservesContainment(t *testing.T) {
	t.Parallel()
	args := isolatedRunArgs("image", "name", "volume", "/socket", "/credential", "codex", providerTurnArgs("codex", true, false))
	args = developmentRunArgs(args, "/approved/repo.bundle", strings.Repeat("a", 64), "commonroom-session-"+strings.Repeat("b", 32))
	joined := strings.Join(args, " ")
	for _, required := range []string{"--network=none", "--read-only", "--cap-drop=ALL", "--security-opt=no-new-privileges:true", "dst=/run/repository.bundle,readonly"} {
		if !strings.Contains(joined, required) {
			t.Fatal("lost boundary", required)
		}
	}
	for _, forbidden := range []string{"--privileged", "SYS_ADMIN", "seccomp=unconfined", "--network=host", "dst=/workspace,readonly"} {
		if strings.Contains(joined, forbidden) {
			t.Fatal(forbidden)
		}
	}
}
