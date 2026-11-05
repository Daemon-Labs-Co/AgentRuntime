package workerport

import (
	"strings"
	"testing"
)

func TestIsolatedCommandPolicy(t *testing.T) {
	t.Parallel()
	image := "example/agent@sha256:" + strings.Repeat("a", 64)
	if !validAgentImage("sha256:" + strings.Repeat("a", 64)) {
		t.Fatal("immutable local image ID rejected")
	}
	if !validAgentImage(image) {
		t.Fatal("pinned image rejected")
	}
	for _, bad := range []string{"agent:latest", "-option@sha256:" + strings.Repeat("a", 64), "agent@sha256:bad", "agent\nother@sha256:" + strings.Repeat("a", 64)} {
		if validAgentImage(bad) {
			t.Fatal("unsafe image accepted")
		}
	}
	arg := "text with ' quotes; $(touch should-never-run)"
	args := isolatedRunArgs(image, "commonroom-test", "commonroom-session-test", "/tmp/socket", "/tmp/auth", "codex", []string{"exec", arg})
	joined := strings.Join(args, " ")
	for _, required := range []string{"--network=none", "--read-only", "--cap-drop=ALL", "no-new-privileges:true", "--pids-limit=128", "--memory=1g", "--cpus=1", "--user 1000:1000", "--pull=never", "--log-driver=none"} {
		if !strings.Contains(joined, required) {
			t.Fatal("missing containment setting", required)
		}
	}
	if args[len(args)-1] != arg {
		t.Fatal("arguments interpreted as shell syntax")
	}
	for _, forbidden := range []string{"--privileged", "--network=host", "docker.sock", "/Users/", "/root/.ssh"} {
		if strings.Contains(joined, forbidden) {
			t.Fatal("host privilege leaked", forbidden)
		}
	}
}

func TestProviderEgressPolicy(t *testing.T) {
	t.Parallel()
	for _, c := range []struct {
		provider, host string
		allowed        bool
	}{
		{"codex", "api.openai.com", true}, {"claude", "api.anthropic.com", true}, {"claude", "claude.com", true}, {"claude", "platform.claude.com", true}, {"claude", "console.anthropic.com", true}, {"claude", "claude.ai", true}, {"claude", "platform.claude.com.attacker.example", false}, {"claude", "evil.platform.claude.com", false}, {"claude", "platform.claude.com.", false}, {"codex", "platform.claude.com", false}, {"unknown", "claude.com", false}, {"claude", "api.openai.com", false}, {"codex", "api.openai.com.attacker.example", false}, {"codex", "localhost", false}, {"codex", "169.254.169.254", false}, {"codex", "api.openai.com.", false}, {"unknown", "api.openai.com", false},
	} {
		if providerHostAllowed(c.provider, c.host) != c.allowed {
			t.Fatal("egress policy incorrect", c)
		}
	}
}

func TestDockerSecurityPrerequisites(t *testing.T) {
	t.Parallel()
	valid := `{"SecurityOptions":["name=rootless","name=seccomp,profile=builtin"],"MemoryLimit":true,"SwapLimit":true,"PidsLimit":true,"CpuCfsQuota":true}`
	if !dockerSecurityReady([]byte(valid)) {
		t.Fatal("valid daemon rejected")
	}
	for _, broken := range []string{strings.Replace(valid, "rootless", "other", 1), strings.Replace(valid, "seccomp", "other", 1), strings.Replace(valid, `"MemoryLimit":true`, `"MemoryLimit":false`, 1), strings.Replace(valid, `"PidsLimit":true`, `"PidsLimit":false`, 1), "{}", "not json"} {
		if dockerSecurityReady([]byte(broken)) {
			t.Fatal("unsafe daemon accepted")
		}
	}
}

// Docker must keep stdin open: Codex receives its bounded prompt over stdin,
// including fresh connection checks. A missing -i silently drops the message.
func TestIsolatedRunKeepsPromptInputOpen(t *testing.T) {
	t.Parallel()
	args := isolatedRunArgs("sha256:trusted", "name", "volume", "/tmp/socket", "/tmp/auth", "codex", []string{"exec", "-"})
	if len(args) < 2 || args[0] != "run" || args[1] != "-i" {
		t.Fatal("isolated turns must accept prompt stdin")
	}
	for _, arg := range args {
		if arg == "-t" || arg == "--tty" {
			t.Fatal("machine-readable turns must not use a terminal")
		}
	}
}
