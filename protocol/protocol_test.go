package protocol

import (
	"strings"
	"testing"
)

const digest = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

func TestValidImageAcceptsOnlyDigests(t *testing.T) {
	t.Parallel()
	good := []string{"sha256:" + digest, "registry.example/agent@sha256:" + digest, "agent@sha256:" + digest}
	bad := []string{
		"", "agent", "agent:latest", "agent:1.2.3", "@sha256:" + digest,
		"agent@sha256:short", "agent@sha256:" + strings.ToUpper(digest[:62]) + "zz",
		"-agent@sha256:" + digest, "ag ent@sha256:" + digest, "agent@sha256:" + digest + "\n",
		"sha256:short", "sha512:" + digest, "agent@sha256:" + digest + "@sha256:" + digest,
	}
	for _, v := range good {
		if !ValidImage(v) {
			t.Errorf("rejected %q", v)
		}
	}
	for _, v := range bad {
		if ValidImage(v) {
			t.Errorf("accepted %q", v)
		}
	}
}

func TestValidJobID(t *testing.T) {
	t.Parallel()
	if !ValidJobID(strings.Repeat("a", 32)) || !ValidJobID("0123456789abcdef0123456789abcdef") {
		t.Fatal("rejected a valid job ID")
	}
	for _, v := range []string{"", strings.Repeat("a", 31), strings.Repeat("a", 33), strings.Repeat("A", 32), strings.Repeat("g", 32), strings.Repeat("a", 31) + "\n"} {
		if ValidJobID(v) {
			t.Errorf("accepted %q", v)
		}
	}
}

func TestActionsAreUniqueVersionedAndComplete(t *testing.T) {
	t.Parallel()
	seen := map[string]bool{}
	for _, a := range Actions {
		if seen[a] {
			t.Errorf("duplicate action %q", a)
		}
		seen[a] = true
		if !strings.Contains(a, "-v") {
			t.Errorf("action %q is not versioned", a)
		}
	}
	if len(Actions) != 13 || !seen[ActionReady] || !seen[ActionRun] {
		t.Fatalf("unexpected action set %v", Actions)
	}
}

func TestCredentialFilesCoverBothProviders(t *testing.T) {
	t.Parallel()
	if CredentialFiles["codex"] != "auth.json" || CredentialFiles["claude"] != ".credentials.json" || len(CredentialFiles) != 2 {
		t.Fatalf("unexpected credential files %v", CredentialFiles)
	}
}
