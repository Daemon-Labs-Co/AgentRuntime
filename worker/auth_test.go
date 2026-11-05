package worker

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"commonroom-runtime/protocol"
)

const authConnection = "conn1"

func authRequest(t *testing.T, v map[string]any) string {
	t.Helper()
	raw, _ := json.Marshal(v)
	return base64.RawURLEncoding.EncodeToString(raw)
}

func goodAuth(t *testing.T, provider string) string {
	return authRequest(t, map[string]any{"version": 1, "connection": authConnection, "provider": provider})
}

// credentialRoot is where the worker keeps one connection's credentials for a provider.
func credentialRoot(f fixture, connection, provider string) string {
	sum := sha256.Sum256([]byte(connection))
	return filepath.Join(f.Auth, hex.EncodeToString(sum[:]), provider)
}

func putCredential(t *testing.T, f fixture, provider string, mode os.FileMode, body string) string {
	t.Helper()
	root := credentialRoot(f, authConnection, provider)
	if err := os.MkdirAll(root, 0o700); err != nil {
		t.Fatal(err)
	}
	name := "auth.json"
	if provider == "claude" {
		name = ".credentials.json"
	}
	path := filepath.Join(root, name)
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, mode); err != nil {
		t.Fatal(err)
	}
	return path
}

type authStatus struct {
	CredentialPresent bool `json:"credentialPresent"`
	RecoveryRequired  bool `json:"recoveryRequired"`
}

func statusOf(t *testing.T, f fixture, provider string) authStatus {
	t.Helper()
	code, out, diag := run(f, protocol.ActionAuthStatus, goodAuth(t, provider))
	if code != 0 {
		t.Fatalf("status failed: code=%d diag=%q", code, diag)
	}
	var s authStatus
	decode(t, out, &s)
	return s
}

func TestAuthStatusReportsOnlyAUsableOwnerOnlyCredential(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name     string
		provider string
		mode     os.FileMode
		body     string
		want     bool
	}{
		{"codex credential", "codex", 0o600, `{"tokens":"synthetic"}`, true},
		{"claude uses its own file name", "claude", 0o600, `{"claudeAiOauth":"synthetic"}`, true},
		{"group-readable is not usable", "codex", 0o640, `{"tokens":"synthetic"}`, false},
		{"world-readable is not usable", "codex", 0o644, `{"tokens":"synthetic"}`, false},
		{"invalid JSON is not usable", "codex", 0o600, `not json at all`, false},
		{"empty object is not usable", "codex", 0o600, `{}`, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			f := newFixture(t, options{})
			putCredential(t, f, tc.provider, tc.mode, tc.body)
			if got := statusOf(t, f, tc.provider); got.CredentialPresent != tc.want || got.RecoveryRequired {
				t.Fatalf("%+v want present=%v", got, tc.want)
			}
		})
	}
}

func TestAuthStatusIsScopedToTheConnectionAndProvider(t *testing.T) {
	t.Parallel()
	f := newFixture(t, options{})
	putCredential(t, f, "codex", 0o600, `{"tokens":"synthetic"}`)
	if statusOf(t, f, "claude").CredentialPresent {
		t.Fatal("a codex credential satisfied a claude status check")
	}
	code, out, _ := run(f, protocol.ActionAuthStatus, authRequest(t, map[string]any{"version": 1, "connection": "other", "provider": "codex"}))
	var s authStatus
	decode(t, out, &s)
	if code != 0 || s.CredentialPresent {
		t.Fatalf("another connection saw this credential: %+v", s)
	}
}

func TestAuthStatusWithholdsACredentialWhileRecoveryIsRequired(t *testing.T) {
	t.Parallel()
	f := newFixture(t, options{})
	path := putCredential(t, f, "codex", 0o600, `{"tokens":"synthetic"}`)
	if err := os.WriteFile(filepath.Join(filepath.Dir(path), ".credential-recovery-required"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	got := statusOf(t, f, "codex")
	if got.CredentialPresent || !got.RecoveryRequired {
		t.Fatalf("%+v", got)
	}
}

func TestAuthStatusNeverEchoesCredentialContents(t *testing.T) {
	t.Parallel()
	f := newFixture(t, options{})
	putCredential(t, f, "codex", 0o600, `{"tokens":"synthetic-secret-value"}`)
	_, out, diag := run(f, protocol.ActionAuthStatus, goodAuth(t, "codex"))
	if strings.Contains(out+diag, "synthetic-secret-value") {
		t.Fatalf("credential leaked: %q %q", out, diag)
	}
}

func TestAuthLogoutClearsTheCredentialWhenTheConnectionIsQuiet(t *testing.T) {
	t.Parallel()
	f := newFixture(t, options{})
	path := putCredential(t, f, "codex", 0o600, `{"tokens":"synthetic"}`)
	code, out, diag := run(f, protocol.ActionAuthLogout, goodAuth(t, "codex"))
	var res struct{ SignedOut bool }
	decode(t, out, &res)
	if code != 0 || !res.SignedOut {
		t.Fatalf("code=%d out=%q diag=%q", code, out, diag)
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatal("credential file still present")
	}
	if statusOf(t, f, "codex").CredentialPresent {
		t.Fatal("status still reports a credential")
	}
	// Signing out twice is harmless.
	if code, _, _ := run(f, protocol.ActionAuthLogout, goodAuth(t, "codex")); code != 0 {
		t.Fatal("second sign-out failed")
	}
}

func TestAuthLogoutRefusesWhileThatConnectionHasUnsettledWork(t *testing.T) {
	t.Parallel()
	f := newFixture(t, options{})
	path := putCredential(t, f, "codex", 0o600, `{"tokens":"synthetic"}`)
	dir := filepath.Join(f.Home, ".local/state/commonroom-worker/jobs")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256([]byte("room1/part1"))
	body, _ := json.Marshal(map[string]any{
		"version": 2, "jobId": jobA, "status": "running", "provider": "codex",
		"roomId": "room1", "participantId": "part1", "connectionId": authConnection,
		"scope":     hex.EncodeToString(sum[:]),
		"startedAt": "2026-11-05T00:00:00Z", "updatedAt": "2026-11-05T00:01:00Z", "deadline": "2026-11-05T00:03:00Z",
		"diagnosticCode": "running",
	})
	if err := os.WriteFile(filepath.Join(dir, jobA+".json"), body, 0o600); err != nil {
		t.Fatal(err)
	}
	code, out, diag := run(f, protocol.ActionAuthLogout, goodAuth(t, "codex"))
	if code == 0 || out != "" || !strings.Contains(diag, "must be fenced") {
		t.Fatalf("code=%d out=%q diag=%q", code, out, diag)
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatal("credential was removed while work was unsettled")
	}
}

func TestAuthActionsRefuseMalformedRequests(t *testing.T) {
	t.Parallel()
	f := newFixture(t, options{})
	putCredential(t, f, "codex", 0o600, `{"tokens":"synthetic"}`)
	base := func(k string, v any) string {
		m := map[string]any{"version": 1, "connection": authConnection, "provider": "codex"}
		m[k] = v
		return authRequest(t, m)
	}
	requests := map[string]string{
		"not base64":         "!!!",
		"oversized":          strings.Repeat("A", 1025),
		"wrong version":      base("version", 2),
		"unknown provider":   base("provider", "gemini"),
		"path in connection": base("connection", "../x"),
		"empty connection":   base("connection", ""),
		"unknown field":      base("extra", true),
		"trailing JSON":      base64.RawURLEncoding.EncodeToString([]byte(`{"version":1,"connection":"conn1","provider":"codex"}{}`)),
	}
	for _, action := range []string{protocol.ActionAuthStatus, protocol.ActionAuthLogout} {
		for name, req := range requests {
			if code, out, _ := run(f, action, req); code == 0 || out != "" {
				t.Errorf("%s accepted %s", action, name)
			}
		}
		if code, out, _ := run(f, action); code == 0 || out != "" {
			t.Errorf("%s accepted no operand", action)
		}
		if code, out, _ := run(f, action, goodAuth(t, "codex"), "extra"); code == 0 || out != "" {
			t.Errorf("%s accepted an extra operand", action)
		}
	}
	if _, err := os.Stat(filepath.Join(credentialRoot(f, authConnection, "codex"), "auth.json")); err != nil {
		t.Error("refused requests must not remove credentials")
	}
}
