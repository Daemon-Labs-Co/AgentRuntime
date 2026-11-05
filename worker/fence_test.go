package worker

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"commonroom-runtime/protocol"
)

const (
	jobC     = "cccccccccccccccccccccccccccccccc"
	fenceKey = "room1/part1/conn1/worker"
)

func encodeFence(t *testing.T, v map[string]any) string {
	t.Helper()
	raw, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return base64.RawURLEncoding.EncodeToString(raw)
}

func fenceRequest(t *testing.T, version int, job string) string {
	return encodeFence(t, map[string]any{"version": version, "jobId": job, "provider": "codex", "key": fenceKey})
}

// dockerWith replaces the fixture's fake docker with one whose "ps" and "rm"
// behavior is supplied by the test. info and context always report a verified
// local rootless daemon.
func dockerWith(t *testing.T, f fixture, ps, rm string) {
	t.Helper()
	script := fmt.Sprintf("#!/bin/sh\ncase \"$1\" in\n info) printf '%%s\\n' '%s' ;;\n context) printf '%%s\\n' 'unix:///run/user/1000/docker.sock' ;;\n ps) %s ;;\n rm) %s ;;\n *) exit 2 ;;\nesac\n", rootlessInfo, ps, rm)
	if err := os.WriteFile(filepath.Join(f.Bin, "docker"), []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
}

func readStoredRecord(t *testing.T, f fixture, job string) map[string]any {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(f.Home, ".local/state/commonroom-worker/jobs", job+".json"))
	if err != nil {
		t.Fatalf("no job record: %v", err)
	}
	var rec map[string]any
	decode(t, string(raw), &rec)
	return rec
}

func TestCancelFencesAJobWhenNoContainerExists(t *testing.T) {
	t.Parallel()
	f := newFixture(t, options{})
	dockerWith(t, f, "printf ''", "exit 0")
	code, out, diag := run(f, protocol.ActionCancel, fenceRequest(t, 2, jobC))
	if code != 0 {
		t.Fatalf("code=%d diag=%q", code, diag)
	}
	var ack struct {
		Version               int
		JobID, Scope          string
		Stopped               bool
		CancellationRequested bool
	}
	decode(t, out, &ack)
	if ack.Version != 2 || ack.JobID != jobC || ack.Scope == "" || !ack.Stopped || !ack.CancellationRequested {
		t.Fatalf("%+v", ack)
	}
	rec := readStoredRecord(t, f, jobC)
	if rec["status"] != "cancelled" || rec["shutdownConfirmed"] != true {
		t.Fatalf("job was not durably fenced: %v", rec)
	}
	// Repeating the request is safe and reports the same outcome.
	code, out2, _ := run(f, protocol.ActionCancel, fenceRequest(t, 2, jobC))
	var again struct{ Stopped bool }
	decode(t, out2, &again)
	if code != 0 || !again.Stopped {
		t.Fatalf("second cancel: code=%d out=%q", code, out2)
	}
}

func TestCancelRemovesAManagedContainerAndProvesAbsence(t *testing.T) {
	t.Parallel()
	f := newFixture(t, options{})
	marker := filepath.Join(t.TempDir(), "removed")
	name := "commonroom-turn-" + jobC
	ps := fmt.Sprintf("if [ -e '%s' ]; then printf ''; else printf '%%s\\n' '%s|true'; fi", marker, name)
	dockerWith(t, f, ps, fmt.Sprintf(": > '%s'", marker))
	code, out, diag := run(f, protocol.ActionCancel, fenceRequest(t, 2, jobC))
	if code != 0 {
		t.Fatalf("code=%d diag=%q", code, diag)
	}
	var ack struct{ Stopped bool }
	decode(t, out, &ack)
	if !ack.Stopped {
		t.Fatalf("shutdown not confirmed: %s", out)
	}
	if _, err := os.Stat(marker); err != nil {
		t.Fatal("the managed container was never removed")
	}
}

func TestCancelRefusesToRemoveAnUnmanagedContainer(t *testing.T) {
	t.Parallel()
	f := newFixture(t, options{})
	marker := filepath.Join(t.TempDir(), "removed")
	name := "commonroom-turn-" + jobC
	dockerWith(t, f, fmt.Sprintf("printf '%%s\\n' '%s|'", name), fmt.Sprintf(": > '%s'", marker))
	code, out, diag := run(f, protocol.ActionCancel, fenceRequest(t, 2, jobC))
	if code == 0 || out != "" || !strings.Contains(diag, "refusing unmanaged container removal") {
		t.Fatalf("code=%d out=%q diag=%q", code, out, diag)
	}
	if _, err := os.Stat(marker); err == nil {
		t.Fatal("an unmanaged container was removed")
	}
}

func TestCancelDoesNotConfirmShutdownWhenAbsenceCannotBeVerified(t *testing.T) {
	t.Parallel()
	f := newFixture(t, options{})
	dockerWith(t, f, "exit 1", "exit 0")
	code, out, diag := run(f, protocol.ActionCancel, fenceRequest(t, 2, jobC))
	if code == 0 || out != "" {
		t.Fatalf("code=%d out=%q diag=%q", code, out, diag)
	}
	if rec := readStoredRecord(t, f, jobC); rec["shutdownConfirmed"] == true {
		t.Fatalf("shutdown was confirmed without proof: %v", rec)
	}
}

func TestCancelRefusesAContainerThatStaysAfterRemoval(t *testing.T) {
	t.Parallel()
	f := newFixture(t, options{})
	name := "commonroom-turn-" + jobC
	dockerWith(t, f, fmt.Sprintf("printf '%%s\\n' '%s|true'", name), "exit 0") // rm "succeeds" but the container persists
	code, out, diag := run(f, protocol.ActionCancel, fenceRequest(t, 2, jobC))
	if code == 0 || out != "" || !strings.Contains(diag, "container shutdown unverified") {
		t.Fatalf("code=%d out=%q diag=%q", code, out, diag)
	}
}

func TestCancelRefusesProtocolVersionMismatches(t *testing.T) {
	t.Parallel()
	f := newFixture(t, options{})
	dockerWith(t, f, "printf ''", "exit 0")
	cases := []struct {
		action  string
		version int
	}{
		{protocol.ActionCancel, 3},
		{protocol.ActionCancelPair, 2},
		{protocol.ActionCancelPairSpace, 2},
		{protocol.ActionCancelPairSpace, 3},
	}
	for _, tc := range cases {
		code, out, diag := run(f, tc.action, fenceRequest(t, tc.version, jobC))
		if code == 0 || out != "" || diag == "" {
			t.Errorf("%s v%d accepted: code=%d out=%q diag=%q", tc.action, tc.version, code, out, diag)
		}
	}
}

func TestCancelRefusesMalformedRequests(t *testing.T) {
	t.Parallel()
	f := newFixture(t, options{})
	dockerWith(t, f, "printf ''", "exit 0")
	good := map[string]any{"version": 2, "jobId": jobC, "provider": "codex", "key": fenceKey}
	with := func(k string, v any) map[string]any {
		m := map[string]any{}
		for a, b := range good {
			m[a] = b
		}
		m[k] = v
		return m
	}
	requests := map[string]string{
		"not base64":         "!!!not-base64!!!",
		"empty":              "",
		"oversized":          strings.Repeat("A", 4097),
		"unknown field":      encodeFence(t, with("extra", 1)),
		"bad job id":         encodeFence(t, with("jobId", "short")),
		"bad provider":       encodeFence(t, with("provider", "gemini")),
		"bad key":            encodeFence(t, with("key", "only/three/parts")),
		"path in key":        encodeFence(t, with("key", "../x/y/z/worker")),
		"repository on v2":   encodeFence(t, with("repository", strings.Repeat("a", 64))),
		"workspace binding":  encodeFence(t, with("expectedWorkspace", map[string]any{"version": 1, "name": "n", "nonce": "x", "createdAt": "2026-11-05T00:00:00Z"})),
		"trailing JSON":      base64.RawURLEncoding.EncodeToString([]byte(`{"version":2,"jobId":"` + jobC + `","provider":"codex","key":"` + fenceKey + `"}{}`)),
		"discard without id": encodeFence(t, with("discardWorkspace", true)),
	}
	for name, req := range requests {
		code, out, _ := run(f, protocol.ActionCancel, req)
		if code == 0 || out != "" {
			t.Errorf("%s: accepted (code=%d out=%q)", name, code, out)
		}
	}
	if entries, _ := os.ReadDir(filepath.Join(f.Home, ".local/state/commonroom-worker/jobs")); len(entries) != 0 {
		t.Errorf("refused requests must leave no job state, found %d entries", len(entries))
	}
}

func TestCancelRefusesDockerEnvironmentOverrides(t *testing.T) {
	t.Parallel()
	f := newFixture(t, options{})
	dockerWith(t, f, "printf ''", "exit 0")
	code, out, diag := runEnv(f, []string{"DOCKER_HOST=unix:///tmp/other.sock"}, protocol.ActionCancel, fenceRequest(t, 2, jobC))
	if code == 0 || out != "" || !strings.Contains(diag, "worker runtime selection is unsupported") {
		t.Fatalf("code=%d out=%q diag=%q", code, out, diag)
	}
}
