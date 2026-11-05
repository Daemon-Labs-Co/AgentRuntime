package worker

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"commonroom-runtime/protocol"
)

const (
	jobA = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	jobB = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
)

// writeRecord stores a legacy (version 0) job record the way the worker does:
// owner-only file in an owner-only state directory.
func writeRecord(t *testing.T, f fixture, id, status string, mode os.FileMode) {
	t.Helper()
	dir := filepath.Join(f.Home, ".local/state/commonroom-worker/jobs")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	body, _ := json.Marshal(map[string]any{"jobId": id, "status": status, "provider": "codex"})
	path := filepath.Join(dir, id+".json")
	if err := os.WriteFile(path, body, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, mode); err != nil {
		t.Fatal(err)
	}
}

// writeSettledRecord stores a valid lifecycle-2 record whose shutdown was
// confirmed, the only kind the worker treats as settled.
func writeSettledRecord(t *testing.T, f fixture, id string) {
	t.Helper()
	dir := filepath.Join(f.Home, ".local/state/commonroom-worker/jobs")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256([]byte("room1/part1"))
	body, _ := json.Marshal(map[string]any{
		"version": 2, "jobId": id, "status": "finished", "provider": "codex",
		"roomId": "room1", "participantId": "part1", "connectionId": "conn1",
		"scope":     hex.EncodeToString(sum[:]),
		"startedAt": "2026-11-05T00:00:00Z", "updatedAt": "2026-11-05T00:01:00Z", "deadline": "2026-11-05T00:03:00Z",
		"shutdownConfirmed": true, "diagnosticCode": "completed",
	})
	path := filepath.Join(dir, id+".json")
	if err := os.WriteFile(path, body, 0o600); err != nil {
		t.Fatal(err)
	}
}

func decode(t *testing.T, out string, into any) {
	t.Helper()
	if err := json.Unmarshal([]byte(out), into); err != nil {
		t.Fatalf("not JSON: %q (%v)", out, err)
	}
}

func TestIdleReportsIdleOnlyWhenNothingManagedOrUnsettled(t *testing.T) {
	t.Parallel()
	type idle struct {
		Version, LifecycleVersion int
		Idle                      bool
	}
	cases := []struct {
		name   string
		o      options
		record string
		want   bool
	}{
		{"nothing running", options{}, "", true},
		{"managed container present", options{psOutput: "abc123\n"}, "", false},
		{"unsettled job record", options{}, "running", false},
		{"legacy record labelled finished", options{}, "finished", false}, // a label is not shutdown proof
		{"settled lifecycle-2 record", options{}, "settled", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			f := newFixture(t, tc.o)
			switch tc.record {
			case "":
			case "settled":
				writeSettledRecord(t, f, jobA)
			default:
				writeRecord(t, f, jobA, tc.record, 0o600)
			}
			code, out, diag := run(f, protocol.ActionIdle)
			if code != 0 {
				t.Fatalf("code=%d diag=%q", code, diag)
			}
			var got idle
			decode(t, out, &got)
			if got.Version != 1 || got.LifecycleVersion != 2 || got.Idle != tc.want {
				t.Fatalf("%+v want idle=%v", got, tc.want)
			}
		})
	}
}

func TestIdleRefusesWithoutAVerifiedRootlessDaemon(t *testing.T) {
	t.Parallel()
	f := newFixture(t, options{infoJSON: `{"SecurityOptions":["name=seccomp"]}`})
	code, out, diag := run(f, protocol.ActionIdle)
	if code == 0 || out != "" || !strings.Contains(diag, "rootless Docker unavailable") {
		t.Fatalf("code=%d out=%q diag=%q", code, out, diag)
	}
}

func TestJobsSnapshotOrdersUnsettledFirstAndCounts(t *testing.T) {
	t.Parallel()
	f := newFixture(t, options{psOutput: "commonroom-x\n"})
	writeSettledRecord(t, f, jobA)
	writeRecord(t, f, jobB, "running", 0o600)
	code, out, diag := run(f, protocol.ActionJobs)
	if code != 0 {
		t.Fatalf("code=%d diag=%q", code, diag)
	}
	var got struct {
		Version           int
		Jobs              []struct{ JobID, Status, LeaseState string }
		ManagedContainers int
		Unresolved        int
		Truncated         bool
	}
	decode(t, out, &got)
	if got.Version != 2 || len(got.Jobs) != 2 || got.ManagedContainers != 1 || got.Unresolved != 1 || got.Truncated {
		t.Fatalf("%+v", got)
	}
	if got.Jobs[0].JobID != jobB || got.Jobs[0].Status != "running" || got.Jobs[0].LeaseState != "legacy" || got.Jobs[1].JobID != jobA || got.Jobs[1].LeaseState != "free" {
		t.Fatalf("unsettled job must come first: %+v", got.Jobs)
	}
}

func TestJobsSnapshotIsEmptyWithoutRecords(t *testing.T) {
	t.Parallel()
	f := newFixture(t, options{})
	code, out, _ := run(f, protocol.ActionJobs)
	if code != 0 {
		t.Fatalf("code=%d", code)
	}
	var got struct {
		Version, ManagedContainers, Unresolved int
		Jobs                                   []any
	}
	decode(t, out, &got)
	if got.Version != 2 || got.Jobs == nil || len(got.Jobs) != 0 || got.ManagedContainers != 0 || got.Unresolved != 0 {
		t.Fatalf("%+v (%s)", got, out)
	}
}

func TestContainerActionsRefuseDockerEnvironmentOverrides(t *testing.T) {
	t.Parallel()
	f := newFixture(t, options{})
	for _, override := range []string{"DOCKER_HOST=unix:///tmp/other.sock", "DOCKER_CONTEXT=remote"} {
		code, out, diag := runEnv(f, []string{override}, protocol.ActionJobs)
		if code == 0 || out != "" || !strings.Contains(diag, "worker runtime selection is unsupported") {
			t.Fatalf("%s: code=%d out=%q diag=%q", override, code, out, diag)
		}
	}
}

func TestJobsRefusesNonLocalDockerContext(t *testing.T) {
	t.Parallel()
	f := newFixture(t, options{})
	script := "#!/bin/sh\ncase \"$1\" in\n info) printf '%s\\n' '" + rootlessInfo + "' ;;\n context) printf '%s\\n' 'tcp://10.0.0.1:2375' ;;\n ps) ;;\n *) exit 2 ;;\nesac\n"
	if err := os.WriteFile(filepath.Join(f.Bin, "docker"), []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	code, out, diag := run(f, protocol.ActionJobs)
	if code == 0 || out != "" || !strings.Contains(diag, "Docker context unverified") {
		t.Fatalf("code=%d out=%q diag=%q", code, out, diag)
	}
}

func TestStatusReturnsOnlyAVerifiedOwnerOnlyRecord(t *testing.T) {
	t.Parallel()
	f := newFixture(t, options{})
	writeRecord(t, f, jobA, "finished", 0o600)
	writeRecord(t, f, jobB, "finished", 0o644)
	code, out, diag := run(f, protocol.ActionStatus, jobA)
	if code != 0 {
		t.Fatalf("code=%d diag=%q", code, diag)
	}
	var rec struct{ JobID, Status string }
	decode(t, out, &rec)
	if rec.JobID != jobA || rec.Status != "finished" {
		t.Fatalf("%+v", rec)
	}
	for name, id := range map[string]string{"group/world readable": jobB, "unknown job": "cccccccccccccccccccccccccccccccc"} {
		code, out, diag := run(f, protocol.ActionStatus, id)
		if code == 0 || out != "" || !strings.Contains(diag, "Invalid or unsafe worker record") && !strings.Contains(diag, "no such file") {
			t.Fatalf("%s: code=%d out=%q diag=%q", name, code, out, diag)
		}
	}
}

func TestStatusRefusesAMismatchedRecordIdentity(t *testing.T) {
	t.Parallel()
	f := newFixture(t, options{})
	writeRecord(t, f, jobA, "finished", 0o600)
	dir := filepath.Join(f.Home, ".local/state/commonroom-worker/jobs")
	if err := os.Rename(filepath.Join(dir, jobA+".json"), filepath.Join(dir, jobB+".json")); err != nil {
		t.Fatal(err)
	}
	code, out, diag := run(f, protocol.ActionStatus, jobB)
	if code == 0 || out != "" || !strings.Contains(diag, "Invalid or unsafe worker record") {
		t.Fatalf("code=%d out=%q diag=%q", code, out, diag)
	}
}

func TestStatusRejectsMalformedJobIdentifiers(t *testing.T) {
	t.Parallel()
	f := newFixture(t, options{})
	for _, id := range []string{"short", "../../etc/passwd", strings.Repeat("A", 32), jobA + "0", jobA[:31] + "g"} {
		code, out, _ := run(f, protocol.ActionStatus, id)
		if code == 0 || out != "" {
			t.Fatalf("%q accepted: code=%d out=%q", id, code, out)
		}
	}
}
