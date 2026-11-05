package workerport

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func fakeWorkerRecord(t *testing.T, job, key string) workerJobRecord {
	t.Helper()
	r, err := newWorkerJobRecord(workerRunRequest{Version: 2, JobID: job, Provider: "codex", Key: key})
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func TestWorkerLeaseChild(t *testing.T) {
	dir := os.Getenv("COMMONROOM_TEST_LEASE_DIRECTORY")
	if dir == "" {
		return
	}
	request := sampleWorkerRequest()
	_, leases, err := admitWorkerJob(context.Background(), dir, request, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer leases.Close()
	fmt.Println("LEASE_READY")
	<-time.After(time.Minute)
}

func TestSupervisorCrashLeavesDurableJobAndBlocksReplacementUntilReconciled(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	cmd := exec.Command(os.Args[0], "-test.run=^TestWorkerLeaseChild$")
	cmd.Env = append(os.Environ(), "COMMONROOM_TEST_LEASE_DIRECTORY="+dir)
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err = cmd.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() {
		if cmd.Process != nil {
			cmd.Process.Kill()
		}
	}()
	ready := make(chan bool, 1)
	go func() {
		scanner := bufio.NewScanner(stdout)
		ready <- scanner.Scan() && scanner.Text() == "LEASE_READY"
	}()
	select {
	case ok := <-ready:
		if !ok {
			t.Fatal("child did not hold lease")
		}
	case <-time.After(3 * time.Second):
		t.Fatal("lease setup timeout")
	}
	job := sampleWorkerRequest().JobID
	lease, free, err := workerTryLease(dir, ".job-"+job+".lease")
	if err != nil || free {
		if lease != nil {
			lease.Close()
		}
		t.Fatal("supervisor lease not held")
	}
	cmd.Process.Kill()
	cmd.Wait()
	request := sampleWorkerRequest()
	request.JobID = strings.Repeat("b", 32)
	if _, next, err := admitWorkerJob(context.Background(), dir, request, nil); err == nil {
		next.Close()
		t.Fatal("abandoned membership admitted replacement")
	}
	fence := workerFenceRequest{Version: 2, JobID: job, Provider: "codex", Key: sampleWorkerRequest().Key}
	record, err := fenceWorkerJob(context.Background(), dir, fence, func(context.Context, string) error { return nil })
	if err != nil || !record.ShutdownConfirmed || record.DiagnosticCode != "abandoned_supervisor_reconciled" {
		t.Fatal("crash reconciliation failed", err)
	}
	_, next, err := admitWorkerJob(context.Background(), dir, request, nil)
	if err != nil {
		t.Fatal("verified shutdown still blocked replacement", err)
	}
	next.Close()
}

func TestWorkerCancellationBeforeLaunchTombstonesIdentity(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	request := sampleWorkerRequest()
	fence := workerFenceRequest{Version: 2, JobID: request.JobID, Provider: request.Provider, Key: request.Key}
	record, err := fenceWorkerJob(context.Background(), dir, fence, func(context.Context, string) error { return nil })
	if err != nil || !record.ShutdownConfirmed || record.DiagnosticCode != "cancelled_before_launch" {
		t.Fatal("missing job not fenced", err)
	}
	if _, leases, err := admitWorkerJob(context.Background(), dir, request, nil); err == nil {
		leases.Close()
		t.Fatal("delayed request launched after cancellation")
	}
}

func TestContainerAbsenceDoesNotProveSupervisorStopped(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	request := sampleWorkerRequest()
	_, leases, err := admitWorkerJob(context.Background(), dir, request, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer leases.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	fence := workerFenceRequest{Version: 2, JobID: request.JobID, Provider: request.Provider, Key: request.Key}
	if _, err = fenceWorkerJob(ctx, dir, fence, func(context.Context, string) error { return nil }); err == nil {
		t.Fatal("missing container bypassed held supervisor")
	}
	record, _ := readWorkerRecord(dir, request.JobID)
	if record.ShutdownConfirmed {
		t.Fatal("held supervisor recorded stopped")
	}
	leases.Close()
	record, err = fenceWorkerJob(context.Background(), dir, fence, func(context.Context, string) error { return errors.New("synthetic runtime outage") })
	if err == nil || record.ShutdownConfirmed || record.Status != "shutdown_unconfirmed" {
		t.Fatal("failed absence check accepted")
	}
}

func TestWorkerScopeLeaseBindsMembershipAcrossConnections(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	one := sampleWorkerRequest()
	_, leases, err := admitWorkerJob(context.Background(), dir, one, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer leases.Close()
	two := sampleWorkerRequest()
	two.JobID = strings.Repeat("b", 32)
	two.Key = "room/agent/other-connection/worker"
	if _, duplicate, err := admitWorkerJob(context.Background(), dir, two, nil); err == nil {
		duplicate.Close()
		t.Fatal("changed connection bypassed membership lock")
	}
	snapshot, err := workerSnapshot(dir, nil)
	if err != nil || snapshot.Unresolved != 1 || snapshot.Jobs[0].LeaseState != "held" {
		t.Fatal("held ownership missing from diagnostics", err)
	}
}

func TestWorkerAdmissionGlobalRoomAndUnknownStateLimits(t *testing.T) {
	t.Parallel()
	next := fakeWorkerRecord(t, strings.Repeat("f", 32), "target/next/connection/worker")
	records := []workerJobRecord{}
	for i := 0; i < 8; i++ {
		records = append(records, fakeWorkerRecord(t, fmt.Sprintf("%032x", i+1), fmt.Sprintf("room-%d/agent-%d/connection/worker", i, i)))
	}
	if workerAdmission(records, nil, next) == nil {
		t.Fatal("global quota bypassed")
	}
	records = records[:4]
	for i := range records {
		records[i] = fakeWorkerRecord(t, fmt.Sprintf("%032x", i+1), fmt.Sprintf("target/agent-%d/connection/worker", i))
	}
	if workerAdmission(records, nil, next) == nil {
		t.Fatal("room quota bypassed")
	}
	if workerAdmission([]workerJobRecord{{JobID: strings.Repeat("a", 32), Status: "running"}}, nil, next) == nil {
		t.Fatal("legacy unresolved job ignored")
	}
	if workerAdmission(nil, []string{"commonroom-turn-" + strings.Repeat("a", 32)}, next) == nil {
		t.Fatal("untracked container ignored")
	}
}

func TestWorkerFencingRejectsWrongBindingAndUnsafeFiles(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	request := sampleWorkerRequest()
	record := fakeWorkerRecord(t, request.JobID, request.Key)
	if err := writeWorkerRecord(dir, record, true); err != nil {
		t.Fatal(err)
	}
	bad := workerFenceRequest{Version: 2, JobID: request.JobID, Provider: "claude", Key: request.Key}
	if _, err := fenceWorkerJob(context.Background(), dir, bad, func(context.Context, string) error { t.Fatal("container touched before binding verified"); return nil }); err == nil {
		t.Fatal("wrong provider cancelled job")
	}
	if _, err := os.Stat(filepath.Join(dir, request.JobID+".cancel")); !os.IsNotExist(err) {
		t.Fatal("wrong binding wrote latch")
	}
	if err := os.Chmod(filepath.Join(dir, request.JobID+".json"), 0644); err != nil {
		t.Fatal(err)
	}
	if _, err := readWorkerRecord(dir, request.JobID); err == nil {
		t.Fatal("public worker record read")
	}
	if err := os.Symlink("unknown", filepath.Join(dir, ".unsafe.lease")); err != nil {
		t.Fatal(err)
	}
	if lease, _, err := workerTryLease(dir, ".unsafe.lease"); err == nil {
		lease.Close()
		t.Fatal("symlink lease accepted")
	}
}

func TestWorkerContainerReservationsIncludeUncreatedAndUnresolvedPairs(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name               string
		existing, incoming int
		wantBlocked        bool
	}{
		{"two pairs fit", 2, 2, false},
		{"third pair refused", 4, 2, true},
		{"mixed jobs fit", 3, 1, false},
		{"mixed jobs overflow", 3, 2, true},
		{"legacy fifth refused", 4, 1, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			records := []workerJobRecord{}
			remaining := tc.existing
			for i := 0; remaining > 0; i++ {
				r := fakeWorkerRecord(t, fmt.Sprintf("%032x", i+1), fmt.Sprintf("room%d/agent/connection/worker", i))
				if remaining >= 2 {
					r.Version = workerPairLifecycleVersion
					r.Execution = workerPairExecution
					r.Pair = &workerPairRecord{Version: 1, Repository: strings.Repeat("b", 64)}
					// A terminal label without shutdown evidence must still reserve both slots.
					r.Status = "failed"
					remaining -= 2
				} else {
					remaining--
				}
				records = append(records, r)
			}
			next := fakeWorkerRecord(t, strings.Repeat("f", 32), "target/new/connection/worker")
			if tc.incoming == 2 {
				next.Version = workerPairLifecycleVersion
				next.Execution = workerPairExecution
				next.Pair = &workerPairRecord{Version: 1, Repository: strings.Repeat("b", 64)}
			}
			if blocked := workerAdmission(records, nil, next) != nil; blocked != tc.wantBlocked {
				t.Fatalf("blocked=%v, want %v", blocked, tc.wantBlocked)
			}
		})
	}
}
