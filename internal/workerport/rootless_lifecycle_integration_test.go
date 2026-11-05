package workerport

import (
	"context"
	"io"
	"os"
	"os/exec"
	"testing"
	"time"
)

// Opt-in maintenance smoke test: a credential-free, network-disabled Node timer,
// never a provider agent. It creates no database data or live job-record fixtures.
func TestRootlessCancellationIntegration(t *testing.T) {
	if os.Getenv("COMMONROOM_ROOTLESS_SMOKE") != "1" {
		t.Skip("explicit rootless worker maintenance verification only")
	}
	if err := configureWorker(); err != nil {
		t.Fatal("worker configuration unavailable")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	idle, err := workerIdleProbe(ctx)
	if err != nil || !idle {
		t.Fatal("worker must be verified idle before maintenance smoke")
	}
	liveDir, err := workerStateDirectory()
	if err != nil {
		t.Fatal(err)
	}
	admission, err := workerWaitLease(ctx, liveDir, ".admission.lease")
	if err != nil {
		t.Fatal(err)
	}
	defer admission.Close()
	names, err := managedWorkerContainers(ctx)
	if err != nil || len(names) != 0 {
		t.Fatal("managed work appeared; smoke aborted")
	}
	job := id()
	name := "commonroom-turn-" + job
	cmd := exec.CommandContext(ctx, "docker", "run", "-d", "--rm", "--name", name, "--label", "commonroom.managed=true", "--network=none", "--read-only", "--user", "1000:1000", "--cap-drop=ALL", "--security-opt=no-new-privileges:true", "--pids-limit=16", "--memory=128m", "--memory-swap=128m", "--cpus=0.1", "--log-driver=none", "--pull=never", "--entrypoint", "node", os.Getenv("COMMONROOM_AGENT_IMAGE"), "-e", "setInterval(()=>{},1000)")
	cmd.Stdout = io.Discard
	cmd.Stderr = io.Discard
	if cmd.Run() != nil {
		t.Fatal("synthetic container could not start")
	}
	defer func() {
		cleanup, done := context.WithTimeout(context.Background(), 5*time.Second)
		defer done()
		if stopWorkerContainer(cleanup, job) != nil {
			t.Error("synthetic container cleanup unverified")
		}
	}()
	dir := t.TempDir()
	request := workerFenceRequest{Version: 2, JobID: job, Provider: "codex", Key: "fixture/fixture-agent/fixture-connection/worker"}
	record, err := request.record()
	if err != nil {
		t.Fatal(err)
	}
	if err = writeWorkerRecord(dir, record, true); err != nil {
		t.Fatal(err)
	}
	record, err = fenceWorkerJob(ctx, dir, request, stopWorkerContainer)
	if err != nil || !record.ShutdownConfirmed {
		t.Fatal("real rootless cancellation could not be confirmed")
	}
	names, err = managedWorkerContainers(ctx)
	if err != nil || len(names) != 0 {
		t.Fatal("managed container remains after cancellation")
	}
}
