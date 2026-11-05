package workerport

import (
	"strings"
	"testing"
)

func TestTerminalLabelCannotReplaceCurrentShutdownProof(t *testing.T) {
	t.Parallel()
	next := fakeWorkerRecord(t, strings.Repeat("f", 32), "target/next/connection/worker")
	for _, status := range []string{"finished", "failed", "cancelled"} {
		for _, version := range []int{0, 1, workerLifecycleVersion, workerLifecycleVersion + 1} {
			for _, confirmed := range []bool{false, true} {
				record := fakeWorkerRecord(t, strings.Repeat("a", 32), "other/agent/connection/worker")
				record.Status, record.Version, record.ShutdownConfirmed = status, version, confirmed
				want := version == workerLifecycleVersion && confirmed
				if workerJobSettled(record) != want {
					t.Fatal("unsupported/unconfirmed record treated as settled", status, version, confirmed)
				}
				if (workerAdmission([]workerJobRecord{record}, nil, next) == nil) != (want || version == workerLifecycleVersion) {
					// Current unconfirmed work in another scope consumes a capacity
					// slot; legacy/future ownership cannot be established at all.
					t.Fatal("incorrect admission for record version", status, version, confirmed)
				}
			}
		}
	}
}

func TestLegacyTerminalSnapshotRemainsUnresolvedAndUnmodified(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	record := fakeWorkerRecord(t, strings.Repeat("a", 32), "room/agent/connection/worker")
	record.Version, record.Status, record.ShutdownConfirmed = 0, "finished", false
	if err := writeWorkerRecord(dir, record, true); err != nil {
		t.Fatal(err)
	}
	snapshot, err := workerSnapshot(dir, nil)
	if err != nil || snapshot.Unresolved != 1 || len(snapshot.Jobs) != 1 {
		t.Fatal("legacy shutdown ambiguity hidden", snapshot, err)
	}
	if snapshot.Jobs[0].LeaseState != "legacy" || snapshot.Jobs[0].ShutdownConfirmed {
		t.Fatal("legacy ownership/proof invented")
	}
	got, err := readWorkerRecord(dir, record.JobID)
	if err != nil || got.Version != 0 || got.ShutdownConfirmed || got.Status != "finished" {
		t.Fatal("legacy record rewritten", err)
	}
}
