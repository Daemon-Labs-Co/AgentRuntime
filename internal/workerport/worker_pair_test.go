package workerport

import (
	"errors"
	"strings"
	"testing"
)

func pairRequest() workerRunRequest {
	r := sampleWorkerRequest()
	r.Version = workerPairLifecycleVersion
	r.Repository = strings.Repeat("b", 64)
	return r
}

func TestWorkerPairAdmissionReservesContainerSlotsAndRejectsOrphans(t *testing.T) {
	t.Parallel()
	next := fakeWorkerRecord(t, strings.Repeat("f", 32), "another/new/connection/worker")
	records := []workerJobRecord{}
	names := []string{}
	for _, suffix := range []string{"a"} {
		r := fakeWorkerRecord(t, strings.Repeat(suffix, 32), "room/agent"+suffix+"/connection/worker")
		r.Version = workerPairLifecycleVersion
		r.Execution = workerPairExecution
		r.Pair = &workerPairRecord{Version: 1, Repository: strings.Repeat("b", 64)}
		records = append(records, r)
		names = append(names, pairContainerName(r.JobID, "engine"), pairContainerName(r.JobID, "tool"))
	}
	if err := workerAdmission(records, names, next); err != nil {
		t.Fatal("available container slots rejected", err)
	}
	if err := workerAdmission(records, append(names, "commonroom-tool-"+strings.Repeat("9", 32)), next); err == nil {
		t.Fatal("orphan admitted")
	}
	r := fakeWorkerRecord(t, strings.Repeat("8", 32), "room/agent8/connection/worker")
	records = append(records, r)
	next.Version = workerPairLifecycleVersion
	next.Execution = workerPairExecution
	next.Pair = &workerPairRecord{Version: 1, Repository: strings.Repeat("b", 64)}
	if err := workerAdmission(records, names, next); err == nil {
		t.Fatal("container limit bypassed")
	}
}

func TestWorkerPairRuntimeEntryPointRemainsUnavailable(t *testing.T) {
	t.Parallel()
	request := pairRequest()
	request.ToolSeparation = true
	if err := validateWorkerRun(request); !errors.Is(err, errCredentialBoundary) {
		t.Fatal("lifecycle component enabled development", err)
	}
}
