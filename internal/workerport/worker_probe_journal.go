package workerport

import (
	"bytes"
	"commonroom-runtime/internal/toolbroker"
	"commonroom-runtime/internal/workspacemount"
	"commonroom-runtime/protocol"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
)

var errWorkerProbeJournal = errors.New("workspace probe journal unavailable")

const workerProbeStop = ".workspace-probe-integrity-stop"

const workerProbeRecordLimit = 1024

type workerProbeEvent = protocol.WorkspaceProbeEvent

type workerProbeRecord struct {
	Version int                             `json:"version"`
	Intent  toolbroker.WorkspaceProbeIntent `json:"intent"`
	Events  []workerProbeEvent              `json:"events"`
}

func probeHex(s string, n int) bool {
	b, e := hex.DecodeString(s)
	return e == nil && len(b) == n && hex.EncodeToString(b) == s
}

func validWorkerProbeIntent(i toolbroker.WorkspaceProbeIntent) bool {
	return validWorkerJobID(i.JobID) && probeHex(i.Repository, 32) && strings.HasPrefix(i.Image, "sha256:") && probeHex(strings.TrimPrefix(i.Image, "sha256:"), 32) && workspacemount.ValidChallenge(i.Challenge) && toolbroker.ValidWorkspaceVolume(i.JobID, i.Volume, true)
}

func probeRecordName(i toolbroker.WorkspaceProbeIntent) string {
	return ".probe-" + i.JobID + "-" + i.Challenge + ".record"
}

func validWorkerProbeRecord(r workerProbeRecord) bool {
	if r.Version != 1 || !validWorkerProbeIntent(r.Intent) || len(r.Events) < 1 || len(r.Events) > 6 {
		return false
	}
	return validWorkerHelperEvents(r.Events)
}

func validWorkerHelperEvents(events []workerProbeEvent) bool {
	if len(events) < 1 || len(events) > 6 {
		return false
	}
	stage, id := "", ""
	for _, e := range events {
		switch e.Stage {
		case "begin":
			if stage != "" || e.ID != "" || e.Absent {
				return false
			}
		case "bound":
			if stage != "begin" || !probeHex(e.ID, 32) || e.Absent {
				return false
			}
			id = e.ID
		case "finish":
			if stage != "begin" && stage != "bound" {
				return false
			}
			if e.ID != "" && !probeHex(e.ID, 32) || id != "" && e.ID != id || e.Absent && e.ID == "" {
				return false
			}
			id = e.ID
		case "recovery":
			if (stage != "bound" && stage != "finish") || id == "" || e.ID != id || e.Absent {
				return false
			}
		case "recovery-finish":
			if stage != "recovery" || e.ID != id || !e.Absent {
				return false
			}
		case "recovered":
			if stage != "recovery-finish" || e.ID != id || !e.Absent {
				return false
			}
		case "confirmed":
			if stage != "finish" || !events[len(events)-2].Absent || !e.Absent || e.ID != id {
				return false
			}
		default:
			return false
		}
		stage = e.Stage
	}
	return true
}

func workerProbeStopped(dir string) bool {
	_, err := os.Lstat(filepath.Join(dir, workerProbeStop))
	return !os.IsNotExist(err)
}

func readWorkerProbeRecords(dir string) (map[string]workerProbeRecord, error) {
	f, err := os.Open(dir)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	entries, err := f.ReadDir(16385)
	if err != nil && err != io.EOF || len(entries) > 16384 {
		return nil, errWorkerProbeJournal
	}
	records := map[string]workerProbeRecord{}
	for _, entry := range entries {
		if !strings.HasPrefix(entry.Name(), ".probe-") {
			continue
		}
		if len(records) >= workerProbeRecordLimit {
			return nil, errWorkerProbeJournal
		}
		raw, err := readPrivateBounded(filepath.Join(dir, entry.Name()), 8192)
		if err != nil {
			return nil, errWorkerProbeJournal
		}
		var r workerProbeRecord
		if json.Unmarshal(raw, &r) != nil || !validWorkerProbeRecord(r) || probeRecordName(r.Intent) != entry.Name() {
			return nil, errWorkerProbeJournal
		}
		canonical, _ := json.Marshal(r)
		if !bytes.Equal(raw, canonical) {
			return nil, errWorkerProbeJournal
		}
		records[entry.Name()] = r
	}
	return records, nil
}

// All callers hold .admission.lease. Missing/invalid evidence never frees a slot.
// The per-worker ceiling is conservative: retained creator roles also stay charged.
func workerProbeCapacity(dir string, jobs []workerJobRecord, next int) error {
	if workerProbeStopped(dir) {
		return errWorkerProbeJournal
	}
	records, err := readWorkerProbeRecords(dir)
	if err != nil {
		return err
	}
	captureSlots, err := workerCaptureSlots(dir)
	if err != nil {
		return err
	}
	readerSlots, err := workerObjectReadSlots(dir)
	if err != nil {
		return err
	}
	count := next + captureSlots + readerSlots
	for _, job := range jobs {
		if !workerJobSettled(job) {
			count += workerContainerSlots(job)
		}
	}
	for _, r := range records {
		if !workerProbeSettled(r) {
			count++
		}
	}
	if count > workerContainerLimit {
		return errWorkerProbeJournal
	}
	return nil
}

func workerProbeSettled(r workerProbeRecord) bool {
	if len(r.Events) == 0 {
		return false
	}
	stage := r.Events[len(r.Events)-1].Stage
	return stage == "confirmed" || stage == "recovered"
}
