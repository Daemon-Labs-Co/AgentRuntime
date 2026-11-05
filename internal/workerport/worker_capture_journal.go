package workerport

import (
	"bytes"
	"commonroom-runtime/internal/toolbroker"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strings"
)

// workerCaptureIntent contains finite immutable metadata, never execution rights.
type workerCaptureIntent = toolbroker.CaptureIntent

type workerCaptureRecord struct {
	Version int                 `json:"version"`
	Intent  workerCaptureIntent `json:"intent"`
	Events  []workerProbeEvent  `json:"events"`
}

func captureRecordName(i workerCaptureIntent) string {
	return ".capture-" + i.Request.Binding.Execution.JobID + "-" + i.Request.Challenge + ".record"
}

func validWorkerCaptureRecord(r workerCaptureRecord) bool {
	if r.Version != 1 || !validWorkerHelperEvents(r.Events) {
		return false
	}
	return toolbroker.ValidCaptureMetadata(r.Intent.Request, r.Intent.Image, r.Intent.Objects)
}

func readWorkerCaptureRecords(dir string) (map[string]workerCaptureRecord, error) {
	f, err := os.Open(dir)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	entries, err := f.ReadDir(16385)
	if err != nil && err != io.EOF || len(entries) > 16384 {
		return nil, errWorkerProbeJournal
	}
	records := map[string]workerCaptureRecord{}
	for _, entry := range entries {
		if !strings.HasPrefix(entry.Name(), ".capture-") {
			continue
		}
		if len(records) >= workerProbeRecordLimit {
			return nil, errWorkerProbeJournal
		}
		raw, err := readPrivateBounded(filepath.Join(dir, entry.Name()), 128*1024)
		var r workerCaptureRecord
		if err != nil || json.Unmarshal(raw, &r) != nil || !validWorkerCaptureRecord(r) || captureRecordName(r.Intent) != entry.Name() {
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

func captureRecordSettled(r workerCaptureRecord) bool {
	if len(r.Events) == 0 {
		return false
	}
	s := r.Events[len(r.Events)-1].Stage
	return s == "confirmed" || s == "recovered"
}

func workerCaptureSlots(dir string) (int, error) {
	records, err := readWorkerCaptureRecords(dir)
	if err != nil {
		return 0, err
	}
	count := 0
	for _, r := range records {
		if !captureRecordSettled(r) {
			count++
		}
	}
	return count, nil
}
