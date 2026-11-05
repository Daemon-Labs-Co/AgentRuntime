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

// workerObjectReadIntent contains finite immutable metadata, never execution rights.
// This local adapter requires a retained-workspace creator lease. It grants no host
// read path, public download or isolation toggle. Source forks can fake guards and
// invalidate the mandatory containment/physical-quota contract. Account-wide audit,
// actual sealed-receipt custody and export authority MUST be independently checked.
type workerObjectReadIntent = toolbroker.ObjectReadIntent

type workerObjectReadRecord struct {
	Version int                    `json:"version"`
	Intent  workerObjectReadIntent `json:"intent"`
	Events  []workerProbeEvent     `json:"events"`
}

func objectReadRecordName(i workerObjectReadIntent) string {
	return ".object-read-" + i.Request.Receipt.Intent.Scope.JobID + "-" + i.Request.Challenge + ".record"
}

func validWorkerObjectReadRecord(r workerObjectReadRecord) bool {
	if r.Version != 1 || !validWorkerHelperEvents(r.Events) {
		return false
	}
	return toolbroker.ValidObjectReadMetadata(r.Intent.Request, r.Intent.Image, r.Intent.Objects)
}

func readWorkerObjectReadRecords(dir string) (map[string]workerObjectReadRecord, error) {
	f, err := os.Open(dir)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	entries, err := f.ReadDir(16385)
	if err != nil && err != io.EOF || len(entries) > 16384 {
		return nil, errWorkerProbeJournal
	}
	records := map[string]workerObjectReadRecord{}
	for _, entry := range entries {
		if !strings.HasPrefix(entry.Name(), ".object-read-") {
			continue
		}
		if len(records) >= workerProbeRecordLimit {
			return nil, errWorkerProbeJournal
		}
		raw, err := readPrivateBounded(filepath.Join(dir, entry.Name()), 16*1024)
		var r workerObjectReadRecord
		if err != nil || json.Unmarshal(raw, &r) != nil || !validWorkerObjectReadRecord(r) || objectReadRecordName(r.Intent) != entry.Name() {
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

func objectReadRecordSettled(r workerObjectReadRecord) bool {
	if len(r.Events) == 0 {
		return false
	}
	s := r.Events[len(r.Events)-1].Stage
	return s == "confirmed" || s == "recovered"
}

func workerObjectReadSlots(dir string) (int, error) {
	records, err := readWorkerObjectReadRecords(dir)
	if err != nil {
		return 0, err
	}
	count := 0
	for _, r := range records {
		if !objectReadRecordSettled(r) {
			count++
		}
	}
	return count, nil
}
