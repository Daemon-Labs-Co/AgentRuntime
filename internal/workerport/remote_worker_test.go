package workerport

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func sampleWorkerRequest() workerRunRequest {
	return workerRunRequest{Version: 2, IssuedAt: time.Now().UTC(), Deadline: time.Now().Add(179 * time.Second).UTC(), JobID: strings.Repeat("a", 32), Provider: "codex", Key: "room/agent/connection/worker", Args: append(providerTurnArgs("codex", false, false), "-")}
}

func TestRemoteWorkerRegistrationAndFlag(t *testing.T) {
	t.Parallel()
	for _, c := range []struct {
		endpoint, alias, flag string
		ok                    bool
	}{{"ssh://worker", "worker", "true", true}, {"ssh://worker/claude", "worker", "true", true}, {"ssh://jerry", "worker", "true", false}, {"ssh://worker", "worker", "false", false}, {"ssh://worker", "worker", "", false}, {"ssh://worker", "-option", "true", false}, {"codex", "worker", "true", false}, {"ssh://worker/sh", "worker", "true", false}} {
		_, _, err := remoteWorkerEndpoint(c.endpoint, c.alias, c.flag)
		if (err == nil) != c.ok {
			t.Fatal(c, err)
		}
	}
}

func TestWorkerRecordsAndDuplicateSubmission(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	v := workerJobRecord{JobID: strings.Repeat("b", 32), Status: "starting", Provider: "codex"}
	if err := writeWorkerRecord(dir, v, true); err != nil {
		t.Fatal(err)
	}
	if err := writeWorkerRecord(dir, v, true); err == nil {
		t.Fatal("duplicate job admitted")
	}
	v.Status = "finished"
	if err := writeWorkerRecord(dir, v, false); err != nil {
		t.Fatal(err)
	}
	got, err := readWorkerRecord(dir, v.JobID)
	if err != nil || !workerTerminal(got.Status) {
		t.Fatal("outcome lost")
	}
	fi, _ := os.Stat(filepath.Join(dir, v.JobID+".json"))
	if fi.Mode().Perm() != 0600 {
		t.Fatal("job record not private")
	}
}

func TestWorkerOutputFailureCancelsExecution(t *testing.T) {
	t.Parallel()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var b bytes.Buffer
	w := workerStreamWriter{writer: &b, remaining: 3, cancel: cancel}
	if _, err := w.Write([]byte("four")); err == nil || ctx.Err() == nil || b.Len() != 0 {
		t.Fatal("output overflow failed to cancel")
	}
}
