package workerport

import (
	"context"
	"io"
	"net"
	"os"
	"testing"
	"time"
)

func awaitAuditResult(t *testing.T, ch <-chan error) {
	t.Helper()
	select {
	case <-ch:
	case <-time.After(2 * time.Second):
		t.Fatal("audit transport did not stop")
	}
}

func TestWorkerAuditRelayCancelsBlockedBothDirections(t *testing.T) {
	t.Parallel()
	ctx, cancel := context.WithCancel(t.Context())
	local, peer := net.Pipe()
	defer peer.Close()
	input, other := net.Pipe()
	defer other.Close()
	done := make(chan error, 1)
	go func() { done <- relayWorkerAudit(ctx, local, input, input) }()
	cancel()
	awaitAuditResult(t, done)
}

func TestAuditCommandChild(t *testing.T) {
	if os.Getenv("COMMONROOM_TEST_AUDIT_COMMAND") != "true" {
		return
	}
	io.Copy(os.Stdout, os.Stdin)
	os.Exit(0)
}
