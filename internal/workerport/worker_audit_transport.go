package workerport

import (
	"commonroom-runtime/internal/toolbroker"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"time"
)

func workerAuditSocket(dir, job string) string {
	sum := sha256.Sum256([]byte(job))
	return filepath.Join(dir, ".audit-"+hex.EncodeToString(sum[:12])+".sock")
}

func auditScopeProof(scope toolbroker.Scope) []byte {
	raw, _ := json.Marshal(scope)
	sum := sha256.Sum256(raw)
	return sum[:]
}

func validWorkerAuditScope(record workerJobRecord, scope toolbroker.Scope) bool {
	return validWorkerRecord(record) && record.Version == workerWorkspaceLifecycleVersion && !workerJobSettled(record) && !workerTerminal(record.Status) &&
		record.JobID == scope.JobID && record.RoomID == scope.Room && record.ParticipantID == scope.Participant && record.ConnectionID == scope.Connection && record.Provider == scope.Provider && record.Pair.Repository == scope.RepositoryDigest && record.Deadline.Equal(scope.Deadline) && toolbroker.ValidAuditScope(scope, time.Now())
}

func decodeWorkerAuditScope(encoded string) (toolbroker.Scope, error) {
	var scope toolbroker.Scope
	if len(encoded) > 4096 {
		return scope, toolbroker.ErrAudit
	}
	raw, err := base64.RawURLEncoding.DecodeString(encoded)
	if err != nil || json.Unmarshal(raw, &scope) != nil || !toolbroker.ValidAuditScope(scope, time.Now()) {
		return toolbroker.Scope{}, toolbroker.ErrAudit
	}
	// Exact canonical encoding rejects unknown, duplicate, omitted and alternative
	// spellings before the request can select a socket.
	canonical, _ := json.Marshal(scope)
	if string(canonical) != string(raw) {
		return toolbroker.Scope{}, toolbroker.ErrAudit
	}
	return scope, nil
}

// workerAttachAudit forwards only a registered private audit socket, over its
// own SSH session. It never executes provider commands or consumes model output.
func workerAttachAudit(ctx context.Context, dir string, scope toolbroker.Scope, in io.Reader, out io.Writer) error {
	record, err := readWorkerRecord(dir, scope.JobID)
	if err != nil || !validWorkerAuditScope(record, scope) {
		return toolbroker.ErrAudit
	}
	lease, free, err := workerTryLease(dir, ".job-"+scope.JobID+".lease")
	if lease != nil {
		lease.Close()
	}
	if err != nil || free {
		return toolbroker.ErrAudit
	}
	fi, err := os.Lstat(dir)
	if err != nil || !fi.IsDir() || fi.Mode().Perm()&0077 != 0 {
		return toolbroker.ErrAudit
	}
	conn, err := (&net.Dialer{}).DialContext(ctx, "unix", workerAuditSocket(dir, scope.JobID))
	if err != nil {
		return toolbroker.ErrAudit
	}
	defer conn.Close()
	stop := context.AfterFunc(ctx, func() { conn.Close() })
	defer stop()
	deadline := time.Now().Add(5 * time.Second)
	if scope.Deadline.Before(deadline) {
		deadline = scope.Deadline
	}
	conn.SetDeadline(deadline)
	if _, err = conn.Write(auditScopeProof(scope)); err != nil {
		return toolbroker.ErrAudit
	}
	ack := []byte{0}
	if _, err = io.ReadFull(conn, ack); err != nil || ack[0] != 1 {
		return toolbroker.ErrAudit
	}
	conn.SetDeadline(scope.Deadline)
	// Read and write are independent. Closing the SSH process ends both; callers
	// must supply owned closable streams, not model pipes or shared stdin.
	return relayWorkerAudit(ctx, conn, in, out)
}

func relayWorkerAudit(ctx context.Context, conn net.Conn, in io.Reader, out io.Writer) error {
	input, ok := in.(io.ReadCloser)
	output, outputOK := out.(io.WriteCloser)
	if !ok || !outputOK {
		return errors.New("audit input must be owned and closable")
	}
	defer input.Close()
	results := make(chan error, 2)
	go func() { _, err := io.Copy(conn, input); results <- err }()
	go func() { _, err := io.Copy(out, conn); results <- err }()
	var err error
	received := 0
	select {
	case err = <-results:
		received = 1
	case <-ctx.Done():
		err = ctx.Err()
	}
	conn.Close()
	input.Close()
	// Both copies must finish before returning. out is an owned SSH pipe whose
	// consumer must drain it or cancel/close the session.
	output.Close()
	for received < 2 {
		<-results
		received++
	}
	if err != nil {
		return toolbroker.ErrAudit
	}
	return nil
}
