package toolbroker

import (
	"bytes"
	"commonroom-runtime/internal/workspacebootstrap"
	"context"
	"encoding/json"
	"io"
	"sync"
)

// StreamingDockerRunner is used only for approved bounded snapshot streams, never
// model commands. The production adapter retains all DockerRunner restrictions.
type StreamingDockerRunner interface {
	RunInput(context.Context, []string, io.Reader, io.Writer) error
}

// Bootstrap initializes the started idle tool container before engine startup.
// The worker supplies a staged approved bundle, never an arbitrary model file.
// It consumes/closes input, including on cancellation, and permits one attempt.
// The supervisor must retain the lease until this call returns and fence both
// containers on any uncertainty. A receipt is not independent image attestation.
func (r *ToolContainerRuntime) Bootstrap(ctx context.Context, input io.ReadCloser) (workspacebootstrap.Receipt, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	var receipt workspacebootstrap.Receipt
	if input == nil {
		return receipt, ErrRejected
	}
	var closeOnce sync.Once
	closeInput := func() { closeOnce.Do(func() { _ = input.Close() }) }
	defer closeInput()
	child, cancel, err := r.context(ctx)
	if err != nil {
		return receipt, err
	}
	defer cancel()
	stop := context.AfterFunc(child, closeInput)
	defer stop()
	runner, ok := r.executor.runner.(StreamingDockerRunner)
	if !ok || !r.running || r.id == "" || r.bootstrapAttempted {
		return receipt, ErrRejected
	}
	r.bootstrapAttempted = true
	if err = r.verify(child, r.id, true); err != nil {
		return receipt, err
	}
	p := r.executor.plan
	output := &boundedOutput{cancel: cancel, maxBytes: 1024}
	args := []string{"exec", "-i", "--user", "1000:1000", "--workdir", "/workspace", r.id, "/opt/commonroom/workspace-bootstrap", p.authority.scope.JobID, p.authority.scope.RepositoryDigest}
	err = runner.RunInput(child, args, io.LimitReader(input, workspacebootstrap.MaxBundleBytes+1), output)
	raw, overflow := output.snapshot()
	if err != nil || overflow || child.Err() != nil {
		return receipt, ErrExecution
	}
	if len(raw) == 0 || !validReceiptJSON(raw, &receipt) || !workspacebootstrap.ValidReceipt(receipt, p.authority.scope.JobID, p.authority.scope.RepositoryDigest) {
		return workspacebootstrap.Receipt{}, ErrRejected
	}
	if err = r.verify(child, r.id, true); err != nil {
		return workspacebootstrap.Receipt{}, err
	}
	if child.Err() != nil || r.lifetime.Err() != nil || r.original.Err() != nil {
		return workspacebootstrap.Receipt{}, ErrExecution
	}
	p.workspace.Store(&workspaceReadiness{lifetime: r.lifetime, original: r.original, containerID: r.id})
	return receipt, nil
}
func validReceiptJSON(raw []byte, receipt *workspacebootstrap.Receipt) bool {
	// Reuse bounded duplicate/case-alias detection before strict field decoding.
	var envelope map[string]json.RawMessage
	if decodeInspection(raw, &envelope) != nil {
		return false
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if decoder.Decode(receipt) != nil {
		return false
	}
	return len(envelope) == 5 && envelope["version"] != nil && envelope["job"] != nil && envelope["repository"] != nil && envelope["commit"] != nil && envelope["branch"] != nil
}
