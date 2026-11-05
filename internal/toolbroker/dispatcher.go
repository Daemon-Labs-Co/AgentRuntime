package toolbroker

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"sync"
	"time"
)

const MaxOutputBytes = 16 * 1024

var (
	ErrBusy        = errors.New("tool job already has active work")
	ErrAudit       = errors.New("tool audit acknowledgement unavailable")
	ErrExecution   = errors.New("tool execution did not complete")
	ErrOutputLimit = errors.New("tool output limit exceeded")
)

// Action contains only admitted workspace input, never capability or launch options.
// Only an isolated credential-free executor may implement its operations. A source
// fork that supplies a host executor bypasses the required security boundary.
type Action struct {
	Operation string
	Path      string
	Content   string
	Command   []string
}

// Intent correlates the exact action digest with trusted scope and call ID. Audit
// implementations must durably persist it before acknowledging; returning nil
// without persistence invalidates the security contract. Raw tokens are excluded.
type Intent struct {
	Scope         Scope  `json:"scope"`
	CallID        string `json:"callId"`
	Operation     string `json:"operation"`
	PayloadDigest string `json:"payloadDigest"`
}

// Outcome is evidence metadata, not raw tool output. Success is acknowledged only
// after completion persistence; failure may represent an ambiguous side effect.
type Outcome struct {
	Status       string `json:"status"`
	OutputBytes  int    `json:"outputBytes"`
	OutputDigest string `json:"outputDigest"`
}

// Auditor is the trusted controller persistence boundary. Implementations must
// honor context cancellation and must never insert capability or provider secrets.
type Auditor interface {
	RecordIntent(context.Context, Intent) error
	RecordOutcome(context.Context, Intent, Outcome) error
}

// Executor must honor cancellation and execute exclusively inside the separate
// tool container. This package supplies no host, Docker or provider implementation.
// The supervisor must prove process/container shutdown; context cancellation alone
// cannot terminate an implementation that ignores it.
type Executor interface {
	Execute(context.Context, Scope, Action, io.Writer) error
}

// Dispatcher gates injected work; it is not connected to any production endpoint.
// All dispatchers sharing an authority also share its single active-work slot.
type Dispatcher struct {
	authority *Authority
	auditor   Auditor
	executor  Executor
}

// NewDispatcher requires explicit dependencies, without automatic fallback.
func NewDispatcher(a *Authority, audit Auditor, exec Executor) (*Dispatcher, error) {
	if a == nil || audit == nil || exec == nil {
		return nil, ErrRejected
	}
	return &Dispatcher{a, audit, exec}, nil
}

// Dispatch consumes an admitted call, persists intent, runs bounded work and
// persists its outcome. Repeated/ambiguous work is never automatically retried.
// The caller owns input until invocation and must not concurrently mutate it.
func (d *Dispatcher) Dispatch(parent context.Context, request Request) ([]byte, error) {
	if parent == nil || parent.Err() != nil {
		return nil, ErrExecution
	}
	if !validRequest(request) {
		return nil, ErrRejected
	}
	request.Command = append([]string(nil), request.Command...)
	select {
	case d.authority.slot <- struct{}{}:
		defer func() { <-d.authority.slot }()
	default:
		return nil, ErrBusy
	}
	if err := d.authority.Reserve(request, time.Now()); err != nil {
		return nil, err
	}
	ctx, cancel := d.authority.executionContext(parent)
	defer cancel()

	action := Action{request.Operation, request.Path, request.Content, request.Command}
	encoded, err := json.Marshal(action)
	if err != nil {
		return nil, ErrRejected
	}
	hash := sha256.Sum256(encoded)
	intent := Intent{d.authority.scope, request.CallID, action.Operation, hex.EncodeToString(hash[:])}
	if err = d.auditor.RecordIntent(ctx, intent); err != nil {
		d.authority.Revoke()
		return nil, ErrAudit
	}
	// Re-check synchronously: revoke may precede the cancellation watcher running.
	aborted := ctx.Err() != nil
	select {
	case <-d.authority.done:
		aborted = true
	default:
	}
	if aborted {
		if err = d.recordOutcome(ctx, intent, "not_executed", nil); err != nil {
			return nil, err
		}
		return nil, ErrExecution
	}
	output := &boundedOutput{cancel: cancel}
	execErr := d.executor.Execute(ctx, d.authority.scope, action, output)
	raw, overflow := output.snapshot()
	overflow = overflow || errors.Is(execErr, ErrOutputLimit)
	status := "succeeded"
	if execErr != nil || ctx.Err() != nil {
		status = "failed"
	}
	if overflow {
		status = "output_limit"
		d.authority.Revoke()
	}
	select {
	case <-d.authority.done:
		if status == "succeeded" {
			status = "failed"
		}
	default:
	}
	if err = d.recordOutcome(ctx, intent, status, raw); err != nil {
		return nil, err
	}
	if overflow {
		return nil, ErrOutputLimit
	}
	if ctx.Err() != nil {
		return nil, ErrExecution
	}
	select {
	case <-d.authority.done:
		return nil, ErrExecution
	default:
	}
	if status != "succeeded" {
		return nil, ErrExecution
	}
	return raw, nil
}

// boundedOutput refuses oversized writes, cancels work and never buffers beyond
// the cap. Executors must stop writing before returning; the mutex supports
// parallel stdout/stderr writes without an unsynchronized buffer.
type boundedOutput struct {
	mu       sync.Mutex
	buffer   bytes.Buffer
	overflow bool
	closed   bool
	maxBytes int
	cancel   context.CancelFunc
}

func (w *boundedOutput) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.closed {
		return 0, ErrExecution
	}
	limit := w.maxBytes
	if limit <= 0 {
		limit = MaxOutputBytes
	}
	if w.overflow || len(p) > limit-w.buffer.Len() {
		w.overflow = true
		w.cancel()
		return 0, ErrOutputLimit
	}
	return w.buffer.Write(p)
}
func (w *boundedOutput) snapshot() ([]byte, bool) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.closed = true
	return append([]byte(nil), w.buffer.Bytes()...), w.overflow
}

// recordOutcome withholds success and fences authority if persistence cannot
// acknowledge. Canceled audit contexts may leave an unresolved durable intent;
// recovery must never automatically replay such a call.
func (d *Dispatcher) recordOutcome(ctx context.Context, intent Intent, status string, raw []byte) error {
	hash := sha256.Sum256(raw)
	outcome := Outcome{status, len(raw), hex.EncodeToString(hash[:])}
	if err := d.auditor.RecordOutcome(ctx, intent, outcome); err != nil {
		d.authority.Revoke()
		return ErrAudit
	}
	return nil
}
