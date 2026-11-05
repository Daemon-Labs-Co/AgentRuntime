package toolbroker

import (
	"context"
	"errors"
	"io"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

type mockAudit struct {
	intent  func(context.Context, Intent) error
	outcome func(context.Context, Intent, Outcome) error
}

func (a mockAudit) RecordIntent(ctx context.Context, i Intent) error {
	if a.intent != nil {
		return a.intent(ctx, i)
	}
	return nil
}
func (a mockAudit) RecordOutcome(ctx context.Context, i Intent, o Outcome) error {
	if a.outcome != nil {
		return a.outcome(ctx, i, o)
	}
	return nil
}

type mockExecutor func(context.Context, Scope, Action, io.Writer) error

func (e mockExecutor) Execute(c context.Context, s Scope, a Action, w io.Writer) error {
	return e(c, s, a, w)
}
func liveFixture(t *testing.T) (*Authority, Request) {
	t.Helper()
	_, r, _ := fixture(t)
	now := time.Now()
	r.Scope.Deadline = now.Add(time.Minute)
	a, token, err := New(r.Scope, []string{"read", "command"}, now)
	if err != nil {
		t.Fatal(err)
	}
	r.Capability = token
	return a, r
}
func dispatcher(t *testing.T, a *Authority, audit Auditor, exec Executor) *Dispatcher {
	t.Helper()
	d, err := NewDispatcher(a, audit, exec)
	if err != nil {
		t.Fatal(err)
	}
	return d
}

func TestAuditBeforeExecutionAndOutcome(t *testing.T) {
	t.Parallel()
	a, r := liveFixture(t)
	stage := 0
	audit := mockAudit{intent: func(ctx context.Context, i Intent) error {
		if stage != 0 || i.Scope != a.scope || i.CallID != r.CallID || i.Operation != "read" || !digest(i.PayloadDigest, 32) {
			t.Error("invalid intent")
		}
		stage = 1
		return nil
	}, outcome: func(ctx context.Context, i Intent, o Outcome) error {
		if stage != 2 || o.Status != "succeeded" || o.OutputBytes != 2 || !digest(o.OutputDigest, 32) {
			t.Error("invalid outcome")
		}
		stage = 3
		return nil
	}}
	d := dispatcher(t, a, audit, mockExecutor(func(ctx context.Context, s Scope, action Action, w io.Writer) error {
		if stage != 1 || s != a.scope || action.Path != r.Path {
			t.Error("execution before intent or wrong scope")
		}
		stage = 2
		_, err := io.WriteString(w, "ok")
		return err
	}))
	raw, err := d.Dispatch(context.Background(), r)
	if err != nil || string(raw) != "ok" || stage != 3 {
		t.Fatalf("result %q %v stage %d", raw, err, stage)
	}
	if _, err = d.Dispatch(context.Background(), r); err != ErrRejected {
		t.Fatal("replayed successful execution")
	}
}
func TestAuditFailureFencesJob(t *testing.T) {
	t.Parallel()
	for _, phase := range []string{"intent", "outcome"} {
		a, r := liveFixture(t)
		count := 0
		secretError := errors.New("synthetic-private-diagnostic")
		audit := mockAudit{intent: func(context.Context, Intent) error {
			if phase == "intent" {
				return secretError
			}
			return nil
		}, outcome: func(context.Context, Intent, Outcome) error { return secretError }}
		d := dispatcher(t, a, audit, mockExecutor(func(context.Context, Scope, Action, io.Writer) error { count++; return nil }))
		raw, err := d.Dispatch(context.Background(), r)
		if raw != nil || err != ErrAudit {
			t.Fatal("audit failure exposed output/error")
		}
		if phase == "intent" && count != 0 || phase == "outcome" && count != 1 {
			t.Fatal("wrong execution count")
		}
		r.CallID = "another"
		if _, err = d.Dispatch(context.Background(), r); err != ErrRejected {
			t.Fatal("audit failure did not fence job")
		}
	}
}
func TestCancellationBeforeExecution(t *testing.T) {
	t.Parallel()
	for _, kind := range []string{"parent", "revoke"} {
		a, r := liveFixture(t)
		ctx, cancel := context.WithCancel(context.Background())
		count := 0
		d := dispatcher(t, a, mockAudit{intent: func(context.Context, Intent) error {
			if kind == "parent" {
				cancel()
			} else {
				a.Revoke()
			}
			return nil
		}}, mockExecutor(func(context.Context, Scope, Action, io.Writer) error { count++; return nil }))
		if raw, err := d.Dispatch(ctx, r); raw != nil || err != ErrExecution || count != 0 {
			t.Fatal("executed canceled intent")
		}
		cancel()
	}
}
func TestSharedJobSlotAndRunningRevocation(t *testing.T) {
	t.Parallel()
	a, r := liveFixture(t)
	started := make(chan struct{})
	result := make(chan error, 1)
	var intents atomic.Int32
	audit := mockAudit{intent: func(context.Context, Intent) error { intents.Add(1); return nil }}
	exec := mockExecutor(func(ctx context.Context, _ Scope, _ Action, _ io.Writer) error {
		close(started)
		<-ctx.Done()
		return ctx.Err()
	})
	d := dispatcher(t, a, audit, exec)
	other := dispatcher(t, a, audit, exec)
	go func() { _, err := d.Dispatch(context.Background(), r); result <- err }()
	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("executor not started")
	}
	candidate := r
	candidate.CallID = "parallel"
	if _, err := other.Dispatch(context.Background(), candidate); err != ErrBusy || intents.Load() != 1 {
		t.Fatal("overlapping work admitted")
	}
	a.Revoke()
	a.Revoke()
	select {
	case err := <-result:
		if err != ErrExecution {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("revocation did not cancel executor")
	}
	if _, err := other.Dispatch(context.Background(), candidate); err != ErrRejected {
		t.Fatal("revoked work admitted")
	}
}
func TestBoundedOutputAndClosedWriter(t *testing.T) {
	t.Parallel()
	a, r := liveFixture(t)
	var retained io.Writer
	var outcome Outcome
	d := dispatcher(t, a, mockAudit{outcome: func(_ context.Context, _ Intent, o Outcome) error { outcome = o; return nil }}, mockExecutor(func(ctx context.Context, _ Scope, _ Action, w io.Writer) error {
		retained = w
		_, err := io.WriteString(w, strings.Repeat("x", MaxOutputBytes))
		if err != nil {
			t.Fatal(err)
		}
		if n, err := w.Write([]byte("overflow")); n != 0 || err != ErrOutputLimit || ctx.Err() == nil {
			t.Error("overflow not canceled")
		}
		return nil
	}))
	if raw, err := d.Dispatch(context.Background(), r); raw != nil || err != ErrOutputLimit || outcome.Status != "output_limit" || outcome.OutputBytes != MaxOutputBytes {
		t.Fatal("overflow returned successful/oversized output")
	}
	if _, err := retained.Write([]byte("late")); err != ErrExecution {
		t.Fatal("late write accepted")
	}
}
func TestOriginalDeadlineAndInputSnapshot(t *testing.T) {
	t.Parallel()
	a, r := liveFixture(t)
	r.Operation = "command"
	r.Path = ""
	r.Command = []string{"go", "test"}
	parent, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	d := dispatcher(t, a, mockAudit{intent: func(context.Context, Intent) error { r.Command[0] = "mutated"; return nil }}, mockExecutor(func(ctx context.Context, _ Scope, action Action, _ io.Writer) error {
		deadline, ok := ctx.Deadline()
		parentDeadline, _ := parent.Deadline()
		if !ok || !deadline.Equal(parentDeadline) || action.Command[0] != "go" {
			t.Error("deadline extended or input mutated")
		}
		return nil
	}))
	if _, err := d.Dispatch(parent, r); err != nil {
		t.Fatal(err)
	}
}
func TestExecutionFailureCannotReplay(t *testing.T) {
	t.Parallel()
	a, r := liveFixture(t)
	count := 0
	d := dispatcher(t, a, mockAudit{}, mockExecutor(func(context.Context, Scope, Action, io.Writer) error {
		count++
		return errors.New("synthetic executor detail")
	}))
	if raw, err := d.Dispatch(context.Background(), r); raw != nil || err != ErrExecution {
		t.Fatal("failed work returned output or internal error")
	}
	if _, err := d.Dispatch(context.Background(), r); err != ErrRejected || count != 1 {
		t.Fatal("failed side effect replayed")
	}
}

func TestDeadlineCancelsRunningWork(t *testing.T) {
	t.Parallel()
	a, r := liveFixture(t)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
	defer cancel()
	d := dispatcher(t, a, mockAudit{}, mockExecutor(func(ctx context.Context, _ Scope, _ Action, _ io.Writer) error { <-ctx.Done(); return nil }))
	if raw, err := d.Dispatch(ctx, r); raw != nil || err != ErrExecution {
		t.Fatal("expired work returned success")
	}
}
func TestMissingDependencies(t *testing.T) {
	t.Parallel()
	a, _ := liveFixture(t)
	exec := mockExecutor(func(context.Context, Scope, Action, io.Writer) error { return nil })
	for _, tc := range []struct {
		a     *Authority
		audit Auditor
		exec  Executor
	}{{nil, mockAudit{}, exec}, {a, nil, exec}, {a, mockAudit{}, nil}} {
		if _, err := NewDispatcher(tc.a, tc.audit, tc.exec); err != ErrRejected {
			t.Fatal("missing dependency admitted")
		}
	}
}

func TestExecutorReportedOutputLimitPreservesFailureEvidence(t *testing.T) {
	t.Parallel()
	authority, request := liveFixture(t)
	request.Operation, request.Path, request.Content = "command", "", ""
	request.Command = []string{"go", "test", "./..."}
	var outcome Outcome
	d := dispatcher(t, authority, mockAudit{outcome: func(_ context.Context, _ Intent, value Outcome) error { outcome = value; return nil }}, mockExecutor(func(context.Context, Scope, Action, io.Writer) error {
		return errors.Join(ErrExecution, ErrOutputLimit)
	}))
	if raw, err := d.Dispatch(t.Context(), request); raw != nil || err != ErrOutputLimit || outcome.Status != "output_limit" || outcome.OutputBytes != 0 {
		t.Fatal("executor overflow was downgraded or released output", err, outcome)
	}
	request.CallID = "after-output-limit"
	if _, err := d.Dispatch(t.Context(), request); err != ErrRejected {
		t.Fatal("overflow authority reused", err)
	}
}
