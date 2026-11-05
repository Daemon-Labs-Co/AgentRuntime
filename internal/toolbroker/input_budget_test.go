package toolbroker

import (
	"context"
	"io"
	"strings"
	"testing"
)

func TestTypedBudgetRefusalDoesNotAllocate(t *testing.T) {
	// AllocsPerRun requires scheduler isolation; Go runs this serially before
	// parallel tests. All fixtures are local and other behavior tests stay parallel.
	_, r, now := fixture(t)
	a, token, err := New(r.Scope, []string{"write", "command"}, now)
	if err != nil {
		t.Fatal(err)
	}
	r.Capability = token
	r.Operation = "write"
	r.Content = strings.Repeat("x", MaxRequestBytes+1)
	allocs := testing.AllocsPerRun(10, func() {
		if a.Reserve(r, now) != ErrRejected {
			t.Fatal("oversized typed write accepted")
		}
	})
	if allocs != 0 {
		t.Fatalf("oversized typed refusal allocated %.0f times", allocs)
	}
	r.Content = ""
	r.Capability = strings.Repeat("a", MaxRequestBytes+1)
	allocs = testing.AllocsPerRun(10, func() {
		if a.Reserve(r, now) != ErrRejected {
			t.Fatal("oversized capability accepted")
		}
	})
	if allocs != 0 {
		t.Fatalf("oversized capability refusal allocated %.0f times", allocs)
	}
}
func TestActionBudgetCountsCombinedCommandInput(t *testing.T) {
	t.Parallel()
	a := Action{Operation: "command"}
	for i := 0; i < 9; i++ {
		a.Command = append(a.Command, strings.Repeat("x", 8192))
	}
	if validAction(a) {
		t.Fatal("aggregate command input exceeded budget")
	}
	a.Command = []string{"go", "test", "./..."}
	if !validAction(a) {
		t.Fatal("valid small command refused")
	}
	if digest(strings.Repeat("a", MaxRequestBytes+1), 32) {
		t.Fatal("unbounded digest accepted")
	}
}
func TestDispatcherBudgetRefusesBeforeDependencyCalls(t *testing.T) {
	t.Parallel()
	a, r, now := fixture(t)
	a, token, err := New(r.Scope, []string{"write"}, now)
	if err != nil {
		t.Fatal(err)
	}
	r.Capability = token
	r.Operation = "write"
	r.Content = strings.Repeat("x", MaxRequestBytes+1)
	d := dispatcher(t, a, mockAudit{intent: func(context.Context, Intent) error { t.Error("oversized input reached audit"); return nil }}, mockExecutor(func(context.Context, Scope, Action, io.Writer) error {
		t.Error("oversized input reached executor")
		return nil
	}))
	if raw, err := d.Dispatch(context.Background(), r); raw != nil || err != ErrRejected {
		t.Fatal("dispatcher accepted oversized typed input")
	}
}

func TestEscapedPayloadStillHasWireLimit(t *testing.T) {
	t.Parallel()
	_, r, now := fixture(t)
	a, token, err := New(r.Scope, []string{"write"}, now)
	if err != nil {
		t.Fatal(err)
	}
	r.Capability = token
	r.Operation = "write"
	r.Content = strings.Repeat("<", MaxRequestBytes/2)
	if !validRequest(r) {
		t.Fatal("fixture must pass text budget before JSON escaping")
	}
	if a.Reserve(r, now) != ErrRejected {
		t.Fatal("escaped JSON exceeded wire budget")
	}
	r.Content = "small"
	if a.Reserve(r, now) != nil {
		t.Fatal("oversize refusal consumed call ID")
	}
}

func TestTypedExecutorBudgetRefusesBeforeDocker(t *testing.T) {
	t.Parallel()
	p, _, _, _, root, scope, _ := executorFixture(t)
	runner := mockDocker(func(context.Context, []string, []byte, io.Writer) error {
		t.Error("oversized action reached Docker")
		return nil
	})
	e := containerExecutor(t, p, runner, root)
	ctx, cancel := context.WithDeadline(context.Background(), scope.Deadline)
	defer cancel()
	action := Action{Operation: "write", Path: "file.go", Content: strings.Repeat("x", MaxRequestBytes+1)}
	if e.Execute(ctx, scope, action, io.Discard) != ErrRejected {
		t.Fatal("oversized typed executor input accepted")
	}
	if validToolImage("tool@sha256:" + strings.Repeat("a", MaxRequestBytes)) {
		t.Fatal("oversized image accepted")
	}
	if _, err := NewContainerExecutor(p, runner, "/"+strings.Repeat("x", 4096)); err != ErrRejected {
		t.Fatal("oversized root accepted")
	}
}
