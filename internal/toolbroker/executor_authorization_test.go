package toolbroker

import (
	"bytes"
	"context"
	"io"
	"strings"
	"testing"
	"time"
)

func TestExecutorRefusesUndeclaredOperationsBeforeDocker(t *testing.T) {
	t.Parallel()
	_, r := liveFixture(t)
	now := time.Now()
	allowed := []string{"read"}
	a, token, err := New(r.Scope, allowed, now)
	if err != nil {
		t.Fatal(err)
	}
	p, err := NewToolContainerPlan(a, "sha256:"+strings.Repeat("c", 64), now)
	if err != nil {
		t.Fatal(err)
	}
	runner := mockDocker(func(context.Context, []string, []byte, io.Writer) error {
		t.Error("undeclared action reached Docker")
		return nil
	})
	e := containerExecutor(t, p, runner, "/home/synthetic/.local/share/docker")
	ctx, cancel := context.WithDeadline(context.Background(), a.scope.Deadline)
	defer cancel()
	actions := []Action{{Operation: "command", Command: []string{"go", "test", "./..."}}, {Operation: "write", Path: "file.go", Content: "synthetic"}, {Operation: "patch", Path: "file.go", Content: "synthetic"}}
	allowed[0] = "command" // Caller cannot mutate the authority's copied tool policy.
	for _, action := range actions {
		if e.Execute(ctx, a.scope, action, io.Discard) != ErrRejected {
			t.Fatalf("accepted undeclared %s", action.Operation)
		}
	}
	r.Capability = token
	r.Operation = "read"
	r.Path = "file.go"
	if a.Reserve(r, time.Now()) != nil {
		t.Fatal("refused action damaged permitted job admission")
	}
}
func TestExecutorPolicyGateAcceptsDeclaredRead(t *testing.T) {
	t.Parallel()
	p, _, raw, vol, root, scope, action := executorFixture(t)
	called := 0
	response := syntheticReadResult(t, "ok")
	runner := runtimeMock(t, raw, vol, func(_ context.Context, _ []string, _ []byte, out io.Writer) error {
		called++
		_, err := out.Write(response)
		return err
	}, nil)
	e := containerExecutor(t, p, runner, root)
	ctx, cancel := context.WithDeadline(context.Background(), scope.Deadline)
	defer cancel()
	var output bytes.Buffer
	if err := e.Execute(ctx, scope, action, &output); err != nil || called != 1 || !bytes.Equal(output.Bytes(), response) {
		t.Fatal("declared read was refused")
	}
}
func TestExecutorPolicyGateScopeAndLifetime(t *testing.T) {
	t.Parallel()
	a, r, now := fixture(t)
	action := Action{Operation: "read", Path: r.Path}
	if !a.permitsAction(r.Scope, action, now) {
		t.Fatal("valid declared action refused")
	}
	changed := r.Scope
	changed.Connection = "other"
	if a.permitsAction(changed, action, now) || a.permitsAction(r.Scope, action, now.Add(-time.Second)) || a.permitsAction(r.Scope, action, r.Scope.Deadline) {
		t.Fatal("mismatched/expired/unissued action accepted")
	}
	a.Revoke()
	if a.permitsAction(r.Scope, action, now) {
		t.Fatal("revoked action accepted")
	}
}
