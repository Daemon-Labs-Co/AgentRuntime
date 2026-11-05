package toolbroker

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func fixture(t *testing.T) (*Authority, Request, time.Time) {
	t.Helper()
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	scope := Scope{1, strings.Repeat("a", 32), "room", "agent", "connection", "codex", strings.Repeat("b", 64), now.Add(time.Minute)}
	a, token, err := New(scope, []string{"read"}, now)
	if err != nil {
		t.Fatal(err)
	}
	return a, Request{Scope: scope, Capability: token, CallID: "call", Operation: "read", Path: "src/main.go"}, now
}
func TestDecodeStrict(t *testing.T) {
	t.Parallel()
	_, r, _ := fixture(t)
	raw, _ := json.Marshal(r)
	if _, err := Decode(bytes.NewReader(raw)); err != nil {
		t.Fatal(err)
	}
	cases := []string{string(raw) + " {}", strings.Replace(string(raw), `"scope":`, `"unknown":1,"scope":`, 1), strings.Replace(string(raw), `"version":1`, `"version":1,"version":1`, 1), strings.Replace(string(raw), `"version":1`, `"Version":1`, 1), strings.Replace(string(raw), `"path":"src/main.go"`, `"path":null`, 1), strings.Repeat(" ", MaxRequestBytes+1)}
	for _, s := range cases {
		if _, err := Decode(strings.NewReader(s)); err == nil {
			t.Fatalf("accepted malformed input (%d bytes)", len(s))
		}
	}
}
func TestScopeAndCapabilityRejection(t *testing.T) {
	t.Parallel()
	changes := []func(*Request){func(r *Request) { r.Capability = strings.Repeat("c", 64) }, func(r *Request) { r.Scope.JobID = strings.Repeat("c", 32) }, func(r *Request) { r.Scope.Room = "other" }, func(r *Request) { r.Scope.Participant = "other" }, func(r *Request) { r.Scope.Connection = "other" }, func(r *Request) { r.Scope.Provider = "claude" }, func(r *Request) { r.Scope.RepositoryDigest = strings.Repeat("c", 64) }, func(r *Request) { r.Scope.Version = 2 }, func(r *Request) { r.Scope.Deadline = r.Scope.Deadline.Add(time.Second) }}
	for _, change := range changes {
		a, r, now := fixture(t)
		change(&r)
		if err := a.Reserve(r, now); err != ErrRejected {
			t.Fatal("accepted changed authority")
		}
	}
	a, r, now := fixture(t)
	if a.Reserve(r, r.Scope.Deadline) != ErrRejected {
		t.Fatal("accepted expired request")
	}
	a.Revoke()
	if a.Reserve(r, now) != ErrRejected {
		t.Fatal("accepted revoked request")
	}
}
func TestReplayConcurrencyAndBudget(t *testing.T) {
	t.Parallel()
	a, r, now := fixture(t)
	var accepted atomic.Int32
	var wg sync.WaitGroup
	for i := 0; i < 32; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if a.Reserve(r, now) == nil {
				accepted.Add(1)
			}
		}()
	}
	wg.Wait()
	if accepted.Load() != 1 {
		t.Fatalf("accepted %d duplicate calls", accepted.Load())
	}
	for i := 1; i < MaxCalls; i++ {
		r.CallID = fmt.Sprintf("call-%d", i)
		if err := a.Reserve(r, now); err != nil {
			t.Fatal(err)
		}
	}
	r.CallID = "overflow"
	if a.Reserve(r, now) != ErrRejected {
		t.Fatal("budget exceeded")
	}
}
func TestOperationAndSizeBounds(t *testing.T) {
	t.Parallel()
	changes := []func(*Request){func(r *Request) { r.Path = "../auth" }, func(r *Request) { r.Path = "/auth" }, func(r *Request) { r.Path = "src/../auth" }, func(r *Request) { r.Path = "src\\auth" }, func(r *Request) { r.Operation = "command"; r.Command = []string{"cat"} }, func(r *Request) { r.Content = "unexpected" }, func(r *Request) { r.CallID = "bad/id" }}
	for _, change := range changes {
		a, r, now := fixture(t)
		change(&r)
		if a.Reserve(r, now) != ErrRejected {
			t.Fatal("accepted invalid operation")
		}
	}
	a, r, now := fixture(t)
	raw, _ := json.Marshal(r)
	decoded, err := Decode(bytes.NewReader(raw))
	if err != nil || a.Reserve(decoded, now) != nil {
		t.Fatal("round trip refused")
	}
	r.CallID = "large"
	r.Operation = "write"
	r.Content = strings.Repeat("x", MaxRequestBytes)
	var token string
	a, token, _ = New(r.Scope, []string{"write"}, now)
	r.Capability = token
	if a.Reserve(r, now) != ErrRejected {
		t.Fatal("oversized request accepted")
	}
}
func TestPolicyValidationAndCopy(t *testing.T) {
	t.Parallel()
	_, r, now := fixture(t)
	allowed := []string{"read"}
	a, token, err := New(r.Scope, allowed, now)
	if err != nil {
		t.Fatal(err)
	}
	allowed[0] = "write"
	r.Capability = token
	if a.Reserve(r, now) != nil {
		t.Fatal("caller mutated policy")
	}
	for _, deadline := range []time.Time{now, now.Add(4 * time.Minute)} {
		s := r.Scope
		s.Deadline = deadline
		if _, _, err := New(s, []string{"read"}, now); err != ErrRejected {
			t.Fatal("invalid lifetime accepted")
		}
	}
	if _, _, err := New(r.Scope, []string{"docker"}, now); err != ErrRejected {
		t.Fatal("launch operation accepted")
	}
}

func TestTypedOperations(t *testing.T) {
	t.Parallel()
	_, r, now := fixture(t)
	for _, op := range []string{"write", "patch", "command"} {
		a, token, err := New(r.Scope, []string{op}, now)
		if err != nil {
			t.Fatal(err)
		}
		candidate := r
		candidate.Capability = token
		candidate.Operation = op
		if op == "command" {
			candidate.Path = ""
			candidate.Command = []string{"go", "test", "./..."}
		} else {
			candidate.Content = "synthetic content"
		}
		if err = a.Reserve(candidate, now); err != nil {
			t.Fatalf("refused %s", op)
		}
	}
	a, r, now := fixture(t)
	if a.Reserve(r, now.Add(-time.Second)) != ErrRejected {
		t.Fatal("pre-issuance request accepted")
	}
}
