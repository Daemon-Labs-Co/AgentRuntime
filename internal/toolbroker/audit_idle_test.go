package toolbroker

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"net"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

type idleAuditMock struct {
	mockAudit
	idle func(context.Context, Scope, IdleStop) error
}

func (m idleAuditMock) RecordIdleStop(ctx context.Context, s Scope, i IdleStop) error {
	return m.idle(ctx, s, i)
}
func auditIdleFixture() IdleStop {
	now := time.Now().UTC()
	return IdleStop{StartedAt: now.Add(-90 * time.Second), RequestedAt: now, Minutes: 1, PolicyRevision: 2}
}
func TestPrivateIdleFrameIsDurableAndTerminal(t *testing.T) {
	t.Parallel()
	authority, _ := liveFixture(t)
	left, right := net.Pipe()
	defer left.Close()
	defer right.Close()
	var committed atomic.Bool
	done := make(chan error, 1)
	go func() {
		done <- ServeAudit(t.Context(), right, authority.scope, idleAuditMock{mockAudit: mockAudit{}, idle: func(_ context.Context, s Scope, stop IdleStop) error {
			if s != authority.scope || stop.Minutes != 1 {
				t.Error("foreign idle metadata")
			}
			committed.Store(true)
			return nil
		}})
	}()
	client, err := NewAuditClient(left, authority.scope)
	if err != nil {
		t.Fatal(err)
	}
	if err = client.RecordIdleStop(t.Context(), auditIdleFixture()); err != nil || !committed.Load() {
		t.Fatal("idle acknowledged before commit", err)
	}
	intent := Intent{Scope: authority.scope, CallID: "after-idle", Operation: "read", PayloadDigest: strings.Repeat("a", 64)}
	if client.RecordIntent(t.Context(), intent) != ErrAudit {
		t.Fatal("tool authority reused after terminal frame")
	}
	if <-done != ErrAudit {
		t.Fatal("terminal stream revived")
	}
}
func TestIdleFrameRefusesOldPeerAndDowngradedAck(t *testing.T) {
	t.Parallel()
	for _, mode := range []string{"old-peer", "version", "digest", "denied"} {
		t.Run(mode, func(t *testing.T) {
			authority, _ := liveFixture(t)
			left, right := net.Pipe()
			defer left.Close()
			defer right.Close()
			done := make(chan struct{})
			go func() {
				defer close(done)
				defer right.Close()
				if mode == "old-peer" {
					_ = ServeAudit(t.Context(), right, authority.scope, mockAudit{})
					return
				}
				var frame AuditFrame
				if auditRead(bufio.NewReader(right), &frame) != nil {
					return
				}
				digest, _ := auditFrameDigest(frame)
				ack := auditAck{Version: 2, Digest: digest, Accepted: true}
				switch mode {
				case "version":
					ack.Version = 1
				case "digest":
					ack.Digest = strings.Repeat("0", 64)
				case "denied":
					ack.Accepted = false
				}
				_ = auditWrite(right, ack)
			}()
			client, _ := NewAuditClient(left, authority.scope)
			if client.RecordIdleStop(t.Context(), auditIdleFixture()) != ErrAudit {
				t.Fatal("unsupported/ambiguous ack accepted", mode)
			}
			if client.RecordIdleStop(t.Context(), auditIdleFixture()) != ErrAudit {
				t.Fatal("failed idle frame retried")
			}
			<-done
		})
	}
}
func TestIdleFrameCannotInterruptPendingTool(t *testing.T) {
	t.Parallel()
	authority, _ := liveFixture(t)
	left, right := net.Pipe()
	defer left.Close()
	defer right.Close()
	var idleCalls atomic.Int32
	done := make(chan error, 1)
	go func() {
		done <- ServeAudit(t.Context(), right, authority.scope, idleAuditMock{mockAudit: mockAudit{intent: func(context.Context, Intent) error { return nil }}, idle: func(context.Context, Scope, IdleStop) error { idleCalls.Add(1); return nil }})
	}()
	client, _ := NewAuditClient(left, authority.scope)
	intent := Intent{Scope: authority.scope, CallID: "pending", Operation: "read", PayloadDigest: strings.Repeat("a", 64)}
	if err := client.RecordIntent(t.Context(), intent); err != nil {
		t.Fatal(err)
	}
	if client.RecordIdleStop(t.Context(), auditIdleFixture()) != ErrAudit || idleCalls.Load() != 0 {
		t.Fatal("pending action became idle")
	}
	<-done
}
func TestAuditBudgetReservesOnlyOneLifecycleFrame(t *testing.T) {
	t.Parallel()
	authority, _ := liveFixture(t)
	left, right := net.Pipe()
	defer left.Close()
	defer right.Close()
	done := make(chan error, 1)
	auditor := idleAuditMock{mockAudit: mockAudit{intent: func(context.Context, Intent) error { return nil }, outcome: func(context.Context, Intent, Outcome) error { return nil }}, idle: func(context.Context, Scope, IdleStop) error { return nil }}
	go func() { done <- ServeAudit(t.Context(), right, authority.scope, auditor) }()
	client, _ := NewAuditClient(left, authority.scope)
	for i := 0; i < MaxCalls; i++ {
		intent := Intent{Scope: authority.scope, CallID: fmt.Sprintf("call-%d", i), Operation: "read", PayloadDigest: strings.Repeat("a", 64)}
		if client.RecordIntent(t.Context(), intent) != nil || client.RecordOutcome(t.Context(), intent, Outcome{Status: "succeeded", OutputDigest: strings.Repeat("b", 64)}) != nil {
			t.Fatal("tool budget changed", i)
		}
	}
	if err := client.RecordIdleStop(t.Context(), auditIdleFixture()); err != nil {
		t.Fatal("no lifecycle budget after final tool", err)
	}
	if client.sequence != 2*MaxCalls+1 {
		t.Fatal("unexpected lifecycle budget")
	}
	left.Close()
	<-done
}
func TestIdleWireRejectsAmbiguityBeforeController(t *testing.T) {
	t.Parallel()
	for _, mode := range []string{"version", "foreign-scope", "tool-payload", "outcome", "duplicate", "missing", "alias", "null", "early", "future", "revision"} {
		t.Run(mode, func(t *testing.T) {
			authority, _ := liveFixture(t)
			left, right := net.Pipe()
			defer left.Close()
			defer right.Close()
			var calls atomic.Int32
			done := make(chan error, 1)
			go func() {
				done <- ServeAudit(t.Context(), right, authority.scope, idleAuditMock{mockAudit: mockAudit{}, idle: func(context.Context, Scope, IdleStop) error { calls.Add(1); return nil }})
			}()
			stop := auditIdleFixture()
			frame := AuditFrame{Version: 2, Sequence: 1, Session: strings.Repeat("a", 32), Stage: "idle-stop", Intent: Intent{Scope: authority.scope}, IdleStop: &stop}
			switch mode {
			case "version":
				frame.Version = 1
			case "foreign-scope":
				frame.Intent.Scope.JobID = strings.Repeat("b", 32)
			case "tool-payload":
				frame.Intent.CallID = "smuggled"
			case "outcome":
				frame.Outcome = &Outcome{Status: "succeeded", OutputDigest: strings.Repeat("b", 64)}
			case "early":
				stop.RequestedAt = stop.StartedAt
			case "future":
				stop.RequestedAt = authority.scope.Deadline.Add(-time.Nanosecond)
			case "revision":
				stop.PolicyRevision = -1
			}
			raw, _ := json.Marshal(frame)
			switch mode {
			case "duplicate":
				raw = []byte(strings.Replace(string(raw), `"minutes":1`, `"minutes":1,"minutes":1`, 1))
			case "missing":
				raw = []byte(strings.Replace(string(raw), `"policyRevision":2`, `"extra":2`, 1))
			case "alias":
				raw = []byte(strings.Replace(string(raw), `"minutes":1`, `"Minutes":1`, 1))
			case "null":
				raw = []byte(strings.Replace(string(raw), `"minutes":1`, `"minutes":null`, 1))
			}
			_, _ = left.Write(append(raw, '\n'))
			if <-done != ErrAudit || calls.Load() != 0 {
				t.Fatal("invalid idle frame reached controller", mode)
			}
		})
	}
}

func TestIdleTerminalServerRejectsFurtherTools(t *testing.T) {
	t.Parallel()
	authority, _ := liveFixture(t)
	left, right := net.Pipe()
	defer left.Close()
	defer right.Close()
	done := make(chan error, 1)
	var tools atomic.Int32
	go func() {
		done <- ServeAudit(t.Context(), right, authority.scope, idleAuditMock{mockAudit: mockAudit{intent: func(context.Context, Intent) error { tools.Add(1); return nil }}, idle: func(context.Context, Scope, IdleStop) error { return nil }})
	}()
	stop := auditIdleFixture()
	frame := AuditFrame{Version: 2, Sequence: 1, Session: strings.Repeat("a", 32), Stage: "idle-stop", Intent: Intent{Scope: authority.scope}, IdleStop: &stop}
	if auditWrite(left, frame) != nil {
		t.Fatal("idle write")
	}
	var ack auditAck
	if auditRead(bufio.NewReader(left), &ack) != nil || !ack.Accepted {
		t.Fatal("idle ack")
	}
	frame = AuditFrame{Version: 1, Sequence: 2, Session: frame.Session, Stage: "intent", Intent: Intent{Scope: authority.scope, CallID: "after-terminal", Operation: "read", PayloadDigest: strings.Repeat("a", 64)}}
	_ = auditWrite(left, frame)
	if <-done != ErrAudit || tools.Load() != 0 {
		t.Fatal("terminal peer admitted tool")
	}
}
func TestSessionIdleCannotRevokeActiveToolSlot(t *testing.T) {
	t.Parallel()
	authority, request := liveFixture(t)
	left, right := net.Pipe()
	defer left.Close()
	defer right.Close()
	client, _ := NewAuditClient(left, authority.scope)
	session := &ToolSession{audit: client, Dispatcher: &Dispatcher{authority: authority}}
	authority.slot <- struct{}{}
	if session.RecordIdleStop(t.Context(), auditIdleFixture()) != ErrBusy {
		t.Fatal("active tool not protected")
	}
	if err := authority.Reserve(request, time.Now()); err != nil {
		t.Fatal("busy idle attempt revoked active authority", err)
	}
	<-authority.slot
}

func TestReservedIdleFrameCannotIncreaseToolBudget(t *testing.T) {
	t.Parallel()
	authority, _ := liveFixture(t)
	left, right := net.Pipe()
	defer left.Close()
	defer right.Close()
	done := make(chan error, 1)
	var calls atomic.Int32
	auditor := idleAuditMock{mockAudit: mockAudit{intent: func(context.Context, Intent) error { calls.Add(1); return nil }, outcome: func(context.Context, Intent, Outcome) error { return nil }}, idle: func(context.Context, Scope, IdleStop) error { return nil }}
	go func() { done <- ServeAudit(t.Context(), right, authority.scope, auditor) }()
	client, _ := NewAuditClient(left, authority.scope)
	for i := 0; i < MaxCalls; i++ {
		intent := Intent{Scope: authority.scope, CallID: fmt.Sprintf("call-%d", i), Operation: "read", PayloadDigest: strings.Repeat("a", 64)}
		if client.RecordIntent(t.Context(), intent) != nil || client.RecordOutcome(t.Context(), intent, Outcome{Status: "succeeded", OutputDigest: strings.Repeat("b", 64)}) != nil {
			t.Fatal("tool call refused", i)
		}
	}
	// Bypass the normal client to verify the controller's own call ceiling.
	raw := AuditFrame{Version: 1, Sequence: 2*MaxCalls + 1, Session: client.session, Stage: "intent", Intent: Intent{Scope: authority.scope, CallID: "extra", Operation: "read", PayloadDigest: strings.Repeat("a", 64)}}
	_ = auditWrite(left, raw)
	if <-done != ErrAudit || calls.Load() != int32(MaxCalls) {
		t.Fatal("reserved lifecycle slot admitted another tool")
	}
}
