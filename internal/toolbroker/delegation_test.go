package toolbroker

import (
	"bufio"
	"context"
	"encoding/json"
	"net"
	"strings"
	"testing"
	"time"
)

type delegationAuditProbe struct{ called bool }

func (*delegationAuditProbe) RecordIntent(context.Context, Intent) error           { return nil }
func (*delegationAuditProbe) RecordOutcome(context.Context, Intent, Outcome) error { return nil }
func (p *delegationAuditProbe) RecordDelegation(context.Context, Scope, DelegationRequest) error {
	p.called = true
	return nil
}
func TestPrivateDelegationFramesRejectMixedOrForgedScope(t *testing.T) {
	t.Parallel()
	for _, mode := range []string{"healthy", "mixed-outcome", "mixed-idle", "claimed-scope", "invalid-version", "unknown-field", "duplicate-field"} {
		t.Run(mode, func(t *testing.T) {
			t.Parallel()
			scope := Scope{Version: 1, JobID: strings.Repeat("a", 32), Room: "engineering", Participant: "source", Connection: "connection", Provider: "codex", RepositoryDigest: strings.Repeat("b", 64), Deadline: time.Now().UTC().Add(time.Minute)}
			frame := AuditFrame{Version: 3, Stage: "delegation", Sequence: 1, Session: strings.Repeat("c", 32), Intent: Intent{Scope: scope}, Delegation: &DelegationRequest{ParentOperations: 1, RequestID: "request", TaskID: "task", TaskRevision: 2, DelegateID: "target"}}
			switch mode {
			case "mixed-outcome":
				frame.Outcome = &Outcome{Status: "succeeded", OutputDigest: strings.Repeat("d", 64)}
			case "mixed-idle":
				frame.IdleStop = &IdleStop{}
			case "claimed-scope":
				frame.Intent.Scope.Participant = "other"
			case "invalid-version":
				frame.Version = 1
			}
			left, right := net.Pipe()
			defer left.Close()
			ctx, cancel := context.WithTimeout(t.Context(), time.Second)
			defer cancel()
			probe := &delegationAuditProbe{}
			done := make(chan error, 1)
			go func() { done <- ServeAudit(ctx, right, scope, probe) }()
			if mode == "unknown-field" || mode == "duplicate-field" {
				raw, _ := json.Marshal(frame)
				extra := `,"actorId":"owner"}`
				if mode == "duplicate-field" {
					extra = `,"stage":"delegation"}`
				}
				raw = append(raw[:len(raw)-1], []byte(extra+"\n")...)
				if _, err := left.Write(raw); err != nil {
					t.Fatal(err)
				}
			} else if auditWrite(left, frame) != nil {
				t.Fatal("write failed")
			}
			var ack auditAck
			err := auditRead(bufio.NewReader(left), &ack)
			if mode == "healthy" {
				if err != nil || !ack.Accepted {
					t.Fatal("healthy proposal refused", err)
				}
				left.Close()
			} else if err == nil && ack.Accepted {
				t.Fatal("forged frame acknowledged")
			}
			<-done
			if probe.called != (mode == "healthy") {
				t.Fatal("invalid frame reached controller")
			}
		})
	}
}

type operationSnapshotProbe struct {
	delegationAuditProbe
	operations uint8
}

func (p *operationSnapshotProbe) RecordDelegation(_ context.Context, _ Scope, r DelegationRequest) error {
	p.called = true
	p.operations = r.ParentOperations
	return nil
}
func TestSupervisorDelegationOverwritesClaimedOperationPermissions(t *testing.T) {
	t.Parallel()
	scope := Scope{Version: 1, JobID: strings.Repeat("a", 32), Room: "engineering", Participant: "source", Connection: "connection", Provider: "codex", RepositoryDigest: strings.Repeat("b", 64), Deadline: time.Now().UTC().Add(time.Minute)}
	authority, _, err := New(scope, []string{"read"}, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	left, right := net.Pipe()
	defer left.Close()
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	probe := &operationSnapshotProbe{}
	done := make(chan error, 1)
	go func() { done <- ServeAudit(ctx, right, scope, probe) }()
	client, err := NewAuditClient(left, scope)
	if err != nil {
		t.Fatal(err)
	}
	session := &ToolSession{audit: client, Dispatcher: &Dispatcher{authority: authority}}
	if err = session.ProposeDelegation(ctx, DelegationRequest{ParentOperations: 15, RequestID: "request", TaskID: "task", TaskRevision: 2, DelegateID: "target"}); err != nil {
		t.Fatal(err)
	}
	left.Close()
	<-done
	if !probe.called || probe.operations != 1 {
		t.Fatal("model-supplied permissions replaced actual parent authority", probe.operations)
	}
}
