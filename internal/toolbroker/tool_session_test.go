package toolbroker

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

type sessionDocker struct {
	*bootstrapScenario
	response     []byte
	executed     int
	auditIntents *atomic.Int32
}

func (f *sessionDocker) Run(ctx context.Context, args []string, in []byte, out io.Writer) error {
	if args[0] == "exec" {
		if f.auditIntents.Load() == 0 {
			f.t.Fatal("tool ran before durable intent")
		}
		if args[len(args)-1] != "/opt/commonroom/tool-call.cjs" || args[len(args)-3] != f.container.ID {
			f.t.Fatal("file helper escaped immutable ID")
		}
		f.executed++
		_, err := out.Write(f.response)
		return err
	}
	return f.runtimeScenario.Run(ctx, args, in, out)
}
func TestToolSessionSharesBootstrapAndDurableDispatcher(t *testing.T) {
	t.Parallel()
	for _, mode := range []string{"success", "intent-failure", "outcome-failure", "bootstrap-failure"} {
		t.Run(mode, func(t *testing.T) {
			t.Parallel()
			p, c, v, root, _ := inspectionFixture(t)
			_, request := liveFixture(t)
			c.State.Running = boolValue(false)
			c.State.Status = "created"
			var intents, outcomes atomic.Int32
			f := &sessionDocker{bootstrapScenario: &bootstrapScenario{runtimeScenario: &runtimeScenario{t: t, plan: p, container: c, volume: v}}, response: syntheticReadResult(t, "synthetic source"), auditIntents: &intents}
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			client, peer := net.Pipe()
			defer client.Close()
			defer peer.Close()
			session, token, err := NewToolSession(ctx, request.Scope, []string{"read"}, p.image, root, time.Now(), client, f)
			if err != nil {
				t.Fatal(err)
			}
			defer session.Close()
			f.plan = session.Runtime.executor.plan
			auditDone := make(chan error, 1)
			scope := f.plan.authority.scope
			go func() {
				auditDone <- ServeAudit(ctx, peer, scope, mockAudit{
					intent: func(context.Context, Intent) error {
						intents.Add(1)
						if mode == "intent-failure" {
							return ErrAudit
						}
						return nil
					},
					outcome: func(context.Context, Intent, Outcome) error {
						outcomes.Add(1)
						if mode == "outcome-failure" {
							return ErrAudit
						}
						return nil
					},
				})
			}()
			intent, err := session.Runtime.WorkspaceIntent(t.Context())
			if err != nil {
				t.Fatal(err)
			}
			if _, err = session.Runtime.PrepareVolume(t.Context(), intent); err != nil {
				t.Fatal(err)
			}
			id, err := session.Runtime.Create(t.Context())
			if err != nil {
				t.Fatal(err)
			}
			if err = session.Runtime.VerifyCreated(t.Context(), id); err != nil {
				t.Fatal(err)
			}
			if err = session.Runtime.Start(t.Context(), id); err != nil {
				t.Fatal(err)
			}
			if mode == "bootstrap-failure" {
				f.mode = "job"
			}
			_, err = session.Runtime.Bootstrap(t.Context(), io.NopCloser(strings.NewReader("synthetic approved snapshot")))
			if (err == nil) != (mode != "bootstrap-failure") {
				t.Fatalf("bootstrap %v", err)
			}
			request.Scope = scope
			request.Capability = token
			request.CallID = "session-call"
			request.Path = "file.txt"
			output, err := session.Dispatcher.Dispatch(t.Context(), request)
			if (err == nil) != (mode == "success") {
				t.Fatalf("dispatch %v", err)
			}
			if mode == "success" && !bytes.Equal(output, f.response) {
				t.Fatal("verified result lost")
			}
			if mode != "success" && output != nil {
				t.Fatal("unverified output escaped")
			}
			shouldExecute := mode == "success" || mode == "outcome-failure"
			if (f.executed == 1) != shouldExecute {
				t.Fatal("audit/bootstrap did not gate execution")
			}
			if mode == "success" && (intents.Load() != 1 || outcomes.Load() != 1) {
				t.Fatal("durable receipt missing")
			}
			session.Close()
			session.Close()
			before := len(f.calls)
			request.CallID = "after-close"
			if _, err = session.Dispatcher.Dispatch(context.Background(), request); err == nil || len(f.calls) != before {
				t.Fatal("closed session revived tools")
			}
			cancel()
			select {
			case <-auditDone:
			case <-time.After(time.Second):
				t.Fatal("audit link leaked")
			}
			encoded, _ := json.Marshal(session)
			if bytes.Contains(encoded, []byte(token)) {
				t.Fatal("session serialization leaked capability")
			}
		})
	}
}
func TestToolSessionConstructionFailureClosesOwnedAudit(t *testing.T) {
	t.Parallel()
	_, request := liveFixture(t)
	client, peer := net.Pipe()
	defer peer.Close()
	runner := mockDocker(func(context.Context, []string, []byte, io.Writer) error {
		t.Fatal("constructor contacted Docker")
		return errors.New("unexpected")
	})
	session, token, err := NewToolSession(t.Context(), request.Scope, []string{"read"}, "mutable:tag", "/var/lib/docker", time.Now(), client, runner)
	if err == nil || session != nil || token != "" {
		t.Fatal("unsafe image admitted")
	}
	_ = peer.SetReadDeadline(time.Now().Add(time.Second))
	var data [1]byte
	if _, err = peer.Read(data[:]); err == nil {
		t.Fatal("failed constructor left audit link open")
	}
}

func TestSessionCommandFlagAndGrantAreIndependent(t *testing.T) {
	t.Parallel()
	for _, mode := range []string{"off-granted", "on-granted", "on-ungranted", "off-ungranted"} {
		t.Run(mode, func(t *testing.T) {
			p, _, _, root, _ := inspectionFixture(t)
			_, request := liveFixture(t)
			enabled := strings.HasPrefix(mode, "on-")
			granted := strings.HasSuffix(mode, "-granted")
			allowed := []string{"read"}
			if granted {
				allowed = append(allowed, "command")
			}
			client, peer := net.Pipe()
			defer client.Close()
			defer peer.Close()
			runner := mockDocker(func(context.Context, []string, []byte, io.Writer) error {
				t.Fatal("construction launched Docker")
				return nil
			})
			session, _, err := NewToolSessionWithCommands(t.Context(), request.Scope, allowed, p.image, root, time.Now(), client, runner, enabled)
			if granted && !enabled {
				if err != ErrRejected {
					t.Fatal("disabled command grant accepted")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			defer session.Close()
			if session.CommandsEnabled() != (enabled && granted) {
				t.Fatal("flag granted permission")
			}
		})
	}
}
