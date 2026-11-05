package toolbroker

import (
	"bytes"
	"commonroom-runtime/internal/toolcommand"
	"context"
	"encoding/json"
	"errors"
	"io"
	"slices"
	"strings"
	"testing"
	"time"
)

type commandDocker struct {
	DockerRunner
	command func(context.Context, []string, io.Writer) (int, error)
}

func (r commandDocker) RunCommand(c context.Context, a []string, w io.Writer) (int, error) {
	return r.command(c, a, w)
}
func TestCommandRequiresFlagAndGrantBeforeDocker(t *testing.T) {
	t.Parallel()
	for _, mode := range []string{"off", "no-grant", "invalid-profile"} {
		t.Run(mode, func(t *testing.T) {
			p, _, _, _, root, scope, _ := executorFixture(t)
			p.commandsEnabled = mode != "off"
			if mode == "no-grant" {
				a, _, err := New(scope, []string{"read"}, time.Now())
				if err != nil {
					t.Fatal(err)
				}
				p.authority = a
			}
			action := Action{Operation: "command", Command: []string{"go", "test", "./..."}}
			if mode == "invalid-profile" {
				action.Command = []string{"sh", "-c", "true"}
			}
			e := containerExecutor(t, p, mockDocker(func(context.Context, []string, []byte, io.Writer) error {
				t.Fatal("denied command reached Docker")
				return nil
			}), root)
			ctx, cancel := context.WithDeadline(context.Background(), scope.Deadline)
			defer cancel()
			var out bytes.Buffer
			if e.Execute(ctx, scope, action, &out) != ErrRejected || out.Len() != 0 {
				t.Fatal("command authorization bypass")
			}
		})
	}
}
func TestCommandReceiptRequiresContainerAbsenceAndConsumesContainer(t *testing.T) {
	t.Parallel()
	for _, mode := range []string{"success", "nonzero", "overflow", "cleanup-failure", "runner-failure"} {
		t.Run(mode, func(t *testing.T) {
			p, c, raw, vol, root, scope, _ := executorFixture(t)
			p.commandsEnabled = true
			var output bytes.Buffer
			removed := false
			absent := false
			calls := 0
			base := runtimeMock(t, raw, vol, func(_ context.Context, args []string, input []byte, _ io.Writer) error {
				if input != nil || !slices.Equal(args, []string{"exec", "--user", "1000:1000", "--workdir", "/workspace", c.ID, "/bin/mkdir", "-p", "/workspace/.commonroom-command/cache", "/workspace/.commonroom-command/tmp", "/workspace/.commonroom-command/modules"}) {
					t.Fatal("unsafe cache preparation")
				}
				return nil
			}, func(args []string, w io.Writer) error {
				if output.Len() != 0 {
					t.Fatal("receipt released before cleanup")
				}
				switch args[0] {
				case "ps":
					if !removed || mode == "cleanup-failure" {
						_, _ = io.WriteString(w, c.ID)
					} else {
						absent = true
					}
					return nil
				case "rm":
					if !slices.Equal(args, []string{"rm", "--force", c.ID}) {
						t.Fatal("wrong cleanup identity")
					}
					removed = true
					return nil
				}
				return errors.New("unexpected cleanup")
			})
			runner := commandDocker{base, func(_ context.Context, args []string, w io.Writer) (int, error) {
				calls++
				if !slices.Equal(args[len(args)-4:], []string{c.ID, "/usr/local/go/bin/go", "test", "./..."}) || !slices.Contains(args, "GOPROXY=off") {
					t.Fatal("unsafe command argv")
				}
				if mode == "overflow" {
					_, _ = io.WriteString(w, strings.Repeat("x", toolcommand.MaxOutputBytes+1))
					return 0, nil
				}
				if mode == "runner-failure" {
					return -1, errors.New("private failure")
				}
				_, _ = io.WriteString(w, "synthetic check output")
				if mode == "nonzero" {
					return 1, nil
				}
				return 0, nil
			}}
			e := containerExecutor(t, p, runner, root)
			ctx, cancel := context.WithDeadline(context.Background(), scope.Deadline)
			defer cancel()
			action := Action{Operation: "command", Command: []string{"go", "test", "./..."}}
			err := e.Execute(ctx, scope, action, &output)
			if mode == "success" || mode == "nonzero" {
				if err != nil || !absent || !validCommandReceipt(output.Bytes(), action) {
					t.Fatal("invalid receipt/absence", err)
				}
				var receipt toolcommand.Receipt
				_ = json.Unmarshal(output.Bytes(), &receipt)
				if mode == "nonzero" && receipt.Completion != "unconfirmed" {
					t.Fatal("nonzero certified")
				}
			} else if err == nil || output.Len() != 0 {
				t.Fatal("failed command released output")
			}
			if mode == "overflow" && (err != ErrOutputLimit || !absent) {
				t.Fatal("overflow lost its output-limit error after confirmed cleanup", err, absent)
			}
			if calls != 1 || !removed {
				t.Fatal("missing command/cleanup")
			}
			if e.Execute(ctx, scope, Action{Operation: "read", Path: "README.md"}, io.Discard) != ErrRejected {
				t.Fatal("container reused after terminal command")
			}
		})
	}
}
func TestCommandReceiptRejectsTampering(t *testing.T) {
	t.Parallel()
	action := Action{Operation: "command", Command: []string{"go", "test", "./..."}}
	receipt, err := toolcommand.Run(context.Background(), action.Command, receiptRunner{})
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(receipt)
	if !validCommandReceipt(raw, action) {
		t.Fatal("valid receipt rejected")
	}
	for _, mutate := range []func(toolcommand.Receipt) toolcommand.Receipt{
		func(r toolcommand.Receipt) toolcommand.Receipt { r.ExitCode = 1; return r },
		func(r toolcommand.Receipt) toolcommand.Receipt { r.CommandDigest = strings.Repeat("0", 64); return r },
		func(r toolcommand.Receipt) toolcommand.Receipt { r.Bytes++; return r },
		func(r toolcommand.Receipt) toolcommand.Receipt { r.SHA256 = strings.Repeat("0", 64); return r },
	} {
		bad, _ := json.Marshal(mutate(receipt))
		if validCommandReceipt(bad, action) {
			t.Fatal("tampered receipt accepted")
		}
	}
	for _, bad := range []string{string(raw) + "{}", strings.Replace(string(raw), `"operation":`, `"operation":"command","operation":`, 1), strings.Replace(string(raw), `"completion":"succeeded"`, `"completion":null`, 1)} {
		if validCommandReceipt([]byte(bad), action) {
			t.Fatal("malformed receipt accepted")
		}
	}
}

type receiptRunner struct{}

func (receiptRunner) Run(context.Context, toolcommand.Spec, io.Writer) (int, error) { return 0, nil }

func TestCommandAuditAcknowledgementsGateEffectsAndOutput(t *testing.T) {
	t.Parallel()
	for _, mode := range []string{"success", "intent-failure", "outcome-failure"} {
		t.Run(mode, func(t *testing.T) {
			a, request := liveFixture(t)
			request.Operation = "command"
			request.Path = ""
			request.Content = ""
			request.Command = []string{"go", "test", "./..."}
			stage := 0
			calls := 0
			audit := mockAudit{intent: func(_ context.Context, i Intent) error {
				if stage != 0 || i.Operation != "command" || i.Scope != a.scope {
					t.Fatal("invalid command intent")
				}
				stage = 1
				if mode == "intent-failure" {
					return ErrAudit
				}
				return nil
			}, outcome: func(_ context.Context, _ Intent, o Outcome) error {
				if stage != 2 || o.Status != "succeeded" || o.OutputBytes == 0 {
					t.Fatal("outcome before execution")
				}
				stage = 3
				if mode == "outcome-failure" {
					return ErrAudit
				}
				return nil
			}}
			executor := mockExecutor(func(_ context.Context, _ Scope, action Action, w io.Writer) error {
				calls++
				if stage != 1 || !slices.Equal(action.Command, request.Command) {
					t.Fatal("execution before durable intent")
				}
				stage = 2
				receipt, _ := toolcommand.Run(context.Background(), action.Command, receiptRunner{})
				raw, _ := json.Marshal(receipt)
				_, err := w.Write(raw)
				return err
			})
			result, err := dispatcher(t, a, audit, executor).Dispatch(t.Context(), request)
			if mode == "success" {
				if err != nil || stage != 3 || len(result) == 0 {
					t.Fatal("missing audited receipt", err)
				}
			} else if err != ErrAudit || len(result) != 0 {
				t.Fatal("audit failure released result")
			}
			if mode == "intent-failure" && calls != 0 {
				t.Fatal("failed intent permitted execution")
			}
		})
	}
}
