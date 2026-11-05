package toolcommand

import (
	"context"
	"encoding/base64"
	"errors"
	"io"
	"slices"
	"strings"
	"testing"
	"testing/synctest"
	"time"
)

func TestCommandTimeoutWithholdsReceiptEvenIfRunnerReportsSuccess(t *testing.T) {
	t.Parallel()
	for _, expires := range []bool{false, true} {
		t.Run(map[bool]string{false: "before-deadline", true: "at-deadline"}[expires], func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				started := time.Now()
				receipt, err := Run(t.Context(), []string{"go", "test", "./..."}, testRunner(func(ctx context.Context, _ Spec, out io.Writer) (int, error) {
					_, _ = io.WriteString(out, "synthetic output before deadline")
					if expires {
						<-ctx.Done()
						if ctx.Err() != context.DeadlineExceeded || time.Since(started) != Timeout {
							t.Fatal("fixed command deadline not enforced", ctx.Err())
						}
					} else {
						time.Sleep(Timeout - time.Nanosecond)
					}
					return 0, nil // A late zero exit must never certify success.
				}))
				if expires {
					if err != ErrExecution || receipt != (Receipt{}) {
						t.Fatal("expired command released a receipt", receipt, err)
					}
				} else if err != nil || receipt.Completion != "succeeded" || receipt.Bytes == 0 {
					t.Fatal("command before deadline was refused", err)
				}
			})
		})
	}
}

type testRunner func(context.Context, Spec, io.Writer) (int, error)

func (f testRunner) Run(c context.Context, s Spec, w io.Writer) (int, error) { return f(c, s, w) }
func TestProfilesAndFixedExecutionPolicy(t *testing.T) {
	t.Parallel()
	for _, argv := range [][]string{{"go", "test", "./..."}, {"go", "build", "./..."}} {
		result, err := Run(context.Background(), argv, testRunner(func(ctx context.Context, s Spec, w io.Writer) (int, error) {
			deadline, ok := ctx.Deadline()
			if !ok || time.Until(deadline) > Timeout {
				t.Fatal("unbounded command")
			}
			if s.Program != "/usr/local/go/bin/go" || s.Dir != "/workspace/repository" || !slices.Equal(s.Args, argv[1:]) {
				t.Fatal("command policy changed")
			}
			for _, env := range []string{"GOPROXY=off", "GOSUMDB=off", "GOTOOLCHAIN=local", "GOENV=off", "GOWORK=off", "CGO_ENABLED=0"} {
				if !slices.Contains(s.Env, env) {
					t.Fatalf("missing %s", env)
				}
			}
			_, err := io.WriteString(w, "synthetic check output")
			return 0, err
		}))
		if err != nil || result.Completion != "succeeded" || result.CommandDigest != Digest(argv) {
			t.Fatal("missing successful receipt", err)
		}
		data, err := base64.StdEncoding.DecodeString(result.Data)
		if err != nil || string(data) != "synthetic check output" || result.Bytes != len(data) {
			t.Fatal("output corrupted")
		}
	}
	for _, argv := range [][]string{nil, {"sh", "-c", "go test ./..."}, {"go", "test", "-race", "./..."}, {"/usr/local/go/bin/go", "test", "./..."}, {"go", "test", "../..."}} {
		_, err := Run(context.Background(), argv, testRunner(func(context.Context, Spec, io.Writer) (int, error) { t.Fatal("rejected profile ran"); return 0, nil }))
		if err != ErrRefused {
			t.Fatal("unsafe profile accepted")
		}
	}
}
func TestOutputAndFailureBounds(t *testing.T) {
	t.Parallel()
	for _, kind := range []string{"limit", "overflow", "runner-error", "negative", "too-large", "nonzero", "cancel"} {
		t.Run(kind, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			result, err := Run(ctx, []string{"go", "test", "./..."}, testRunner(func(c context.Context, _ Spec, w io.Writer) (int, error) {
				switch kind {
				case "limit":
					_, err := io.WriteString(w, strings.Repeat("x", MaxOutputBytes))
					return 0, err
				case "overflow":
					_, _ = io.WriteString(w, strings.Repeat("x", MaxOutputBytes+1))
					if c.Err() == nil {
						t.Fatal("overflow did not cancel")
					}
					return 0, nil
				case "runner-error":
					return 0, errors.New("synthetic private error")
				case "negative":
					return -1, nil
				case "too-large":
					return 256, nil
				case "nonzero":
					return 1, nil
				default:
					cancel()
					return 0, nil
				}
			}))
			if kind == "limit" {
				if err != nil || result.Bytes != MaxOutputBytes {
					t.Fatal("exact limit refused")
				}
			} else if kind == "nonzero" {
				if err != nil || result.ExitCode != 1 || result.Completion != "unconfirmed" {
					t.Fatal("client error misrepresented")
				}
			} else if !errors.Is(err, ErrExecution) || result.Data != "" {
				t.Fatal("failed execution leaked receipt", err)
			}
		})
	}
}

func TestOverflowHasDistinctFailureCauseAndWithholdsReceipt(t *testing.T) {
	t.Parallel()
	receipt, err := Run(t.Context(), []string{"go", "test", "./..."}, testRunner(func(ctx context.Context, _ Spec, out io.Writer) (int, error) {
		_, _ = io.WriteString(out, strings.Repeat("x", MaxOutputBytes+1))
		if ctx.Err() == nil {
			t.Fatal("overflow did not cancel command")
		}
		return 0, nil
	}))
	if !errors.Is(err, ErrOutputLimit) || !errors.Is(err, ErrExecution) || receipt.Data != "" {
		t.Fatal("overflow cause lost or receipt released", err)
	}
}
