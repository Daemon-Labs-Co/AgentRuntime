package workerport

import (
	"commonroom-runtime/internal/toolbroker"
	"context"
	"errors"
	"io"
	"os"
	"os/exec"
	"slices"
	"strings"
	"testing"
	"time"
)

func TestCaptureStreamSyntheticChild(t *testing.T) {
	mode := os.Getenv("COMMONROOM_SYNTHETIC_CAPTURE")
	if mode == "" {
		return
	}
	os.Stderr.WriteString("synthetic-private-diagnostic")
	switch mode {
	case "final":
		os.Stdout.WriteString("synthetic-final-ack\n")
		os.Exit(0)
	case "failure":
		os.Exit(17)
	default:
		io.Copy(os.Stdout, os.Stdin)
		os.Exit(0)
	}
}

func captureSyntheticFactory(mode string) func(context.Context) *exec.Cmd {
	return func(ctx context.Context) *exec.Cmd {
		cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestCaptureStreamSyntheticChild$")
		cmd.Env = []string{"COMMONROOM_SYNTHETIC_CAPTURE=" + mode}
		return cmd
	}
}

func TestCaptureStreamSuccessfulWaitPreservesBufferedAck(t *testing.T) {
	t.Parallel()
	stream, err := openCaptureCommand(t.Context(), captureSyntheticFactory("final"))
	if err != nil {
		t.Fatal(err)
	}
	defer stream.Close()
	ctx, cancel := context.WithTimeout(t.Context(), 3*time.Second)
	defer cancel()
	if stream.Wait(ctx) != nil {
		t.Fatal("synthetic process failed")
	}
	raw, err := io.ReadAll(stream)
	if err != nil || string(raw) != "synthetic-final-ack\n" {
		t.Fatal("lost final acknowledgment or exposed stderr", string(raw), err)
	}
	if stream.Wait(ctx) != nil {
		t.Fatal("repeated wait changed outcome")
	}
}

func TestCaptureStreamFailureIsSanitized(t *testing.T) {
	t.Parallel()
	stream, err := openCaptureCommand(t.Context(), captureSyntheticFactory("failure"))
	if err != nil {
		t.Fatal(err)
	}
	defer stream.Close()
	ctx, cancel := context.WithTimeout(t.Context(), 3*time.Second)
	defer cancel()
	if err = stream.Wait(ctx); !errors.Is(err, toolbroker.ErrExecution) || strings.Contains(err.Error(), "diagnostic") {
		t.Fatal("wrong private failure", err)
	}
	raw, e := io.ReadAll(stream)
	if e != nil || len(raw) != 0 {
		t.Fatal("stderr forwarded", e, string(raw))
	}
}

func TestCaptureStreamDuplexCancelAndCloseReaps(t *testing.T) {
	t.Parallel()
	stream, err := openCaptureCommand(t.Context(), captureSyntheticFactory("echo"))
	if err != nil {
		t.Fatal(err)
	}
	defer stream.Close()
	if _, err = stream.Write([]byte("synthetic-request\n")); err != nil {
		t.Fatal(err)
	}
	raw := make([]byte, len("synthetic-request\n"))
	if _, err = io.ReadFull(stream, raw); err != nil || string(raw) != "synthetic-request\n" {
		t.Fatal("duplex protocol corrupted", err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if !errors.Is(stream.Wait(ctx), context.Canceled) {
		t.Fatal("canceled wait claimed success")
	}
	done := make(chan error, 1)
	go func() { done <- stream.Close() }()
	select {
	case err = <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("close failed to reap")
	}
	if err = stream.Wait(t.Context()); !errors.Is(err, toolbroker.ErrExecution) {
		t.Fatal("killed CLI claimed successful exit", err)
	}
	if stream.Close() != nil {
		t.Fatal("repeated close failed")
	}
}

func TestCaptureStartPolicyAndInvalidInput(t *testing.T) {
	t.Parallel()
	id := strings.Repeat("a", 64)
	cmd := captureStartCommand(t.Context(), id)
	if !slices.Equal(cmd.Args, []string{"docker", "start", "--attach", "--interactive", id}) {
		t.Fatal("unexpected launch policy", cmd.Args)
	}
	if len(cmd.Env) != 3 {
		t.Fatal("inherited unapproved environment")
	}
	for i, key := range []string{"PATH=", "HOME=", "XDG_RUNTIME_DIR="} {
		if !strings.HasPrefix(cmd.Env[i], key) {
			t.Fatal("wrong environment key")
		}
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	for _, tc := range []struct {
		ctx context.Context
		id  string
	}{{nil, id}, {ctx, id}, {t.Context(), "mutable-name"}, {t.Context(), id + " --privileged"}} {
		if _, err := (dockerCLIRunner{}).StartCapture(tc.ctx, tc.id); err == nil {
			t.Fatal("invalid launch admitted")
		}
	}
	if _, err := openCaptureCommand(ctx, func(context.Context) *exec.Cmd { t.Fatal("canceled factory invoked"); return nil }); err == nil {
		t.Fatal("canceled command admitted")
	}
	if _, err := openCaptureCommand(t.Context(), nil); err == nil {
		t.Fatal("nil factory admitted")
	}
	if _, err := openCaptureCommand(t.Context(), func(context.Context) *exec.Cmd { return nil }); err == nil {
		t.Fatal("nil command admitted")
	}
	if _, err := openCaptureCommand(t.Context(), func(ctx context.Context) *exec.Cmd {
		return exec.CommandContext(ctx, "/commonroom-synthetic-missing-executable")
	}); err == nil {
		t.Fatal("failed start accepted")
	}
}
