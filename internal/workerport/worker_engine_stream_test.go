package workerport

import (
	"context"
	"io"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"
)

func TestEngineStreamChild(t *testing.T) {
	if os.Getenv("COMMONROOM_SYNTHETIC_ENGINE") != "1" {
		return
	}
	os.Stderr.WriteString("synthetic-private-stderr")
	if os.Getenv("COMMONROOM_SYNTHETIC_FINAL_FRAME") == "1" {
		os.Stdout.WriteString("synthetic-final-frame\n")
		os.Exit(0)
	}
	io.Copy(os.Stdout, os.Stdin)
	os.Exit(0)
}

func TestEngineCommandPreservesFinalFrameAfterProcessExit(t *testing.T) {
	t.Parallel()
	stream, err := openEngineCommand(t.Context(), func(ctx context.Context) *exec.Cmd {
		cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestEngineStreamChild$")
		cmd.Env = []string{"COMMONROOM_SYNTHETIC_ENGINE=1", "COMMONROOM_SYNTHETIC_FINAL_FRAME=1"}
		return cmd
	})
	if err != nil {
		t.Fatal(err)
	}
	defer stream.Close()
	select {
	case <-stream.(*engineCommandStream).done:
	case <-time.After(3 * time.Second):
		t.Fatal("synthetic child did not exit")
	}
	raw, err := io.ReadAll(stream)
	if err != nil || string(raw) != "synthetic-final-frame\n" {
		t.Fatalf("final frame lost: %q %v", raw, err)
	}
}

func TestEngineCommandDuplexCloseReapsAndDiscardsStderr(t *testing.T) {
	t.Parallel()
	stream, err := openEngineCommand(t.Context(), func(ctx context.Context) *exec.Cmd {
		cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestEngineStreamChild$")
		cmd.Env = []string{"COMMONROOM_SYNTHETIC_ENGINE=1"}
		return cmd
	})
	if err != nil {
		t.Fatal(err)
	}
	defer stream.Close()
	if _, err = stream.Write([]byte("synthetic-frame\n")); err != nil {
		t.Fatal(err)
	}
	got := make([]byte, len("synthetic-frame\n"))
	if _, err = io.ReadFull(stream, got); err != nil || string(got) != "synthetic-frame\n" {
		t.Fatalf("protocol corrupted: %q %v", got, err)
	}
	closed := make(chan error, 1)
	go func() { closed <- stream.Close() }()
	select {
	case err = <-closed:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("attachment process not reaped")
	}
	if stream.Close() != nil {
		t.Fatal("repeated close failed")
	}
	select {
	case <-stream.(*engineCommandStream).done:
	default:
		t.Fatal("close returned before process wait")
	}
}

func TestEngineCommandCancelledAndFailedStart(t *testing.T) {
	t.Parallel()
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if _, err := openEngineCommand(ctx, func(context.Context) *exec.Cmd { t.Fatal("cancelled command constructed"); return nil }); err == nil {
		t.Fatal("cancelled attach accepted")
	}
	if _, err := openEngineCommand(t.Context(), func(ctx context.Context) *exec.Cmd {
		return exec.CommandContext(ctx, "/commonroom-synthetic-missing-executable")
	}); err == nil {
		t.Fatal("failed launch accepted")
	}
	if _, err := (dockerCLIRunner{}).OpenEngine(t.Context(), "foreign-name"); err == nil {
		t.Fatal("mutable identity accepted")
	}
	if _, err := (dockerCLIRunner{}).OpenEngine(ctx, strings.Repeat("a", 64)); err == nil {
		t.Fatal("cancelled immutable attachment accepted")
	}
}
