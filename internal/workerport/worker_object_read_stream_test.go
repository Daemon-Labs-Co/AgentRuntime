package workerport

import (
	"commonroom-runtime/internal/toolbroker"
	"context"
	"errors"
	"io"
	"os/exec"
	"strings"
	"testing"
	"time"
)

func TestObjectReadStreamWaitAndSanitizedExit(t *testing.T) {
	t.Parallel()
	for _, mode := range []string{"final", "failure"} {
		t.Run(mode, func(t *testing.T) {
			t.Parallel()
			stream, err := openObjectReadCommand(t.Context(), captureSyntheticFactory(mode))
			if err != nil {
				t.Fatal(err)
			}
			defer stream.Close()
			ctx, cancel := context.WithTimeout(t.Context(), 3*time.Second)
			defer cancel()
			err = stream.Wait(ctx)
			if mode == "failure" {
				if !errors.Is(err, toolbroker.ErrExecution) || strings.Contains(err.Error(), "diagnostic") {
					t.Fatal("unsanitized failure", err)
				}
			} else if err != nil {
				t.Fatal(err)
			}
			raw, e := io.ReadAll(stream)
			want := ""
			if mode == "final" {
				want = "synthetic-final-ack\n"
			}
			if e != nil || string(raw) != want {
				t.Fatal("lost final bytes or leaked stderr", string(raw), e)
			}
		})
	}
}

func TestObjectReadStreamCancelCloseAndRefusals(t *testing.T) {
	t.Parallel()
	stream, err := openObjectReadCommand(t.Context(), captureSyntheticFactory("echo"))
	if err != nil {
		t.Fatal(err)
	}
	defer stream.Close()
	if _, err = stream.Write([]byte("synthetic-read\n")); err != nil {
		t.Fatal(err)
	}
	raw := make([]byte, len("synthetic-read\n"))
	if _, err = io.ReadFull(stream, raw); err != nil || string(raw) != "synthetic-read\n" {
		t.Fatal(err)
	}
	dead, cancel := context.WithCancel(t.Context())
	cancel()
	if !errors.Is(stream.Wait(dead), context.Canceled) {
		t.Fatal("canceled wait succeeded")
	}
	done := make(chan error, 1)
	go func() { done <- stream.Close() }()
	select {
	case err = <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("close did not join")
	}
	if !errors.Is(stream.Wait(t.Context()), toolbroker.ErrExecution) {
		t.Fatal("killed process succeeded")
	}
	for _, tc := range []struct {
		ctx context.Context
		id  string
	}{{nil, strings.Repeat("a", 64)}, {dead, strings.Repeat("a", 64)}, {t.Context(), "mutable-name"}, {t.Context(), strings.Repeat("a", 64) + " --privileged"}} {
		if _, err := (dockerCLIRunner{}).StartObjectRead(tc.ctx, tc.id); err == nil {
			t.Fatal("invalid helper start accepted")
		}
	}
	if _, err := openObjectReadCommand(dead, func(context.Context) *exec.Cmd { t.Fatal("canceled factory invoked"); return nil }); err == nil {
		t.Fatal("dead start")
	}
	if _, err := openObjectReadCommand(t.Context(), nil); err == nil {
		t.Fatal("missing command accepted")
	}
	if _, err := openObjectReadCommand(t.Context(), func(context.Context) *exec.Cmd { return nil }); err == nil {
		t.Fatal("nil command accepted")
	}
}
