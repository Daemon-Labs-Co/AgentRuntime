package workerport

import (
	"bytes"
	"context"
	"os/exec"
	"slices"
	"testing"
)

func TestCommandProcessCapturesBothStreamsAndClientStatus(t *testing.T) {
	t.Parallel()
	for _, mode := range []string{"success", "nonzero", "start-failure"} {
		t.Run(mode, func(t *testing.T) {
			var output bytes.Buffer
			code, err := runDockerCommand(t.Context(), []string{"exec", "synthetic"}, &output, func(ctx context.Context, args []string) *exec.Cmd {
				if !slices.Equal(args, []string{"exec", "synthetic"}) {
					t.Fatal("argv changed")
				}
				if mode == "start-failure" {
					return exec.CommandContext(ctx, t.TempDir()+"/missing")
				}
				script := "printf stdout; printf stderr >&2"
				if mode == "nonzero" {
					script += "; exit 17"
				}
				return exec.CommandContext(ctx, "/bin/sh", "-c", script)
			})
			if mode == "start-failure" {
				if err == nil || output.Len() != 0 {
					t.Fatal("start failure accepted")
				}
				return
			}
			if err != nil || !bytes.Contains(output.Bytes(), []byte("stdout")) || !bytes.Contains(output.Bytes(), []byte("stderr")) {
				t.Fatal("lost streams", err)
			}
			if mode == "nonzero" && code != 17 || mode == "success" && code != 0 {
				t.Fatal("client status lost")
			}
		})
	}
}

func TestCommandProcessRejectsCanceledContext(t *testing.T) {
	t.Parallel()
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	_, err := runDockerCommand(ctx, nil, &bytes.Buffer{}, func(context.Context, []string) *exec.Cmd { t.Fatal("canceled process started"); return nil })
	if err == nil {
		t.Fatal("cancellation ignored")
	}
}
