package workerport

import (
	"commonroom-runtime/internal/toolbroker"
	"context"
	"io"
	"os"
	"os/exec"
	"sync"
	"time"
)

// OpenEngine attaches only to a checked immutable ID. Rootless daemon selection
// is revalidated per invocation, as for Run. No host provider, shell, restart or
// stderr forwarding is allowed. Closing this CLI proves no container absence;
// the supervisor must still fence both roles through its normal shutdown path.
func (dockerCLIRunner) OpenEngine(ctx context.Context, id string) (io.ReadWriteCloser, error) {
	if ctx == nil || ctx.Err() != nil || !repositoryDigestPattern.MatchString(id) {
		return nil, toolbroker.ErrRejected
	}
	if verifiedLocalDockerContext(ctx) != nil {
		return nil, toolbroker.ErrRejected
	}
	return openEngineCommand(ctx, func(child context.Context) *exec.Cmd {
		cmd := exec.CommandContext(child, "docker", "attach", "--sig-proxy=false", "--detach-keys=", id)
		cmd.Env = []string{"PATH=" + os.Getenv("PATH"), "HOME=" + os.Getenv("HOME"), "XDG_RUNTIME_DIR=" + os.Getenv("XDG_RUNTIME_DIR")}
		return cmd
	})
}

// The factory is internal trusted process policy, injected only by synthetic
// process tests. Never accept an executable or arguments from a model/request.
func openEngineCommand(ctx context.Context, command func(context.Context) *exec.Cmd) (io.ReadWriteCloser, error) {
	if ctx == nil || ctx.Err() != nil || command == nil {
		return nil, toolbroker.ErrRejected
	}
	child, cancel := context.WithCancel(ctx)
	cmd := command(child)
	if cmd == nil {
		cancel()
		return nil, toolbroker.ErrRejected
	}
	cmd.WaitDelay = 2 * time.Second
	cmd.Stderr = io.Discard
	in, err := cmd.StdinPipe()
	if err != nil {
		cancel()
		return nil, toolbroker.ErrExecution
	}
	// Own stdout separately: Cmd.Wait must not close a StdoutPipe before the
	// callback driver has consumed the final buffered protocol frame.
	out, outputWriter, err := os.Pipe()
	if err != nil {
		cancel()
		in.Close()
		return nil, toolbroker.ErrExecution
	}
	cmd.Stdout = outputWriter
	if cmd.Start() != nil {
		cancel()
		in.Close()
		out.Close()
		outputWriter.Close()
		return nil, toolbroker.ErrExecution
	}
	outputWriter.Close()
	s := &engineCommandStream{in: in, out: out, cancel: cancel, done: make(chan struct{})}
	go func() {
		// Raw CLI errors may contain private host paths and are never returned.
		if cmd.Wait() != nil {
			s.waitErr = toolbroker.ErrExecution
		}
		close(s.done)
	}()
	return s, nil
}

type engineCommandStream struct {
	in      io.WriteCloser
	out     io.ReadCloser
	cancel  context.CancelFunc
	done    chan struct{}
	waitErr error
	once    sync.Once
}

func (s *engineCommandStream) Read(p []byte) (int, error) { return s.out.Read(p) }

func (s *engineCommandStream) Write(p []byte) (int, error) { return s.in.Write(p) }

func (s *engineCommandStream) Close() error {
	s.once.Do(func() { s.cancel(); s.in.Close(); s.out.Close(); <-s.done })
	return nil
}

// Wait reports the sanitized CLI outcome after process reaping without closing
// stdout: final buffered protocol bytes remain readable. Container exit/absence
// must still be independently inspected by CaptureRuntime. Cancellation is not
// proof of success; Close remains responsible for interrupting I/O and joining.
func (s *engineCommandStream) Wait(ctx context.Context) error {
	if ctx == nil {
		return toolbroker.ErrRejected
	}
	select {
	case <-s.done:
		if ctx.Err() != nil {
			return ctx.Err()
		}
		return s.waitErr
	case <-ctx.Done():
		return ctx.Err()
	}
}
