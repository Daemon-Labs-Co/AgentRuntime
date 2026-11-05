package toolbroker

import (
	"context"
	"io"
	"sync"
)

// EngineStreamRunner attaches only protocol stdin/stdout to an existing immutable
// container ID on the same approved rootless daemon as Run. Implementations must
// discard stderr, disable detach keys and signal proxying, close blocked I/O on
// cancellation, and reap the attachment process on Close. It must never start,
// exec, adopt or reconnect a provider. A source replacement can violate this
// contract; this interface is not protection against a hostile worker host.
type EngineStreamRunner interface {
	DockerRunner
	OpenEngine(context.Context, string) (io.ReadWriteCloser, error)
}

// Attach consumes one attachment attempt after rechecking the running policy.
// Failure is uncertain: callers must fence the job rather than reconnect. The
// returned stream belongs to the callback driver and remains lifetime-bound.
func (r *EngineContainerRuntime) Attach(ctx context.Context, id string) (io.ReadWriteCloser, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	child, done, err := r.context(ctx)
	if err != nil {
		return nil, err
	}
	if id != r.id || !r.running || !r.verified || r.attached {
		done()
		return nil, ErrRejected
	}
	r.attached = true
	runner, ok := r.runner.(EngineStreamRunner)
	if !ok {
		done()
		return nil, ErrRejected
	}
	raw, err := r.inspect(child)
	if err != nil || r.verify(raw, true) != nil {
		done()
		return nil, ErrRejected
	}
	stream, err := runner.OpenEngine(child, id)
	if err != nil || stream == nil {
		done()
		if stream != nil {
			stream.Close()
		}
		return nil, ErrExecution
	}
	var once sync.Once
	var closeErr error
	closeStream := func() { once.Do(func() { done(); closeErr = stream.Close() }) }
	stop := context.AfterFunc(child, closeStream)
	owned := &engineStream{ReadWriteCloser: stream, ctx: child, original: r.original, lifetime: r.ctx,
		close: func() error { stop(); closeStream(); return closeErr }}
	raw, err = r.inspect(child)
	if err != nil || r.verify(raw, true) != nil {
		owned.Close()
		return nil, ErrRejected
	}
	if child.Err() != nil || r.ctx.Err() != nil || r.original.Err() != nil {
		owned.Close()
		return nil, ErrRejected
	}
	return owned, nil
}

type engineStream struct {
	io.ReadWriteCloser
	ctx, original, lifetime context.Context
	close                   func() error
}

func (s *engineStream) Read(p []byte) (int, error) {
	if s.ctx.Err() != nil || s.original.Err() != nil || s.lifetime.Err() != nil {
		return 0, ErrRejected
	}
	n, err := s.ReadWriteCloser.Read(p)
	if s.ctx.Err() != nil || s.original.Err() != nil || s.lifetime.Err() != nil {
		clear(p[:n])
		return 0, ErrRejected
	}
	return n, err
}
func (s *engineStream) Write(p []byte) (int, error) {
	if s.ctx.Err() != nil || s.original.Err() != nil || s.lifetime.Err() != nil {
		return 0, ErrRejected
	}
	return s.ReadWriteCloser.Write(p)
}
func (s *engineStream) Close() error { return s.close() }
