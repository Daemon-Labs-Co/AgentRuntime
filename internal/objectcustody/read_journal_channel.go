package objectcustody

import (
	"context"
	"io"
	"sync"
	"time"
)

// ReadJournalChannel is the fixed isolated reader's read-only journal relay. The
// stream is already authenticated and supervisor-owned, pinned to one receipt,
// never model pipes. ServeReadChannel must own request/body framing on this same
// stream; methods run synchronously only during its trusted store Get. There is no
// database credential, permissive local acknowledgment, write or host fallback.
type ReadJournalChannel struct {
	mu       sync.Mutex
	stream   io.ReadWriteCloser
	lifetime context.Context
	receipt  Receipt
	phase    int
	failed   bool
	stop     func()
	once     sync.Once
}

func NewReadJournalChannel(ctx context.Context, stream io.ReadWriteCloser, receipt Receipt, stop func()) (*ReadJournalChannel, error) {
	if ctx == nil || ctx.Err() != nil || readChannelAbsent(stream) || !validReceipt(receipt) || stop == nil {
		return nil, ErrRefused
	}
	return &ReadJournalChannel{stream: stream, lifetime: ctx, receipt: receipt, stop: stop}, nil
}

// Close revokes local read authority and closes the owned stream exactly once.
// The stop callback must be local/nonblocking and must not reenter this journal.
func (c *ReadJournalChannel) Close() error {
	if c != nil {
		c.once.Do(func() { _ = c.stream.Close(); c.stop() })
	}
	return nil
}
func (c *ReadJournalChannel) exchange(ctx context.Context, r Receipt, operation, response string, phase int) error {
	if c == nil || ctx == nil {
		return ErrRefused
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	fail := func() error { c.failed = true; _ = c.Close(); return ErrRefused }
	if c.failed || c.lifetime.Err() != nil || ctx.Err() != nil || r != c.receipt || c.phase != phase {
		return fail()
	}
	child, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	stopLifetime := context.AfterFunc(c.lifetime, cancel)
	defer stopLifetime()
	stopIO := context.AfterFunc(child, func() { _ = c.Close() })
	defer stopIO()
	if writeReadChannelHeader(c.stream, readChannelHeader{Version: 1, Operation: operation, Receipt: r}) != nil {
		return fail()
	}
	h, err := readReadChannelHeader(c.stream)
	if err != nil || h.Version != 1 || h.Operation != response || h.Receipt != r || child.Err() != nil || c.lifetime.Err() != nil {
		return fail()
	}
	c.phase++
	return nil
}
func (c *ReadJournalChannel) AuthorizeRead(ctx context.Context, scope Scope, r Receipt) error {
	if c == nil {
		return ErrRefused
	}
	if scope != c.receipt.Intent.Scope {
		_ = c.Close()
		return ErrRefused
	}
	return c.exchange(ctx, r, "source-authorize", "source-authorized", 0)
}
func (c *ReadJournalChannel) AcknowledgeRead(ctx context.Context, r Receipt) error {
	return c.exchange(ctx, r, "source-acknowledge", "source-acknowledged", 1)
}
func (*ReadJournalChannel) Reserve(context.Context, Intent) error { return ErrRefused }
func (*ReadJournalChannel) Seal(context.Context, Receipt) error   { return ErrRefused }

var _ Journal = (*ReadJournalChannel)(nil)
