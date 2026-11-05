//go:build linux || darwin

package objectcustody

import (
	"bytes"
	"context"
	"encoding/binary"
	"io"
	"net"
	"strings"
	"sync/atomic"
	"testing"
)

type channelReleaseGuard struct {
	receipt                 Receipt
	deny, failAck           bool
	authorize, ack, stopped atomic.Int32
}

func (g *channelReleaseGuard) AuthorizeRead(ctx context.Context, s Scope, r Receipt) error {
	g.authorize.Add(1)
	if g.deny || r != g.receipt || s != r.Intent.Scope {
		return ErrRefused
	}
	return ctx.Err()
}
func (g *channelReleaseGuard) AcknowledgeRead(ctx context.Context, r Receipt) error {
	g.ack.Add(1)
	if g.failAck || r != g.receipt {
		return ErrRefused
	}
	return ctx.Err()
}
func (g *channelReleaseGuard) StopReadAuthority() { g.stopped.Add(1) }
func TestReadChannelActualSealedObject(t *testing.T) {
	t.Parallel()
	for _, content := range [][]byte{nil, []byte("synthetic binary\x00\xff\nartifact")} {
		t.Run(string(rune(len(content)+65)), func(t *testing.T) {
			t.Parallel()
			store, j, _ := custodyFixture(t)
			scope := syntheticScope()
			receipt, err := store.Put(t.Context(), scope, 128, bytes.NewReader(content))
			if err != nil {
				t.Fatal(err)
			}
			left, right := net.Pipe()
			g := &channelReleaseGuard{receipt: receipt}
			done := make(chan error, 1)
			go func() { done <- ServeReadChannel(t.Context(), right, scope, receipt, store) }()
			raw, err := ReadChannel(t.Context(), left, scope, receipt, g)
			if err != nil || !bytes.Equal(raw, content) {
				t.Fatal("sealed delivery", err)
			}
			if err = <-done; err != nil {
				t.Fatal(err)
			}
			if g.authorize.Load() != 1 || g.ack.Load() != 1 || g.stopped.Load() != 0 {
				t.Fatal("missing release authority")
			}
			j.mu.Lock()
			events := strings.Join(j.events, ",")
			total := j.total
			j.mu.Unlock()
			if events != "reserve,seal,authorize-read,acknowledge-read" || total != 128 {
				t.Fatal("source audit/charge changed", events, total)
			}
		})
	}
}
func TestReadChannelRefusalsReturnNoBytes(t *testing.T) {
	t.Parallel()
	for _, mode := range []string{"client-denied", "client-ack", "store-denied", "store-ack"} {
		t.Run(mode, func(t *testing.T) {
			t.Parallel()
			store, j, _ := custodyFixture(t)
			scope := syntheticScope()
			receipt, err := store.Put(t.Context(), scope, 128, strings.NewReader("synthetic"))
			if err != nil {
				t.Fatal(err)
			}
			g := &channelReleaseGuard{receipt: receipt, deny: mode == "client-denied", failAck: mode == "client-ack"}
			j.failRead = mode == "store-denied"
			j.failAck = mode == "store-ack"
			left, right := net.Pipe()
			done := make(chan error, 1)
			go func() { done <- ServeReadChannel(t.Context(), right, scope, receipt, store) }()
			raw, err := ReadChannel(t.Context(), left, scope, receipt, g)
			<-done
			if err == nil || raw != nil || g.stopped.Load() != 1 {
				t.Fatal("failure released bytes", err, raw)
			}
			if mode != "client-ack" && g.ack.Load() != 0 {
				t.Fatal("acknowledged incomplete body")
			}
			if j.total != 128 || len(j.sealed) != 1 {
				t.Fatal("failure refunded/deleted retained object")
			}
		})
	}
}
func TestReadChannelRejectsHostileBodyAndHeaders(t *testing.T) {
	t.Parallel()
	for _, mode := range []string{"digest", "truncated", "trailing", "receipt", "version", "operation", "unknown-field", "oversized-header", "canceled"} {
		t.Run(mode, func(t *testing.T) {
			t.Parallel()
			store, _, _ := custodyFixture(t)
			scope := syntheticScope()
			content := []byte("synthetic")
			receipt, err := store.Put(t.Context(), scope, 128, bytes.NewReader(content))
			if err != nil {
				t.Fatal(err)
			}
			g := &channelReleaseGuard{receipt: receipt}
			left, right := net.Pipe()
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			done := make(chan struct{})
			go func() {
				defer close(done)
				defer right.Close()
				if _, err := readReadChannelHeader(right); err != nil {
					return
				}
				if mode == "canceled" {
					cancel()
					var b [1]byte
					_, _ = right.Read(b[:])
					return
				}
				h := readChannelHeader{Version: 1, Operation: "object", Receipt: receipt}
				switch mode {
				case "receipt":
					h.Receipt.Intent.ObjectID = strings.Repeat("9", 32)
				case "version":
					h.Version = 2
				case "operation":
					h.Operation = "read"
				}
				if mode == "oversized-header" {
					var n [4]byte
					binary.BigEndian.PutUint32(n[:], readChannelFrameLimit+1)
					_, _ = right.Write(n[:])
					return
				}
				if mode == "unknown-field" {
					raw := []byte(`{"version":1,"operation":"object","receipt":{},"extra":true}`)
					var n [4]byte
					binary.BigEndian.PutUint32(n[:], uint32(len(raw)))
					_, _ = right.Write(n[:])
					_, _ = right.Write(raw)
					return
				}
				if writeReadChannelHeader(right, h) != nil {
					return
				}
				switch mode {
				case "digest":
					content[0] = 'X'
				case "truncated":
					content = content[:2]
				case "trailing":
					content = append(content, 'x')
				}
				_ = writeReadChannelBytes(right, content)
			}()
			raw, err := ReadChannel(ctx, left, scope, receipt, g)
			<-done
			if err == nil || raw != nil || g.ack.Load() != 0 || g.stopped.Load() != 1 {
				t.Fatal("hostile response accepted", mode, err, g.ack.Load())
			}
		})
	}
}

type channelCountingReader struct {
	calls atomic.Int32
	raw   []byte
}

func (r *channelCountingReader) Get(context.Context, Scope, Receipt) ([]byte, error) {
	r.calls.Add(1)
	return r.raw, nil
}
func TestServeReadChannelRejectsSubstitutionBeforeStore(t *testing.T) {
	t.Parallel()
	store, _, _ := custodyFixture(t)
	scope := syntheticScope()
	receipt, err := store.Put(t.Context(), scope, 128, strings.NewReader("synthetic"))
	if err != nil {
		t.Fatal(err)
	}
	left, right := net.Pipe()
	reader := &channelCountingReader{}
	done := make(chan error, 1)
	go func() { done <- ServeReadChannel(t.Context(), right, scope, receipt, reader) }()
	other := receipt
	other.Intent.ObjectID = strings.Repeat("9", 32)
	_ = writeReadChannelHeader(left, readChannelHeader{Version: 1, Operation: "read", Receipt: other})
	var b [1]byte
	if _, err = left.Read(b[:]); err != io.EOF {
		t.Fatal(err)
	}
	left.Close()
	if <-done == nil || reader.calls.Load() != 0 {
		t.Fatal("substituted request reached store")
	}
}
func TestReadChannelMissingAuthorityAndBounds(t *testing.T) {
	t.Parallel()
	store, _, _ := custodyFixture(t)
	scope := syntheticScope()
	receipt, err := store.Put(t.Context(), scope, 128, strings.NewReader("synthetic"))
	if err != nil {
		t.Fatal(err)
	}
	left, right := net.Pipe()
	defer left.Close()
	defer right.Close()
	var missing *channelReleaseGuard
	if raw, err := ReadChannel(t.Context(), left, scope, receipt, missing); err == nil || raw != nil {
		t.Fatal("missing authority")
	}
	huge := receipt
	huge.Intent.MaxBytes = MaxObjectBytes + 1
	if raw, err := ReadChannel(t.Context(), left, scope, huge, &channelReleaseGuard{receipt: huge}); err == nil || raw != nil {
		t.Fatal("unbounded receipt")
	}
	if ServeReadChannel(t.Context(), right, scope, receipt, (*channelCountingReader)(nil)) == nil {
		t.Fatal("missing source")
	}
}
