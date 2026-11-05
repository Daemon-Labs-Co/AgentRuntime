//go:build linux || darwin

package objectcustody

import (
	"context"
	"net"
	"os"
	"strings"
	"sync/atomic"
	"testing"
)

func TestReadJournalChannelActualStoreRelay(t *testing.T) {
	t.Parallel()
	for _, deny := range []bool{false, true} {
		t.Run(map[bool]string{false: "durable-release", true: "source-ack-denied"}[deny], func(t *testing.T) {
			t.Parallel()
			store, j, dir := custodyFixture(t)
			scope := syntheticScope()
			receipt, err := store.Put(t.Context(), scope, 128, strings.NewReader("synthetic relay bytes"))
			if err != nil {
				t.Fatal(err)
			}
			root, err := os.OpenRoot(dir)
			if err != nil {
				t.Fatal(err)
			}
			defer root.Close()
			left, right := net.Pipe()
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			var stopped atomic.Int32
			relay, err := NewReadJournalChannel(ctx, right, receipt, func() { stopped.Add(1); cancel() })
			if err != nil {
				t.Fatal(err)
			}
			defer relay.Close()
			readStore, err := New(root, relay)
			if err != nil {
				t.Fatal(err)
			}
			g := &channelReleaseGuard{receipt: receipt, failAck: deny}
			done := make(chan error, 1)
			go func() { done <- ServeReadChannel(ctx, right, scope, receipt, readStore) }()
			raw, err := ReadChannel(t.Context(), left, scope, receipt, g)
			serveErr := <-done
			if deny {
				if err == nil || serveErr == nil || raw != nil || g.ack.Load() != 1 || g.stopped.Load() != 1 || stopped.Load() != 1 {
					t.Fatal("source audit refusal released data", err, serveErr)
				}
			} else {
				if err != nil || serveErr != nil || string(raw) != "synthetic relay bytes" || g.authorize.Load() != 2 || g.ack.Load() != 2 {
					t.Fatal("incomplete source/receiver authority", err, serveErr, g.authorize.Load(), g.ack.Load())
				}
			}
			if j.total != 128 || len(j.sealed) != 1 {
				t.Fatal("relay changed retained storage charge")
			}
			if relay.Reserve(t.Context(), receipt.Intent) == nil || relay.Seal(t.Context(), receipt) == nil {
				t.Fatal("read relay gained write authority")
			}
		})
	}
}
func TestReadChannelRejectsRelayPhaseSubstitution(t *testing.T) {
	t.Parallel()
	for _, mode := range []string{"ack-first", "repeat-authorize", "object-before-ack", "repeat-ack"} {
		t.Run(mode, func(t *testing.T) {
			t.Parallel()
			store, _, _ := custodyFixture(t)
			scope := syntheticScope()
			receipt, err := store.Put(t.Context(), scope, 128, strings.NewReader("synthetic"))
			if err != nil {
				t.Fatal(err)
			}
			left, right := net.Pipe()
			g := &channelReleaseGuard{receipt: receipt}
			done := make(chan struct{})
			go func() {
				defer close(done)
				defer right.Close()
				if _, err := readReadChannelHeader(right); err != nil {
					return
				}
				send := func(op string) bool {
					if writeReadChannelHeader(right, readChannelHeader{Version: 1, Operation: op, Receipt: receipt}) != nil {
						return false
					}
					_, err := readReadChannelHeader(right)
					return err == nil
				}
				if mode == "ack-first" {
					_ = send("source-acknowledge")
					return
				}
				if !send("source-authorize") {
					return
				}
				if mode == "repeat-authorize" {
					_ = send("source-authorize")
					return
				}
				if mode == "object-before-ack" {
					_ = send("object")
					return
				}
				if !send("source-acknowledge") {
					return
				}
				_ = send("source-acknowledge")
			}()
			raw, err := ReadChannel(t.Context(), left, scope, receipt, g)
			<-done
			if err == nil || raw != nil || g.stopped.Load() != 1 {
				t.Fatal("relay phase bypass")
			}
			expected := int32(0)
			if mode == "repeat-ack" {
				expected = 1
			}
			if g.ack.Load() != expected {
				t.Fatal("unexpected audit calls", g.ack.Load())
			}
		})
	}
}
func TestReadJournalChannelRejectsWrongAckAndDeadLifetime(t *testing.T) {
	t.Parallel()
	for _, mode := range []string{"wrong-receipt", "wrong-operation", "dead-lifetime", "out-of-order"} {
		t.Run(mode, func(t *testing.T) {
			t.Parallel()
			store, _, _ := custodyFixture(t)
			scope := syntheticScope()
			receipt, err := store.Put(t.Context(), scope, 128, strings.NewReader("synthetic"))
			if err != nil {
				t.Fatal(err)
			}
			left, right := net.Pipe()
			defer right.Close()
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			var stopped atomic.Int32
			relay, err := NewReadJournalChannel(ctx, left, receipt, func() { stopped.Add(1) })
			if err != nil {
				t.Fatal(err)
			}
			done := make(chan struct{})
			go func() {
				defer close(done)
				defer right.Close()
				if _, err := readReadChannelHeader(right); err != nil {
					return
				}
				h := readChannelHeader{Version: 1, Operation: "source-authorized", Receipt: receipt}
				if mode == "wrong-receipt" {
					h.Receipt.Digest = strings.Repeat("9", 64)
				} else {
					h.Operation = "source-acknowledged"
				}
				_ = writeReadChannelHeader(right, h)
			}()
			if mode == "dead-lifetime" {
				cancel()
			}
			if mode == "out-of-order" {
				err = relay.AcknowledgeRead(t.Context(), receipt)
			} else {
				err = relay.AuthorizeRead(t.Context(), scope, receipt)
			}
			<-done
			if err == nil || stopped.Load() != 1 {
				t.Fatal("uncertain relay revived", err, stopped.Load())
			}
			if relay.AuthorizeRead(t.Context(), scope, receipt) == nil {
				t.Fatal("poisoned relay reused")
			}
		})
	}
}
