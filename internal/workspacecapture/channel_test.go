package workspacecapture

import (
	"bytes"
	"commonroom-runtime/internal/objectcustody"
	"commonroom-runtime/internal/workspacemount"
	"commonroom-runtime/internal/workspacesnapshot"
	"context"
	"encoding/binary"
	"errors"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

type channelResult struct {
	report Report
	err    error
}

func TestCaptureChannelActualCustodyTransfer(t *testing.T) {
	t.Parallel()
	v, b, m := captureFixture(t)
	request := Request{b, m, v.proof.Challenge}
	root, dir := transferRoot(t)
	left, right := net.Pipe()
	var stopped atomic.Int32
	client, err := NewCaptureChannel(t.Context(), left, request, func() { stopped.Add(1) })
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	journal := &transferJournal{}
	authority := &fixtureAuthority{}
	done := make(chan channelResult, 1)
	go func() {
		r, e := ServeCaptureChannel(t.Context(), right, request, authority, journal)
		done <- channelResult{r, e}
	}()
	result, err := captureToCustody(t.Context(), v, request, client, root, client)
	if err != nil {
		t.Fatal(err)
	}
	if err = client.Finish(t.Context(), result); err != nil {
		t.Fatal(err)
	}
	served := <-done
	if served.err != nil || len(served.report.Receipts) != 1 || served.report.Scope != result.Snapshot.Scope || served.report.SnapshotDigest != result.Snapshot.Digest || stopped.Load() != 0 {
		t.Fatal("round trip failed", served, stopped.Load())
	}
	if journal.charged != 128 || len(journal.receipts) != 1 || journal.reads != 0 || authority.calls < 4 {
		t.Fatal("missing durable lifecycle", journal, authority.calls)
	}
	receipt := served.report.Receipts[0]
	data, err := os.ReadFile(filepath.Join(dir, "object-"+receipt.Intent.ObjectID+".blob"))
	if err != nil || string(data) != "synthetic captured result\n" {
		t.Fatal("stored bytes differ", err)
	}
	if client.Finish(t.Context(), result) == nil {
		t.Fatal("finished channel replayed")
	}
}
func TestCaptureChannelDenialAndUncertainCustody(t *testing.T) {
	t.Parallel()
	for _, mode := range []string{"observe", "reserve", "seal"} {
		t.Run(mode, func(t *testing.T) {
			t.Parallel()
			v, b, m := captureFixture(t)
			request := Request{b, m, v.proof.Challenge}
			root, dir := transferRoot(t)
			left, right := net.Pipe()
			var stopped atomic.Int32
			client, err := NewCaptureChannel(t.Context(), left, request, func() { stopped.Add(1) })
			if err != nil {
				t.Fatal(err)
			}
			defer client.Close()
			authority := &fixtureAuthority{}
			journal := &transferJournal{}
			switch mode {
			case "observe":
				authority.check = func(context.Context, workspacesnapshot.Binding, workspacemount.Proof) error {
					return errors.New("denied")
				}
			case "reserve":
				journal.reserve = func(objectcustody.Intent) error { return errors.New("quota unavailable") }
			case "seal":
				journal.seal = func(objectcustody.Receipt) error { return errors.New("audit unavailable") }
			}
			done := make(chan error, 1)
			go func() { _, err := ServeCaptureChannel(t.Context(), right, request, authority, journal); done <- err }()
			result, err := captureToCustody(t.Context(), v, request, client, root, client)
			if err == nil || len(result.Receipts) != 0 {
				t.Fatal("denial released result", err)
			}
			servedErr := <-done
			if servedErr == nil || stopped.Load() != 1 {
				t.Fatal("authority not stopped", servedErr, stopped.Load())
			}
			if mode != "observe" && (!errors.Is(servedErr, objectcustody.ErrUnconfirmed) || journal.charged != 128) {
				t.Fatal("uncertain reservation lost", servedErr, journal.charged)
			}
			files, _ := os.ReadDir(dir)
			if mode == "reserve" && len(files) != 0 || mode == "seal" && len(files) != 1 {
				t.Fatal("wrong uncertain file outcome", files)
			}
		})
	}
}
func TestCaptureChannelRejectsMalformedFramesBeforeAuthority(t *testing.T) {
	t.Parallel()
	for _, mode := range []string{"version", "sequence", "scope", "operation", "multiple payloads", "unknown field", "duplicate field", "oversized", "truncated"} {
		t.Run(mode, func(t *testing.T) {
			t.Parallel()
			v, b, m := captureFixture(t)
			request := Request{b, m, v.proof.Challenge}
			digest, _ := RequestDigest(request)
			left, right := net.Pipe()
			defer left.Close()
			authority := &fixtureAuthority{}
			journal := &transferJournal{}
			done := make(chan error, 1)
			go func() { _, err := ServeCaptureChannel(t.Context(), right, request, authority, journal); done <- err }()
			f := captureFrame{Version: 1, Sequence: 1, BindingDigest: digest, Operation: "observe", Proof: &v.proof}
			switch mode {
			case "version":
				f.Version = 2
			case "sequence":
				f.Sequence = 2
			case "scope":
				f.BindingDigest = strings.Repeat("f", 64)
			case "operation":
				f.Operation = "read"
			case "multiple payloads":
				f.Intent = &objectcustody.Intent{}
			}
			var wire bytes.Buffer
			switch mode {
			case "oversized":
				var header [4]byte
				binary.BigEndian.PutUint32(header[:], MaxControlFrameBytes+1)
				wire.Write(header[:])
			case "truncated":
				wire.Write([]byte{0, 0})
			default:
				controlWrite(&wire, f)
				if mode == "unknown field" || mode == "duplicate field" {
					raw := wire.Bytes()[4:]
					extra := `,"actorId":"owner"}`
					if mode == "duplicate field" {
						extra = `,"version":1}`
					}
					raw = append(append([]byte{}, raw[:len(raw)-1]...), []byte(extra)...)
					wire.Reset()
					var header [4]byte
					binary.BigEndian.PutUint32(header[:], uint32(len(raw)))
					wire.Write(header[:])
					wire.Write(raw)
				}
			}
			left.Write(wire.Bytes())
			if mode == "truncated" {
				left.Close()
			}
			if <-done == nil || authority.calls != 0 || len(journal.intents) != 0 {
				t.Fatal("invalid frame invoked authority")
			}
		})
	}
}
func TestCaptureChannelCancellationAndWrongAcknowledgment(t *testing.T) {
	t.Parallel()
	for _, mode := range []string{"cancel", "sequence", "version"} {
		t.Run(mode, func(t *testing.T) {
			t.Parallel()
			v, b, m := captureFixture(t)
			left, right := net.Pipe()
			defer right.Close()
			var stopped atomic.Int32
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			client, err := NewCaptureChannel(ctx, left, Request{b, m, v.proof.Challenge}, func() { stopped.Add(1) })
			if err != nil {
				t.Fatal(err)
			}
			defer client.Close()
			read := make(chan struct{})
			go func() {
				var f captureFrame
				controlRead(right, &f)
				close(read)
				if mode != "cancel" {
					ack := captureAck{1, 1, true}
					if mode == "sequence" {
						ack.Sequence = 2
					} else {
						ack.Version = 2
					}
					controlWrite(right, ack)
				}
			}()
			done := make(chan error, 1)
			go func() { done <- client.AuthorizeFrozenSource(ctx, b, v.proof) }()
			<-read
			if mode == "cancel" {
				cancel()
			}
			select {
			case err := <-done:
				if err == nil {
					t.Fatal("wrong ack accepted")
				}
			case <-time.After(time.Second):
				t.Fatal("cancellation did not unblock")
			}
			if stopped.Load() != 1 || client.AuthorizeFrozenSource(t.Context(), b, v.proof) == nil {
				t.Fatal("poisoned stream reused")
			}
		})
	}
}

func TestCaptureChannelRejectsInvalidLifecycleTransitions(t *testing.T) {
	t.Parallel()
	for _, mode := range []string{"reserve before observation", "replayed sequence", "changed mount", "duplicate member", "duplicate object", "changed revision", "seal without reservation", "changed seal", "duplicate seal", "partial finish", "changed finish"} {
		t.Run(mode, func(t *testing.T) {
			t.Parallel()
			v, b, m := captureFixture(t)
			m = append(m, workspacesnapshot.Member{OutputName: "second", Name: "z.txt", MaxBytes: 128})
			request := Request{b, m, v.proof.Challenge}
			digest, _ := RequestDigest(request)
			scope := b.Execution
			scope.RevisionDigest = strings.Repeat("c", 64)
			first := objectcustody.Intent{ObjectID: strings.Repeat("1", 32), Scope: objectcustody.Scope{ExecutionScope: scope, OutputName: m[0].OutputName, MemberName: m[0].Name}, MaxBytes: 128}
			second := objectcustody.Intent{ObjectID: strings.Repeat("2", 32), Scope: objectcustody.Scope{ExecutionScope: scope, OutputName: m[1].OutputName, MemberName: m[1].Name}, MaxBytes: 128}
			r1 := objectcustody.Receipt{Intent: first, Bytes: 1, Digest: strings.Repeat("a", 64)}
			r2 := objectcustody.Receipt{Intent: second, Bytes: 1, Digest: strings.Repeat("b", 64)}
			left, right := net.Pipe()
			defer left.Close()
			journal := &transferJournal{}
			authority := &fixtureAuthority{}
			done := make(chan error, 1)
			go func() { _, err := ServeCaptureChannel(t.Context(), right, request, authority, journal); done <- err }()
			sequence := uint64(0)
			accept := func(f captureFrame) {
				t.Helper()
				sequence++
				f.Version = 1
				f.Sequence = sequence
				f.BindingDigest = digest
				if controlWrite(left, f) != nil {
					t.Fatal("accepted frame write")
				}
				var ack captureAck
				if controlRead(left, &ack) != nil || !ack.Accepted {
					t.Fatal("setup frame rejected", f.Operation)
				}
			}
			bad := captureFrame{Operation: "reserve", Intent: &first}
			if mode != "reserve before observation" {
				accept(captureFrame{Operation: "observe", Proof: &v.proof})
			}
			switch mode {
			case "replayed sequence":
				bad = captureFrame{Operation: "observe", Proof: &v.proof}
			case "changed mount":
				p := v.proof
				p.MountID++
				bad = captureFrame{Operation: "observe", Proof: &p}
			case "seal without reservation":
				bad = captureFrame{Operation: "seal", Receipt: &r1}
			case "duplicate member":
				accept(captureFrame{Operation: "reserve", Intent: &first})
				second.Scope = first.Scope
				bad = captureFrame{Operation: "reserve", Intent: &second}
			case "duplicate object":
				accept(captureFrame{Operation: "reserve", Intent: &first})
				second.ObjectID = first.ObjectID
				bad = captureFrame{Operation: "reserve", Intent: &second}
			case "changed revision":
				accept(captureFrame{Operation: "reserve", Intent: &first})
				second.Scope.RevisionDigest = strings.Repeat("f", 64)
				bad = captureFrame{Operation: "reserve", Intent: &second}
			case "changed seal":
				accept(captureFrame{Operation: "reserve", Intent: &first})
				r1.Intent.MaxBytes++
				bad = captureFrame{Operation: "seal", Receipt: &r1}
			case "duplicate seal":
				accept(captureFrame{Operation: "reserve", Intent: &first})
				accept(captureFrame{Operation: "seal", Receipt: &r1})
				bad = captureFrame{Operation: "seal", Receipt: &r1}
			case "partial finish":
				accept(captureFrame{Operation: "reserve", Intent: &first})
				accept(captureFrame{Operation: "seal", Receipt: &r1})
				report := Report{1, scope, strings.Repeat("e", 64), []objectcustody.Receipt{r1}}
				bad = captureFrame{Operation: "finish", Report: &report}
			case "changed finish":
				accept(captureFrame{Operation: "reserve", Intent: &first})
				accept(captureFrame{Operation: "seal", Receipt: &r1})
				accept(captureFrame{Operation: "reserve", Intent: &second})
				accept(captureFrame{Operation: "seal", Receipt: &r2})
				r2.Digest = strings.Repeat("f", 64)
				report := Report{1, scope, strings.Repeat("e", 64), []objectcustody.Receipt{r1, r2}}
				bad = captureFrame{Operation: "finish", Report: &report}
			}
			sequence++
			bad.Version = 1
			bad.Sequence = sequence
			bad.BindingDigest = digest
			if mode == "replayed sequence" {
				bad.Sequence = 1
			}
			controlWrite(left, bad)
			if <-done == nil {
				t.Fatal("invalid lifecycle accepted", mode)
			}
		})
	}
}
func TestCaptureChannelBoundsObservationMessages(t *testing.T) {
	t.Parallel()
	v, b, m := captureFixture(t)
	request := Request{b, m, v.proof.Challenge}
	left, right := net.Pipe()
	defer left.Close()
	authority := &fixtureAuthority{}
	journal := &transferJournal{}
	done := make(chan error, 1)
	go func() { _, err := ServeCaptureChannel(t.Context(), right, request, authority, journal); done <- err }()
	digest, _ := RequestDigest(request)
	for n := uint64(1); n <= MaxControlMessages; n++ {
		if controlWrite(left, captureFrame{Version: 1, Sequence: n, BindingDigest: digest, Operation: "observe", Proof: &v.proof}) != nil {
			t.Fatal("bounded observation failed", n)
		}
		var ack captureAck
		if controlRead(left, &ack) != nil || !ack.Accepted {
			t.Fatal("observation ack", n)
		}
	}
	if <-done == nil || authority.calls != MaxControlMessages || len(journal.intents) != 0 {
		t.Fatal("unbounded control stream", authority.calls)
	}
}

type supervisedCaptureTestStream struct {
	net.Conn
	entered chan struct{}
	reading atomic.Bool
	closed  atomic.Bool
}

func (s *supervisedCaptureTestStream) Read(raw []byte) (int, error) {
	if !s.reading.Swap(true) {
		close(s.entered)
	}
	return s.Conn.Read(raw)
}
func (s *supervisedCaptureTestStream) Close() error { s.closed.Store(true); return s.Conn.Close() }
func TestSupervisedCaptureChannelStillClosesOnFailure(t *testing.T) {
	t.Parallel()
	for _, mode := range []string{"canceled", "malformed"} {
		t.Run(mode, func(t *testing.T) {
			t.Parallel()
			view, binding, members := captureFixture(t)
			request := Request{binding, members, view.proof.Challenge}
			left, right := net.Pipe()
			defer left.Close()
			stream := &supervisedCaptureTestStream{Conn: right, entered: make(chan struct{})}
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			journal := &transferJournal{}
			done := make(chan channelResult, 1)
			go func() {
				report, err := ServeSupervisedCaptureChannel(ctx, stream, request, &fixtureAuthority{}, journal)
				done <- channelResult{report, err}
			}()
			<-stream.entered
			if mode == "canceled" {
				cancel()
			} else {
				digest, _ := RequestDigest(request)
				_ = controlWrite(left, captureFrame{Version: 1, Sequence: 2, BindingDigest: digest, Operation: "observe", Proof: &view.proof})
			}
			select {
			case result := <-done:
				if result.err == nil || result.report.Version != 0 || !stream.closed.Load() || journal.charged != 0 {
					t.Fatal("failed supervised stream left active", result.err)
				}
			case <-time.After(time.Second):
				t.Fatal("failed supervised stream did not unblock")
			}
		})
	}
}
