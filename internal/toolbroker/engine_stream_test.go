package toolbroker

import (
	"context"
	"errors"
	"io"
	"net"
	"strings"
	"testing"
	"time"
)

type streamEngineFake struct {
	*engineDockerFake
	opens     int
	stream    io.ReadWriteCloser
	openError error
	onOpen    func()
}

func (f *streamEngineFake) OpenEngine(ctx context.Context, id string) (io.ReadWriteCloser, error) {
	f.opens++
	if id != f.runtime.id || ctx.Err() != nil {
		return nil, ErrRejected
	}
	if f.onOpen != nil {
		f.onOpen()
	}
	return f.stream, f.openError
}
func streamFixture(t *testing.T) (*EngineContainerRuntime, *streamEngineFake, net.Conn) {
	t.Helper()
	r, docker := engineFixture(t)
	client, peer := net.Pipe()
	t.Cleanup(func() { client.Close(); peer.Close() })
	f := &streamEngineFake{engineDockerFake: docker, stream: client}
	r.runner = f
	id, err := r.Create(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if err = r.Start(t.Context(), id); err != nil {
		t.Fatal(err)
	}
	return r, f, peer
}
func TestEngineStreamOneShotDuplexAndCancellation(t *testing.T) {
	t.Parallel()
	r, f, peer := streamFixture(t)
	stream, err := r.Attach(t.Context(), r.id)
	if err != nil {
		t.Fatal(err)
	}
	defer stream.Close()
	transferred := make(chan error, 1)
	go func() { _, err := peer.Write([]byte("synthetic-frame")); transferred <- err }()
	got := make([]byte, len("synthetic-frame"))
	if _, err = io.ReadFull(stream, got); err != nil || string(got) != "synthetic-frame" {
		t.Fatalf("read: %q %v", got, err)
	}
	if err = <-transferred; err != nil {
		t.Fatal(err)
	}
	go func() {
		b := make([]byte, 4)
		_, err := io.ReadFull(peer, b)
		if err == nil && string(b) != "ping" {
			err = errors.New("wrong request")
		}
		transferred <- err
	}()
	if _, err = stream.Write([]byte("ping")); err != nil {
		t.Fatal(err)
	}
	if err = <-transferred; err != nil {
		t.Fatal(err)
	}
	if _, err = r.Attach(t.Context(), r.id); err == nil || f.opens != 1 {
		t.Fatal("stream reattached")
	}
	readDone := make(chan error, 1)
	go func() { _, err := stream.Read(make([]byte, 1)); readDone <- err }()
	r.Close()
	select {
	case err = <-readDone:
		if err == nil {
			t.Fatal("cancelled read succeeded")
		}
	case <-time.After(time.Second):
		t.Fatal("cancelled read stuck")
	}
	if _, err = stream.Write([]byte("late")); err == nil {
		t.Fatal("write after close")
	}
	if stream.Close() != nil || stream.Close() != nil {
		t.Fatal("close not idempotent")
	}
}
func TestEngineStreamRefusesPolicyDriftAndUncertainRetry(t *testing.T) {
	t.Parallel()
	for _, mode := range []string{"before", "after", "open failure", "foreign"} {
		t.Run(mode, func(t *testing.T) {
			r, f, _ := streamFixture(t)
			drift := func(raw map[string]any) { raw["Name"] = "/foreign" }
			id := r.id
			switch mode {
			case "before":
				f.mutation = drift
			case "after":
				f.onOpen = func() { f.mutation = drift }
			case "open failure":
				f.openError = errors.New("synthetic private path")
			case "foreign":
				id = strings.Repeat("f", 64)
			}
			if stream, err := r.Attach(t.Context(), id); err == nil {
				stream.Close()
				t.Fatal("unsafe attachment accepted")
			}
			if mode == "foreign" {
				if f.opens != 0 {
					t.Fatal("foreign container opened")
				}
				return
			}
			f.mutation = nil
			f.openError = nil
			f.onOpen = nil
			before := f.opens
			if _, err := r.Attach(t.Context(), r.id); err == nil || f.opens != before {
				t.Fatal("uncertain attempt retried")
			}
		})
	}
}
