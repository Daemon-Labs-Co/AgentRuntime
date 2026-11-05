package workerport

import (
	"context"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

type syntheticGatewayListener struct {
	incoming chan net.Conn
	done     chan struct{}
	once     sync.Once
}

func (l *syntheticGatewayListener) Accept() (net.Conn, error) {
	select {
	case c := <-l.incoming:
		return c, nil
	case <-l.done:
		return nil, net.ErrClosed
	}
}

func (l *syntheticGatewayListener) Close() error { l.once.Do(func() { close(l.done) }); return nil }

func (l *syntheticGatewayListener) Addr() net.Addr {
	return &net.UnixAddr{Name: "synthetic", Net: "unix"}
}

func TestGatewayListenerBoundsAndReleasesConnections(t *testing.T) {
	t.Parallel()
	base := &syntheticGatewayListener{incoming: make(chan net.Conn, 4), done: make(chan struct{})}
	defer base.Close()
	l := &gatewayListener{Listener: base, slots: make(chan struct{}, 2)}
	first, firstPeer := net.Pipe()
	defer firstPeer.Close()
	base.incoming <- first
	a, err := l.Accept()
	if err != nil {
		t.Fatal(err)
	}
	defer a.Close()
	second, secondPeer := net.Pipe()
	defer secondPeer.Close()
	base.incoming <- second
	b, err := l.Accept()
	if err != nil {
		t.Fatal(err)
	}
	defer b.Close()
	rejected, peer := net.Pipe()
	defer peer.Close()
	base.incoming <- rejected
	result := make(chan net.Conn, 1)
	errs := make(chan error, 1)
	go func() {
		c, err := l.Accept()
		if err != nil {
			errs <- err
		} else {
			result <- c
		}
	}()
	peer.SetReadDeadline(time.Now().Add(time.Second))
	var probe [1]byte
	if _, err := peer.Read(probe[:]); err != io.EOF {
		t.Fatalf("excess client was not closed: %v", err)
	}
	a.Close()
	a.Close() // double cleanup must not consume another active slot
	if len(l.slots) != 1 {
		t.Fatal("double close corrupted connection admission")
	}
	next, nextPeer := net.Pipe()
	defer nextPeer.Close()
	base.incoming <- next
	select {
	case c := <-result:
		c.Close()
	case err := <-errs:
		t.Fatal(err)
	case <-time.After(time.Second):
		t.Fatal("released slot did not admit client")
	}
	b.Close()
	if len(l.slots) != 0 {
		t.Fatal("connection slots leaked")
	}
	base.Close()
	if _, err := l.Accept(); !errors.Is(err, net.ErrClosed) {
		t.Fatal("listener shutdown not propagated")
	}
}

func TestGatewayClientConcurrentClose(t *testing.T) {
	t.Parallel()
	conn, peer := net.Pipe()
	defer peer.Close()
	slots := make(chan struct{}, 1)
	slots <- struct{}{}
	c := &gatewayClient{Conn: conn, release: func() { <-slots }}
	var wg sync.WaitGroup
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func() { defer wg.Done(); c.Close() }()
	}
	wg.Wait()
	if len(slots) != 0 {
		t.Fatal("close did not release admission")
	}
}

func TestGatewayCapsClientsBeforeHeaders(t *testing.T) {
	t.Parallel()
	dir, err := os.MkdirTemp("/tmp", "gateway-cap-")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(dir)
	g, err := newProviderGateway(context.Background(), filepath.Join(dir, "gateway.sock"), "codex")
	if err != nil {
		t.Fatal(err)
	}
	defer g.Close()
	listener, ok := g.listener.(*gatewayListener)
	if !ok {
		t.Fatal("gateway does not use bounded listener")
	}
	var clients []net.Conn
	defer func() {
		for _, c := range clients {
			c.Close()
		}
	}()
	for i := 0; i < maximumGatewayConnections; i++ {
		c, err := net.DialTimeout("unix", g.socket, time.Second)
		if err != nil {
			t.Fatal(err)
		}
		clients = append(clients, c)
	}
	waitGatewaySlots(t, listener, maximumGatewayConnections)
	excess, err := net.DialTimeout("unix", g.socket, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer excess.Close()
	excess.SetReadDeadline(time.Now().Add(time.Second))
	var probe [1]byte
	if _, err = excess.Read(probe[:]); err != io.EOF {
		t.Fatalf("pre-header client not refused: %v", err)
	}
	clients[0].Close()
	waitGatewaySlots(t, listener, maximumGatewayConnections-1)
	g.Close()
	waitGatewaySlots(t, listener, 0)
}

func waitGatewaySlots(t *testing.T, l *gatewayListener, want int) {
	t.Helper()
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		if len(l.slots) == want {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatalf("active gateway connections %d, want %d", len(l.slots), want)
}
