package workerport

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestGatewayCloseCancelsPendingResolution(t *testing.T) {
	t.Parallel()
	// macOS Unix-socket paths are shorter than its default test temp root.
	dir, err := os.MkdirTemp("/tmp", "gateway-test-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	g, err := newProviderGateway(context.Background(), filepath.Join(dir, "gateway.sock"), "codex")
	if err != nil {
		t.Fatal(err)
	}
	defer g.Close()
	started := make(chan struct{})
	g.lookupIP = func(ctx context.Context, network, host string) ([]net.IP, error) {
		if network != "ip" || host != "api.openai.com" {
			t.Error("wrong lookup target")
		}
		close(started)
		<-ctx.Done()
		return nil, ctx.Err()
	}
	done := make(chan int, 1)
	go func() {
		r := httptest.NewRequest("CONNECT", "http://example", nil)
		r.Host = "api.openai.com:443"
		w := httptest.NewRecorder()
		g.connect(w, r, "codex")
		done <- w.Code
	}()
	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("lookup never started")
	}
	g.Close()
	select {
	case status := <-done:
		if status != http.StatusBadGateway {
			t.Fatal("cancelled lookup accepted", status)
		}
	case <-time.After(time.Second):
		t.Fatal("shutdown did not cancel pending resolution")
	}
	if g.ctx.Err() == nil {
		t.Fatal("gateway context remains active")
	}
	r := httptest.NewRequest("CONNECT", "http://example", nil)
	r.Host = "api.openai.com:443"
	w := httptest.NewRecorder()
	g.connect(w, r, "codex")
	if w.Code != http.StatusServiceUnavailable {
		t.Fatal("new work admitted after close", w.Code)
	}
}
