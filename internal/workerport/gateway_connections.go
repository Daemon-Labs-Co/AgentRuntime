package workerport

import (
	"net"
	"sync"
)

// maximumGatewayConnections also bounds connections stalled before CONNECT
// parsing/DNS. Tunnel slots alone cannot protect the worker from idle clients.
// This required safety limit has no off switch or host-execution fallback.
const maximumGatewayConnections = 16

// gatewayListener caps accepted connections before net/http allocates per-client
// handler state. Excess clients are closed immediately, without parsing secrets
// or performing DNS. A source fork CAN remove it, BUT exposes worker resources to
// untrusted pre-header clients. It does not prevent volumetric socket/CPU attacks.
type gatewayListener struct {
	net.Listener
	slots chan struct{}
}

func (l *gatewayListener) Accept() (net.Conn, error) {
	for {
		conn, err := l.Listener.Accept()
		if err != nil {
			return nil, err
		}
		select {
		case l.slots <- struct{}{}:
			return &gatewayClient{Conn: conn, release: func() { <-l.slots }}, nil
		default:
			conn.Close()
		}
	}
}

// gatewayClient releases admission once even when HTTP shutdown and tunnel
// cleanup both close the same connection. Keep the slot for the whole tunnel.
type gatewayClient struct {
	net.Conn
	once     sync.Once
	release  func()
	closeErr error
}

func (c *gatewayClient) Close() error {
	c.once.Do(func() { c.closeErr = c.Conn.Close(); c.release() })
	return c.closeErr
}
