package remote

import (
	"errors"
	"net"
	"sync"
)

// MaxTLSConnections bounds handshake and accepted-connection work before an
// HTTP server can apply request deadlines. Two enrolled collectors plus one
// enrollment exchange and one short overlap during rotation fit this cap.
const MaxTLSConnections = 4

type boundedListener struct {
	net.Listener
	slots chan struct{}
}

type boundedConnection struct {
	net.Conn
	release func()
	once    sync.Once
}

// NewBoundedListener gates raw accepted sockets before TLS allocates handshake
// state. Excess connections are closed promptly and never reach ServeTLS.
func NewBoundedListener(listener net.Listener, maximum int) (net.Listener, error) {
	if listener == nil || maximum < 1 || maximum > MaxTLSConnections {
		return nil, errors.New("invalid remote TLS connection bound")
	}
	return &boundedListener{Listener: listener, slots: make(chan struct{}, maximum)}, nil
}

func (l *boundedListener) Accept() (net.Conn, error) {
	for {
		connection, err := l.Listener.Accept()
		if err != nil {
			return nil, err
		}
		select {
		case l.slots <- struct{}{}:
			return &boundedConnection{Conn: connection, release: func() { <-l.slots }}, nil
		default:
			_ = connection.Close()
		}
	}
}

func (c *boundedConnection) Close() error {
	err := c.Conn.Close()
	c.once.Do(c.release)
	return err
}
