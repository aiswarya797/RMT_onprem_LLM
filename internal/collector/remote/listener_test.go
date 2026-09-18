package remote

import (
	"errors"
	"io"
	"net"
	"sync"
	"testing"
	"time"
)

func TestBoundedListenerRejectsBeforeHandshakeAndReleasesOnClose(t *testing.T) {
	base := newQueuedListener()
	listener, err := NewBoundedListener(base, 1)
	if err != nil {
		t.Fatal(err)
	}
	firstClient, firstServer := net.Pipe()
	defer firstClient.Close()
	base.connections <- firstServer
	first, err := listener.Accept()
	if err != nil {
		t.Fatal(err)
	}

	accepted := make(chan net.Conn, 1)
	acceptErr := make(chan error, 1)
	go func() {
		connection, err := listener.Accept()
		if err != nil {
			acceptErr <- err
			return
		}
		accepted <- connection
	}()
	secondClient, secondServer := net.Pipe()
	base.connections <- secondServer
	if err := secondClient.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	buffer := make([]byte, 1)
	if _, err := secondClient.Read(buffer); !errors.Is(err, io.EOF) {
		t.Fatalf("excess pre-TLS connection was not closed promptly: %v", err)
	}
	_ = secondClient.Close()

	if err := first.Close(); err != nil {
		t.Fatal(err)
	}
	thirdClient, thirdServer := net.Pipe()
	defer thirdClient.Close()
	base.connections <- thirdServer
	select {
	case third := <-accepted:
		_ = third.Close()
	case err := <-acceptErr:
		t.Fatalf("accept after release: %v", err)
	case <-time.After(time.Second):
		t.Fatal("released connection slot was not reusable")
	}
	if err := listener.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := listener.Accept(); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("accept after shutdown=%v", err)
	}
}

type queuedListener struct {
	connections chan net.Conn
	closed      chan struct{}
	once        sync.Once
}

func newQueuedListener() *queuedListener {
	return &queuedListener{connections: make(chan net.Conn, MaxTLSConnections), closed: make(chan struct{})}
}

func (l *queuedListener) Accept() (net.Conn, error) {
	select {
	case connection := <-l.connections:
		return connection, nil
	case <-l.closed:
		return nil, net.ErrClosed
	}
}

func (l *queuedListener) Close() error {
	l.once.Do(func() { close(l.closed) })
	return nil
}

func (l *queuedListener) Addr() net.Addr { return queuedAddress("bounded-listener-test") }

type queuedAddress string

func (a queuedAddress) Network() string { return "pipe" }
func (a queuedAddress) String() string  { return string(a) }
