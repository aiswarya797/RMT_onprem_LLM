package lifecycle

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"syscall"
	"time"

	"rmt.local/monitor/internal/config"
	"rmt.local/monitor/internal/protocol"
)

func ValidateOwnerSocketPath(path string) error {
	if len([]byte(path)) >= 104 {
		return fmt.Errorf("owner socket path is too long for macOS (%d bytes, maximum 103): %s", len([]byte(path)), path)
	}
	return config.RejectSymlinkTree(filepath.Dir(path))
}

func ServeOwnerSocket(ctx context.Context, path string, status func(context.Context) (any, error)) error {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /v1/status", func(w http.ResponseWriter, r *http.Request) {
		value, statusErr := status(r.Context())
		if statusErr != nil {
			http.Error(w, "status unavailable", http.StatusServiceUnavailable)
			return
		}
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		w.Header().Set("Cache-Control", "no-store")
		_ = protocol.WriteJSON(w, value)
	})
	return ServeOwnerSocketHandler(ctx, path, mux)
}

type ownerPeerKey struct{}

// OwnerPeer is set only from the Unix connection's kernel credentials.
func OwnerPeer(ctx context.Context) bool { value, _ := ctx.Value(ownerPeerKey{}).(bool); return value }

func ServeOwnerSocketHandler(ctx context.Context, path string, handler http.Handler) error {
	if err := ValidateOwnerSocketPath(path); err != nil {
		return err
	}
	if err := config.EnsurePrivateDir(filepath.Dir(path)); err != nil {
		return err
	}
	if info, err := os.Lstat(path); err == nil {
		if info.Mode()&os.ModeSocket == 0 {
			return fmt.Errorf("owner socket path is occupied by a non-socket: %s", path)
		}
		conn, dialErr := net.DialTimeout("unix", path, 100*time.Millisecond)
		if dialErr == nil {
			conn.Close()
			return fmt.Errorf("owner socket is already active: %s", path)
		}
		if err := os.Remove(path); err != nil {
			return err
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	listener, err := net.Listen("unix", path)
	if err != nil {
		return fmt.Errorf("listen owner socket: %w", err)
	}
	defer listener.Close()
	defer os.Remove(path)
	if err := os.Chmod(path, 0o600); err != nil {
		return err
	}
	guard := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !OwnerPeer(r.Context()) {
			http.Error(w, "installing-user peer required", http.StatusForbidden)
			return
		}
		w.Header().Set("Cache-Control", "no-store")
		handler.ServeHTTP(w, r)
	})
	server := &http.Server{Handler: guard, ConnContext: func(ctx context.Context, conn net.Conn) context.Context {
		return context.WithValue(ctx, ownerPeerKey{}, sameUserPeer(conn))
	}, ReadHeaderTimeout: 2 * time.Second, ReadTimeout: 5 * time.Second, WriteTimeout: 5 * time.Second, IdleTimeout: 15 * time.Second, MaxHeaderBytes: 16 << 10}
	done := make(chan error, 1)
	go func() { done <- server.Serve(listener) }()
	select {
	case <-ctx.Done():
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		_ = server.Shutdown(shutdownCtx)
		err := <-done
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return err
	case err := <-done:
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return err
	}
}

func ReadOwnerStatus(ctx context.Context, path string) ([]byte, error) {
	if err := ValidateOwnerSocketPath(path); err != nil {
		return nil, err
	}
	dialer := net.Dialer{Timeout: 300 * time.Millisecond}
	transport := &http.Transport{DialContext: func(dialCtx context.Context, _, _ string) (net.Conn, error) {
		return dialer.DialContext(dialCtx, "unix", path)
	}}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: time.Second}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://owner/v1/status", nil)
	if err != nil {
		return nil, err
	}
	response, err := client.Do(request)
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("owner status returned %d", response.StatusCode)
	}
	return io.ReadAll(io.LimitReader(response.Body, 64*1024))
}

// ProbeOwnerSocket reports whether a process currently owns the socket. It
// only treats a missing inode or an explicit connection refusal as inactive;
// timeouts, permission failures, and other unknown states remain blocking.
func ProbeOwnerSocket(ctx context.Context, path string) (bool, error) {
	if err := ValidateOwnerSocketPath(path); err != nil {
		return false, err
	}
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	if info.Mode()&os.ModeSocket == 0 {
		return false, fmt.Errorf("owner socket path is occupied by a non-socket: %s", path)
	}
	dialCtx, cancel := context.WithTimeout(ctx, 300*time.Millisecond)
	defer cancel()
	conn, err := (&net.Dialer{}).DialContext(dialCtx, "unix", path)
	if err == nil {
		_ = conn.Close()
		return true, nil
	}
	if errors.Is(err, syscall.ECONNREFUSED) || errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	return false, fmt.Errorf("owner socket liveness is unknown: %w", err)
}
