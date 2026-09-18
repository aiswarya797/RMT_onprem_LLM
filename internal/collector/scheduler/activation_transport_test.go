package scheduler

import (
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"rmt.local/monitor/internal/protocol"
)

type activationRoundTripFunc func(*http.Request) (*http.Response, error)

func (f activationRoundTripFunc) RoundTrip(request *http.Request) (*http.Response, error) {
	return f(request)
}

func TestLocalAndRemoteTransportsAcceptRestoredSessionHighWater(t *testing.T) {
	request := protocol.SessionActivation{
		Protocol:                   "1.0",
		DeploymentID:               "10000000-0000-4000-8000-000000000001",
		HostID:                     "10000000-0000-4000-8000-000000000002",
		SecurityGeneration:         "10000000-0000-4000-8000-000000000003",
		ActivationRequestID:        "10000000-0000-4000-8000-000000000004",
		CollectorBootID:            "10000000-0000-4000-8000-000000000005",
		ExpectedPreviousGeneration: 0,
	}
	response := protocol.NewSessionResult(request, 2, 10)
	roundTrip := activationRoundTripFunc(func(*http.Request) (*http.Response, error) {
		body, err := json.Marshal(response)
		if err != nil {
			return nil, err
		}
		return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader(string(body))), Header: make(http.Header)}, nil
	})

	socketRoot, err := filepath.Abs(filepath.Join("..", "..", "..", ".work", "u02-tests"))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(socketRoot, 0o700); err != nil {
		t.Fatal(err)
	}
	socketDir, err := os.MkdirTemp(socketRoot, "sock-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(socketDir) })
	socket := filepath.Join(socketDir, "hub.sock")
	listener, err := net.Listen("unix", socket)
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	if err := os.Chmod(socket, 0o600); err != nil {
		t.Fatal(err)
	}
	remoteURL, _ := url.Parse("https://127.0.0.1:9444")
	transports := map[string]func() (protocol.SessionResult, error){
		"local": func() (protocol.SessionResult, error) {
			return (&LocalTransport{socket: socket, client: &http.Client{Transport: roundTrip}}).Activate(context.Background(), request)
		},
		"remote": func() (protocol.SessionResult, error) {
			return (&RemoteTransport{client: &http.Client{Transport: roundTrip}, baseURL: remoteURL}).Activate(context.Background(), request)
		},
	}
	for name, activate := range transports {
		t.Run(name+"_accepts_retained_high_water", func(t *testing.T) {
			result, err := activate()
			if err != nil || result.SessionGeneration != 2 {
				t.Fatalf("activation=%#v err=%v", result, err)
			}
		})
	}

	response.SessionGeneration = 0
	for name, activate := range transports {
		t.Run(name+"_rejects_non_advancing_result", func(t *testing.T) {
			if _, err := activate(); err == nil {
				t.Fatal("non-advancing activation acknowledgement accepted")
			}
		})
	}
}
