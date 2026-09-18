package scheduler

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strconv"
	"time"

	"rmt.local/monitor/internal/config"
	"rmt.local/monitor/internal/domain"
	"rmt.local/monitor/internal/protocol"
)

const (
	transportTimeout = 5 * time.Second
	maxACKBytes      = 64 << 10
)

var ErrTransportClosed = errors.New("collector transport closed")

type AdmissionError struct {
	StatusCode int
	RetryAfter time.Duration
}

func (e *AdmissionError) Error() string {
	return fmt.Sprintf("collector admission returned HTTP %d", e.StatusCode)
}
func (e *AdmissionError) Retryable() bool {
	return e.StatusCode == http.StatusTooManyRequests || e.StatusCode == http.StatusServiceUnavailable || e.StatusCode >= 500
}
func (e *AdmissionError) Poison() bool {
	return e.StatusCode == http.StatusUnprocessableEntity
}
func (e *AdmissionError) Fenced() bool {
	return e.StatusCode == http.StatusUnauthorized || e.StatusCode == http.StatusForbidden || e.StatusCode == http.StatusConflict
}

type LocalTransport struct {
	socket string
	client *http.Client
}

func NewLocalTransport(socket string) (*LocalTransport, error) {
	if socket == "" || len([]byte(socket)) >= 104 {
		return nil, errors.New("invalid local hub socket path")
	}
	if err := config.RejectSymlinkTree(socket); err != nil {
		return nil, err
	}
	dialer := &net.Dialer{Timeout: 500 * time.Millisecond}
	transport := &http.Transport{
		Proxy: nil,
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return dialer.DialContext(ctx, "unix", socket)
		},
		DisableCompression:  true,
		MaxConnsPerHost:     1,
		MaxIdleConnsPerHost: 1,
	}
	return &LocalTransport{socket: socket, client: &http.Client{
		Transport: transport,
		Timeout:   transportTimeout,
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
			return errors.New("collector transport redirects are disabled")
		},
	}}, nil
}

func (t *LocalTransport) Close() {
	if t.client == nil {
		return
	}
	if transport, ok := t.client.Transport.(*http.Transport); ok {
		transport.CloseIdleConnections()
	}
	t.client = nil
}

type localPairRequest struct {
	HostID         string `json:"host_id"`
	InstallationID string `json:"installation_id"`
}
type localPairResult struct {
	Durable bool   `json:"durable"`
	HostID  string `json:"host_id"`
}
type hubTimeResult struct {
	HubTimeMS int64 `json:"hub_time_ms"`
}
type hubProcessIdentity struct {
	PID   int                  `json:"pid"`
	Start domain.Uint64Decimal `json:"process_start_identity"`
}
type hubStatusResult struct {
	SchemaVersion     string                 `json:"schema_version"`
	Service           string                 `json:"service"`
	State             string                 `json:"state"`
	DeploymentState   domain.DeploymentState `json:"deployment_state"`
	HostCount         int                    `json:"host_count"`
	TargetCount       int                    `json:"target_count"`
	CollectionStarted bool                   `json:"collection_started"`
	InferenceStarted  bool                   `json:"inference_started"`
	ProcessIdentity   *hubProcessIdentity    `json:"process_identity"`
}

func (t *LocalTransport) Pair(ctx context.Context, hostID, installationID string) error {
	request := localPairRequest{HostID: hostID, InstallationID: installationID}
	var result localPairResult
	if err := t.post(ctx, "/collector/v1/local-pair", request, 4096, &result); err != nil {
		return err
	}
	if !result.Durable || result.HostID != hostID {
		return errors.New("local pair acknowledgement conflicts with request")
	}
	return nil
}

func (t *LocalTransport) Activate(ctx context.Context, request protocol.SessionActivation) (protocol.SessionResult, error) {
	var result protocol.SessionResult
	err := t.post(ctx, "/collector/v1/sessions", request, protocol.MaxInventoryBytes, &result)
	if err == nil {
		err = validateActivationAcknowledgement(request, result)
	}
	return result, err
}

func validateActivationAcknowledgement(request protocol.SessionActivation, result protocol.SessionResult) error {
	if result.ActivationRequestID != request.ActivationRequestID || result.SecurityGeneration != request.SecurityGeneration || result.CollectorBootID != request.CollectorBootID || !result.Current || result.SessionGeneration <= request.ExpectedPreviousGeneration || result.SessionGeneration > protocol.MaxUint53 || result.ActivatedMS < 0 {
		return errors.New("session acknowledgement conflicts with activation")
	}
	return nil
}

func (t *LocalTransport) Inventory(ctx context.Context, request protocol.CollectorInventory) (protocol.InventoryResult, error) {
	var result protocol.InventoryResult
	err := t.post(ctx, "/collector/v1/inventory", request, protocol.MaxInventoryBytes, &result)
	if err == nil && (!result.Durable || !result.Current || result.InventoryRevision != request.InventoryRevision) {
		err = errors.New("inventory acknowledgement conflicts with request")
	}
	return result, err
}

func (t *LocalTransport) Batch(ctx context.Context, request protocol.CollectorBatch) (protocol.BatchACK, error) {
	var result protocol.BatchACK
	err := t.post(ctx, "/collector/v1/batches", request, protocol.MaxBatchBytes, &result)
	if err == nil && (!result.Durable || result.BatchID != request.BatchID || result.Accepted < 0 || result.Duplicate < 0 || result.Accepted+result.Duplicate != len(request.Frames)) {
		err = errors.New("batch acknowledgement conflicts with request")
	}
	return result, err
}

// RecoveryReplay is deliberately outside the steady-state collectorTransport
// interface. Only the stopped-collector owner recovery CLI can call it.
func (t *LocalTransport) RecoveryReplay(ctx context.Context, request protocol.RecoveryReplay) (protocol.RecoveryACK, error) {
	var result protocol.RecoveryACK
	err := t.post(ctx, "/collector/v1/recovery-replay", request, protocol.MaxBatchBytes, &result)
	if err == nil {
		err = result.Validate(request)
	}
	return result, err
}

func (t *LocalTransport) SourceStatus(ctx context.Context, request protocol.SourceStatus) (protocol.StatusACK, error) {
	var result protocol.StatusACK
	err := t.post(ctx, "/collector/v1/status", request, protocol.MaxStatusBytes, &result)
	if err == nil && (!result.Durable || result.CollectorBootID != request.CollectorBootID || result.Sequence != request.Sequence) {
		err = errors.New("source status acknowledgement conflicts with request")
	}
	return result, err
}

func (t *LocalTransport) Time(ctx context.Context) (int64, error) {
	var result hubTimeResult
	if err := t.do(ctx, http.MethodGet, "/collector/v1/time", nil, &result); err != nil {
		return 0, err
	}
	if result.HubTimeMS < 0 || result.HubTimeMS > protocol.MaxUint53 {
		return 0, errors.New("invalid hub time response")
	}
	return result.HubTimeMS, nil
}

func (t *LocalTransport) HubProcessIdentity(ctx context.Context) (int, uint64, bool, error) {
	var result hubStatusResult
	if err := t.do(ctx, http.MethodGet, "/v1/status", nil, &result); err != nil {
		return 0, 0, false, err
	}
	if result.SchemaVersion != domain.SchemaVersion || result.Service != "hub" {
		return 0, 0, false, errors.New("invalid hub status identity")
	}
	if result.ProcessIdentity == nil {
		return 0, 0, false, nil
	}
	start, err := strconv.ParseUint(string(result.ProcessIdentity.Start), 10, 64)
	if err != nil || start == 0 || result.ProcessIdentity.PID < 1 || result.ProcessIdentity.PID > 2147483647 {
		return 0, 0, false, errors.New("invalid hub process identity")
	}
	return result.ProcessIdentity.PID, start, true, nil
}

func (t *LocalTransport) post(ctx context.Context, path string, value any, limit int64, result any) error {
	body, err := json.Marshal(value)
	if err != nil {
		return err
	}
	if int64(len(body)) > limit {
		return errors.New("collector request exceeds route limit")
	}
	return t.do(ctx, http.MethodPost, path, body, result)
}

func (t *LocalTransport) do(ctx context.Context, method, path string, body []byte, result any) error {
	if t.client == nil {
		return ErrTransportClosed
	}
	if err := ensurePrivateSocket(t.socket); err != nil {
		return err
	}
	requestCtx, cancel := context.WithTimeout(ctx, transportTimeout)
	defer cancel()
	var reader io.Reader
	if body != nil {
		reader = bytes.NewReader(body)
	}
	request, err := http.NewRequestWithContext(requestCtx, method, "http://owner"+path, reader)
	if err != nil {
		return err
	}
	request.Header.Set("Accept", "application/json")
	request.Header.Set("User-Agent", "llm-monitor-collector/0.1")
	if body != nil {
		request.Header.Set("Content-Type", "application/json")
		request.Header.Set("Content-Encoding", "identity")
	}
	response, err := t.client.Do(request)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, 4096))
		return &AdmissionError{StatusCode: response.StatusCode, RetryAfter: retryAfter(response.Header.Get("Retry-After"))}
	}
	if result == nil {
		_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, maxACKBytes))
		return nil
	}
	return protocol.DecodeStrictJSON(response.Body, maxACKBytes, result)
}

func retryAfter(raw string) time.Duration {
	seconds, err := strconv.Atoi(raw)
	if err != nil || seconds < 1 || seconds > 60 {
		return time.Second
	}
	return time.Duration(seconds) * time.Second
}

func ensurePrivateSocket(path string) error {
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if info.Mode()&os.ModeSocket == 0 || info.Mode().Perm() != 0o600 {
		return errors.New("hub owner socket is not a private Unix socket")
	}
	return nil
}
