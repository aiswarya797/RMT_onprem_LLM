package scheduler

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptrace"
	"net/url"
	"os"
	"sync/atomic"
	"time"

	"rmt.local/monitor/internal/config"
	"rmt.local/monitor/internal/domain"
	"rmt.local/monitor/internal/enrollment"
	"rmt.local/monitor/internal/protocol"
)

type RemoteTransport struct {
	client  *http.Client
	baseURL *url.URL
	paths   config.Paths
	remote  enrollment.RemoteConfig
	leaf    *x509.Certificate
}

type transportPhase uint32

const (
	transportPhaseDial transportPhase = iota + 1
	transportPhaseTLS
	transportPhaseWrite
	transportPhaseRead
)

type transportError struct {
	phase transportPhase
	err   error
}

func (e *transportError) Error() string { return e.err.Error() }
func (e *transportError) Unwrap() error { return e.err }

// doRemoteRequest records only the broad request phase. The owner status must
// never expose URLs, certificate details, request bodies or raw transport
// errors, but phase information separates a real dial failure from a broken
// request/response exchange.
func doRemoteRequest(client *http.Client, request *http.Request) (*http.Response, error) {
	var phase atomic.Uint32
	phase.Store(uint32(transportPhaseDial))
	trace := &httptrace.ClientTrace{
		TLSHandshakeStart: func() { phase.Store(uint32(transportPhaseTLS)) },
		TLSHandshakeDone: func(_ tls.ConnectionState, err error) {
			if err != nil {
				phase.Store(uint32(transportPhaseTLS))
				return
			}
			phase.Store(uint32(transportPhaseWrite))
		},
		WroteRequest: func(info httptrace.WroteRequestInfo) {
			if info.Err != nil {
				phase.Store(uint32(transportPhaseWrite))
				return
			}
			phase.Store(uint32(transportPhaseRead))
		},
		GotFirstResponseByte: func() { phase.Store(uint32(transportPhaseRead)) },
	}
	response, err := client.Do(request.WithContext(httptrace.WithClientTrace(request.Context(), trace)))
	if err != nil {
		return nil, &transportError{phase: transportPhase(phase.Load()), err: err}
	}
	return response, nil
}

type pendingCredentialRenewal struct {
	SchemaVersion  string `json:"schema_version"`
	CurrentSerial  string `json:"current_serial"`
	CSRPEM         string `json:"csr_pem"`
	IdempotencyKey string `json:"idempotency_key"`
}

func NewRemoteTransport(paths config.Paths, expectedDeployment, expectedGeneration string) (*RemoteTransport, error) {
	for _, path := range []string{paths.RemoteCollectorConfig, paths.CollectorKey, paths.CollectorCert, paths.CollectorCA} {
		if err := config.ValidatePrivateFile(path); err != nil {
			return nil, err
		}
	}
	configData, err := readBoundedFile(paths.RemoteCollectorConfig, 64<<10)
	if err != nil {
		return nil, err
	}
	var remote enrollment.RemoteConfig
	if err := protocol.DecodeStrictJSON(bytes.NewReader(configData), 64<<10, &remote); err != nil {
		return nil, err
	}
	if remote.SchemaVersion != domain.SchemaVersion || remote.DeploymentID != expectedDeployment || remote.DeploymentGeneration != expectedGeneration {
		return nil, errors.New("remote collector configuration identity is invalid")
	}
	parsed, err := url.Parse(remote.HubURL)
	if err != nil || parsed.Scheme != "https" || parsed.Hostname() == "" || parsed.Port() == "" || parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" || (parsed.Path != "" && parsed.Path != "/") {
		return nil, errors.New("remote hub URL is invalid")
	}
	caPEM, err := readBoundedFile(paths.CollectorCA, 64<<10)
	if err != nil {
		return nil, err
	}
	fingerprint, err := enrollment.FingerprintCertificatePEM(caPEM)
	if err != nil || fingerprint != remote.HubCAFingerprintSHA256 {
		return nil, errors.New("remote hub CA does not match pinned fingerprint")
	}
	certPEM, err := readBoundedFile(paths.CollectorCert, 64<<10)
	if err != nil {
		return nil, err
	}
	keyPEM, err := readBoundedFile(paths.CollectorKey, 32<<10)
	if err != nil {
		return nil, err
	}
	certificate, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil || len(certificate.Certificate) == 0 {
		return nil, errors.New("remote collector certificate and key are invalid")
	}
	leaf, err := x509.ParseCertificate(certificate.Certificate[0])
	if err != nil {
		return nil, err
	}
	identity, err := enrollment.ParseCollectorIdentity(leaf)
	if err != nil || identity.DeploymentID != remote.DeploymentID || identity.HostID != remote.HostID || identity.SecurityGeneration != remote.DeploymentGeneration {
		return nil, errors.New("remote collector certificate identity conflicts with configuration")
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(caPEM) {
		return nil, errors.New("remote hub CA is invalid")
	}
	if _, err := leaf.Verify(x509.VerifyOptions{Roots: roots, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}); err != nil {
		return nil, errors.New("remote collector certificate chain verification failed")
	}
	if leaf.NotAfter.UnixMilli() != remote.CertificateExpiresMS {
		remote.CertificateExpiresMS = leaf.NotAfter.UnixMilli()
		if err := writeRemoteConfig(paths.RemoteCollectorConfig, remote); err != nil {
			return nil, err
		}
	}
	dialer := &net.Dialer{Timeout: 2 * time.Second}
	transport := &http.Transport{Proxy: nil, DialContext: dialer.DialContext, DisableCompression: true, MaxConnsPerHost: 1, MaxIdleConnsPerHost: 1, TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS13, RootCAs: roots, ServerName: parsed.Hostname(), Certificates: []tls.Certificate{certificate}}}
	return &RemoteTransport{client: &http.Client{Transport: transport, Timeout: transportTimeout, CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
		return errors.New("remote collector redirects are disabled")
	}}, baseURL: parsed, paths: paths, remote: remote, leaf: leaf}, nil
}

// MaintainCredential renews only inside the documented 30-day window. It
// persists the CSR/idempotency tuple before the request, so a lost response is
// retried exactly. Renewal reuses the existing private key, avoiding a
// crash-sensitive two-file key/certificate swap.
func (t *RemoteTransport) MaintainCredential(ctx context.Context) error {
	if t == nil || t.client == nil || t.leaf == nil {
		return ErrTransportClosed
	}
	now := time.Now()
	if t.leaf.NotAfter.Sub(now) > enrollment.RenewBefore {
		if _, err := os.Lstat(t.paths.CollectorRenewal); err == nil {
			_ = os.Remove(t.paths.CollectorRenewal)
		}
		return nil
	}
	keyPEM, err := readBoundedFile(t.paths.CollectorKey, 32<<10)
	if err != nil {
		return err
	}
	pending, err := t.loadOrCreateRenewal(keyPEM)
	if err != nil {
		return err
	}
	requestValue := enrollment.ExchangeRequest{Protocol: domain.ProtocolVersion, DeploymentID: t.remote.DeploymentID, HostID: t.remote.HostID, InstallationID: t.remote.InstallationID, CSRPEM: pending.CSRPEM, HubCAFingerprintSHA256: t.remote.HubCAFingerprintSHA256}
	body, err := json.Marshal(requestValue)
	if err != nil || len(body) > 32<<10 {
		return errors.New("credential renewal request exceeds bound")
	}
	var result enrollment.ExchangeResult
	if err := t.doWithIdempotency(ctx, http.MethodPost, "/collector/v1/credentials/renew", body, pending.IdempotencyKey, &result); err != nil {
		return err
	}
	caPEM, err := readBoundedFile(t.paths.CollectorCA, 64<<10)
	if err != nil {
		return err
	}
	if err := enrollment.VerifyCredentialResult(t.remote, keyPEM, caPEM, result, now); err != nil {
		return err
	}
	if err := config.WritePrivateFile(t.paths.CollectorCert, []byte(result.CertificatePEM)); err != nil {
		return err
	}
	t.remote.CertificateExpiresMS = result.ExpiresMS
	if err := writeRemoteConfig(t.paths.RemoteCollectorConfig, t.remote); err != nil {
		return err
	}
	_ = os.Remove(t.paths.CollectorRenewal)
	replacement, err := NewRemoteTransport(t.paths, t.remote.DeploymentID, t.remote.DeploymentGeneration)
	if err != nil {
		return err
	}
	oldClient := t.client
	t.client, t.baseURL, t.remote, t.leaf = replacement.client, replacement.baseURL, replacement.remote, replacement.leaf
	replacement.client = nil
	if transport, ok := oldClient.Transport.(*http.Transport); ok {
		transport.CloseIdleConnections()
	}
	return nil
}

func (t *RemoteTransport) loadOrCreateRenewal(keyPEM []byte) (pendingCredentialRenewal, error) {
	serial := t.leaf.SerialNumber.Text(16)
	if data, err := readBoundedFile(t.paths.CollectorRenewal, 32<<10); err == nil {
		var pending pendingCredentialRenewal
		if protocol.DecodeStrictJSON(bytes.NewReader(data), 32<<10, &pending) != nil || pending.SchemaVersion != domain.SchemaVersion || pending.CurrentSerial != serial || len(pending.CSRPEM) < 64 || len(pending.CSRPEM) > 16384 || len(pending.IdempotencyKey) < 16 || len(pending.IdempotencyKey) > 128 {
			return pendingCredentialRenewal{}, errors.New("pending credential renewal is invalid")
		}
		return pending, nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return pendingCredentialRenewal{}, err
	}
	csr, err := enrollment.CSRForPrivateKey(t.remote.HostID, keyPEM)
	if err != nil {
		return pendingCredentialRenewal{}, err
	}
	idempotencyKey, err := domain.NewUUID()
	if err != nil {
		return pendingCredentialRenewal{}, err
	}
	pending := pendingCredentialRenewal{SchemaVersion: domain.SchemaVersion, CurrentSerial: serial, CSRPEM: string(csr), IdempotencyKey: idempotencyKey}
	encoded, err := json.MarshalIndent(pending, "", "  ")
	if err != nil {
		return pendingCredentialRenewal{}, err
	}
	if err := config.WritePrivateFile(t.paths.CollectorRenewal, append(encoded, '\n')); err != nil {
		return pendingCredentialRenewal{}, err
	}
	return pending, nil
}

func writeRemoteConfig(path string, remote enrollment.RemoteConfig) error {
	encoded, err := json.MarshalIndent(remote, "", "  ")
	if err != nil {
		return err
	}
	return config.WritePrivateFile(path, append(encoded, '\n'))
}

func (t *RemoteTransport) Pair(context.Context, string, string) error { return nil }

func (t *RemoteTransport) Activate(ctx context.Context, request protocol.SessionActivation) (protocol.SessionResult, error) {
	var result protocol.SessionResult
	err := t.post(ctx, "/collector/v1/sessions", request, protocol.MaxInventoryBytes, &result)
	if err == nil {
		err = validateActivationAcknowledgement(request, result)
	}
	return result, err
}

func (t *RemoteTransport) Inventory(ctx context.Context, request protocol.CollectorInventory) (protocol.InventoryResult, error) {
	var result protocol.InventoryResult
	err := t.post(ctx, "/collector/v1/inventory", request, protocol.MaxInventoryBytes, &result)
	if err == nil && (!result.Durable || !result.Current || result.InventoryRevision != request.InventoryRevision) {
		err = errors.New("inventory acknowledgement conflicts with request")
	}
	return result, err
}

func (t *RemoteTransport) Batch(ctx context.Context, request protocol.CollectorBatch) (protocol.BatchACK, error) {
	var result protocol.BatchACK
	err := t.post(ctx, "/collector/v1/batches", request, protocol.MaxBatchBytes, &result)
	if err == nil && (!result.Durable || result.BatchID != request.BatchID || result.Accepted < 0 || result.Duplicate < 0 || result.Accepted+result.Duplicate != len(request.Frames)) {
		err = errors.New("batch acknowledgement conflicts with request")
	}
	return result, err
}

// RecoveryReplay is deliberately outside the steady-state collectorTransport
// interface. Only the stopped-collector owner recovery CLI can call it.
func (t *RemoteTransport) RecoveryReplay(ctx context.Context, request protocol.RecoveryReplay) (protocol.RecoveryACK, error) {
	var result protocol.RecoveryACK
	err := t.post(ctx, "/collector/v1/recovery-replay", request, protocol.MaxBatchBytes, &result)
	if err == nil {
		err = result.Validate(request)
	}
	return result, err
}

func (t *RemoteTransport) SourceStatus(ctx context.Context, request protocol.SourceStatus) (protocol.StatusACK, error) {
	var result protocol.StatusACK
	err := t.post(ctx, "/collector/v1/status", request, protocol.MaxStatusBytes, &result)
	if err == nil && (!result.Durable || result.CollectorBootID != request.CollectorBootID || result.Sequence != request.Sequence) {
		err = errors.New("source status acknowledgement conflicts with request")
	}
	return result, err
}

func (t *RemoteTransport) Time(ctx context.Context) (int64, error) {
	var result hubTimeResult
	if err := t.do(ctx, http.MethodGet, "/collector/v1/time", nil, &result); err != nil {
		return 0, err
	}
	if result.HubTimeMS < 0 || result.HubTimeMS > protocol.MaxUint53 {
		return 0, errors.New("invalid hub time response")
	}
	return result.HubTimeMS, nil
}

func (t *RemoteTransport) HubProcessIdentity(context.Context) (int, uint64, bool, error) {
	// A hub on another Mac is not a process on this host.
	return 0, 0, false, nil
}

func (t *RemoteTransport) Close() {
	if t.client == nil {
		return
	}
	if transport, ok := t.client.Transport.(*http.Transport); ok {
		transport.CloseIdleConnections()
	}
	t.client = nil
}

func (t *RemoteTransport) post(ctx context.Context, path string, value any, limit int64, result any) error {
	body, err := json.Marshal(value)
	if err != nil || int64(len(body)) > limit {
		return errors.New("collector request exceeds route limit")
	}
	return t.do(ctx, http.MethodPost, path, body, result)
}

func (t *RemoteTransport) doWithIdempotency(ctx context.Context, method, path string, body []byte, idempotencyKey string, result any) error {
	if t.client == nil {
		return ErrTransportClosed
	}
	requestContext, cancel := context.WithTimeout(ctx, transportTimeout)
	defer cancel()
	endpoint := *t.baseURL
	endpoint.Path = path
	request, err := http.NewRequestWithContext(requestContext, method, endpoint.String(), bytes.NewReader(body))
	if err != nil {
		return err
	}
	request.Header.Set("Accept", "application/json")
	request.Header.Set("User-Agent", "llm-monitor-collector/0.1")
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Content-Encoding", "identity")
	request.Header.Set("Idempotency-Key", idempotencyKey)
	response, err := doRemoteRequest(t.client, request)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, 4096))
		return &AdmissionError{StatusCode: response.StatusCode, RetryAfter: retryAfter(response.Header.Get("Retry-After"))}
	}
	return protocol.DecodeStrictJSON(response.Body, maxACKBytes, result)
}

func (t *RemoteTransport) do(ctx context.Context, method, path string, body []byte, result any) error {
	if t.client == nil {
		return ErrTransportClosed
	}
	requestContext, cancel := context.WithTimeout(ctx, transportTimeout)
	defer cancel()
	endpoint := *t.baseURL
	endpoint.Path = path
	var reader io.Reader
	if body != nil {
		reader = bytes.NewReader(body)
	}
	request, err := http.NewRequestWithContext(requestContext, method, endpoint.String(), reader)
	if err != nil {
		return err
	}
	request.Header.Set("Accept", "application/json")
	request.Header.Set("User-Agent", "llm-monitor-collector/0.1")
	if body != nil {
		request.Header.Set("Content-Type", "application/json")
		request.Header.Set("Content-Encoding", "identity")
	}
	response, err := doRemoteRequest(t.client, request)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, 4096))
		return &AdmissionError{StatusCode: response.StatusCode, RetryAfter: retryAfter(response.Header.Get("Retry-After"))}
	}
	return protocol.DecodeStrictJSON(response.Body, maxACKBytes, result)
}

func readBoundedFile(path string, limit int64) ([]byte, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	value, err := io.ReadAll(io.LimitReader(file, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(value)) > limit {
		return nil, errors.New("private collector file exceeds limit")
	}
	return value, nil
}

var _ collectorTransport = (*RemoteTransport)(nil)
