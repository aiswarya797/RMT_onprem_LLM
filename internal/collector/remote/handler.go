package remote

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"

	"rmt.local/monitor/internal/domain"
	"rmt.local/monitor/internal/enrollment"
	"rmt.local/monitor/internal/protocol"
	"rmt.local/monitor/internal/store"
)

const (
	MaxEnrollmentBody int64 = 32 << 10
	MaxResponseBody         = 64 << 10
)

type Handler struct {
	store          *store.Store
	authority      *enrollment.Authority
	enrollmentGate chan struct{}
	mu             sync.Mutex
	hosts          map[string]*hostAdmission
}

type hostAdmission struct {
	gate                chan struct{}
	updated             time.Time
	totalBytes          float64
	replayBytes         float64
	lastControlAccepted time.Time
}

type authenticatedCollector struct {
	identity   enrollment.Identity
	credential store.CredentialIdentity
}

const (
	remoteTotalBytesPerSecond  = 256 << 10
	remoteReplayBytesPerSecond = 128 << 10
	remoteTotalBurstBytes      = 256 << 10
	remoteControlBytes         = 4 << 10
)

func NewHandler(st *store.Store, authority *enrollment.Authority) (*Handler, error) {
	if st == nil || authority == nil {
		return nil, errors.New("remote collector handler requires store and authority")
	}
	return &Handler{store: st, authority: authority, enrollmentGate: make(chan struct{}, 1), hosts: make(map[string]*hostAdmission, 2)}, nil
}

func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	if r.Method == http.MethodPost && r.URL.Path == "/collector/v1/enrollments" {
		h.handleEnrollment(w, r)
		return
	}
	if r.Method == http.MethodGet && r.URL.Path == "/collector/v1/bootstrap" {
		h.handleBootstrap(w, r)
		return
	}
	authenticated, ok := h.authenticateCertificate(r.Context(), r)
	if !ok {
		http.Error(w, "collector certificate rejected", http.StatusUnauthorized)
		return
	}
	identity := authenticated.identity
	if r.Method == http.MethodPost && r.URL.Path == "/collector/v1/credentials/renew" {
		h.handleCredentialRenewal(w, r, authenticated)
		return
	}
	if r.Method == http.MethodGet && r.URL.Path == "/collector/v1/time" {
		writeJSON(w, map[string]int64{"hub_time_ms": time.Now().UnixMilli()})
		return
	}
	if r.Method != http.MethodPost {
		http.NotFound(w, r)
		return
	}
	admission, ok := h.hostAdmission(identity.HostID)
	if !ok || !acquireHost(admission) {
		w.Header().Set("Retry-After", "1")
		http.Error(w, "collector admission busy", http.StatusServiceUnavailable)
		return
	}
	defer releaseHost(admission)
	if !validBodyHeaders(r, protocol.MaxBatchBytes) {
		http.Error(w, "bounded identity-encoded body required", http.StatusRequestEntityTooLarge)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, protocol.MaxBatchBytes)
	matches := func(deploymentID, hostID, generation string) bool {
		return deploymentID == identity.DeploymentID && hostID == identity.HostID && generation == identity.SecurityGeneration
	}
	var result any
	var err error
	switch r.URL.Path {
	case "/collector/v1/sessions":
		if !allowBody(admission, r.ContentLength, false, false) {
			admissionBusy(w)
			return
		}
		var request protocol.SessionActivation
		request, err = protocol.DecodeSessionActivation(r.Body)
		if err == nil && !matches(request.DeploymentID, request.HostID, request.SecurityGeneration) {
			err = store.ErrOwnershipMismatch
		}
		if err == nil {
			result, err = h.store.ActivateCollectorSession(r.Context(), request)
		}
	case "/collector/v1/inventory":
		if !allowBody(admission, r.ContentLength, false, false) {
			admissionBusy(w)
			return
		}
		var request protocol.CollectorInventory
		request, err = protocol.DecodeCollectorInventory(r.Body)
		if err == nil && !matches(request.DeploymentID, request.HostID, request.SecurityGeneration) {
			err = store.ErrOwnershipMismatch
		}
		if err == nil {
			result, err = h.store.RegisterCollectorInventory(r.Context(), request)
		}
	case "/collector/v1/batches":
		if !allowBody(admission, r.ContentLength, false, false) {
			admissionBusy(w)
			return
		}
		var request protocol.CollectorBatch
		request, err = protocol.DecodeCollectorBatch(r.Body)
		if err == nil && request.DeliveryMode == "replay" && !allowBody(admission, r.ContentLength, true, false) {
			admissionBusy(w)
			return
		}
		if err == nil && !matches(request.DeploymentID, request.HostID, request.SecurityGeneration) {
			err = store.ErrOwnershipMismatch
		}
		if err == nil {
			result, err = h.store.IngestCollectorBatch(r.Context(), request)
		}
	case "/collector/v1/recovery-replay":
		if !allowBody(admission, r.ContentLength, false, false) || !allowBody(admission, r.ContentLength, true, false) {
			admissionBusy(w)
			return
		}
		var request protocol.RecoveryReplay
		request, err = protocol.DecodeRecoveryReplay(r.Body)
		if err == nil && !matches(request.DeploymentID, request.HostID, request.AdmittingSecurityGeneration) {
			err = store.ErrOwnershipMismatch
		}
		if err == nil {
			result, err = h.store.IngestRecoveryReplay(r.Context(), request)
		}
	case "/collector/v1/status":
		if !allowBody(admission, r.ContentLength, false, true) {
			admissionBusy(w)
			return
		}
		var request protocol.SourceStatus
		request, err = protocol.DecodeSourceStatus(r.Body)
		if err == nil && !matches(request.DeploymentID, request.HostID, request.SecurityGeneration) {
			err = store.ErrOwnershipMismatch
		}
		if err == nil {
			result, err = h.store.IngestSourceStatus(r.Context(), request)
		}
	default:
		http.NotFound(w, r)
		return
	}
	if err != nil {
		admissionError(w, err)
		return
	}
	writeJSON(w, result)
}

// handleBootstrap is the only unauthenticated TLS route. Possession of the
// short-lived pairing code authorizes one bounded response containing the CA
// and enrollment identity; the collector pins that CA before using mTLS.
func (h *Handler) handleBootstrap(w http.ResponseWriter, r *http.Request) {
	if r.URL.RawQuery != "" || r.ContentLength != 0 {
		http.Error(w, "pairing bootstrap accepts an empty request", http.StatusBadRequest)
		return
	}
	token, ok := bearerToken(r.Header.Get("Authorization"))
	if !ok {
		http.Error(w, "pairing code rejected", http.StatusUnauthorized)
		return
	}
	authorization, err := h.store.AuthenticateCollectorEnrollment(r.Context(), enrollment.HashToken(token))
	if err != nil {
		http.Error(w, "pairing code rejected", http.StatusUnauthorized)
		return
	}
	file := enrollment.File{
		SchemaVersion:          domain.SchemaVersion,
		DeploymentID:           authorization.DeploymentID,
		HostID:                 authorization.ReservedHostID,
		HubURL:                 authorization.HubURL,
		HubCAFingerprintSHA256: authorization.HubCAFingerprintSHA256,
		HubCACertificatePEM:    h.authority.CertificatePEM(),
		Token:                  token,
		ExpiresMS:              authorization.ExpiresMS,
	}
	if err := enrollment.ValidateFile(file, time.Now()); err != nil {
		http.Error(w, "pairing code expired", http.StatusUnauthorized)
		return
	}
	writeJSON(w, file)
}

func (h *Handler) handleCredentialRenewal(w http.ResponseWriter, r *http.Request, authenticated authenticatedCollector) {
	admission, ok := h.hostAdmission(authenticated.identity.HostID)
	if !ok || !acquireHost(admission) {
		admissionBusy(w)
		return
	}
	defer releaseHost(admission)
	if !validBodyHeaders(r, MaxEnrollmentBody) {
		http.Error(w, "bounded identity-encoded body required", http.StatusRequestEntityTooLarge)
		return
	}
	if !allowBody(admission, r.ContentLength, false, false) {
		admissionBusy(w)
		return
	}
	idempotencyKey := r.Header.Get("Idempotency-Key")
	if len(idempotencyKey) < 16 || len(idempotencyKey) > 128 {
		http.Error(w, "idempotency key required", http.StatusBadRequest)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, MaxEnrollmentBody)
	var request enrollment.ExchangeRequest
	if err := protocol.DecodeStrictJSON(r.Body, MaxEnrollmentBody, &request); err != nil {
		admissionError(w, err)
		return
	}
	requestHash, err := store.CanonicalEnrollmentRequestHash(request)
	if err != nil {
		admissionError(w, err)
		return
	}
	result, err := h.store.RenewCollectorCredential(r.Context(), authenticated.credential, idempotencyKey, requestHash, request, h.authority.SignCollectorCSR)
	if err != nil {
		admissionError(w, err)
		return
	}
	writeJSON(w, result)
}

func (h *Handler) handleEnrollment(w http.ResponseWriter, r *http.Request) {
	token, ok := bearerToken(r.Header.Get("Authorization"))
	if !ok {
		http.Error(w, "enrollment token rejected", http.StatusUnauthorized)
		return
	}
	// Authenticate before inspecting Content-Length or decoding attacker input.
	authorization, err := h.store.AuthenticateCollectorEnrollment(r.Context(), enrollment.HashToken(token))
	if err != nil {
		http.Error(w, "enrollment token rejected", http.StatusUnauthorized)
		return
	}
	if !validBodyHeaders(r, MaxEnrollmentBody) {
		http.Error(w, "bounded identity-encoded body required", http.StatusRequestEntityTooLarge)
		return
	}
	select {
	case h.enrollmentGate <- struct{}{}:
		defer func() { <-h.enrollmentGate }()
	default:
		admissionBusy(w)
		return
	}
	idempotencyKey := r.Header.Get("Idempotency-Key")
	if len(idempotencyKey) < 16 || len(idempotencyKey) > 128 {
		http.Error(w, "idempotency key required", http.StatusBadRequest)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, MaxEnrollmentBody)
	var request enrollment.ExchangeRequest
	if err := protocol.DecodeStrictJSON(r.Body, MaxEnrollmentBody, &request); err != nil {
		admissionError(w, err)
		return
	}
	requestHash, err := store.CanonicalEnrollmentRequestHash(request)
	if err != nil {
		admissionError(w, err)
		return
	}
	result, err := h.store.RedeemCollectorEnrollment(r.Context(), authorization, idempotencyKey, requestHash, request, h.authority.SignCollectorCSR)
	if err != nil {
		admissionError(w, err)
		return
	}
	writeJSON(w, result)
}

func (h *Handler) hostAdmission(hostID string) (*hostAdmission, bool) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if value := h.hosts[hostID]; value != nil {
		return value, true
	}
	if len(h.hosts) >= 2 {
		var evictID string
		var oldest time.Time
		for id, candidate := range h.hosts {
			if len(candidate.gate) != 0 {
				continue
			}
			if evictID == "" || candidate.updated.Before(oldest) {
				evictID, oldest = id, candidate.updated
			}
		}
		if evictID == "" {
			return nil, false
		}
		delete(h.hosts, evictID)
	}
	now := time.Now()
	value := &hostAdmission{gate: make(chan struct{}, 1), updated: now, totalBytes: remoteTotalBurstBytes, replayBytes: remoteReplayBytesPerSecond}
	h.hosts[hostID] = value
	return value, true
}

func acquireHost(value *hostAdmission) bool {
	select {
	case value.gate <- struct{}{}:
		return true
	default:
		return false
	}
}

func releaseHost(value *hostAdmission) { <-value.gate }

// allowBody is called only while the host gate is held, so bucket updates and
// control-lane spacing are serialized without another lock. A replay first
// consumes the total bucket and then this function consumes its replay bucket.
func allowBody(value *hostAdmission, size int64, replayOnly, control bool) bool {
	if size < 0 {
		return false
	}
	now := time.Now()
	if control {
		if size > remoteControlBytes || (!value.lastControlAccepted.IsZero() && now.Sub(value.lastControlAccepted) < 5*time.Second) {
			return false
		}
		value.lastControlAccepted = now
		value.updated = now
		return true
	}
	elapsed := now.Sub(value.updated)
	if elapsed < 0 {
		elapsed = 0
	}
	value.updated = now
	value.totalBytes = min(remoteTotalBurstBytes, value.totalBytes+elapsed.Seconds()*remoteTotalBytesPerSecond)
	value.replayBytes = min(remoteReplayBytesPerSecond, value.replayBytes+elapsed.Seconds()*remoteReplayBytesPerSecond)
	bytes := float64(size)
	if replayOnly {
		if bytes > value.replayBytes {
			return false
		}
		value.replayBytes -= bytes
		return true
	}
	if bytes > value.totalBytes {
		return false
	}
	value.totalBytes -= bytes
	return true
}

func admissionBusy(w http.ResponseWriter) {
	w.Header().Set("Retry-After", "1")
	http.Error(w, "collector admission busy", http.StatusServiceUnavailable)
}

func (h *Handler) authenticateCertificate(ctx context.Context, r *http.Request) (authenticatedCollector, bool) {
	if r.TLS == nil || len(r.TLS.VerifiedChains) < 1 || len(r.TLS.PeerCertificates) < 1 {
		return authenticatedCollector{}, false
	}
	certificate := r.TLS.PeerCertificates[0]
	identity, err := enrollment.ParseCollectorIdentity(certificate)
	if err != nil {
		return authenticatedCollector{}, false
	}
	credential := store.CredentialIdentity{
		Serial: certificate.SerialNumber.Text(16), FingerprintSHA256: enrollment.CertificateFingerprint(certificate),
		DeploymentID: identity.DeploymentID, HostID: identity.HostID, SecurityGeneration: identity.SecurityGeneration,
		ExpiresMS: certificate.NotAfter.UnixMilli(),
	}
	if h.store.AuthenticateCollectorCredential(ctx, credential) != nil {
		return authenticatedCollector{}, false
	}
	return authenticatedCollector{identity: identity, credential: credential}, true
}

func ServerTLSConfig(serverCertificate tls.Certificate, clientCA *x509.CertPool) (*tls.Config, error) {
	if len(serverCertificate.Certificate) == 0 || clientCA == nil {
		return nil, errors.New("remote collector TLS requires server certificate and client CA")
	}
	return &tls.Config{
		MinVersion:   tls.VersionTLS13,
		Certificates: []tls.Certificate{serverCertificate},
		ClientAuth:   tls.VerifyClientCertIfGiven,
		ClientCAs:    clientCA,
		NextProtos:   []string{"h2", "http/1.1"},
	}, nil
}

func NewServer(address string, handler http.Handler, tlsConfig *tls.Config) (*http.Server, error) {
	if address == "" || handler == nil || tlsConfig == nil {
		return nil, errors.New("remote collector server is incomplete")
	}
	return &http.Server{Addr: address, Handler: handler, TLSConfig: tlsConfig, ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 15 * time.Second, WriteTimeout: 30 * time.Second, IdleTimeout: 60 * time.Second, MaxHeaderBytes: 32 << 10}, nil
}

func validBodyHeaders(r *http.Request, limit int64) bool {
	return r.ContentLength >= 0 && r.ContentLength <= limit && (r.Header.Get("Content-Encoding") == "" || r.Header.Get("Content-Encoding") == "identity")
}

func bearerToken(header string) (string, bool) {
	const prefix = "Bearer "
	if !strings.HasPrefix(header, prefix) || strings.Contains(header[len(prefix):], " ") {
		return "", false
	}
	token := header[len(prefix):]
	return token, len(token) >= 32 && len(token) <= 256
}

func writeJSON(w http.ResponseWriter, value any) {
	w.Header().Set("Content-Type", "application/json")
	_ = protocol.WriteJSON(w, value)
}

func admissionError(w http.ResponseWriter, err error) {
	code := http.StatusUnprocessableEntity
	message := "collector_admission_rejected"
	if errors.Is(err, store.ErrEnrollmentUnavailable) || errors.Is(err, store.ErrEnrollmentExpired) || errors.Is(err, store.ErrEnrollmentConsumed) || errors.Is(err, store.ErrCredentialRevoked) {
		code = http.StatusUnauthorized
	}
	if errors.Is(err, store.ErrOwnershipMismatch) {
		code = http.StatusForbidden
	}
	if errors.Is(err, store.ErrEnrollmentConflict) || errors.Is(err, store.ErrGenerationConflict) || errors.Is(err, store.ErrAdmissionFenced) {
		code = http.StatusConflict
	}
	if errors.Is(err, store.ErrCredentialRenewalNotDue) {
		code = http.StatusConflict
		message = "credential_renewal_not_due"
	}
	if errors.Is(err, store.ErrStatusObservationExpired) {
		code = http.StatusGone
		message = "status_observation_expired"
	}
	if errors.Is(err, store.ErrRecoveryGrantExpired) {
		code = http.StatusGone
		message = "recovery_grant_expired"
	}
	if errors.Is(err, store.ErrRecoveryConflict) || errors.Is(err, store.ErrRecoveryDefinition) {
		code = http.StatusConflict
		message = "recovery_scope_conflict"
	}
	if errors.Is(err, store.ErrWriterBackpressure) || errors.Is(err, protocol.ErrDecoderBusy) {
		code = http.StatusServiceUnavailable
		w.Header().Set("Retry-After", "1")
	}
	if errors.Is(err, store.ErrCapacityMeasurementUnavailable) || errors.Is(err, store.ErrBulkIngestPaused) {
		code = http.StatusServiceUnavailable
		w.Header().Set("Retry-After", "5")
	}
	if errors.Is(err, store.ErrRecoveryCapacityBusy) {
		code = http.StatusServiceUnavailable
		message = "recovery_capacity_busy"
		w.Header().Set("Retry-After", "5")
	}
	w.WriteHeader(code)
	_, _ = io.WriteString(w, message+"\n")
}
