package httpapi

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"time"

	"rmt.local/monitor/internal/alertruntime"
	"rmt.local/monitor/internal/auth"
	"rmt.local/monitor/internal/config"
	"rmt.local/monitor/internal/domain"
	"rmt.local/monitor/internal/enrollment"
	"rmt.local/monitor/internal/notify"
	"rmt.local/monitor/internal/protocol"
	"rmt.local/monitor/internal/query"
	"rmt.local/monitor/internal/store"
)

const sessionCookie = "rmt_session"

type Server struct {
	store               *store.Store
	auth                *auth.Service
	clock               domain.Clock
	ui                  http.Handler
	allowedHosts        map[string]struct{}
	queries             *query.Service
	enrollment          *enrollmentIssuance
	evaluatorStatus     func() alertruntime.Status
	notificationVault   *notify.Vault
	localProbeMu        sync.Mutex
	localProbeEndpoint  string
	localProbeAdmission func() (bool, string)
}

type enrollmentIssuance struct {
	hubURL        string
	caFingerprint string
}

type enrollmentCreateRequest struct {
	HostDisplayName   string  `json:"host_display_name"`
	ExpiresInSeconds  int     `json:"expires_in_seconds"`
	ReplacementHostID *string `json:"replacement_host_id,omitempty"`
}

type apiTokenCreateRequest struct {
	DisplayName      string `json:"display_name"`
	ExpiresInSeconds int64  `json:"expires_in_seconds"`
}

type apiTokenListResponse struct {
	Items []store.APITokenRecord `json:"items"`
}

type apiTokenRevokeResponse struct {
	ID        string `json:"id"`
	RevokedMS int64  `json:"revoked_ms"`
}

type bootstrapResponse struct {
	SchemaVersion string `json:"schema_version"`
	State         string `json:"state"`
	ExpiresMS     *int64 `json:"expires_ms"`
}

type bootstrapTokenResponse struct {
	Token     string `json:"token"`
	ExpiresMS int64  `json:"expires_ms"`
}

type bootstrapRequest struct {
	BootstrapToken string `json:"bootstrap_token"`
	Username       string `json:"username"`
	Password       string `json:"password"`
}

type credentialsRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

type statusResponse struct {
	ExperimentalFeatures bool                   `json:"experimental_features"`
	SchemaVersion        string                 `json:"schema_version"`
	GeneratedMS          int64                  `json:"generated_ms"`
	DeploymentState      domain.DeploymentState `json:"deployment_state"`
	HubState             string                 `json:"hub_state"`
	CollectorState       string                 `json:"collector_state"`
	TargetState          string                 `json:"target_state"`
	HostCount            int                    `json:"host_count"`
	TargetCount          int                    `json:"target_count"`
	SourceCount          int                    `json:"source_count"`
	CollectionStarted    bool                   `json:"collection_started"`
	InferenceStarted     bool                   `json:"inference_started"`
	StorageState         string                 `json:"storage_state"`
	Evaluator            alertruntime.Status    `json:"evaluator"`
}

func New(st *store.Store, authService *auth.Service, clock domain.Clock, allowedAddress string, ui http.Handler) *Server {
	if clock == nil {
		clock = domain.RealClock{}
	}
	hosts := make(map[string]struct{})
	if host, port, err := net.SplitHostPort(allowedAddress); err == nil {
		hosts[net.JoinHostPort(host, port)] = struct{}{}
		if host == "127.0.0.1" || host == "::1" || host == "localhost" {
			hosts[net.JoinHostPort("127.0.0.1", port)] = struct{}{}
			hosts[net.JoinHostPort("localhost", port)] = struct{}{}
			hosts[net.JoinHostPort("[::1]", port)] = struct{}{}
		}
	} else {
		hosts[allowedAddress] = struct{}{}
	}
	return &Server{
		store: st, auth: authService, clock: clock, ui: ui, allowedHosts: hosts, queries: query.New(st, clock),
		localProbeEndpoint: localProbeEndpointDefault,
		// The current macOS safety evidence does not admit model load/generation:
		// its headroom proxy is not independently validated and pressure is not
		// normal. Keep the request path available while failing closed here.
		localProbeAdmission: func() (bool, string) { return false, "inference_policy_unresolved" },
	}
}

// ConfigureEnrollmentIssuance enables the admin enrollment route only after
// the executable hub has loaded its reviewed opt-in TLS collector listener.
// The API never guesses an address or trusts the browser to supply one.
func (s *Server) ConfigureEnrollmentIssuance(hubURL string, caCertificatePEM []byte) error {
	parsed, err := url.Parse(hubURL)
	if err != nil || parsed.Scheme != "https" || parsed.Hostname() == "" || parsed.Port() == "" || parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" || (parsed.Path != "" && parsed.Path != "/") {
		return errors.New("collector enrollment requires an explicit reviewed HTTPS host and port")
	}
	fingerprint, err := enrollment.FingerprintCertificatePEM(caCertificatePEM)
	if err != nil {
		return err
	}
	s.enrollment = &enrollmentIssuance{hubURL: hubURL, caFingerprint: fingerprint}
	return nil
}

func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	requestID, _ := domain.NewUUID()
	w.Header().Set("X-Request-ID", requestID)
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Referrer-Policy", "no-referrer")
	if !s.validHost(r.Host) {
		s.writeError(w, http.StatusBadRequest, requestID, "invalid_host", "Request host is not allowed.", "fix_input", 2, false)
		return
	}
	if !validOrigin(r) {
		s.writeError(w, http.StatusForbidden, requestID, "invalid_origin", "Request origin is not allowed.", "authenticate", 4, false)
		return
	}
	if r.URL.Path == "/healthz" || r.URL.Path == "/readyz" {
		s.handleHealth(w, r, requestID)
		return
	}
	if !config.ExperimentalFeaturesEnabled() && experimentalRoute(r.URL.Path) {
		s.writeError(w, http.StatusForbidden, requestID, "preview_feature_disabled", config.ExperimentalMessage, "none", 2, false)
		return
	}
	state, err := s.store.DeploymentState(r.Context())
	if err == nil {
		w.Header().Set("X-Deployment-ID", state.DeploymentID)
		w.Header().Set("X-Deployment-Generation", state.DeploymentGeneration)
	}

	switch {
	case r.URL.Path == "/api/v1/auth/bootstrap" && r.Method == http.MethodGet:
		s.handleBootstrapState(w, r, requestID)
	case r.URL.Path == "/api/v1/auth/bootstrap/token" && r.Method == http.MethodGet:
		s.handleBootstrapToken(w, r, requestID)
	case r.URL.Path == "/api/v1/auth/bootstrap" && r.Method == http.MethodPost:
		s.handleBootstrapCreate(w, r, requestID)
	case r.URL.Path == "/api/v1/auth/sessions" && r.Method == http.MethodPost:
		s.handleLogin(w, r, requestID)
	case r.URL.Path == "/api/v1/auth/session" && r.Method == http.MethodGet:
		s.handleSession(w, r, requestID)
	case r.URL.Path == "/api/v1/auth/session" && r.Method == http.MethodDelete:
		s.handleLogout(w, r, requestID)
	case r.URL.Path == "/api/v1/auth/tokens" && r.Method == http.MethodGet:
		s.handleAPITokenList(w, r, requestID)
	case r.URL.Path == "/api/v1/auth/tokens" && r.Method == http.MethodPost:
		s.handleAPITokenCreate(w, r, requestID)
	case strings.HasPrefix(r.URL.Path, "/api/v1/auth/tokens/") && r.Method == http.MethodDelete:
		s.handleAPITokenRevoke(w, r, requestID, strings.TrimPrefix(r.URL.Path, "/api/v1/auth/tokens/"))
	case r.URL.Path == "/api/v1/deployment-state" && r.Method == http.MethodGet:
		if _, _, ok := s.requireSession(w, r, requestID); ok {
			s.writeJSON(w, http.StatusOK, state)
		}
	case r.URL.Path == "/api/v1/status" && r.Method == http.MethodGet:
		if _, _, ok := s.requireSession(w, r, requestID); ok {
			s.handleStatus(w, r, requestID)
		}
	case r.URL.Path == "/api/v1/monitor-health/summary" && r.Method == http.MethodGet:
		if _, _, ok := s.requireSession(w, r, requestID); ok {
			s.handleMonitorHealth(w, r, requestID)
		}
	case r.URL.Path == "/api/v1/monitor-health" && r.Method == http.MethodGet:
		if s.requireAdminSession(w, r, requestID) {
			s.handleMonitorHealth(w, r, requestID)
		}
	case r.URL.Path == "/api/v1/storage/forecast" && r.Method == http.MethodGet:
		if s.requireAdminSession(w, r, requestID) {
			s.handleStorageForecast(w, r, requestID)
		}
	case r.URL.Path == "/api/v1/enrollments" && r.Method == http.MethodPost:
		s.handleEnrollmentCreate(w, r, requestID)
	case strings.HasPrefix(r.URL.Path, "/api/v1/enrollments/") && strings.HasSuffix(r.URL.Path, "/status") && r.Method == http.MethodGet:
		hostID := strings.TrimSuffix(strings.TrimPrefix(r.URL.Path, "/api/v1/enrollments/"), "/status")
		s.handleEnrollmentStatus(w, r, requestID, hostID)
	case r.URL.Path == "/api/v1/overview" && r.Method == http.MethodGet:
		if _, _, ok := s.requireSession(w, r, requestID); ok {
			s.handleOverview(w, r, requestID)
		}
	case r.URL.Path == "/api/v1/history/catalog" && r.Method == http.MethodGet:
		if _, _, ok := s.requireSession(w, r, requestID); ok {
			s.handleHistoryCatalog(w, r, requestID)
		}
	case r.URL.Path == "/api/v1/hosts" && r.Method == http.MethodGet:
		if _, _, ok := s.requireSession(w, r, requestID); ok {
			s.handleHosts(w, r, requestID)
		}
	case strings.HasPrefix(r.URL.Path, "/api/v1/hosts/") && strings.HasSuffix(r.URL.Path, "/revoke") && r.Method == http.MethodPost:
		hostID := strings.TrimSuffix(strings.TrimPrefix(r.URL.Path, "/api/v1/hosts/"), "/revoke")
		s.handleHostCredentialRevoke(w, r, requestID, hostID)
	case strings.HasPrefix(r.URL.Path, "/api/v1/hosts/") && r.Method == http.MethodGet:
		if _, _, ok := s.requireSession(w, r, requestID); ok {
			s.handleHost(w, r, requestID, strings.TrimPrefix(r.URL.Path, "/api/v1/hosts/"))
		}
	case r.URL.Path == "/api/v1/targets" && r.Method == http.MethodGet:
		if _, _, ok := s.requireSession(w, r, requestID); ok {
			s.handleTargets(w, r, requestID)
		}
	case strings.HasPrefix(r.URL.Path, "/api/v1/targets/") && r.Method == http.MethodGet:
		if _, _, ok := s.requireSession(w, r, requestID); ok {
			s.handleTarget(w, r, requestID, strings.TrimPrefix(r.URL.Path, "/api/v1/targets/"))
		}
	case r.URL.Path == "/api/v1/series" && r.Method == http.MethodGet:
		if _, _, ok := s.requireSession(w, r, requestID); ok {
			s.handleSeries(w, r, requestID)
		}
	case r.URL.Path == "/api/v1/recovery-grants" && r.Method == http.MethodPost:
		s.handleRecoveryGrantCreate(w, r, requestID)
	case r.URL.Path == "/api/v1/recovery-grants" && r.Method == http.MethodGet:
		s.handleRecoveryGrantList(w, r, requestID)
	case strings.HasPrefix(r.URL.Path, "/api/v1/recovery-grants/") && strings.HasSuffix(r.URL.Path, "/revoke") && r.Method == http.MethodPost:
		s.handleRecoveryGrantRevoke(w, r, requestID, strings.TrimSuffix(strings.TrimPrefix(r.URL.Path, "/api/v1/recovery-grants/"), "/revoke"))
	case strings.HasPrefix(r.URL.Path, "/api/v1/recovery-grants/") && r.Method == http.MethodGet:
		s.handleRecoveryGrantShow(w, r, requestID, strings.TrimPrefix(r.URL.Path, "/api/v1/recovery-grants/"))
	case s.handleComparisonRoute(w, r, requestID):
	case s.handleLocalProbeRoute(w, r, requestID):
	case s.handleInvestigationRoute(w, r, requestID):
	case s.handleRuleRoute(w, r, requestID):
	case s.handleDestinationTestRoute(w, r, requestID):
	case s.handleDestinationRoute(w, r, requestID):
	case s.handleNotificationJobRoute(w, r, requestID):
	case s.handleNotificationDeliveryRoute(w, r, requestID):
	case strings.HasPrefix(r.URL.Path, "/api/"):
		s.writeError(w, http.StatusNotFound, requestID, "route_not_found", "API route is not available.", "none", 2, false)
	case s.ui != nil:
		s.ui.ServeHTTP(w, r)
	default:
		http.NotFound(w, r)
	}
}

func (s *Server) handleHostCredentialRevoke(w http.ResponseWriter, r *http.Request, requestID, hostID string) {
	session, cookieToken, ok := s.requireSession(w, r, requestID)
	if !ok {
		return
	}
	if session.User.Role != "admin" {
		s.writeError(w, http.StatusForbidden, requestID, "administrator_required", "Administrator access is required.", "authenticate", 4, false)
		return
	}
	if cookieToken != "" && !s.auth.ValidCSRF(cookieToken, r.Header.Get("X-CSRF-Token")) {
		s.writeError(w, http.StatusForbidden, requestID, "csrf_required", "A valid CSRF token is required.", "authenticate", 4, false)
		return
	}
	state, idempotencyKey, ok := s.mutationHeaders(w, r, requestID)
	if !ok {
		return
	}
	if r.URL.RawQuery != "" || !resourceIDPattern.MatchString(hostID) || (r.ContentLength != 0 && r.ContentLength != -1) {
		s.writeError(w, http.StatusBadRequest, requestID, "invalid_host", "Credential revocation requires one valid host ID and an empty body.", "fix_input", 2, false)
		return
	}
	canonical, _ := json.Marshal(struct {
		HostID string `json:"host_id"`
	}{hostID})
	digest := sha256.Sum256(canonical)
	requestHash := hex.EncodeToString(digest[:])
	actor := store.SessionRecord{User: session.User, DeploymentID: state.DeploymentID, Generation: state.DeploymentGeneration, ExpiresMS: session.ExpiresMS}
	if _, err := s.store.RevokeCollectorCredentialsIdempotent(r.Context(), actor, hostID, idempotencyKey, requestHash); err != nil {
		s.hostCredentialError(w, requestID, err)
		return
	}
	ctx, cancel := interactiveQueryContext(r)
	defer cancel()
	host, err := s.queries.Host(ctx, hostID)
	if err != nil {
		s.queryError(w, requestID, err)
		return
	}
	s.writeJSON(w, http.StatusOK, host)
}

func (s *Server) hostCredentialError(w http.ResponseWriter, requestID string, err error) {
	switch {
	case errors.Is(err, store.ErrCredentialRevoked):
		s.writeError(w, http.StatusConflict, requestID, "credential_already_revoked", "This host has no active collector credential.", "review_current_state", 7, false)
	case errors.Is(err, store.ErrEnrollmentConflict):
		s.writeError(w, http.StatusConflict, requestID, "idempotency_conflict", "The idempotency key was already used for different input.", "fix_input", 7, false)
	case errors.Is(err, store.ErrAdmissionFenced), errors.Is(err, store.ErrGenerationConflict):
		s.writeError(w, http.StatusConflict, requestID, "restore_state_changed", "The deployment generation changed before credential revocation.", "review_current_state", 7, false)
	case errors.Is(err, store.ErrOwnershipMismatch):
		s.writeError(w, http.StatusForbidden, requestID, "administrator_required", "Administrator access is required for this host.", "authenticate", 4, false)
	case errors.Is(err, store.ErrWriterBackpressure):
		w.Header().Set("Retry-After", "1")
		s.writeError(w, http.StatusServiceUnavailable, requestID, "write_busy", "Credential storage is busy.", "retry_later", 7, true)
	default:
		s.internalError(w, requestID)
	}
}

func (s *Server) handleEnrollmentCreate(w http.ResponseWriter, r *http.Request, requestID string) {
	session, rawToken, ok := s.requireSession(w, r, requestID)
	if !ok {
		return
	}
	if session.User.Role != "admin" {
		s.writeError(w, http.StatusForbidden, requestID, "administrator_required", "Administrator access is required.", "authenticate", 4, false)
		return
	}
	if rawToken != "" && !s.auth.ValidCSRF(rawToken, r.Header.Get("X-CSRF-Token")) {
		s.writeError(w, http.StatusForbidden, requestID, "csrf_required", "A valid CSRF token is required.", "authenticate", 4, false)
		return
	}
	state, err := s.store.DeploymentState(r.Context())
	if err != nil {
		s.internalError(w, requestID)
		return
	}
	if generation := r.Header.Get("If-Deployment-Generation"); generation == "" || generation != state.DeploymentGeneration || !state.MutationsAllowed {
		s.writeError(w, http.StatusConflict, requestID, "restore_state_changed", "Review the current deployment generation before creating enrollment.", "review_current_state", 7, false)
		return
	}
	idempotencyKey := r.Header.Get("Idempotency-Key")
	if len(idempotencyKey) < 16 || len(idempotencyKey) > 128 {
		s.writeError(w, http.StatusBadRequest, requestID, "idempotency_key_required", "A bounded idempotency key is required.", "fix_input", 2, false)
		return
	}
	if s.enrollment == nil {
		s.writeError(w, http.StatusServiceUnavailable, requestID, "collector_listener_disabled", "Enable and review the TLS collector listener before creating enrollment.", "use_local_owner_command", 5, false)
		return
	}
	var body enrollmentCreateRequest
	if !s.decodeJSON(w, r, requestID, &body) {
		return
	}
	if strings.TrimSpace(body.HostDisplayName) == "" || len(body.HostDisplayName) > 128 || body.ExpiresInSeconds != 600 || (body.ReplacementHostID != nil && !validAPIUUID(*body.ReplacementHostID)) {
		s.writeError(w, http.StatusBadRequest, requestID, "invalid_enrollment", "Enrollment requires a host name and the fixed 600 second expiry.", "fix_input", 2, false)
		return
	}
	canonical, _ := json.Marshal(enrollmentCreateRequest{HostDisplayName: body.HostDisplayName, ExpiresInSeconds: body.ExpiresInSeconds, ReplacementHostID: body.ReplacementHostID})
	digest := sha256.Sum256(canonical)
	requestHash := hex.EncodeToString(digest[:])
	token, err := s.auth.EnrollmentToken(state.DeploymentID, state.DeploymentGeneration, session.User.ID, idempotencyKey, requestHash)
	if err != nil {
		s.internalError(w, requestID)
		return
	}
	actor := store.SessionRecord{User: session.User, DeploymentID: state.DeploymentID, Generation: state.DeploymentGeneration, ExpiresMS: session.ExpiresMS}
	replacementHostID := ""
	if body.ReplacementHostID != nil {
		replacementHostID = *body.ReplacementHostID
	}
	result, err := s.store.IssueCollectorEnrollment(r.Context(), actor, idempotencyKey, requestHash, token, body.HostDisplayName, s.enrollment.hubURL, s.enrollment.caFingerprint, replacementHostID)
	if err != nil {
		s.enrollmentError(w, requestID, err)
		return
	}
	s.writeJSON(w, http.StatusOK, result)
}

func (s *Server) handleEnrollmentStatus(w http.ResponseWriter, r *http.Request, requestID, hostID string) {
	if !validAPIUUID(hostID) || r.URL.RawQuery != "" {
		s.writeError(w, http.StatusBadRequest, requestID, "invalid_enrollment", "The pairing reservation identifier is invalid.", "fix_input", 2, false)
		return
	}
	if !s.requireAdminSession(w, r, requestID) {
		return
	}
	state, err := s.store.DeploymentState(r.Context())
	if err != nil {
		s.internalError(w, requestID)
		return
	}
	result, err := s.store.CollectorEnrollmentStatus(r.Context(), state.DeploymentID, hostID)
	if errors.Is(err, store.ErrEnrollmentUnavailable) {
		s.writeError(w, http.StatusNotFound, requestID, "enrollment_not_found", "The pairing reservation was not found.", "review_current_state", 7, false)
		return
	}
	if err != nil {
		s.internalError(w, requestID)
		return
	}
	s.writeJSON(w, http.StatusOK, result)
}

func (s *Server) handleAPITokenList(w http.ResponseWriter, r *http.Request, requestID string) {
	if r.URL.RawQuery != "" {
		s.writeError(w, http.StatusBadRequest, requestID, "invalid_query", "API token list does not accept query parameters.", "fix_input", 2, false)
		return
	}
	session, _, ok := s.requireSession(w, r, requestID)
	if !ok {
		return
	}
	state, err := s.store.DeploymentState(r.Context())
	if err != nil {
		s.internalError(w, requestID)
		return
	}
	items, err := s.store.ListAPITokens(r.Context(), store.SessionRecord{User: session.User, DeploymentID: state.DeploymentID, Generation: state.DeploymentGeneration, ExpiresMS: session.ExpiresMS})
	if err != nil {
		s.apiTokenError(w, requestID, err)
		return
	}
	s.writeJSON(w, http.StatusOK, apiTokenListResponse{Items: items})
}

func (s *Server) handleAPITokenCreate(w http.ResponseWriter, r *http.Request, requestID string) {
	session, cookieToken, ok := s.requireSession(w, r, requestID)
	if !ok {
		return
	}
	if cookieToken != "" && !s.auth.ValidCSRF(cookieToken, r.Header.Get("X-CSRF-Token")) {
		s.writeError(w, http.StatusForbidden, requestID, "csrf_required", "A valid CSRF token is required.", "authenticate", 4, false)
		return
	}
	state, idempotencyKey, ok := s.mutationHeaders(w, r, requestID)
	if !ok {
		return
	}
	var body apiTokenCreateRequest
	if !s.decodeJSON(w, r, requestID, &body) {
		return
	}
	body.DisplayName = strings.TrimSpace(body.DisplayName)
	if body.DisplayName == "" || len(body.DisplayName) > 128 || body.ExpiresInSeconds < 300 || body.ExpiresInSeconds > int64(store.APITokenMaxValidity/time.Second) {
		s.writeError(w, http.StatusBadRequest, requestID, "invalid_api_token", "API token requires a name and an expiry from 300 seconds through 90 days.", "fix_input", 2, false)
		return
	}
	canonical, _ := json.Marshal(body)
	digest := sha256.Sum256(canonical)
	requestHash := hex.EncodeToString(digest[:])
	token, err := s.auth.APIToken(state.DeploymentID, state.DeploymentGeneration, session.User.ID, idempotencyKey, requestHash)
	if err != nil {
		s.internalError(w, requestID)
		return
	}
	actor := store.SessionRecord{User: session.User, DeploymentID: state.DeploymentID, Generation: state.DeploymentGeneration, ExpiresMS: session.ExpiresMS}
	result, err := s.store.CreateAPIToken(r.Context(), actor, idempotencyKey, requestHash, token, body.DisplayName, s.clock.Now().Add(time.Duration(body.ExpiresInSeconds)*time.Second).UnixMilli())
	if err != nil {
		s.apiTokenError(w, requestID, err)
		return
	}
	s.writeJSON(w, http.StatusCreated, result)
}

func (s *Server) handleAPITokenRevoke(w http.ResponseWriter, r *http.Request, requestID, tokenID string) {
	session, cookieToken, ok := s.requireSession(w, r, requestID)
	if !ok {
		return
	}
	if cookieToken != "" && !s.auth.ValidCSRF(cookieToken, r.Header.Get("X-CSRF-Token")) {
		s.writeError(w, http.StatusForbidden, requestID, "csrf_required", "A valid CSRF token is required.", "authenticate", 4, false)
		return
	}
	state, idempotencyKey, ok := s.mutationHeaders(w, r, requestID)
	if !ok {
		return
	}
	if r.URL.RawQuery != "" || !sha256HexPatternHTTP.MatchString(tokenID) {
		s.writeError(w, http.StatusBadRequest, requestID, "invalid_api_token", "The API token identifier is invalid.", "fix_input", 2, false)
		return
	}
	canonical, _ := json.Marshal(struct {
		TokenID string `json:"token_id"`
	}{tokenID})
	digest := sha256.Sum256(canonical)
	requestHash := hex.EncodeToString(digest[:])
	actor := store.SessionRecord{User: session.User, DeploymentID: state.DeploymentID, Generation: state.DeploymentGeneration, ExpiresMS: session.ExpiresMS}
	revokedMS, err := s.store.RevokeAPIToken(r.Context(), actor, tokenID, idempotencyKey, requestHash)
	if err != nil {
		s.apiTokenError(w, requestID, err)
		return
	}
	s.writeJSON(w, http.StatusOK, apiTokenRevokeResponse{ID: tokenID, RevokedMS: revokedMS})
}

var sha256HexPatternHTTP = regexp.MustCompile(`^[0-9a-f]{64}$`)

func (s *Server) mutationHeaders(w http.ResponseWriter, r *http.Request, requestID string) (domain.DeploymentState, string, bool) {
	state, err := s.store.DeploymentState(r.Context())
	if err != nil {
		s.internalError(w, requestID)
		return domain.DeploymentState{}, "", false
	}
	if generation := r.Header.Get("If-Deployment-Generation"); generation == "" || generation != state.DeploymentGeneration || !state.MutationsAllowed {
		s.writeError(w, http.StatusConflict, requestID, "restore_state_changed", "Review the current deployment generation before changing API tokens.", "review_current_state", 7, false)
		return domain.DeploymentState{}, "", false
	}
	idempotencyKey := r.Header.Get("Idempotency-Key")
	if len(idempotencyKey) < 16 || len(idempotencyKey) > 128 {
		s.writeError(w, http.StatusBadRequest, requestID, "idempotency_key_required", "A bounded idempotency key is required.", "fix_input", 2, false)
		return domain.DeploymentState{}, "", false
	}
	return state, idempotencyKey, true
}

func (s *Server) apiTokenError(w http.ResponseWriter, requestID string, err error) {
	switch {
	case errors.Is(err, store.ErrAPITokenUnavailable):
		s.writeError(w, http.StatusNotFound, requestID, "api_token_not_found", "The API token was not found.", "review_current_state", 7, false)
	case errors.Is(err, store.ErrAPITokenLimit):
		s.writeError(w, http.StatusConflict, requestID, "api_token_limit_reached", "Revoke an existing API token before creating another.", "review_current_state", 7, false)
	case errors.Is(err, store.ErrAPITokenConflict):
		s.writeError(w, http.StatusConflict, requestID, "idempotency_conflict", "The idempotency key was already used for different input.", "fix_input", 7, false)
	case errors.Is(err, store.ErrAdmissionFenced), errors.Is(err, store.ErrGenerationConflict):
		s.writeError(w, http.StatusConflict, requestID, "restore_state_changed", "The deployment generation changed before the API token operation completed.", "review_current_state", 7, false)
	case errors.Is(err, store.ErrOwnershipMismatch):
		s.writeError(w, http.StatusForbidden, requestID, "permission_denied", "The API token is outside this account's authority.", "authenticate", 4, false)
	case errors.Is(err, store.ErrWriterBackpressure):
		w.Header().Set("Retry-After", "1")
		s.writeError(w, http.StatusServiceUnavailable, requestID, "write_busy", "API token storage is busy.", "retry_later", 7, true)
	default:
		s.internalError(w, requestID)
	}
}

func (s *Server) enrollmentError(w http.ResponseWriter, requestID string, err error) {
	switch {
	case errors.Is(err, store.ErrHostLimit):
		s.writeError(w, http.StatusConflict, requestID, "host_limit_reached", "The two-host enrollment limit is reached.", "review_current_state", 7, false)
	case errors.Is(err, store.ErrEnrollmentConflict):
		s.writeError(w, http.StatusConflict, requestID, "idempotency_conflict", "The idempotency key was already used for different input.", "fix_input", 7, false)
	case errors.Is(err, store.ErrReEnrollmentDenied):
		s.writeError(w, http.StatusConflict, requestID, "reenrollment_not_allowed", "The reviewed host is not an eligible retained host from this restored deployment.", "review_current_state", 7, false)
	case errors.Is(err, store.ErrAdmissionFenced), errors.Is(err, store.ErrGenerationConflict):
		s.writeError(w, http.StatusConflict, requestID, "restore_state_changed", "The deployment generation changed before enrollment was created.", "review_current_state", 7, false)
	case errors.Is(err, store.ErrOwnershipMismatch):
		s.writeError(w, http.StatusForbidden, requestID, "administrator_required", "Administrator access is required.", "authenticate", 4, false)
	case errors.Is(err, store.ErrWriterBackpressure):
		w.Header().Set("Retry-After", "1")
		s.writeError(w, http.StatusServiceUnavailable, requestID, "write_busy", "Enrollment storage is busy.", "retry_later", 7, true)
	default:
		s.internalError(w, requestID)
	}
}

func validAPIUUID(value string) bool {
	if len(value) != 36 {
		return false
	}
	for index, r := range value {
		if index == 8 || index == 13 || index == 18 || index == 23 {
			if r != '-' {
				return false
			}
			continue
		}
		if !((r >= '0' && r <= '9') || (r >= 'a' && r <= 'f') || (r >= 'A' && r <= 'F')) {
			return false
		}
	}
	return value[14] >= '1' && value[14] <= '5' && strings.ContainsRune("89abAB", rune(value[19]))
}

func (s *Server) handleMonitorHealth(w http.ResponseWriter, r *http.Request, requestID string) {
	if r.URL.RawQuery != "" {
		s.writeError(w, http.StatusBadRequest, requestID, "invalid_query", "Monitor health does not accept query parameters.", "fix_input", 2, false)
		return
	}
	ctx, cancel := interactiveQueryContext(r)
	defer cancel()
	value, err := s.queries.MonitorHealth(ctx)
	if err != nil {
		s.queryError(w, requestID, err)
		return
	}
	s.writeJSON(w, http.StatusOK, struct {
		query.MonitorHealth
		Evaluator alertruntime.Status `json:"evaluator"`
	}{value, s.alertEvaluatorStatus()})
}

func (s *Server) handleStorageForecast(w http.ResponseWriter, r *http.Request, requestID string) {
	if r.URL.RawQuery != "" {
		s.writeError(w, http.StatusBadRequest, requestID, "invalid_query", "Storage forecast does not accept query parameters.", "fix_input", 2, false)
		return
	}
	ctx, cancel := interactiveQueryContext(r)
	defer cancel()
	value, err := s.queries.StorageForecast(ctx)
	if err != nil {
		s.queryError(w, requestID, err)
		return
	}
	s.writeJSON(w, http.StatusOK, value)
}

var resourceIDPattern = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$`)

func (s *Server) handleOverview(w http.ResponseWriter, r *http.Request, requestID string) {
	if !onlyQueryKeys(r, "start", "end") {
		s.writeError(w, http.StatusBadRequest, requestID, "invalid_query", "The overview query contains unsupported parameters.", "fix_input", 2, false)
		return
	}
	values := r.URL.Query()
	if values.Has("start") != values.Has("end") {
		s.writeError(w, http.StatusBadRequest, requestID, "invalid_query", "Overview start and end must be supplied together.", "fix_input", 2, false)
		return
	}
	if values.Has("start") {
		start, startErr := time.Parse(time.RFC3339, values.Get("start"))
		end, endErr := time.Parse(time.RFC3339, values.Get("end"))
		if startErr != nil || endErr != nil || !end.After(start) || end.Sub(start) > 6*time.Hour {
			s.writeError(w, http.StatusBadRequest, requestID, "invalid_query", "Overview requires a valid range no longer than six hours.", "fix_input", 2, false)
			return
		}
	}
	ctx, cancel := interactiveQueryContext(r)
	defer cancel()
	value, err := s.queries.Overview(ctx)
	if err != nil {
		s.queryError(w, requestID, err)
		return
	}
	s.writeJSON(w, http.StatusOK, value)
}

func (s *Server) handleHistoryCatalog(w http.ResponseWriter, r *http.Request, requestID string) {
	if r.URL.RawQuery != "" {
		s.writeError(w, http.StatusBadRequest, requestID, "invalid_query", "The history catalog does not accept query parameters.", "fix_input", 2, false)
		return
	}
	ctx, cancel := interactiveQueryContext(r)
	defer cancel()
	value, err := s.queries.HistoryCatalog(ctx)
	if err != nil {
		s.queryError(w, requestID, err)
		return
	}
	s.writeJSON(w, http.StatusOK, value)
}

func (s *Server) handleHosts(w http.ResponseWriter, r *http.Request, requestID string) {
	if r.URL.RawQuery != "" {
		s.writeError(w, http.StatusBadRequest, requestID, "invalid_query", "The hosts list does not accept query parameters.", "fix_input", 2, false)
		return
	}
	ctx, cancel := interactiveQueryContext(r)
	defer cancel()
	items, err := s.queries.Hosts(ctx)
	if err != nil {
		s.queryError(w, requestID, err)
		return
	}
	s.writeJSON(w, http.StatusOK, struct {
		Items []query.Host `json:"items"`
	}{items})
}

func (s *Server) handleHost(w http.ResponseWriter, r *http.Request, requestID, id string) {
	if !resourceIDPattern.MatchString(id) || r.URL.RawQuery != "" {
		s.writeError(w, http.StatusBadRequest, requestID, "invalid_query", "The host identifier is invalid.", "fix_input", 2, false)
		return
	}
	ctx, cancel := interactiveQueryContext(r)
	defer cancel()
	value, err := s.queries.Host(ctx, id)
	if err != nil {
		s.queryError(w, requestID, err)
		return
	}
	s.writeJSON(w, http.StatusOK, value)
}

func (s *Server) handleTargets(w http.ResponseWriter, r *http.Request, requestID string) {
	if r.URL.RawQuery != "" {
		s.writeError(w, http.StatusBadRequest, requestID, "invalid_query", "The targets list does not accept query parameters.", "fix_input", 2, false)
		return
	}
	ctx, cancel := interactiveQueryContext(r)
	defer cancel()
	items, err := s.queries.Targets(ctx)
	if err != nil {
		s.queryError(w, requestID, err)
		return
	}
	s.writeJSON(w, http.StatusOK, struct {
		Items []query.Target `json:"items"`
	}{items})
}

func (s *Server) handleTarget(w http.ResponseWriter, r *http.Request, requestID, id string) {
	if !resourceIDPattern.MatchString(id) || r.URL.RawQuery != "" {
		s.writeError(w, http.StatusBadRequest, requestID, "invalid_query", "The target identifier is invalid.", "fix_input", 2, false)
		return
	}
	ctx, cancel := interactiveQueryContext(r)
	defer cancel()
	value, err := s.queries.Target(ctx, id)
	if err != nil {
		s.queryError(w, requestID, err)
		return
	}
	s.writeJSON(w, http.StatusOK, value)
}

func (s *Server) handleSeries(w http.ResponseWriter, r *http.Request, requestID string) {
	if !onlyQueryKeys(r, "scope", "metric", "start", "end", "resolution") {
		s.writeError(w, http.StatusBadRequest, requestID, "invalid_query", "The series query contains unsupported or repeated parameters.", "fix_input", 2, false)
		return
	}
	values := r.URL.Query()
	start, startErr := time.Parse(time.RFC3339, values.Get("start"))
	end, endErr := time.Parse(time.RFC3339, values.Get("end"))
	parameters := query.SeriesParameters{Scope: values.Get("scope"), Metric: values.Get("metric"), Resolution: values.Get("resolution")}
	if startErr != nil || endErr != nil || parameters.Scope == "" || parameters.Metric == "" || parameters.Resolution == "" {
		s.writeError(w, http.StatusBadRequest, requestID, "invalid_query", "Series requires valid scope, metric, start, end and resolution parameters.", "fix_input", 2, false)
		return
	}
	parameters.Start, parameters.End = start.UnixMilli(), end.UnixMilli()
	ctx, cancel := interactiveQueryContext(r)
	defer cancel()
	result, err := s.queries.Series(ctx, parameters)
	if err != nil {
		s.queryError(w, requestID, err)
		return
	}
	s.writeJSON(w, http.StatusOK, result)
}

func interactiveQueryContext(r *http.Request) (context.Context, context.CancelFunc) {
	return context.WithTimeout(r.Context(), 2*time.Second)
}

func onlyQueryKeys(r *http.Request, allowed ...string) bool {
	accepted := make(map[string]bool, len(allowed))
	for _, key := range allowed {
		accepted[key] = true
	}
	for key, values := range r.URL.Query() {
		if !accepted[key] || len(values) != 1 {
			return false
		}
	}
	return true
}

func (s *Server) queryError(w http.ResponseWriter, requestID string, err error) {
	switch {
	case errors.Is(err, context.DeadlineExceeded):
		s.writeError(w, http.StatusServiceUnavailable, requestID, "query_timeout", "The local query exceeded its two second limit.", "retry_later", 8, true)
	case errors.Is(err, query.ErrNotFound):
		s.writeError(w, http.StatusNotFound, requestID, "resource_not_found", "The requested monitor resource was not found.", "fix_input", 2, false)
	case errors.Is(err, query.ErrInvalidQuery):
		s.writeError(w, http.StatusBadRequest, requestID, "invalid_query", "The requested range or scope is invalid.", "fix_input", 2, false)
	case errors.Is(err, query.ErrUnsupportedResolution):
		s.writeError(w, http.StatusUnprocessableEntity, requestID, "resolution_unavailable", "That resolution is not available for this retained range.", "fix_input", 2, false)
	case errors.Is(err, query.ErrUnsupportedMetric):
		s.writeError(w, http.StatusUnprocessableEntity, requestID, "metric_scope_unavailable", "That metric is not available for the selected scope.", "fix_input", 2, false)
	case errors.Is(err, query.ErrPointLimit):
		s.writeError(w, http.StatusUnprocessableEntity, requestID, "point_limit_exceeded", "The selected range exceeds the 2,000 point limit.", "fix_input", 2, false)
	default:
		s.internalError(w, requestID)
	}
}

func (s *Server) handleBootstrapState(w http.ResponseWriter, r *http.Request, requestID string) {
	state, err := s.auth.BootstrapState(r.Context())
	if err != nil {
		s.internalError(w, requestID)
		return
	}
	s.writeJSON(w, http.StatusOK, bootstrapResponse{SchemaVersion: domain.SchemaVersion, State: state.State, ExpiresMS: state.ExpiresMS})
}

func (s *Server) handleBootstrapToken(w http.ResponseWriter, r *http.Request, requestID string) {
	if r.URL.RawQuery != "" {
		s.writeError(w, http.StatusBadRequest, requestID, "invalid_query", "Bootstrap handoff does not accept query parameters.", "fix_input", 2, false)
		return
	}
	if !isLoopbackRequest(r) {
		s.writeError(w, http.StatusForbidden, requestID, "local_setup_required", "First-administrator setup is available only from this Mac.", "use_local_owner_command", 4, false)
		return
	}
	token, expires, err := s.auth.LocalBootstrapToken(r.Context())
	if err != nil {
		s.bootstrapTokenError(w, requestID, err)
		return
	}
	s.writeJSON(w, http.StatusOK, bootstrapTokenResponse{Token: token, ExpiresMS: expires.UnixMilli()})
}

func (s *Server) bootstrapTokenError(w http.ResponseWriter, requestID string, err error) {
	switch {
	case errors.Is(err, store.ErrBootstrapExpired):
		s.writeError(w, http.StatusGone, requestID, "bootstrap_expired", "The setup handoff expired. Renew it with the local admin command, then try again.", "use_local_owner_command", 4, false)
	case errors.Is(err, store.ErrAdminExists):
		s.writeError(w, http.StatusConflict, requestID, "bootstrap_already_completed", "The first administrator is already configured.", "authenticate", 7, false)
	case errors.Is(err, store.ErrBootstrapUnavailable), errors.Is(err, store.ErrBootstrapConsumed):
		s.writeError(w, http.StatusServiceUnavailable, requestID, "bootstrap_token_unavailable", "The local setup handoff is unavailable. Run monitor status and try again.", "retry_later", 8, true)
	default:
		s.internalError(w, requestID)
	}
}

func (s *Server) handleBootstrapCreate(w http.ResponseWriter, r *http.Request, requestID string) {
	var body bootstrapRequest
	if !s.decodeJSON(w, r, requestID, &body) {
		return
	}
	remoteIP, _, _ := net.SplitHostPort(r.RemoteAddr)
	session, token, err := s.auth.CreateFirstAdmin(r.Context(), body.BootstrapToken, body.Username, body.Password, remoteIP)
	if err != nil {
		s.authError(w, requestID, err, true)
		return
	}
	s.setSessionCookie(w, r, token)
	s.writeJSON(w, http.StatusCreated, session)
}

func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request, requestID string) {
	var body credentialsRequest
	if !s.decodeJSON(w, r, requestID, &body) {
		return
	}
	remoteIP, _, _ := net.SplitHostPort(r.RemoteAddr)
	session, token, err := s.auth.Login(r.Context(), body.Username, body.Password, remoteIP)
	if err != nil {
		s.authError(w, requestID, err, false)
		return
	}
	s.setSessionCookie(w, r, token)
	s.writeJSON(w, http.StatusOK, session)
}

func (s *Server) handleSession(w http.ResponseWriter, r *http.Request, requestID string) {
	session, _, ok := s.requireSession(w, r, requestID)
	if !ok {
		return
	}
	s.writeJSON(w, http.StatusOK, session)
}

func (s *Server) handleLogout(w http.ResponseWriter, r *http.Request, requestID string) {
	_, rawToken, ok := s.requireSession(w, r, requestID)
	if !ok {
		return
	}
	if !s.auth.ValidCSRF(rawToken, r.Header.Get("X-CSRF-Token")) {
		s.writeError(w, http.StatusForbidden, requestID, "csrf_required", "A valid CSRF token is required.", "authenticate", 4, false)
		return
	}
	if err := s.auth.Logout(r.Context(), rawToken); err != nil {
		s.internalError(w, requestID)
		return
	}
	http.SetCookie(w, &http.Cookie{Name: sessionCookie, Value: "", Path: "/", HttpOnly: true, Secure: r.TLS != nil, SameSite: http.SameSiteStrictMode, MaxAge: -1})
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) handleStatus(w http.ResponseWriter, r *http.Request, requestID string) {
	ctx, cancel := interactiveQueryContext(r)
	defer cancel()
	status, err := s.store.FoundationStatus(ctx)
	if err != nil {
		s.queryError(w, requestID, err)
		return
	}
	overview, err := s.queries.Overview(ctx)
	if err != nil {
		s.queryError(w, requestID, err)
		return
	}
	collectionStarted, err := s.store.HasCollectedFrames(ctx, status.State.DeploymentID)
	if err != nil {
		s.queryError(w, requestID, err)
		return
	}
	targetState := "none"
	if status.TargetCount > 0 {
		targetState = targetFoundationState(overview.Targets)
	}
	collectorState := collectorFoundationState(status.HostCount, collectionStarted, overview.Hosts)
	capacity, err := s.store.ReadCapacityState(ctx, status.State.DeploymentID, s.clock.Now().UnixMilli())
	if err != nil {
		s.queryError(w, requestID, err)
		return
	}
	inferenceStarted, err := s.store.HasDirectProbe(ctx, status.State.DeploymentID)
	if err != nil {
		s.queryError(w, requestID, err)
		return
	}
	s.writeJSON(w, http.StatusOK, statusResponse{
		SchemaVersion: domain.SchemaVersion, GeneratedMS: s.clock.Now().UnixMilli(), DeploymentState: status.State,
		HubState: "configured", CollectorState: collectorState, TargetState: targetState,
		HostCount: status.HostCount, TargetCount: status.TargetCount, SourceCount: status.SourceCount,
		CollectionStarted: collectionStarted, InferenceStarted: inferenceStarted, StorageState: capacity.State,
		Evaluator: s.alertEvaluatorStatus(), ExperimentalFeatures: config.ExperimentalFeaturesEnabled(),
	})
}

func collectorFoundationState(hostCount int, collected bool, hosts []query.Host) string {
	if hostCount == 0 {
		return "not_registered"
	}
	if !collected {
		return "registered_not_observed"
	}
	for _, host := range hosts {
		if host.State != "retired" && (host.SourceState == query.SourceFresh || host.SourceState == query.SourcePartial) {
			return "observing"
		}
	}
	return "stale_or_disconnected"
}

func targetFoundationState(targets []query.Target) string {
	var known *bool
	unknown := false
	for _, target := range targets {
		if target.Retired {
			continue
		}
		if (target.SourceState != query.SourceFresh && target.SourceState != query.SourcePartial) || target.Reachable.Value == nil || target.Reachable.MissingReason != nil {
			unknown = true
			continue
		}
		var reachable bool
		if json.Unmarshal(target.Reachable.Value, &reachable) != nil {
			unknown = true
			continue
		}
		if known != nil && *known != reachable {
			unknown = true
		}
		known = pointerBool(reachable)
	}
	if unknown || known == nil {
		return "partial_or_unknown"
	}
	if *known {
		return "reachable"
	}
	return "unreachable"
}

func pointerBool(value bool) *bool { return &value }

func (s *Server) requireSession(w http.ResponseWriter, r *http.Request, requestID string) (domain.Session, string, bool) {
	if authorization := r.Header.Get("Authorization"); authorization != "" {
		if _, err := r.Cookie(sessionCookie); err == nil {
			s.writeError(w, http.StatusBadRequest, requestID, "ambiguous_authentication", "Use either a bearer token or browser session, not both.", "authenticate", 4, false)
			return domain.Session{}, "", false
		}
		const prefix = "Bearer "
		if !strings.HasPrefix(authorization, prefix) || strings.ContainsAny(authorization[len(prefix):], " \t\r\n") {
			s.writeError(w, http.StatusUnauthorized, requestID, "authentication_required", "A valid API bearer token is required.", "authenticate", 4, false)
			return domain.Session{}, "", false
		}
		session, err := s.auth.APISession(r.Context(), authorization[len(prefix):])
		if err != nil {
			s.writeError(w, http.StatusUnauthorized, requestID, "api_token_rejected", "The API bearer token is expired or revoked.", "authenticate", 4, false)
			return domain.Session{}, "", false
		}
		return session, "", true
	}
	cookie, err := r.Cookie(sessionCookie)
	if err != nil || cookie.Value == "" {
		s.writeError(w, http.StatusUnauthorized, requestID, "authentication_required", "Sign in to continue.", "authenticate", 4, false)
		return domain.Session{}, "", false
	}
	session, err := s.auth.Session(r.Context(), cookie.Value)
	if err != nil {
		s.writeError(w, http.StatusUnauthorized, requestID, "session_expired", "Your session has expired. Sign in again.", "authenticate", 4, false)
		return domain.Session{}, "", false
	}
	return session, cookie.Value, true
}

func (s *Server) requireAdminSession(w http.ResponseWriter, r *http.Request, requestID string) bool {
	session, _, ok := s.requireSession(w, r, requestID)
	if !ok {
		return false
	}
	if session.User.Role != "admin" {
		s.writeError(w, http.StatusForbidden, requestID, "administrator_required", "Administrator access is required.", "authenticate", 4, false)
		return false
	}
	return true
}

func (s *Server) decodeJSON(w http.ResponseWriter, r *http.Request, requestID string, dst any) bool {
	if mediaType := strings.ToLower(strings.TrimSpace(strings.Split(r.Header.Get("Content-Type"), ";")[0])); mediaType != "application/json" {
		s.writeError(w, http.StatusUnsupportedMediaType, requestID, "json_required", "Content-Type must be application/json.", "fix_input", 2, false)
		return false
	}
	r.Body = http.MaxBytesReader(w, r.Body, 64*1024)
	if err := protocol.DecodeStrictJSON(r.Body, 64*1024, dst); err != nil {
		s.writeError(w, http.StatusBadRequest, requestID, "invalid_json", "Request body must contain one JSON object.", "fix_input", 2, false)
		return false
	}
	return true
}

func (s *Server) validHost(host string) bool {
	_, ok := s.allowedHosts[strings.ToLower(host)]
	return ok
}

func isLoopbackRequest(r *http.Request) bool {
	if r == nil {
		return false
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return false
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

func validOrigin(r *http.Request) bool {
	origin := r.Header.Get("Origin")
	if origin == "" {
		return true
	}
	parsed, err := url.Parse(origin)
	if err != nil || parsed.User != nil || parsed.Path != "" || parsed.RawQuery != "" || parsed.Fragment != "" {
		return false
	}
	wantScheme := "http"
	if r.TLS != nil {
		wantScheme = "https"
	}
	return parsed.Scheme == wantScheme && strings.EqualFold(parsed.Host, r.Host)
}

func (s *Server) setSessionCookie(w http.ResponseWriter, r *http.Request, token string) {
	http.SetCookie(w, &http.Cookie{Name: sessionCookie, Value: token, Path: "/", HttpOnly: true, Secure: r.TLS != nil, SameSite: http.SameSiteStrictMode, MaxAge: int((7 * 24 * time.Hour).Seconds())})
}

func (s *Server) authError(w http.ResponseWriter, requestID string, err error, bootstrap bool) {
	switch {
	case errors.Is(err, auth.ErrRateLimited), errors.Is(err, auth.ErrHashBusy):
		s.writeError(w, http.StatusTooManyRequests, requestID, "login_rate_limited", "Too many sign-in attempts. Try again later.", "retry_later", 4, true)
	case errors.Is(err, store.ErrBootstrapExpired):
		s.writeError(w, http.StatusGone, requestID, "bootstrap_expired", "The setup token expired. Renew it with the local admin command.", "use_local_owner_command", 4, false)
	case errors.Is(err, store.ErrAdminExists):
		s.writeError(w, http.StatusConflict, requestID, "bootstrap_already_completed", "The first administrator is already configured.", "authenticate", 7, false)
	case errors.Is(err, store.ErrBootstrapUnavailable), errors.Is(err, store.ErrBootstrapConsumed), errors.Is(err, store.ErrInvalidCredentials):
		message := "Username or password is incorrect."
		code := "invalid_credentials"
		if bootstrap {
			message = "The setup token is invalid or already used."
			code = "invalid_bootstrap_token"
		}
		s.writeError(w, http.StatusUnauthorized, requestID, code, message, "authenticate", 4, false)
	default:
		if strings.Contains(err.Error(), "username") || strings.Contains(err.Error(), "password") {
			s.writeError(w, http.StatusBadRequest, requestID, "invalid_input", err.Error(), "fix_input", 2, false)
			return
		}
		s.internalError(w, requestID)
	}
}

func (s *Server) internalError(w http.ResponseWriter, requestID string) {
	s.writeError(w, http.StatusInternalServerError, requestID, "internal_error", "The monitor could not complete the request.", "retry_later", 8, true)
}

func (s *Server) writeError(w http.ResponseWriter, status int, requestID, code, message, recovery string, cliExit int, retryable bool) {
	s.writeJSON(w, status, domain.APIError{SchemaVersion: domain.SchemaVersion, Code: code, Message: message, RecoveryAction: recovery, RequestID: requestID, Retryable: retryable, CLIExitCode: cliExit})
}

func (s *Server) writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	if err := protocol.WriteJSON(w, value); err != nil {
		return
	}
}

func (s *Server) String() string {
	return fmt.Sprintf("httpapi with %d allowed hosts", len(s.allowedHosts))
}

func experimentalRoute(path string) bool {
	for _, prefix := range []string{"/api/v1/enrollments", "/api/v1/probes", "/api/v1/comparisons", "/api/v1/destinations", "/api/v1/deliveries", "/api/v1/jobs"} {
		if path == prefix || strings.HasPrefix(path, prefix+"/") {
			return true
		}
	}
	return strings.HasPrefix(path, "/api/v1/incidents/") && strings.HasSuffix(path, "/comparisons")
}
