package httpapi

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"rmt.local/monitor/internal/auth"
	"rmt.local/monitor/internal/config"
	"rmt.local/monitor/internal/domain"
	"rmt.local/monitor/internal/query"
	"rmt.local/monitor/internal/store"
)

type apiClock struct{ now time.Time }

func (c *apiClock) Now() time.Time { return c.now }

func TestBootstrapSessionSecurityAndNoTargetStatus(t *testing.T) {
	t.Setenv("LLM_MONITOR_EXPERIMENTAL", "1")
	clock := &apiClock{now: time.Unix(1_800_000_000, 0)}
	paths := config.ForHome(t.TempDir())
	st, err := store.Open(paths.Database, clock)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	state, _, err := st.EnsureDeployment(context.Background(), "Test")
	if err != nil {
		t.Fatal(err)
	}
	authService, err := auth.NewService(st, paths, clock)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, _, err := authService.RenewBootstrap(context.Background()); err != nil {
		t.Fatal(err)
	}
	tokenBytes, _ := os.ReadFile(paths.BootstrapToken)
	token := strings.TrimSpace(string(tokenBytes))
	server := New(st, authService, clock, "127.0.0.1:9443", http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusTeapot) }))

	badHost := request(t, server, http.MethodGet, "/api/v1/auth/bootstrap", "evil.example", "", nil, nil)
	assertError(t, badHost, http.StatusBadRequest, "invalid_host")
	badOrigin := request(t, server, http.MethodGet, "/api/v1/auth/bootstrap", "127.0.0.1:9443", "http://evil.example", nil, nil)
	assertError(t, badOrigin, http.StatusForbidden, "invalid_origin")

	discovery := request(t, server, http.MethodGet, "/api/v1/auth/bootstrap", "127.0.0.1:9443", "", nil, nil)
	if discovery.Code != http.StatusOK || discovery.Header().Get("X-Deployment-Generation") != state.DeploymentGeneration || !strings.Contains(discovery.Body.String(), `"state":"required"`) {
		t.Fatalf("bootstrap discovery code=%d headers=%v body=%s", discovery.Code, discovery.Header(), discovery.Body.String())
	}
	remoteHandoff := request(t, server, http.MethodGet, "/api/v1/auth/bootstrap/token", "127.0.0.1:9443", "", nil, nil, func(r *http.Request) { r.RemoteAddr = "203.0.113.10:40000" })
	assertError(t, remoteHandoff, http.StatusForbidden, "local_setup_required")
	handoff := request(t, server, http.MethodGet, "/api/v1/auth/bootstrap/token", "127.0.0.1:9443", "", nil, nil)
	if handoff.Code != http.StatusOK || !strings.Contains(handoff.Body.String(), `"token":"`+token+`"`) {
		t.Fatalf("local bootstrap handoff code=%d body=%s", handoff.Code, handoff.Body.String())
	}
	body := map[string]string{"bootstrap_token": token, "username": "admin", "password": "a sufficiently long password"}
	created := request(t, server, http.MethodPost, "/api/v1/auth/bootstrap", "127.0.0.1:9443", "http://127.0.0.1:9443", body, nil)
	if created.Code != http.StatusCreated {
		t.Fatalf("bootstrap code=%d body=%s", created.Code, created.Body.String())
	}
	cookies := created.Result().Cookies()
	if len(cookies) != 1 || !cookies[0].HttpOnly || cookies[0].SameSite != http.SameSiteStrictMode {
		t.Fatalf("session cookie=%#v", cookies)
	}
	completedHandoff := request(t, server, http.MethodGet, "/api/v1/auth/bootstrap/token", "127.0.0.1:9443", "", nil, nil)
	assertError(t, completedHandoff, http.StatusConflict, "bootstrap_already_completed")
	var session domain.Session
	if err := json.Unmarshal(created.Body.Bytes(), &session); err != nil {
		t.Fatal(err)
	}
	sessionRead := request(t, server, http.MethodGet, "/api/v1/auth/session", "127.0.0.1:9443", "", nil, cookies[0])
	if sessionRead.Code != http.StatusOK || !strings.Contains(sessionRead.Body.String(), `"role":"admin"`) {
		t.Fatalf("session read code=%d body=%s", sessionRead.Code, sessionRead.Body.String())
	}
	tokenHeaders := func(r *http.Request) {
		r.Header.Set("X-CSRF-Token", session.CSRFToken)
		r.Header.Set("If-Deployment-Generation", state.DeploymentGeneration)
		r.Header.Set("Idempotency-Key", "00000000-0000-4000-8000-000000000061")
	}
	tokenBody := map[string]any{"display_name": "CLI", "expires_in_seconds": 3600}
	tokenCreated := request(t, server, http.MethodPost, "/api/v1/auth/tokens", "127.0.0.1:9443", "http://127.0.0.1:9443", tokenBody, cookies[0], tokenHeaders)
	if tokenCreated.Code != http.StatusCreated {
		t.Fatalf("API token create code=%d body=%s", tokenCreated.Code, tokenCreated.Body.String())
	}
	var apiToken store.APITokenOnce
	if err := json.Unmarshal(tokenCreated.Body.Bytes(), &apiToken); err != nil || apiToken.Token == "" || apiToken.Record.Scope != "admin" {
		t.Fatalf("API token result=%#v err=%v", apiToken, err)
	}
	tokenRetry := request(t, server, http.MethodPost, "/api/v1/auth/tokens", "127.0.0.1:9443", "http://127.0.0.1:9443", tokenBody, cookies[0], tokenHeaders)
	if tokenRetry.Code != http.StatusCreated || tokenRetry.Body.String() != tokenCreated.Body.String() {
		t.Fatalf("API token retry code=%d equal=%t", tokenRetry.Code, tokenRetry.Body.String() == tokenCreated.Body.String())
	}
	bearer := func(r *http.Request) { r.Header.Set("Authorization", "Bearer "+apiToken.Token) }
	tokenList := request(t, server, http.MethodGet, "/api/v1/auth/tokens", "127.0.0.1:9443", "", nil, nil, bearer)
	if tokenList.Code != http.StatusOK || !strings.Contains(tokenList.Body.String(), apiToken.Record.ID) {
		t.Fatalf("API token list code=%d body=%s", tokenList.Code, tokenList.Body.String())
	}
	bearerSession := request(t, server, http.MethodGet, "/api/v1/auth/session", "127.0.0.1:9443", "", nil, nil, bearer)
	if bearerSession.Code != http.StatusOK || !strings.Contains(bearerSession.Body.String(), `"role":"admin"`) {
		t.Fatalf("bearer session code=%d body=%s", bearerSession.Code, bearerSession.Body.String())
	}
	caPEM := testCACertificate(t, clock.now)
	if err := server.ConfigureEnrollmentIssuance("https://127.0.0.1:9444", caPEM); err != nil {
		t.Fatal(err)
	}
	enrollmentBody := map[string]any{"host_display_name": "Second Mac", "expires_in_seconds": 600}
	enrollmentHeaders := func(r *http.Request) {
		r.Header.Set("X-CSRF-Token", session.CSRFToken)
		r.Header.Set("If-Deployment-Generation", state.DeploymentGeneration)
		r.Header.Set("Idempotency-Key", "00000000-0000-4000-8000-000000000071")
	}
	createdEnrollment := request(t, server, http.MethodPost, "/api/v1/enrollments", "127.0.0.1:9443", "http://127.0.0.1:9443", enrollmentBody, cookies[0], enrollmentHeaders)
	if createdEnrollment.Code != http.StatusOK || !strings.Contains(createdEnrollment.Body.String(), `"hub_url":"https://127.0.0.1:9444"`) || !strings.Contains(createdEnrollment.Body.String(), `"token":`) {
		t.Fatalf("enrollment issue code=%d body=%s", createdEnrollment.Code, createdEnrollment.Body.String())
	}
	var enrollmentResult store.EnrollmentToken
	if err := json.Unmarshal(createdEnrollment.Body.Bytes(), &enrollmentResult); err != nil {
		t.Fatal(err)
	}
	enrollmentStatus := request(t, server, http.MethodGet, "/api/v1/enrollments/"+enrollmentResult.HostID+"/status", "127.0.0.1:9443", "", nil, cookies[0])
	if enrollmentStatus.Code != http.StatusOK || !strings.Contains(enrollmentStatus.Body.String(), `"state":"waiting"`) || !strings.Contains(enrollmentStatus.Body.String(), `"display_name":"Second Mac"`) || strings.Contains(enrollmentStatus.Body.String(), enrollmentResult.Token) {
		t.Fatalf("enrollment status code=%d body=%s", enrollmentStatus.Code, enrollmentStatus.Body.String())
	}
	retriedEnrollment := request(t, server, http.MethodPost, "/api/v1/enrollments", "127.0.0.1:9443", "http://127.0.0.1:9443", enrollmentBody, cookies[0], enrollmentHeaders)
	if retriedEnrollment.Code != http.StatusOK || retriedEnrollment.Body.String() != createdEnrollment.Body.String() {
		t.Fatalf("enrollment retry code=%d equal=%t", retriedEnrollment.Code, retriedEnrollment.Body.String() == createdEnrollment.Body.String())
	}
	changedEnrollment := request(t, server, http.MethodPost, "/api/v1/enrollments", "127.0.0.1:9443", "http://127.0.0.1:9443", map[string]any{"host_display_name": "Changed", "expires_in_seconds": 600}, cookies[0], enrollmentHeaders)
	assertError(t, changedEnrollment, http.StatusConflict, "idempotency_conflict")
	status := request(t, server, http.MethodGet, "/api/v1/status", "127.0.0.1:9443", "", nil, cookies[0])
	if status.Code != http.StatusOK || !strings.Contains(status.Body.String(), `"target_state":"none"`) || !strings.Contains(status.Body.String(), `"inference_started":false`) || !strings.Contains(status.Body.String(), `"storage_state":"bulk_ingest_paused"`) {
		t.Fatalf("status code=%d body=%s", status.Code, status.Body.String())
	}
	health := request(t, server, http.MethodGet, "/api/v1/monitor-health/summary", "127.0.0.1:9443", "", nil, cookies[0])
	if health.Code != http.StatusOK || !strings.Contains(health.Body.String(), `"storage_state":"bulk_ingest_paused"`) || !strings.Contains(health.Body.String(), `"collector_states":[]`) || !strings.Contains(health.Body.String(), `"evaluator":`) {
		t.Fatalf("health code=%d body=%s", health.Code, health.Body.String())
	}
	forecast := request(t, server, http.MethodGet, "/api/v1/storage/forecast", "127.0.0.1:9443", "", nil, cookies[0])
	if forecast.Code != http.StatusOK || !strings.Contains(forecast.Body.String(), `"live_limit_bytes":17179869184`) || !strings.Contains(forecast.Body.String(), `"estimated_days_remaining":null`) {
		t.Fatalf("forecast code=%d body=%s", forecast.Code, forecast.Body.String())
	}
	overview := request(t, server, http.MethodGet, "/api/v1/overview", "127.0.0.1:9443", "", nil, cookies[0])
	if overview.Code != http.StatusOK || !strings.Contains(overview.Body.String(), `"state":"not_observed"`) || !strings.Contains(overview.Body.String(), `"hosts":[]`) || !strings.Contains(overview.Body.String(), `"targets":[]`) {
		t.Fatalf("overview code=%d body=%s", overview.Code, overview.Body.String())
	}
	historyCatalog := request(t, server, http.MethodGet, "/api/v1/history/catalog", "127.0.0.1:9443", "", nil, cookies[0])
	if historyCatalog.Code != http.StatusOK || !strings.Contains(historyCatalog.Body.String(), `"scopes":[]`) || !strings.Contains(historyCatalog.Body.String(), `"earliest_retained_ms":null`) {
		t.Fatalf("history catalog code=%d body=%s", historyCatalog.Code, historyCatalog.Body.String())
	}
	badHistoryCatalog := request(t, server, http.MethodGet, "/api/v1/history/catalog?all=true", "127.0.0.1:9443", "", nil, cookies[0])
	if badHistoryCatalog.Code != http.StatusBadRequest {
		t.Fatalf("history catalog query code=%d body=%s", badHistoryCatalog.Code, badHistoryCatalog.Body.String())
	}
	hosts := request(t, server, http.MethodGet, "/api/v1/hosts", "127.0.0.1:9443", "", nil, cookies[0])
	if hosts.Code != http.StatusOK || hosts.Body.String() != "{\"items\":[]}\n" {
		t.Fatalf("hosts code=%d body=%s", hosts.Code, hosts.Body.String())
	}
	targets := request(t, server, http.MethodGet, "/api/v1/targets", "127.0.0.1:9443", "", nil, cookies[0])
	if targets.Code != http.StatusOK || targets.Body.String() != "{\"items\":[]}\n" {
		t.Fatalf("targets code=%d body=%s", targets.Code, targets.Body.String())
	}
	badRange := request(t, server, http.MethodGet, "/api/v1/overview?start=2026-01-01T00:00:00Z", "127.0.0.1:9443", "", nil, cookies[0])
	assertError(t, badRange, http.StatusBadRequest, "invalid_query")
	unauthenticatedQuery := request(t, server, http.MethodGet, "/api/v1/overview", "127.0.0.1:9443", "", nil, nil)
	assertError(t, unauthenticatedQuery, http.StatusUnauthorized, "authentication_required")
	noCSRF := request(t, server, http.MethodDelete, "/api/v1/auth/session", "127.0.0.1:9443", "http://127.0.0.1:9443", nil, cookies[0])
	assertError(t, noCSRF, http.StatusForbidden, "csrf_required")
	logout := request(t, server, http.MethodDelete, "/api/v1/auth/session", "127.0.0.1:9443", "http://127.0.0.1:9443", nil, cookies[0], func(r *http.Request) { r.Header.Set("X-CSRF-Token", session.CSRFToken) })
	if logout.Code != http.StatusNoContent {
		t.Fatalf("logout code=%d body=%s", logout.Code, logout.Body.String())
	}
	after := request(t, server, http.MethodGet, "/api/v1/auth/session", "127.0.0.1:9443", "", nil, cookies[0])
	assertError(t, after, http.StatusUnauthorized, "session_expired")
}

func testCACertificate(t *testing.T, now time.Time) []byte {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "API enrollment test CA"}, NotBefore: now.Add(-time.Minute), NotAfter: now.AddDate(1, 0, 0), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

func TestFoundationStateLabelsUseObservationTruth(t *testing.T) {
	if got := collectorFoundationState(1, false, nil); got != "registered_not_observed" {
		t.Fatalf("registered collector = %q", got)
	}
	if got := collectorFoundationState(1, true, []query.Host{{State: "active", SourceState: query.SourceStale}}); got != "stale_or_disconnected" {
		t.Fatalf("stale collector = %q", got)
	}
	if got := collectorFoundationState(1, true, []query.Host{{State: "active", SourceState: query.SourcePartial}}); got != "observing" {
		t.Fatalf("partial but current collector = %q", got)
	}
	reachable := query.MetricReading{Value: json.RawMessage(`true`)}
	if got := targetFoundationState([]query.Target{{SourceState: query.SourceFresh, Reachable: reachable}}); got != "reachable" {
		t.Fatalf("reachable target = %q", got)
	}
	reachable.Value = json.RawMessage(`false`)
	if got := targetFoundationState([]query.Target{{SourceState: query.SourceFresh, Reachable: reachable}}); got != "unreachable" {
		t.Fatalf("unreachable target = %q", got)
	}
	if got := targetFoundationState([]query.Target{{SourceState: query.SourceStale, Reachable: reachable}}); got != "partial_or_unknown" {
		t.Fatalf("stale target = %q", got)
	}
}

func TestAPITokenBearerGenerationRevocationAndCookieAmbiguity(t *testing.T) {
	clock := &apiClock{now: time.Unix(1_800_000_000, 0)}
	paths := config.ForHome(t.TempDir())
	st, err := store.Open(paths.Database, clock)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	state, _, err := st.EnsureDeployment(context.Background(), "Bearer test")
	if err != nil {
		t.Fatal(err)
	}
	authService, err := auth.NewService(st, paths, clock)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, _, err := authService.RenewBootstrap(context.Background()); err != nil {
		t.Fatal(err)
	}
	bootstrapBytes, _ := os.ReadFile(paths.BootstrapToken)
	session, sessionToken, err := authService.CreateFirstAdmin(context.Background(), strings.TrimSpace(string(bootstrapBytes)), "admin", "a sufficiently long password", "127.0.0.1")
	if err != nil {
		t.Fatal(err)
	}
	server := New(st, authService, clock, "127.0.0.1:9443", nil)
	cookie := &http.Cookie{Name: sessionCookie, Value: sessionToken}
	createBody := map[string]any{"display_name": "CLI", "expires_in_seconds": 3600}
	createHeaders := func(generation, key string) requestOption {
		return func(r *http.Request) {
			r.Header.Set("X-CSRF-Token", session.CSRFToken)
			r.Header.Set("If-Deployment-Generation", generation)
			r.Header.Set("Idempotency-Key", key)
		}
	}
	wrongGeneration := request(t, server, http.MethodPost, "/api/v1/auth/tokens", "127.0.0.1:9443", "http://127.0.0.1:9443", createBody, cookie, createHeaders("00000000-0000-4000-8000-000000000999", "00000000-0000-4000-8000-000000000111"))
	assertError(t, wrongGeneration, http.StatusConflict, "restore_state_changed")
	created := request(t, server, http.MethodPost, "/api/v1/auth/tokens", "127.0.0.1:9443", "http://127.0.0.1:9443", createBody, cookie, createHeaders(state.DeploymentGeneration, "00000000-0000-4000-8000-000000000112"))
	if created.Code != http.StatusCreated {
		t.Fatalf("token create code=%d body=%s", created.Code, created.Body.String())
	}
	var token store.APITokenOnce
	if err := json.Unmarshal(created.Body.Bytes(), &token); err != nil {
		t.Fatal(err)
	}
	bearer := func(r *http.Request) { r.Header.Set("Authorization", "Bearer "+token.Token) }
	read := request(t, server, http.MethodGet, "/api/v1/auth/session", "127.0.0.1:9443", "", nil, nil, bearer)
	if read.Code != http.StatusOK || !strings.Contains(read.Body.String(), `"role":"admin"`) {
		t.Fatalf("bearer auth code=%d body=%s", read.Code, read.Body.String())
	}
	ambiguous := request(t, server, http.MethodGet, "/api/v1/auth/session", "127.0.0.1:9443", "", nil, cookie, bearer)
	assertError(t, ambiguous, http.StatusBadRequest, "ambiguous_authentication")
	childHeaders := func(r *http.Request) {
		bearer(r)
		r.Header.Set("If-Deployment-Generation", state.DeploymentGeneration)
		r.Header.Set("Idempotency-Key", "00000000-0000-4000-8000-000000000113")
	}
	child := request(t, server, http.MethodPost, "/api/v1/auth/tokens", "127.0.0.1:9443", "", map[string]any{"display_name": "Child", "expires_in_seconds": 600}, nil, childHeaders)
	if child.Code != http.StatusCreated {
		t.Fatalf("bearer token create code=%d body=%s", child.Code, child.Body.String())
	}
	revokeHeaders := func(r *http.Request) {
		r.Header.Set("X-CSRF-Token", session.CSRFToken)
		r.Header.Set("If-Deployment-Generation", state.DeploymentGeneration)
		r.Header.Set("Idempotency-Key", "00000000-0000-4000-8000-000000000114")
	}
	revoked := request(t, server, http.MethodDelete, "/api/v1/auth/tokens/"+token.Record.ID, "127.0.0.1:9443", "http://127.0.0.1:9443", nil, cookie, revokeHeaders)
	if revoked.Code != http.StatusOK {
		t.Fatalf("token revoke code=%d body=%s", revoked.Code, revoked.Body.String())
	}
	retried := request(t, server, http.MethodDelete, "/api/v1/auth/tokens/"+token.Record.ID, "127.0.0.1:9443", "http://127.0.0.1:9443", nil, cookie, revokeHeaders)
	if retried.Code != http.StatusOK || retried.Body.String() != revoked.Body.String() {
		t.Fatalf("token revoke retry code=%d equal=%t", retried.Code, retried.Body.String() == revoked.Body.String())
	}
	rejected := request(t, server, http.MethodGet, "/api/v1/auth/session", "127.0.0.1:9443", "", nil, nil, bearer)
	assertError(t, rejected, http.StatusUnauthorized, "api_token_rejected")
}

type requestOption func(*http.Request)

func request(t *testing.T, handler http.Handler, method, path, host, origin string, body any, cookie *http.Cookie, options ...requestOption) *httptest.ResponseRecorder {
	t.Helper()
	var reader *bytes.Reader
	if body == nil {
		reader = bytes.NewReader(nil)
	} else {
		encoded, _ := json.Marshal(body)
		reader = bytes.NewReader(encoded)
	}
	req := httptest.NewRequest(method, "http://"+host+path, reader)
	req.Host = host
	req.RemoteAddr = "127.0.0.1:40000"
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if origin != "" {
		req.Header.Set("Origin", origin)
	}
	if cookie != nil {
		req.AddCookie(cookie)
	}
	for _, option := range options {
		option(req)
	}
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, req)
	return recorder
}

func assertError(t *testing.T, recorder *httptest.ResponseRecorder, status int, code string) {
	t.Helper()
	if recorder.Code != status || !strings.Contains(recorder.Body.String(), `"code":"`+code+`"`) {
		t.Fatalf("error code=%d body=%s", recorder.Code, recorder.Body.String())
	}
}
