package httpapi

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"rmt.local/monitor/internal/auth"
	"rmt.local/monitor/internal/config"
	"rmt.local/monitor/internal/store"
)

func TestRuleHTTPReviewedRevisionRetryAndSecurity(t *testing.T) {
	ctx := context.Background()
	clock := &apiClock{now: time.UnixMilli(1_800_000_600_000)}
	paths := config.ForHome(t.TempDir())
	st, err := store.Open(paths.Database, clock)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	state, _, err := st.EnsureDeployment(ctx, "Rule HTTP")
	if err != nil {
		t.Fatal(err)
	}
	service, err := auth.NewService(st, paths, clock)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, _, err := service.RenewBootstrap(ctx); err != nil {
		t.Fatal(err)
	}
	bootstrap, err := os.ReadFile(paths.BootstrapToken)
	if err != nil {
		t.Fatal(err)
	}
	session, rawSession, err := service.CreateFirstAdmin(ctx, strings.TrimSpace(string(bootstrap)), "admin", "a sufficiently long password", "127.0.0.1")
	if err != nil {
		t.Fatal(err)
	}
	const hostID = "72000000-0000-4000-8000-000000000001"
	if err := st.RegisterLocalHost(ctx, store.TrustedOwnerContext{DeploymentID: state.DeploymentID, SecurityGeneration: state.DeploymentGeneration, InstallingUID: 501, VerifiedOSOwner: true}, store.LocalHostRegistration{HostID: hostID, InstallationUUID: "72000000-0000-4000-8000-000000000002", DisplayName: "Mac", CollectorVersion: "fixture"}); err != nil {
		t.Fatal(err)
	}
	server := New(st, service, clock, "127.0.0.1:9443", nil)
	cookie := &http.Cookie{Name: sessionCookie, Value: rawSession}
	key := "72000000-0000-4000-8000-000000000003"
	headers := func(r *http.Request) {
		r.Header.Set("X-CSRF-Token", session.CSRFToken)
		r.Header.Set("If-Deployment-Generation", state.DeploymentGeneration)
		r.Header.Set("Idempotency-Key", key)
	}
	body := map[string]any{"expected_revision": nil, "evaluator_type": "heavy_cpu", "scope_id": hostID, "enabled": true, "metric_id": nil, "request_population": nil, "aggregation": nil, "threshold": 0.9, "dwell_ms": 60000, "recovery_ms": 60000}
	post := func(extra ...requestOption) *httptest.ResponseRecorder {
		return request(t, server, http.MethodPost, "/api/v1/rules", "127.0.0.1:9443", "http://127.0.0.1:9443", body, cookie, append([]requestOption{headers}, extra...)...)
	}
	assertError(t, post(func(r *http.Request) { r.Header.Del("X-CSRF-Token") }), 403, "csrf_required")
	assertError(t, post(func(r *http.Request) {
		r.Header.Set("If-Deployment-Generation", "72000000-0000-4000-8000-000000000004")
	}), 409, "restore_state_changed")
	delete(body, "enabled")
	assertError(t, post(), 400, "invalid_rule")
	body["enabled"] = true
	created := post()
	if created.Code != 201 {
		t.Fatalf("create code=%d body=%s", created.Code, created.Body.String())
	}
	var original store.RuleRecord
	if err := json.Unmarshal(created.Body.Bytes(), &original); err != nil {
		t.Fatal(err)
	}
	retry := post()
	if retry.Code != 201 || retry.Body.String() != created.Body.String() {
		t.Fatalf("retry changed result: %s", retry.Body.String())
	}
	body["enabled"] = false
	assertError(t, post(), 409, "idempotency_conflict")
	key = "72000000-0000-4000-8000-000000000005"
	body["expected_revision"] = 1
	updated := request(t, server, http.MethodPut, "/api/v1/rules/"+original.ID, "127.0.0.1:9443", "http://127.0.0.1:9443", body, cookie, headers)
	if updated.Code != 200 || !strings.Contains(updated.Body.String(), `"revision":2`) {
		t.Fatalf("edit code=%d body=%s", updated.Code, updated.Body.String())
	}
	key = "72000000-0000-4000-8000-000000000003"
	body["enabled"], body["expected_revision"] = true, nil
	oldRetry := post()
	if oldRetry.Code != 201 || oldRetry.Body.String() != created.Body.String() {
		t.Fatalf("old retry changed result: %s", oldRetry.Body.String())
	}
	current := request(t, server, http.MethodGet, "/api/v1/rules/"+original.ID, "127.0.0.1:9443", "", nil, cookie)
	if current.Code != 200 || !strings.Contains(current.Body.String(), `"revision":2`) || !strings.Contains(current.Body.String(), `"enabled":false`) {
		t.Fatalf("old retry changed current definition: %s", current.Body.String())
	}
	listed := request(t, server, http.MethodGet, "/api/v1/rules", "127.0.0.1:9443", "", nil, cookie)
	if listed.Code != 200 || !strings.Contains(listed.Body.String(), original.ID) {
		t.Fatalf("list failed: %s", listed.Body.String())
	}
}
