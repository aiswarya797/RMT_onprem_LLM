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
	"rmt.local/monitor/internal/notify"
	"rmt.local/monitor/internal/store"
)

func TestDestinationHTTPSecretPrivacyAndExactRetry(t *testing.T) {
	t.Setenv("LLM_MONITOR_EXPERIMENTAL", "1")
	ctx := context.Background()
	clock := &apiClock{now: time.UnixMilli(1800000600000)}
	paths := config.ForHome(t.TempDir())
	st, err := store.Open(paths.Database, clock)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	state, _, err := st.EnsureDeployment(ctx, "Destination HTTP")
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
	s := New(st, service, clock, "127.0.0.1:9443", nil)
	s.ConfigureNotifications(notify.Vault{Dir: paths.NotificationSecrets, KeyFile: paths.NotificationKey})
	cookie := &http.Cookie{Name: sessionCookie, Value: rawSession}
	key := "d7200000-0000-4000-8000-000000000003"
	headers := func(r *http.Request) {
		r.Header.Set("X-CSRF-Token", session.CSRFToken)
		r.Header.Set("If-Deployment-Generation", state.DeploymentGeneration)
		r.Header.Set("Idempotency-Key", key)
	}
	body := map[string]any{"expected_revision": nil, "type": "webhook", "display_name": "Fixture receiver", "webhook": map[string]any{"https_url": "https://localhost:9444/events", "hmac_enabled": true}, "smtp": nil, "secret_input": "destination-secret-canary"}
	post := func(extra ...requestOption) *httptest.ResponseRecorder {
		return request(t, s, http.MethodPost, "/api/v1/destinations", "127.0.0.1:9443", "http://127.0.0.1:9443", body, cookie, append([]requestOption{headers}, extra...)...)
	}
	assertError(t, post(func(r *http.Request) { r.Header.Del("X-CSRF-Token") }), 403, "csrf_required")
	created := post()
	if created.Code != 201 {
		t.Fatalf("create %d %s", created.Code, created.Body.String())
	}
	if strings.Contains(created.Body.String(), "destination-secret-canary") || strings.Contains(created.Body.String(), "secret_ref") {
		t.Fatal("secret leaked in response")
	}
	if retry := post(); retry.Body.String() != created.Body.String() {
		t.Fatalf("retry changed: %s", retry.Body.String())
	}
	var original destinationResponse
	if err := json.Unmarshal(created.Body.Bytes(), &original); err != nil {
		t.Fatal(err)
	}
	key = "d7200000-0000-4000-8000-000000000004"
	body["expected_revision"], body["display_name"], body["secret_input"] = 1, "Changed name", nil
	edited := request(t, s, http.MethodPut, "/api/v1/destinations/"+original.ID, "127.0.0.1:9443", "http://127.0.0.1:9443", body, cookie, headers)
	if edited.Code != 200 || !strings.Contains(edited.Body.String(), `"revision":2`) {
		t.Fatalf("edit %d %s", edited.Code, edited.Body.String())
	}
	key = "d7200000-0000-4000-8000-000000000003"
	body["expected_revision"], body["display_name"], body["secret_input"] = nil, "Fixture receiver", "destination-secret-canary"
	if retry := post(); retry.Body.String() != created.Body.String() {
		t.Fatal("historical retry lost original receipt")
	}
	for _, path := range []string{paths.Database, paths.Database + "-wal"} {
		data, _ := os.ReadFile(path)
		if strings.Contains(string(data), "destination-secret-canary") {
			t.Fatal("secret stored in database")
		}
	}
	key = "d7200000-0000-4000-8000-000000000005"
	removed := request(t, s, http.MethodDelete, "/api/v1/destinations/"+original.ID, "127.0.0.1:9443", "http://127.0.0.1:9443", nil, cookie, headers, func(r *http.Request) { r.Header.Set("If-Match", "2") })
	if removed.Code != 204 {
		t.Fatalf("remove %d %s", removed.Code, removed.Body.String())
	}
}
