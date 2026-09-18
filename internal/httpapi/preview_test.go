package httpapi

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestPreviewBlocksExperimentalRoutesBeforeAnySideEffect(t *testing.T) {
	t.Setenv("LLM_MONITOR_EXPERIMENTAL", "")
	server := New(nil, nil, nil, "127.0.0.1:9443", nil)
	for _, path := range []string{"/api/v1/enrollments", "/api/v1/probes/run", "/api/v1/comparisons", "/api/v1/incidents/id/comparisons", "/api/v1/destinations/id/tests", "/api/v1/deliveries/id", "/api/v1/jobs/id"} {
		req := httptest.NewRequest(http.MethodPost, "http://127.0.0.1:9443"+path, nil)
		response := httptest.NewRecorder()
		server.ServeHTTP(response, req)
		if response.Code != http.StatusForbidden || !strings.Contains(response.Body.String(), "preview_feature_disabled") {
			t.Fatalf("%s: %d %s", path, response.Code, response.Body.String())
		}
	}
	for _, path := range []string{"/api/v1/status", "/api/v1/overview", "/api/v1/series", "/api/v1/incidents", "/api/v1/rules"} {
		if experimentalRoute(path) {
			t.Fatalf("local workflow gated: %s", path)
		}
	}
}
