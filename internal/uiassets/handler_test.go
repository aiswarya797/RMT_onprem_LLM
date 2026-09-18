package uiassets

import (
	"io/fs"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestHandlerServesBuiltAssetsWithStableTypes(t *testing.T) {
	t.Parallel()
	assets, err := fs.Glob(embedded, "dist/assets/*")
	if err != nil || len(assets) < 2 {
		t.Fatalf("built assets missing: assets=%v err=%v", assets, err)
	}
	for _, asset := range assets {
		route := "/" + strings.TrimPrefix(asset, "dist/")
		recorder := httptest.NewRecorder()
		Handler().ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, route, nil))
		if recorder.Code != http.StatusOK || recorder.Body.Len() == 0 {
			t.Fatalf("%s returned status=%d bytes=%d", route, recorder.Code, recorder.Body.Len())
		}
		expectedType := "text/css"
		if strings.HasSuffix(route, ".js") {
			expectedType = "javascript"
		}
		if contentType := recorder.Header().Get("Content-Type"); !strings.Contains(contentType, expectedType) {
			t.Fatalf("%s content type = %q", route, contentType)
		}
		if got := recorder.Header().Get("Cache-Control"); got != "public, max-age=31536000, immutable" {
			t.Fatalf("%s Cache-Control = %q", route, got)
		}
	}
}

func TestHandlerServesShellAndClientRoutes(t *testing.T) {
	t.Parallel()
	for _, route := range []string{"/", "/signed-in"} {
		recorder := httptest.NewRecorder()
		request := httptest.NewRequest(http.MethodGet, route, nil)
		Handler().ServeHTTP(recorder, request)
		if recorder.Code != http.StatusOK {
			t.Fatalf("%s returned %d", route, recorder.Code)
		}
		if !strings.Contains(recorder.Body.String(), "LLM Monitor") {
			t.Fatalf("%s did not receive the web shell", route)
		}
		if got := recorder.Header().Get("Cache-Control"); got != "no-store" {
			t.Fatalf("%s Cache-Control = %q", route, got)
		}
		if got := recorder.Header().Get("Content-Security-Policy"); !strings.Contains(got, "connect-src 'self'") {
			t.Fatalf("%s missing restrictive CSP: %q", route, got)
		}
	}
}

func TestHandlerDoesNotTurnMissingAPIsOrAssetsIntoHTML(t *testing.T) {
	t.Parallel()
	for _, route := range []string{"/api/v1/missing", "/assets/missing.js", "/missing.css"} {
		recorder := httptest.NewRecorder()
		Handler().ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, route, nil))
		if recorder.Code != http.StatusNotFound {
			t.Fatalf("%s returned %d, want 404", route, recorder.Code)
		}
	}
}

func TestHandlerSupportsHeadAndRejectsWrites(t *testing.T) {
	t.Parallel()
	head := httptest.NewRecorder()
	Handler().ServeHTTP(head, httptest.NewRequest(http.MethodHead, "/", nil))
	if head.Code != http.StatusOK || head.Body.Len() != 0 {
		t.Fatalf("HEAD returned status=%d body=%q", head.Code, head.Body.String())
	}

	post := httptest.NewRecorder()
	Handler().ServeHTTP(post, httptest.NewRequest(http.MethodPost, "/", nil))
	if post.Code != http.StatusMethodNotAllowed || post.Header().Get("Allow") != "GET, HEAD" {
		t.Fatalf("POST returned status=%d allow=%q", post.Code, post.Header().Get("Allow"))
	}
}
