package lifecycle

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestRulesCLIPreservesExactReviewedDefinitionOnRetry(t *testing.T) {
	const id = "00000000-0000-4000-8000-000000000001"
	const generation = "00000000-0000-4000-8000-000000000002"
	const key = "00000000-0000-4000-8000-000000000003"
	directory := t.TempDir()
	token, definition := filepath.Join(directory, "token"), filepath.Join(directory, "rule.json")
	for path, content := range map[string]string{token: strings.Repeat("x", 48), definition: `{"expected_revision":7,"enabled":false}`} {
		if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	var bodies []string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPut || r.URL.Path != "/api/v1/rules/"+id || r.Header.Get("If-Deployment-Generation") != generation || r.Header.Get("Idempotency-Key") != key {
			t.Error("rule request lost reviewed method, identity, generation or retry key")
		}
		body, _ := io.ReadAll(r.Body)
		bodies = append(bodies, string(body))
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"revision":8}`))
	}))
	defer server.Close()
	manager := NewManager(testPaths(t), newFakeRunner(), fixedClock{time.UnixMilli(1800000000000)})
	manager.ListenAddress, manager.ListenAddressExplicit = strings.TrimPrefix(server.URL, "http://"), true
	args := []string{"rules", "disable", "--id", id, "--definition-file", definition, "--deployment-generation", generation, "--idempotency-key", key, "--token-file", token, "--json"}
	for range 2 {
		var stdout, stderr bytes.Buffer
		if code := RunCLI(context.Background(), args, &stdout, &stderr, manager); code != 0 {
			t.Fatalf("rule retry code=%d stdout=%s stderr=%s", code, stdout.String(), stderr.String())
		}
	}
	if len(bodies) != 2 || bodies[0] != bodies[1] || bodies[0] != `{"expected_revision":7,"enabled":false}` {
		t.Fatalf("rule retry changed reviewed body: %v", bodies)
	}
	if code := RunCLI(context.Background(), append(args, "--unknown", "ignored"), &bytes.Buffer{}, &bytes.Buffer{}, manager); code != 2 || len(bodies) != 2 {
		t.Fatal("invalid option reached mutation API")
	}
}

func TestRuleDefinitionIsBoundedAndRejectsAmbiguousJSON(t *testing.T) {
	path := filepath.Join(t.TempDir(), "definition.json")
	for _, data := range []string{`null`, `[]`, `{"enabled":false,"enabled":true}`, `{"enabled":false} {}`, strings.Repeat(" ", 64<<10) + "{}", `{"enabled":true}`} {
		if err := os.WriteFile(path, []byte(data), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := readRuleDefinition(path, "disable"); err == nil {
			t.Fatalf("invalid disable definition accepted (%d bytes)", len(data))
		}
	}
}
