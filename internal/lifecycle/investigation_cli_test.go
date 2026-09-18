package lifecycle

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestIncidentCLIUpdatesPreserveReviewedRevisionAndRejectIgnoredChanges(t *testing.T) {
	tokenPath := filepath.Join(t.TempDir(), "token")
	if err := os.WriteFile(tokenPath, []byte(strings.Repeat("x", 48)), 0o600); err != nil {
		t.Fatal(err)
	}
	const incident = "00000000-0000-4000-8000-000000000001"
	const generation = "00000000-0000-4000-8000-000000000002"
	const key = "00000000-0000-4000-8000-000000000003"
	requests := 0
	var body map[string]any
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests++
		if r.Method != http.MethodPatch || r.URL.Path != "/api/v1/incidents/"+incident || r.Header.Get("If-Deployment-Generation") != generation || r.Header.Get("Idempotency-Key") != key {
			t.Error("mutation lost its method, target, generation or retry identity")
		}
		body = nil
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Error(err)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"schema_version":"1.0"}`))
	}))
	defer server.Close()
	manager := NewManager(testPaths(t), newFakeRunner(), fixedClock{time.UnixMilli(1800000000000)})
	manager.ListenAddress, manager.ListenAddressExplicit = strings.TrimPrefix(server.URL, "http://"), true
	var output, stderr bytes.Buffer
	run := func(operation string, extra ...string) int {
		output.Reset()
		stderr.Reset()
		args := []string{"incidents", operation, "--id", incident, "--expected-revision", "7", "--deployment-generation", generation, "--idempotency-key", key, "--token-file", tokenPath, "--json"}
		return RunCLI(context.Background(), append(args, extra...), &output, &stderr, manager)
	}
	if code := run("close"); code != 0 || body["workflow_state"] != "closed" || body["expected_revision"] != float64(7) || len(body) != 2 {
		t.Fatalf("close code=%d body=%v output=%s", code, body, output.String())
	}
	if code := run("reopen"); code != 0 || body["workflow_state"] != "open" {
		t.Fatalf("reopen code=%d body=%v", code, body)
	}
	title := strings.Repeat("観", 160)
	if code := run("update", "--title", title); code != 0 || body["title"] != title || len(body) != 2 {
		t.Fatalf("Unicode title within schema limit rejected: code=%d output=%s", code, output.String())
	}
	before := requests
	for _, options := range [][]string{{"--title", "", "--workflow-state", "closed"}, {"--title", strings.Repeat("観", 161)}, {"--workflow-state", "resolved"}, {"--start", "2026-09-16T00:00:00Z"}} {
		if code := run("update", options...); code != 2 {
			t.Fatalf("invalid edit accepted: %v code=%d", options, code)
		}
	}
	if code := run("close", "--title", "ignored"); code != 2 || requests != before {
		t.Fatal("unsupported or empty changes reached the API")
	}
}

func TestAlertControlCLIUsesReviewedInputAndStableRetry(t *testing.T) {
	tokenPath := filepath.Join(t.TempDir(), "token")
	if err := os.WriteFile(tokenPath, []byte(strings.Repeat("x", 48)), 0o600); err != nil {
		t.Fatal(err)
	}
	const incident = "00000000-0000-4000-8000-000000000001"
	const generation = "00000000-0000-4000-8000-000000000002"
	const key = "00000000-0000-4000-8000-000000000003"
	type captured struct{ method, path, body string }
	var calls []captured
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		payload, err := io.ReadAll(io.LimitReader(r.Body, 65537))
		if err != nil {
			t.Error(err)
		}
		calls = append(calls, captured{r.Method, r.URL.Path, string(payload)})
		if r.Header.Get("If-Deployment-Generation") != generation || r.Header.Get("Idempotency-Key") != key {
			t.Error("missing reviewed generation or retry identity")
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"notification_may_be_in_flight":false}`))
	}))
	defer server.Close()
	manager := NewManager(testPaths(t), newFakeRunner(), fixedClock{time.UnixMilli(1800000000000)})
	manager.ListenAddress, manager.ListenAddressExplicit = strings.TrimPrefix(server.URL, "http://"), true
	run := func(operation string, extra ...string) int {
		var output, stderr bytes.Buffer
		args := []string{"incidents", operation, "--id", incident, "--deployment-generation", generation, "--idempotency-key", key, "--token-file", tokenPath, "--json"}
		return RunCLI(context.Background(), append(args, extra...), &output, &stderr, manager)
	}
	for _, test := range []struct {
		operation, method, suffix, body string
		flags                           []string
	}{
		{"acknowledge", "POST", "/acknowledgements", `{"observed_transition_seq":7}`, []string{"--observed-transition-seq", "7"}},
		{"mute", "POST", "/mute", `{"reason":"Planned maintenance","expires_ms":1800003600000}`, []string{"--reason", "Planned maintenance", "--expires", time.UnixMilli(1800003600000).UTC().Format(time.RFC3339)}},
		{"unmute", "DELETE", "/mute", "", nil},
	} {
		before := len(calls)
		for range 2 {
			if code := run(test.operation, test.flags...); code != 0 {
				t.Fatalf("%s code=%d", test.operation, code)
			}
		}
		if len(calls) != before+2 || calls[before] != calls[before+1] || calls[before].method != test.method || calls[before].path != "/api/v1/incidents/"+incident+test.suffix || calls[before].body != test.body {
			t.Fatalf("%s wire calls=%#v", test.operation, calls[before:])
		}
	}
	before := len(calls)
	if run("acknowledge") != 2 || run("mute", "--reason", "ignored") != 2 || run("unmute", "--observed-transition-seq", "7") != 2 || len(calls) != before {
		t.Fatal("invalid or ignored control input reached the API")
	}
}
