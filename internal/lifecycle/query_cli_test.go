package lifecycle

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestReadAndInvestigationCLIKeepQueriesAndExactJSON(t *testing.T) {
	token := strings.Repeat("x", 48)
	tokenPath := filepath.Join(t.TempDir(), "token")
	if err := os.WriteFile(tokenPath, []byte(token), 0o600); err != nil {
		t.Fatal(err)
	}
	var gotPath string
	var gotQuery map[string][]string
	requests := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests++
		if r.Method != http.MethodGet || r.Header.Get("Authorization") != "Bearer "+token {
			t.Error("read lost method or credential")
		}
		gotPath, gotQuery = r.URL.Path, r.URL.Query()
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"schema_version":"1.0","exact":"18446744073709551615","items":[],"next_cursor":null}`))
	}))
	defer server.Close()
	manager := NewManager(testPaths(t), newFakeRunner(), fixedClock{time.UnixMilli(1800000000000)})
	manager.ListenAddress, manager.ListenAddressExplicit = strings.TrimPrefix(server.URL, "http://"), true
	var output, stderr bytes.Buffer
	run := func(args ...string) int {
		output.Reset()
		stderr.Reset()
		return RunCLI(context.Background(), append(args, "--token-file", tokenPath, "--json"), &output, &stderr, manager)
	}
	if code := run("series", "query", "--scope", "00000000-0000-4000-8000-000000000001", "--metric", "host.cpu.busy_ratio", "--start", "2026-09-16T10:00:00+05:30", "--end", "2026-09-16T10:05:00+05:30"); code != 0 {
		t.Fatalf("series code=%d %s", code, output.String())
	}
	if gotPath != "/api/v1/series" || gotQuery["start"][0] != "2026-09-16T04:30:00Z" || gotQuery["resolution"][0] != "auto" || !strings.Contains(output.String(), "18446744073709551615") {
		t.Fatalf("series query/output lost semantics: %s %#v %s", gotPath, gotQuery, output.String())
	}
	if code := run("incidents", "list", "--limit", "25", "--cursor", "00000000-0000-4000-8000-000000000002"); code != 0 {
		t.Fatalf("list: %s", output.String())
	}
	if gotPath != "/api/v1/incidents" || gotQuery["limit"][0] != "25" || gotQuery["cursor"][0] != "00000000-0000-4000-8000-000000000002" {
		t.Fatalf("list cursor lost: %s %#v", gotPath, gotQuery)
	}
	if code := run("annotations", "list", "--incident", "00000000-0000-4000-8000-000000000003", "--limit", "10"); code != 0 {
		t.Fatalf("annotation list: %s", output.String())
	}
	if gotPath != "/api/v1/incidents/00000000-0000-4000-8000-000000000003/annotations" || gotQuery["limit"][0] != "10" {
		t.Fatalf("annotation path: %s %#v", gotPath, gotQuery)
	}
	before := requests
	if code := run("monitor-health", "show"); code != 0 || gotPath != "/api/v1/monitor-health/summary" || len(gotQuery) != 0 {
		t.Fatalf("monitor health path/code lost: %s %s", gotPath, output.String())
	}
	before = requests
	if code := run("monitor-health", "show", "--id", "00000000-0000-4000-8000-000000000003"); code != 2 {
		t.Fatalf("ignored monitor health option code=%d", code)
	}
	if code := run("incidents", "list", "--limit", "101"); code != 2 {
		t.Fatalf("invalid page code=%d", code)
	}
	if code := run("hosts", "list", "--start", "2026-09-16T00:00:00Z"); code != 2 {
		t.Fatalf("ignored option code=%d", code)
	}
	if requests != before {
		t.Fatal("invalid input reached the API")
	}
}
