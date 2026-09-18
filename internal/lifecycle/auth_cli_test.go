package lifecycle

import (
	"bytes"
	"context"
	"encoding/json"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"rmt.local/monitor/internal/config"
	"rmt.local/monitor/internal/domain"
	"rmt.local/monitor/internal/enrollment"
	"rmt.local/monitor/internal/protocol"
	"rmt.local/monitor/internal/store"
)

func TestAuthTokenCLIUsesPrivateBearerAndNeverPrintsCreatedSecret(t *testing.T) {
	paths := testPaths(t)
	if err := config.EnsurePrivateDir(paths.Support); err != nil {
		t.Fatal(err)
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	deploymentID := "00000000-0000-4000-8000-000000000101"
	generation := "00000000-0000-4000-8000-000000000102"
	hubConfig := savedHubConfig{SchemaVersion: domain.SchemaVersion, DeploymentID: deploymentID, Listen: listener.Addr().String(), Database: paths.Database, OwnerSocket: paths.HubSocket, CollectionEnabled: true}
	if err := writeJSONFile(paths.HubConfig, hubConfig); err != nil {
		t.Fatal(err)
	}
	existingToken := strings.Repeat("e", 43)
	existingPath := filepath.Join(paths.Support, "existing-api.token")
	createdPath := filepath.Join(paths.Support, "created-api.token")
	if err := config.WritePrivateFile(existingPath, []byte(existingToken+"\n")); err != nil {
		t.Fatal(err)
	}
	createdSecret := strings.Repeat("n", 43)
	record := store.APITokenRecord{ID: strings.Repeat("a", 64), UserID: "00000000-0000-4000-8000-000000000103", Username: "admin", DisplayName: "Automation", Scope: "admin", CreatedMS: 1_800_000_000_000, ExpiresMS: 1_800_003_600_000}
	var mu sync.Mutex
	seen := map[string]int{}
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		seen[r.Method+" "+r.URL.Path]++
		mu.Unlock()
		if r.Header.Get("Authorization") != "Bearer "+existingToken {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/api/v1/auth/tokens":
			_ = protocol.WriteJSON(w, apiTokenListBody{Items: []store.APITokenRecord{record}})
		case r.Method == http.MethodPost && r.URL.Path == "/api/v1/auth/tokens":
			if r.Header.Get("If-Deployment-Generation") != generation || r.Header.Get("Idempotency-Key") == "" {
				http.Error(w, "headers", http.StatusBadRequest)
				return
			}
			_ = protocol.WriteJSON(w, store.APITokenOnce{Token: createdSecret, Record: record})
		case r.Method == http.MethodDelete && r.URL.Path == "/api/v1/auth/tokens/"+record.ID:
			_ = protocol.WriteJSON(w, apiTokenRevokeBody{ID: record.ID, RevokedMS: 1_800_000_000_100})
		default:
			http.NotFound(w, r)
		}
	})
	server := &http.Server{Handler: handler}
	serverErr := make(chan error, 1)
	go func() { serverErr <- server.Serve(listener) }()
	defer func() {
		_ = server.Shutdown(context.Background())
		<-serverErr
	}()
	manager := NewManager(paths, newFakeRunner(), fixedClock{now: time.UnixMilli(1_800_000_000_000)})
	var stdout, stderr bytes.Buffer
	code := RunCLI(context.Background(), []string{"auth", "token", "create", "--token-file", existingPath, "--output-token-file", createdPath, "--name", "Automation", "--expires", "1h", "--deployment-generation", generation, "--idempotency-key", "00000000-0000-4000-8000-000000000104", "--json"}, &stdout, &stderr, manager)
	if code != 0 || strings.Contains(stdout.String(), createdSecret) || stderr.Len() != 0 {
		t.Fatalf("create code=%d stdout=%q stderr=%q", code, stdout.String(), stderr.String())
	}
	written, err := os.ReadFile(createdPath)
	if err != nil || strings.TrimSpace(string(written)) != createdSecret {
		t.Fatalf("created token file=%q err=%v", written, err)
	}
	if info, err := os.Stat(createdPath); err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("created token permissions info=%v err=%v", info, err)
	}
	stdout.Reset()
	if code := RunCLI(context.Background(), []string{"auth", "token", "list", "--token-file", existingPath, "--json"}, &stdout, &stderr, manager); code != 0 || !strings.Contains(stdout.String(), record.ID) {
		t.Fatalf("list code=%d stdout=%q stderr=%q", code, stdout.String(), stderr.String())
	}
	stdout.Reset()
	if code := RunCLI(context.Background(), []string{"auth", "token", "revoke", "--token-file", existingPath, "--token", record.ID, "--deployment-generation", generation, "--idempotency-key", "00000000-0000-4000-8000-000000000105", "--json"}, &stdout, &stderr, manager); code != 0 || !strings.Contains(stdout.String(), record.ID) {
		t.Fatalf("revoke code=%d stdout=%q stderr=%q", code, stdout.String(), stderr.String())
	}
	mu.Lock()
	defer mu.Unlock()
	if seen["POST /api/v1/auth/tokens"] != 1 || seen["GET /api/v1/auth/tokens"] != 1 || seen["DELETE /api/v1/auth/tokens/"+record.ID] != 1 {
		encoded, _ := json.Marshal(seen)
		t.Fatalf("unexpected API calls %s", encoded)
	}
}

func TestHostsEnrollCLIStoresOneUseSecretOnlyInPrivateFile(t *testing.T) {
	paths := testPaths(t)
	now := time.Now().UTC().Truncate(time.Second)
	if err := config.EnsurePrivateDir(paths.Support); err != nil {
		t.Fatal(err)
	}
	if _, err := ensureLocalCA(paths, now); err != nil {
		t.Fatal(err)
	}
	caPEM, _ := os.ReadFile(paths.CACert)
	fingerprint, err := enrollment.FingerprintCertificatePEM(caPEM)
	if err != nil {
		t.Fatal(err)
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	deploymentID := "00000000-0000-4000-8000-000000000131"
	generation := "00000000-0000-4000-8000-000000000132"
	if err := writeJSONFile(paths.HubConfig, savedHubConfig{SchemaVersion: domain.SchemaVersion, DeploymentID: deploymentID, Listen: listener.Addr().String(), Database: paths.Database, OwnerSocket: paths.HubSocket, CollectionEnabled: true, CollectorListen: "127.0.0.1:9444"}); err != nil {
		t.Fatal(err)
	}
	adminBearer := strings.Repeat("a", 43)
	adminTokenPath := filepath.Join(paths.Support, "admin-api.token")
	if err := config.WritePrivateFile(adminTokenPath, []byte(adminBearer+"\n")); err != nil {
		t.Fatal(err)
	}
	enrollmentSecret := strings.Repeat("s", 43)
	hostID := "00000000-0000-4000-8000-000000000133"
	server := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/api/v1/enrollments" || r.Header.Get("Authorization") != "Bearer "+adminBearer || r.Header.Get("If-Deployment-Generation") != generation {
			http.Error(w, "unexpected request", http.StatusBadRequest)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = protocol.WriteJSON(w, store.EnrollmentToken{HostID: hostID, Token: enrollmentSecret, ExpiresMS: now.Add(enrollment.TokenValidity).UnixMilli(), HubURL: "https://127.0.0.1:9444", HubCAFingerprintSHA256: fingerprint})
	})}
	serverErr := make(chan error, 1)
	go func() { serverErr <- server.Serve(listener) }()
	defer func() {
		_ = server.Shutdown(context.Background())
		<-serverErr
	}()
	manager := NewManager(paths, newFakeRunner(), fixedClock{now: now})
	outputPath := filepath.Join(paths.Support, "remote.enrollment.json")
	var stdout, stderr bytes.Buffer
	code := RunCLI(context.Background(), []string{"hosts", "enroll", "--token-file", adminTokenPath, "--name", "Second Mac", "--output-enrollment-file", outputPath, "--deployment-generation", generation, "--idempotency-key", "00000000-0000-4000-8000-000000000134", "--json"}, &stdout, &stderr, manager)
	if code != 0 || strings.Contains(stdout.String(), enrollmentSecret) || stderr.Len() != 0 {
		t.Fatalf("hosts enroll code=%d stdout=%q stderr=%q", code, stdout.String(), stderr.String())
	}
	if info, err := os.Stat(outputPath); err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("enrollment permissions info=%v err=%v", info, err)
	}
	file, err := readEnrollmentFile(outputPath, now)
	if err != nil || file.Token != enrollmentSecret || file.DeploymentID != deploymentID || file.HostID != hostID {
		t.Fatalf("enrollment file=%#v err=%v", file, err)
	}
}
