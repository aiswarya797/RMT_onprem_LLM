package lifecycle

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"rmt.local/monitor/internal/collector/pairing"
	"rmt.local/monitor/internal/collector/remote"
	"rmt.local/monitor/internal/collector/scheduler"
	"rmt.local/monitor/internal/domain"
	"rmt.local/monitor/internal/enrollment"
	"rmt.local/monitor/internal/store"
)

// TestRemoteCollectorSetupOverLoopbackTLS uses two disjoint installation
// roots. It proves the one-use bootstrap exchange and the executable
// collector's certificate-authenticated session/inventory path without
// opening an external interface or contacting an Ollama runtime.
func TestRemoteCollectorSetupOverLoopbackTLS(t *testing.T) {
	t.Setenv("LLM_MONITOR_EXPERIMENTAL", "1")
	now := time.Now().UTC().Truncate(time.Second)
	clock := fixedClock{now: now}
	hubPaths := testPaths(t)
	collectorPaths := testPaths(t)
	if hubPaths.Home == collectorPaths.Home {
		t.Fatal("hub and collector test installations must be disjoint")
	}
	if _, err := ensureLocalCA(hubPaths, now); err != nil {
		t.Fatal(err)
	}
	caPEM, err := os.ReadFile(hubPaths.CACert)
	if err != nil {
		t.Fatal(err)
	}
	caKeyPEM, err := os.ReadFile(hubPaths.CAKey)
	if err != nil {
		t.Fatal(err)
	}
	authority, err := enrollment.NewAuthority(caPEM, caKeyPEM, clock)
	if err != nil {
		t.Fatal(err)
	}

	hubStore, err := store.Open(hubPaths.Database, clock)
	if err != nil {
		t.Fatal(err)
	}
	defer hubStore.Close()
	deployment, _, err := hubStore.EnsureDeployment(context.Background(), "TLS workflow")
	if err != nil {
		t.Fatal(err)
	}
	bootstrapHash := "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	if err := hubStore.PutFirstAdminBootstrap(context.Background(), bootstrapHash, now.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	admin, err := hubStore.ConsumeBootstrapAndCreateAdmin(context.Background(), bootstrapHash, "admin", "test-password-hash-with-at-least-32-bytes")
	if err != nil {
		t.Fatal(err)
	}
	actor := store.SessionRecord{User: admin, DeploymentID: deployment.DeploymentID, Generation: deployment.DeploymentGeneration, ExpiresMS: now.Add(time.Hour).UnixMilli()}

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	serverCertificate, err := tls.LoadX509KeyPair(hubPaths.HubCert, hubPaths.HubKey)
	if err != nil {
		listener.Close()
		t.Fatal(err)
	}
	clientRoots := x509.NewCertPool()
	if !clientRoots.AppendCertsFromPEM(caPEM) {
		listener.Close()
		t.Fatal("load collector client CA")
	}
	remoteHandler, err := remote.NewHandler(hubStore, authority)
	if err != nil {
		listener.Close()
		t.Fatal(err)
	}
	tlsConfig, err := remote.ServerTLSConfig(serverCertificate, clientRoots)
	if err != nil {
		listener.Close()
		t.Fatal(err)
	}
	server, err := remote.NewServer(listener.Addr().String(), remoteHandler, tlsConfig)
	if err != nil {
		listener.Close()
		t.Fatal(err)
	}
	serverErr := make(chan error, 1)
	go func() { serverErr <- server.ServeTLS(listener, "", "") }()
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = server.Shutdown(ctx)
		if err := <-serverErr; err != nil && !errors.Is(err, http.ErrServerClosed) {
			t.Errorf("remote TLS server: %v", err)
		}
	})

	token, tokenHash, err := enrollment.NewToken()
	if err != nil {
		t.Fatal(err)
	}
	remoteHostID, err := domain.NewUUID()
	if err != nil {
		t.Fatal(err)
	}
	hubURL := "https://" + listener.Addr().String()
	reservation, err := hubStore.ReserveCollectorEnrollment(context.Background(), actor, tokenHash, remoteHostID, "Remote Mac", hubURL, authority.FingerprintSHA256())
	if err != nil {
		t.Fatal(err)
	}
	enrollmentPath := filepath.Join(collectorPaths.Support, "remote-enrollment.json")
	file := enrollment.File{SchemaVersion: domain.SchemaVersion, DeploymentID: deployment.DeploymentID, HostID: remoteHostID, HubURL: hubURL, HubCAFingerprintSHA256: authority.FingerprintSHA256(), HubCACertificatePEM: string(caPEM), Token: token, ExpiresMS: reservation.ExpiresMS}
	if err := writeJSONFile(enrollmentPath, file); err != nil {
		t.Fatal(err)
	}

	collectorManager := NewManager(collectorPaths, newFakeRunner(), clock)
	configured, err := collectorManager.SetupCollector(context.Background(), enrollmentPath, false)
	if err != nil {
		t.Fatal(err)
	}
	if configured.DeploymentID != deployment.DeploymentID || configured.HostID != remoteHostID || configured.CollectorState != "not_started" {
		t.Fatalf("remote setup result=%#v", configured)
	}
	for _, path := range []string{collectorPaths.CollectorKey, collectorPaths.CollectorCert, collectorPaths.CollectorCA, collectorPaths.RemoteCollectorConfig} {
		if err := configPrivateFile(path); err != nil {
			t.Fatal(err)
		}
	}
	repeatManager := NewManager(collectorPaths, newFakeRunner(), fixedClock{now: now.Add(11 * time.Minute)})
	repeated, err := repeatManager.SetupCollector(context.Background(), enrollmentPath, false)
	if err != nil || repeated.Status != "already_configured" || repeated.HostID != remoteHostID || repeated.CertificateExpiresMS != configured.CertificateExpiresMS {
		t.Fatalf("expired-token repeat changed configured identity: result=%#v err=%v", repeated, err)
	}
	changedFile := file
	changedFile.HostID, _ = domain.NewUUID()
	if err := writeJSONFile(enrollmentPath, changedFile); err != nil {
		t.Fatal(err)
	}
	if _, err := repeatManager.SetupCollector(context.Background(), enrollmentPath, false); err == nil {
		t.Fatal("changed enrollment identity was accepted over active configuration")
	}

	runContext, cancelRun := context.WithCancel(context.Background())
	runErr := make(chan error, 1)
	go func() { runErr <- scheduler.Run(runContext, collectorPaths) }()
	deadline := time.Now().Add(10 * time.Second)
	for {
		inventory, readErr := hubStore.ReadQueryInventory(context.Background())
		if readErr == nil && enrolledHostReady(inventory, remoteHostID) {
			break
		}
		if time.Now().After(deadline) {
			cancelRun()
			<-runErr
			t.Fatalf("remote collector did not activate and register inventory: %v", readErr)
		}
		time.Sleep(20 * time.Millisecond)
	}
	cancelRun()
	if err := <-runErr; err != nil {
		t.Fatalf("remote collector shutdown: %v", err)
	}
}

func enrolledHostReady(inventory store.QueryInventory, hostID string) bool {
	for _, host := range inventory.Hosts {
		if host.ID != hostID || host.CurrentSessionGeneration < 1 || host.LastBootID == nil {
			continue
		}
		for _, source := range inventory.Sources {
			if source.HostID == hostID && source.Kind == "host" && source.RetiredMS == nil {
				return true
			}
		}
	}
	return false
}

func configPrivateFile(path string) error {
	info, err := os.Stat(path)
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() || info.Mode().Perm() != 0o600 {
		return errors.New("remote collector artifact is not a private regular file")
	}
	return nil
}

func TestReEnrollmentJournalAcceptsOnlyOldOrIssuedPairingGeneration(t *testing.T) {
	deployment := "11111111-1111-4111-8111-111111111111"
	host := "22222222-2222-4222-8222-222222222222"
	installation := "33333333-3333-4333-8333-333333333333"
	oldGeneration := "44444444-4444-4444-8444-444444444444"
	newGeneration := "55555555-5555-4555-8555-555555555555"
	oldFingerprint := "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	newFingerprint := "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	file := enrollment.File{SchemaVersion: domain.SchemaVersion, DeploymentID: deployment, HostID: host, HubURL: "https://127.0.0.1:9444", HubCAFingerprintSHA256: newFingerprint}
	remoteConfig := enrollment.RemoteConfig{SchemaVersion: domain.SchemaVersion, DeploymentID: deployment, DeploymentGeneration: oldGeneration, HostID: host, InstallationID: installation, HubURL: file.HubURL, HubCAFingerprintSHA256: oldFingerprint}
	result := enrollment.ExchangeResult{Protocol: domain.ProtocolVersion, DeploymentID: deployment, HostID: host, SecurityGeneration: newGeneration, HubCAFingerprintSHA256: newFingerprint}
	journal := remoteReEnrollmentJournal{SchemaVersion: domain.SchemaVersion, State: "issued", DeploymentID: deployment, HostID: host, InstallationID: installation, PreviousGeneration: oldGeneration, HubURL: file.HubURL, PreviousCAFingerprint: oldFingerprint, NextCAFingerprint: newFingerprint, CSRPEM: "-----BEGIN CERTIFICATE REQUEST-----\n" + strings.Repeat("A", 80), IdempotencyKey: "66666666-6666-4666-8666-666666666666", StartedMS: 1, Result: &result}
	for _, generation := range []string{oldGeneration, newGeneration} {
		retained := pairing.State{Version: 1, DeploymentID: deployment, Generation: generation, InstallationID: installation, HostID: host, HostSourceID: "77777777-7777-4777-8777-777777777777"}
		if err := validateReEnrollmentJournal(journal, file, remoteConfig, retained); err != nil {
			t.Fatalf("generation %s rejected: %v", generation, err)
		}
	}
	foreign := pairing.State{Version: 1, DeploymentID: deployment, Generation: "88888888-8888-4888-8888-888888888888", InstallationID: installation, HostID: host, HostSourceID: "77777777-7777-4777-8777-777777777777"}
	if err := validateReEnrollmentJournal(journal, file, remoteConfig, foreign); err == nil {
		t.Fatal("unrelated pairing generation admitted during retry")
	}
}
