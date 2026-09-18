package lifecycle

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"os"
	"testing"
	"time"

	"rmt.local/monitor/internal/store"
)

func TestCollectorListenerRequiresExplicitPrivateEndpoint(t *testing.T) {
	for _, address := range []string{"", ":9444", "0.0.0.0:9444", "[::]:9444", "example.com:9444", "8.8.8.8:9444", "127.0.0.1:0", "127.0.0.1:09444", "[fe80::1%en0]:9444"} {
		if ValidateCollectorListenAddress(address) == nil {
			t.Errorf("accepted %q", address)
		}
	}
	for _, address := range []string{"127.0.0.1:9444", "[::1]:9444", "192.168.1.2:9444", "[fd00::1]:9444"} {
		if err := ValidateCollectorListenAddress(address); err != nil {
			t.Errorf("rejected %q: %v", address, err)
		}
	}
}

func TestCollectorListenerOptInPreservesTrustAndRequiresCurrentConfirmation(t *testing.T) {
	t.Setenv("LLM_MONITOR_EXPERIMENTAL", "1")
	ctx := context.Background()
	paths := testPaths(t)
	clock := fixedClock{now: time.Now().UTC().Truncate(time.Second)}
	manager := NewManager(paths, newFakeRunner(), clock)
	initial, err := manager.SetupLocal(ctx, false)
	if err != nil {
		t.Fatal(err)
	}
	st, err := store.OpenExisting(paths.Database, clock)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	if server, err := RemoteCollectorServer(paths, st, clock); err != nil || server != nil {
		t.Fatalf("default listener: %v, %v", server, err)
	}
	originalCA, _ := os.ReadFile(paths.CACert)
	originalKey, _ := os.ReadFile(paths.HubKey)
	originalConfig, _ := os.ReadFile(paths.HubConfig)
	manager.CollectorListenAddress, manager.CollectorListenExplicit = "192.168.1.2:9444", true
	if _, err := manager.SetupLocal(ctx, false); err == nil {
		t.Fatal("enabled network listener without confirmation")
	}
	unchanged, _ := os.ReadFile(paths.HubConfig)
	if string(unchanged) != string(originalConfig) {
		t.Fatal("rejected change altered configuration")
	}
	manager.ConfirmDeployment, manager.ConfirmGeneration = initial.DeploymentID, initial.DeploymentGeneration
	if _, err := manager.SetupLocal(ctx, false); err != nil {
		t.Fatal(err)
	}
	server, err := RemoteCollectorServer(paths, st, clock)
	if err != nil || server == nil || server.Addr != "192.168.1.2:9444" {
		t.Fatalf("configured server: %v, %v", server, err)
	}
	// Construction never binds this non-loopback address.
	ca, _ := os.ReadFile(paths.CACert)
	key, _ := os.ReadFile(paths.HubKey)
	if string(ca) != string(originalCA) || string(key) != string(originalKey) {
		t.Fatal("enabling remote collector replaced existing trust or key")
	}
	certificate, err := tls.LoadX509KeyPair(paths.HubCert, paths.HubKey)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := x509.ParseCertificate(certificate.Certificate[0])
	if err != nil || leaf.VerifyHostname("192.168.1.2") != nil {
		t.Fatal("server leaf does not bind reviewed IP")
	}
	savedLeaf, _ := os.ReadFile(paths.HubCert)
	repeated := NewManager(paths, newFakeRunner(), clock)
	if _, err := repeated.SetupLocal(ctx, false); err != nil {
		t.Fatal(err)
	}
	again, _ := os.ReadFile(paths.HubCert)
	if string(again) != string(savedLeaf) {
		t.Fatal("unchanged setup rotated certificate")
	}
	repeated.CollectorListenExplicit, repeated.CollectorListenAddress = true, ""
	repeated.ConfirmDeployment, repeated.ConfirmGeneration = initial.DeploymentID, initial.DeploymentGeneration
	if _, err := repeated.SetupLocal(ctx, false); err != nil {
		t.Fatal(err)
	}
	if server, err := RemoteCollectorServer(paths, st, clock); err != nil || server != nil {
		t.Fatalf("disabled listener: %v, %v", server, err)
	}
}
