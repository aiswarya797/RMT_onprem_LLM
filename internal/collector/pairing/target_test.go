package pairing

import (
	"strings"
	"testing"
)

func testManifest() TargetManifest {
	return TargetManifest{SchemaVersion: "1.0", ManifestID: id, ManifestRevision: 1, AdapterID: "ollama", Endpoint: Endpoint{Scheme: "http", Host: "127.0.0.1", Port: 11434}, IdentityRevision: strings.Repeat("a", 64), DisplayName: "Local Ollama"}
}

func TestTargetChangeIsDurableIdempotentAndKeepsHistoricalEndpointIdentity(t *testing.T) {
	dir := t.TempDir()
	manifest := testManifest()
	hash := strings.Repeat("b", 64)
	first, err := ApplyTarget(dir, id, id, "add", "", 0, &manifest, hash)
	if err != nil {
		t.Fatal(err)
	}
	retry, err := ApplyTarget(dir, id, id, "add", "", 0, &manifest, hash)
	if err != nil || *retry.ResourceID != *first.ResourceID {
		t.Fatalf("retry changed identity: %+v %v", retry, err)
	}
	manifest.DisplayName = "Different"
	if _, err := ApplyTarget(dir, id, id, "add", "", 0, &manifest, hash); err == nil {
		t.Fatal("idempotency key accepted different request")
	}
	manifest.ManifestRevision = 2
	manifest.Endpoint.Port = 11435
	changed, err := ApplyTarget(dir, id, boot, "edit", *first.ResourceID, 1, &manifest, hash)
	if err != nil {
		t.Fatal(err)
	}
	if *changed.ResourceID == *first.ResourceID {
		t.Fatal("endpoint change rewrote historical identity")
	}
	state, err := ReadTargets(dir, id)
	if err != nil {
		t.Fatal(err)
	}
	if len(state.Targets) != 2 || !state.Targets[0].Retired || state.Targets[0].Manifest.Endpoint.Port != 11434 || state.Targets[1].Retired || state.Targets[1].Manifest.Endpoint.Port != 11435 {
		t.Fatalf("history changed: %+v", state.Targets)
	}
	manifest.ManifestRevision = 3
	manifest.Endpoint.Port = 11434
	restored, err := ApplyTarget(dir, id, "20000000-0000-4000-8000-000000000001", "edit", *changed.ResourceID, 1, &manifest, hash)
	if err != nil {
		t.Fatal(err)
	}
	if restored.ResourceID == nil || *restored.ResourceID != *first.ResourceID {
		t.Fatalf("restored endpoint did not reuse its retired identity: %+v", restored)
	}
	state, err = ReadTargets(dir, id)
	if err != nil {
		t.Fatal(err)
	}
	if len(state.Targets) != 2 || state.Targets[0].Retired || state.Targets[0].Revision != 2 || state.Targets[0].Manifest.ManifestRevision != 3 || !state.Targets[1].Retired {
		t.Fatalf("restored endpoint history changed: %+v", state.Targets)
	}
	if _, err := ReadTargets(dir, boot); err == nil {
		t.Fatal("restored generation accepted old config")
	}
}

func TestTargetManifestRejectsUnapprovedNetworkSurface(t *testing.T) {
	for _, host := range []string{"localhost", "127.0.0.2", "example.com", "::ffff:127.0.0.1"} {
		manifest := testManifest()
		manifest.Endpoint.Host = host
		if err := manifest.Validate(); err == nil {
			t.Fatalf("accepted host %q", host)
		}
	}
	manifest := testManifest()
	manifest.Endpoint.BasePath = "/api"
	if err := manifest.Validate(); err == nil {
		t.Fatal("accepted arbitrary base path")
	}
	manifest = testManifest()
	manifest.DisplayName = "model\nInjected"
	if err := manifest.Validate(); err == nil {
		t.Fatal("accepted control characters")
	}
}
