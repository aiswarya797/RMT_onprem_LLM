package pairing

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"rmt.local/monitor/internal/config"
	"rmt.local/monitor/internal/protocol"
)

const id = "11111111-1111-4111-8111-111111111111"
const boot = "22222222-2222-4222-8222-222222222222"

func TestActivationSurvivesLostResponseWithoutGuessing(t *testing.T) {
	dir := t.TempDir()
	state, err := Create(dir, id, id)
	if err != nil {
		t.Fatal(err)
	}
	first, err := state.PrepareActivation(boot)
	if err != nil {
		t.Fatal(err)
	}
	reopened, err := Open(dir, id, id)
	if err != nil {
		t.Fatal(err)
	}
	retry, err := reopened.PrepareActivation(id)
	if err != nil {
		t.Fatal(err)
	}
	if retry != first {
		t.Fatal("pending activation was replaced after lost response")
	}
	wrong := protocol.NewSessionResult(first, 0, 1000)
	if err := reopened.CompleteActivation(wrong); err == nil {
		t.Fatal("non-advancing generation accepted")
	}
	result := protocol.NewSessionResult(first, 1, 1000)
	if err := reopened.CompleteActivation(result); err != nil {
		t.Fatal(err)
	}
	reopened, err = Open(dir, id, id)
	if err != nil {
		t.Fatal(err)
	}
	second, err := reopened.PrepareActivation(id)
	if err != nil {
		t.Fatal(err)
	}
	if second.ExpectedPreviousGeneration != 1 || second.ActivationRequestID == first.ActivationRequestID {
		t.Fatal("durable predecessor not used")
	}
	if _, err := Open(dir, id, boot); err == nil {
		t.Fatal("security generation change silently accepted")
	}
}

func TestRandomModelIdentityPersistsWithoutChangingEarlierRevision(t *testing.T) {
	dir := t.TempDir()
	state, err := Create(dir, id, id)
	if err != nil {
		t.Fatal(err)
	}
	first, err := state.ResolveModelID(context.Background(), id, "model", "sha256:first")
	if err != nil {
		t.Fatal(err)
	}
	second, err := state.ResolveModelID(context.Background(), id, "model", "sha256:second")
	if err != nil {
		t.Fatal(err)
	}
	if first == second {
		t.Fatal("model revision identity reused")
	}
	state, err = Open(dir, id, id)
	if err != nil {
		t.Fatal(err)
	}
	again, err := state.ResolveModelID(context.Background(), id, "model", "sha256:first")
	if err != nil {
		t.Fatal(err)
	}
	if again != first {
		t.Fatal("model ID not durable")
	}
}

func TestReEnrollmentPreservesStableIdentitiesAndSpoolWhileResettingSession(t *testing.T) {
	dir := t.TempDir()
	oldGeneration := "33333333-3333-4333-8333-333333333333"
	newGeneration := "44444444-4444-4444-8444-444444444444"
	installation := "55555555-5555-4555-8555-555555555555"
	host := "66666666-6666-4666-8666-666666666666"
	state, err := CreateEnrolled(dir, id, oldGeneration, installation, host)
	if err != nil {
		t.Fatal(err)
	}
	targetID := "77777777-7777-4777-8777-777777777777"
	sourceID := "88888888-8888-4888-8888-888888888888"
	modelID, err := state.ResolveModelID(context.Background(), targetID, "model", "sha256:digest")
	if err != nil {
		t.Fatal(err)
	}
	pending := protocol.SessionActivation{Protocol: "1.0", DeploymentID: id, HostID: host, SecurityGeneration: oldGeneration, ActivationRequestID: "99999999-9999-4999-8999-999999999999", CollectorBootID: boot, ExpectedPreviousGeneration: 4}
	state.value.PreviousSession = 4
	state.value.PendingActivation = &pending
	state.value.InventorySources = []protocol.InventorySource{{SourceID: state.value.HostSourceID, Kind: "host", CapabilityRevision: "mac-ollama-1", Active: true}, {SourceID: sourceID, Kind: "runtime", TargetID: &targetID, CapabilityRevision: "mac-ollama-1", Active: true}}
	state.value.PendingInventoryRevision = strings.Repeat("a", 64)
	if err := state.save(state.value); err != nil {
		t.Fatal(err)
	}
	manifest := TargetManifest{SchemaVersion: "1.0", ManifestID: "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa", ManifestRevision: 1, AdapterID: "ollama", Endpoint: Endpoint{Scheme: "http", Host: "127.0.0.1", Port: 11434}, IdentityRevision: strings.Repeat("b", 64), DisplayName: "Retained Ollama"}
	targets := TargetState{Version: 1, Generation: oldGeneration, Targets: []LocalTarget{{TargetID: targetID, SourceID: sourceID, Revision: 1, Manifest: manifest, ManifestSHA256: strings.Repeat("c", 64), SelectorSHA256: strings.Repeat("d", 64)}}, Receipts: []targetReceipt{{Key: id, Hash: strings.Repeat("e", 64), AtMS: 1}}}
	targetBytes, _ := json.Marshal(targets)
	if err := config.WritePrivateFile(filepath.Join(dir, "targets.json"), targetBytes); err != nil {
		t.Fatal(err)
	}
	spoolPath := filepath.Join(dir, "spool", "retained.segment")
	spoolBytes := []byte("old-generation-checksummed-spool-bytes")
	if err := config.WritePrivateFile(spoolPath, spoolBytes); err != nil {
		t.Fatal(err)
	}

	reenrolled, err := ReEnroll(dir, id, oldGeneration, newGeneration, installation, host)
	if err != nil {
		t.Fatal(err)
	}
	got := reenrolled.Snapshot()
	if got.Generation != newGeneration || got.InstallationID != installation || got.HostID != host || got.HostSourceID != state.value.HostSourceID || got.PreviousSession != 0 || got.PendingActivation != nil || got.PendingInventoryRevision != "" || !got.Registered {
		t.Fatalf("re-enrolled state=%#v", got)
	}
	if len(got.Models) != 1 || got.Models[0].ID != modelID || len(got.InventorySources) != 2 || got.InventorySources[1].SourceID != sourceID {
		t.Fatalf("stable identities changed: models=%#v sources=%#v", got.Models, got.InventorySources)
	}
	updatedTargets, err := ReadTargets(dir, newGeneration)
	if err != nil || len(updatedTargets.Targets) != 1 || updatedTargets.Targets[0].TargetID != targetID || updatedTargets.Targets[0].SourceID != sourceID || len(updatedTargets.Receipts) != 0 {
		t.Fatalf("targets=%#v err=%v", updatedTargets, err)
	}
	retainedSpool, err := os.ReadFile(spoolPath)
	if err != nil || string(retainedSpool) != string(spoolBytes) {
		t.Fatalf("spool changed: %q err=%v", retainedSpool, err)
	}
	if _, err := Open(dir, id, oldGeneration); err == nil {
		t.Fatal("ordinary startup accepted the old trust generation")
	}
	activation, err := reenrolled.PrepareActivation("aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee")
	if err != nil || activation.ExpectedPreviousGeneration != 0 {
		t.Fatalf("restored activation=%#v err=%v", activation, err)
	}
	// The restored database retains immutable historical session generations,
	// so the hub may allocate above one even though the restored host pointer is
	// deliberately reset to zero.
	result := protocol.NewSessionResult(activation, 5, 1000)
	if err := reenrolled.CompleteActivation(result); err != nil || reenrolled.Snapshot().PreviousSession != 5 {
		t.Fatalf("restored high-water activation rejected: state=%#v err=%v", reenrolled.Snapshot(), err)
	}
}
