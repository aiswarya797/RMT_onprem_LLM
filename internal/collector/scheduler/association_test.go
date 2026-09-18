package scheduler

import (
	"strings"
	"testing"

	adapter "rmt.local/monitor/internal/adapters/ollama"
	"rmt.local/monitor/internal/collect/identity"
	collectollama "rmt.local/monitor/internal/collect/ollama"
	"rmt.local/monitor/internal/collector/pairing"
	"rmt.local/monitor/internal/domain"
)

func TestEndpointAssociationRequiresListenerRuntimeAndExactManifest(t *testing.T) {
	selector := strings.Repeat("a", 64)
	key := strings.Repeat("b", 64)
	pID, start := 44, domain.DecimalUint64(900)
	target := pairing.LocalTarget{
		TargetID: "11111111-1111-4111-8111-111111111111", SourceID: "22222222-2222-4222-8222-222222222222", Revision: 3,
		Manifest:       pairing.TargetManifest{SchemaVersion: "1.0", ManifestID: "33333333-3333-4333-8333-333333333333", ManifestRevision: 2, AdapterID: "ollama", Endpoint: pairing.Endpoint{Scheme: "http", Host: "127.0.0.1", Port: 11434}, IdentityRevision: strings.Repeat("c", 64), DisplayName: "Local Ollama"},
		ManifestSHA256: strings.Repeat("d", 64), SelectorSHA256: selector,
	}
	process := domain.ProcessObservation{PID: pID, ProcessStartIdentity: start, ProcessKey: key, Category: domain.ProcessOtherSameUser, AssociationQuality: domain.AssociationNone}
	collection := domain.ProcessCollection{
		Processes:   []domain.ProcessObservation{process},
		Association: domain.EndpointAssociation{TargetID: target.TargetID, EndpointHash: selector, PID: &pID, ProcessStartIdentity: &start, ProcessKey: &key, Quality: domain.AssociationVerified, Provenance: domain.Provenance{Source: domain.ProvenanceDarwinAPI, MethodRevision: "darwin-proc-rusage-candidate-1", Verification: domain.VerificationDirectCapture}},
	}
	version, sourcePin := "0.12.10", "ollama-0.12.10-source"
	runtime := collectollama.Snapshot{Runtime: domain.RuntimeObservation{Reachable: domain.RuntimeReported(true, domain.Provenance{Source: domain.ProvenanceRuntimeAPI, MethodRevision: "ollama-bounded-read-v1", Verification: domain.VerificationDirectCapture}), Version: &version}, RuntimeSourcePinID: &sourcePin, RuntimeCompatibility: compatibilityPointer(adapter.CompatibilityUnverified)}
	runner := &Runner{target: &target}
	runner.finalizeEndpointAssociation(&collection, runtime)
	association := collection.Association
	if association.Quality != domain.AssociationVerified || association.ManifestRevision != 2 || association.TargetRevision != 3 || association.RuntimeVersion == nil || association.RuntimeSourcePinID == nil || collection.Processes[0].Category != domain.ProcessSelectedOllama || len(runner.expected) != 1 || runner.expected[0].Role != identity.RoleSelectedOllama {
		t.Fatalf("final association=%+v process=%+v expected=%+v", association, collection.Processes[0], runner.expected)
	}

	failed := collection
	failed.Association = domain.EndpointAssociation{TargetID: target.TargetID, EndpointHash: selector, PID: &pID, ProcessStartIdentity: &start, ProcessKey: &key, Quality: domain.AssociationVerified, Provenance: association.Provenance}
	runner.finalizeEndpointAssociation(&failed, collectollama.Snapshot{})
	if failed.Association.Quality != domain.AssociationDeclaredUnverified || failed.Association.PID != nil || len(runner.expected) != 1 || runner.expected[0].ProcessKey != key {
		t.Fatalf("runtime failure promoted or forgot last verified identity: association=%+v expected=%+v", failed.Association, runner.expected)
	}

	exit := domain.VerifiedProcessExit{PID: pID, ProcessStartIdentity: start, ProcessKey: key, LastSeenMS: 1}
	exited := domain.ProcessCollection{Association: domain.EndpointAssociation{TargetID: target.TargetID, EndpointHash: selector, Quality: domain.AssociationDeclaredUnverified, Reason: missingReasonPointer(domain.MissingIdentityUnverified), VerifiedExit: &exit, Provenance: association.Provenance}}
	runner.finalizeEndpointAssociation(&exited, runtime)
	if len(runner.expected) != 0 || exited.Association.VerifiedExit == nil {
		t.Fatalf("verified exit did not remove only the exact pin: association=%+v expected=%+v", exited.Association, runner.expected)
	}
}

func compatibilityPointer(value adapter.CompatibilityState) *adapter.CompatibilityState {
	return &value
}
func missingReasonPointer(value domain.MissingReason) *domain.MissingReason { return &value }

func TestInventoryAssociationStateKeepsAmbiguityExplicit(t *testing.T) {
	for _, item := range []struct {
		quality domain.AssociationQuality
		want    string
	}{{domain.AssociationVerified, "verified"}, {domain.AssociationAmbiguous, "ambiguous"}, {domain.AssociationDeclaredUnverified, "declared_unverified"}, {domain.AssociationNone, "declared_unverified"}} {
		collection := &domain.ProcessCollection{Association: domain.EndpointAssociation{Quality: item.quality}}
		if got := inventoryAssociationState(collection); got != item.want {
			t.Fatalf("quality %q state=%q want=%q", item.quality, got, item.want)
		}
	}
}
