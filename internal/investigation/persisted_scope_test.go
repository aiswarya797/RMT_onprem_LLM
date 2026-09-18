package investigation

import (
	"context"
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"rmt.local/monitor/internal/domain"
	"rmt.local/monitor/internal/protocol"
	"rmt.local/monitor/internal/query"
	"rmt.local/monitor/internal/store"
)

const (
	persistedHostID       = "71000000-0000-4000-8000-000000000001"
	persistedInstallID    = "71000000-0000-4000-8000-000000000002"
	persistedBootID       = "71000000-0000-4000-8000-000000000003"
	persistedActivationID = "71000000-0000-4000-8000-000000000004"
	persistedTargetID     = "71000000-0000-4000-8000-000000000005"
	persistedHostSourceID = "71000000-0000-4000-8000-000000000006"
	persistedRunSourceID  = "71000000-0000-4000-8000-000000000007"
	persistedModelID      = "71000000-0000-4000-8000-000000000008"
	persistedProcessKey   = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
)

type persistedClock struct{ now time.Time }

func (clock persistedClock) Now() time.Time { return clock.now }

func TestPersistedModelAndProcessScopesBuildCapsules(t *testing.T) {
	ctx := context.Background()
	now := time.UnixMilli(1_800_010_000_000)
	clock := persistedClock{now: now}
	st, err := store.Open(filepath.Join(t.TempDir(), "monitor.db"), clock)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	state, _, err := st.EnsureDeployment(ctx, "persisted-scope-test")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := st.MeasureAndRecordCapacity(ctx, state.DeploymentID, now.UnixMilli(), store.ExternalCapacityUsage{}); err != nil {
		t.Fatal(err)
	}
	owner := store.TrustedOwnerContext{DeploymentID: state.DeploymentID, SecurityGeneration: state.DeploymentGeneration, InstallingUID: 501, VerifiedOSOwner: true}
	registration := store.LocalHostRegistration{HostID: persistedHostID, InstallationUUID: persistedInstallID, DisplayName: "Local Mac", CollectorVersion: "test"}
	if err := st.RegisterLocalHost(ctx, owner, registration); err != nil {
		t.Fatal(err)
	}
	session, err := st.ActivateCollectorSession(ctx, protocol.SessionActivation{Protocol: domain.ProtocolVersion, DeploymentID: state.DeploymentID, HostID: persistedHostID, SecurityGeneration: state.DeploymentGeneration, ActivationRequestID: persistedActivationID, CollectorBootID: persistedBootID})
	if err != nil {
		t.Fatal(err)
	}
	digest := "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	inventory := protocol.CollectorInventory{
		Protocol: domain.ProtocolVersion, DeploymentID: state.DeploymentID, HostID: persistedHostID, SecurityGeneration: state.DeploymentGeneration, SessionGeneration: session.SessionGeneration, CollectorBootID: persistedBootID,
		InventoryRevision: "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
		Sources:           []protocol.InventorySource{{SourceID: persistedHostSourceID, Kind: "host", CapabilityRevision: domain.RegistryRevision, Active: true}, {SourceID: persistedRunSourceID, Kind: "runtime", TargetID: persistedStringPointer(persistedTargetID), CapabilityRevision: domain.RegistryRevision, Active: true}},
		Targets:           []protocol.InventoryTarget{{TargetID: persistedTargetID, AdapterID: "ollama", LocalSelectorSHA256: "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd", AssociationState: "declared_unverified"}},
		Models:            []protocol.InventoryModel{{ModelID: persistedModelID, TargetID: persistedTargetID, Alias: "fixture:latest", Digest: &digest, ReportedLoaded: true}},
	}
	if _, err := st.RegisterCollectorInventory(ctx, inventory); err != nil {
		t.Fatal(err)
	}
	observed := now.Add(-time.Minute)
	modelFrame := persistedFrame(persistedRunSourceID, 1, observed, "ollama-0.34.0-bounded-ps-v1")
	modelFrame.Quality = domain.QualityRuntimeReported
	modelFrame.ModelObservations = []domain.ModelObservation{{ModelID: persistedModelID, Digest: digest, Loaded: true, Missing: []domain.MissingCapability{}, Provenance: modelFrame.Provenance}}
	if _, err := st.IngestCollectorBatch(ctx, persistedBatch(state, session, "71000000-0000-4000-8000-000000000009", modelFrame)); err != nil {
		t.Fatal(err)
	}
	processFrame := persistedFrame(persistedHostSourceID, 1, observed.Add(time.Second), "darwin-proc-rusage-candidate-1")
	processFrame.ProcessObservations = []domain.ProcessObservation{{HostID: persistedHostID, BootID: persistedBootID, PID: 42, ProcessStartIdentity: "100", ProcessKey: persistedProcessKey, Category: domain.ProcessOtherSameUser, AssociationQuality: domain.AssociationNone, CPUBusyRatio: persistedFloatPointer(0.1), Missing: []domain.MissingCapability{}, Provenance: processFrame.Provenance}}
	processFrame.ProcessSummary = &domain.ProcessSummary{EligiblePIDCount: 1, ExaminedPIDCount: 1, RetainedProcessCount: 1, Coverage: "complete", MethodRevision: "darwin-proc-rusage-candidate-1", SampleIntervalMS: 15000, ScanDurationMS: 1}
	if _, err := st.IngestCollectorBatch(ctx, persistedBatch(state, session, "71000000-0000-4000-8000-000000000010", processFrame)); err != nil {
		t.Fatal(err)
	}
	configA := persistedConfigFrame(2, observed.Add(10*time.Second), "0.34.0", nil)
	if _, err := st.IngestCollectorBatch(ctx, persistedBatch(state, session, "71000000-0000-4000-8000-000000000011", configA)); err != nil {
		t.Fatal(err)
	}
	configB := persistedConfigFrame(3, observed.Add(40*time.Second), "0.35.0", configA.ConfigObservation)
	if _, err := st.IngestCollectorBatch(ctx, persistedBatch(state, session, "71000000-0000-4000-8000-000000000012", configB)); err != nil {
		t.Fatal(err)
	}

	builder := NewBuilder(query.New(st, clock), st, func() int64 { return now.UnixMilli() })
	focus := Window{StartMS: now.Add(-5 * time.Minute).UnixMilli(), EndMS: now.UnixMilli()}
	for _, scope := range []Scope{{Kind: "model", ID: persistedModelID}, {Kind: "process", ID: persistedProcessKey}} {
		capsule, err := builder.Build(ctx, state.DeploymentID, scope, focus)
		if err != nil {
			t.Fatalf("build %s capsule: %v", scope.Kind, err)
		}
		if capsule.Scope != scope || len(capsule.Cards) == 0 {
			t.Fatalf("%s capsule=%#v", scope.Kind, capsule)
		}
		payload, digest, err := capsule.Marshal()
		if err != nil || len(payload) == 0 || len(digest) != 64 || !json.Valid(payload) {
			t.Fatalf("marshal %s capsule bytes=%d digest=%q err=%v", scope.Kind, len(payload), digest, err)
		}
	}
	runtimeCapsule, err := builder.Build(ctx, state.DeploymentID, Scope{Kind: "runtime", ID: persistedTargetID}, focus)
	if err != nil {
		t.Fatalf("build runtime capsule: %v", err)
	}
	change := cardByID(runtimeCapsule.Cards, "EC05")
	if change == nil || change.Eligibility != "eligible" || len(change.ConfigIDs) != 2 || len(change.ReferencedEventIDs) != 1 || !contains(change.ReasonCodes, "config_hash_changed") {
		t.Fatalf("persisted EC05=%#v", change)
	}
	if !strings.Contains(change.Summary, "exact change time is not inferred") {
		t.Fatalf("persisted EC05 summary=%q", change.Summary)
	}
}

func persistedFrame(source string, sequence int64, observed time.Time, method string) protocol.CollectorFrame {
	provenance := domain.Provenance{Source: domain.ProvenanceRuntimeAPI, MethodRevision: method, Verification: domain.VerificationDirectCapture}
	if source == persistedHostSourceID {
		provenance.Source = domain.ProvenanceDarwinAPI
	}
	return protocol.CollectorFrame{SourceID: source, Sequence: sequence, ObservedWallMS: observed.UnixMilli(), MonotonicStartNS: domain.DecimalUint64(uint64(sequence * 100)), MonotonicEndNS: domain.DecimalUint64(uint64(sequence*100 + 1)), DefinitionRevision: domain.RegistryRevision, Quality: domain.QualityMeasured, Provenance: provenance, Gauges: map[string]protocol.MetricValue{}, NetworkObservations: []domain.NetworkObservation{}, ModelObservations: []domain.ModelObservation{}, ProcessObservations: []domain.ProcessObservation{}, CapabilitiesMissing: []domain.MissingCapability{}}
}

func persistedBatch(state domain.DeploymentState, session protocol.SessionResult, id string, frame protocol.CollectorFrame) protocol.CollectorBatch {
	return protocol.CollectorBatch{Protocol: domain.ProtocolVersion, DeliveryMode: "current", SecurityGeneration: state.DeploymentGeneration, SessionGeneration: session.SessionGeneration, DeploymentID: state.DeploymentID, HostID: persistedHostID, CollectorBootID: persistedBootID, BatchID: id, Frames: []protocol.CollectorFrame{frame}}
}

func persistedConfigFrame(sequence int64, observed time.Time, version string, previous *domain.RuntimeConfigObservation) protocol.CollectorFrame {
	at := observed.UnixMilli()
	provenance := domain.Provenance{Source: domain.ProvenanceRuntimeAPI, MethodRevision: "ollama-0.34.0-bounded-read-v1", Verification: domain.VerificationDirectCapture, ObservedAtMS: &at}
	fields := domain.RuntimeConfigFields{ServerVersion: version}
	fieldProvenance := domain.RuntimeConfigFieldProvenance{ServerVersion: provenance}
	config := &domain.RuntimeConfigObservation{TargetID: persistedTargetID, Fields: fields, FieldProvenance: fieldProvenance}
	config.ConfigHash = domain.RuntimeConfigHash(config.Fields, config.FieldProvenance)
	if previous != nil {
		previousHash := previous.ConfigHash
		previousMS := *previous.FieldProvenance.ServerVersion.ObservedAtMS
		config.PreviousConfigHash, config.PreviousObservedMS = &previousHash, &previousMS
	}
	frame := persistedFrame(persistedRunSourceID, sequence, observed, "ollama-0.34.0-bounded-read-v1")
	frame.Quality = domain.QualityRuntimeReported
	frame.ConfigObservation = config
	return frame
}

func persistedStringPointer(value string) *string  { return &value }
func persistedFloatPointer(value float64) *float64 { return &value }
