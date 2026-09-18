package store

import (
	"context"
	"encoding/json"
	"errors"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"rmt.local/monitor/internal/domain"
	"rmt.local/monitor/internal/protocol"
)

const (
	testHostID       = "10000000-0000-4000-8000-000000000001"
	testInstallID    = "10000000-0000-4000-8000-000000000002"
	testBootID       = "10000000-0000-4000-8000-000000000004"
	testActivationID = "10000000-0000-4000-8000-000000000005"
	testTargetID     = "10000000-0000-4000-8000-000000000006"
	testSourceID     = "10000000-0000-4000-8000-000000000007"
	testModelID      = "10000000-0000-4000-8000-000000000008"
	testBatchID      = "10000000-0000-4000-8000-000000000009"
	testHostSourceID = "10000000-0000-4000-8000-000000000010"
)

type ingestSetup struct {
	store     *Store
	state     domain.DeploymentState
	session   protocol.SessionResult
	inventory protocol.CollectorInventory
}

func newIngestSetup(t *testing.T) ingestSetup {
	t.Helper()
	ctx := context.Background()
	store, err := Open(filepath.Join(t.TempDir(), "monitor.db"), domain.RealClock{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { store.Close() })
	state, _, err := store.EnsureDeployment(ctx, "test")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.MeasureAndRecordCapacity(ctx, state.DeploymentID, store.clock.Now().UnixMilli(), ExternalCapacityUsage{}); err != nil {
		t.Fatal(err)
	}
	err = store.RegisterLocalHost(ctx, TrustedOwnerContext{DeploymentID: state.DeploymentID, SecurityGeneration: state.DeploymentGeneration, InstallingUID: 501, VerifiedOSOwner: true}, LocalHostRegistration{HostID: testHostID, InstallationUUID: testInstallID, DisplayName: "Local Mac", CollectorVersion: "0.1.0", Capabilities: map[string]bool{"ollama": true}})
	if err != nil {
		t.Fatal(err)
	}
	activation := protocol.SessionActivation{Protocol: "1.0", DeploymentID: state.DeploymentID, HostID: testHostID, SecurityGeneration: state.DeploymentGeneration, ActivationRequestID: testActivationID, CollectorBootID: testBootID, ExpectedPreviousGeneration: 0}
	session, err := store.ActivateCollectorSession(ctx, activation)
	if err != nil {
		t.Fatal(err)
	}
	digest := "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	inventory := protocol.CollectorInventory{Protocol: "1.0", DeploymentID: state.DeploymentID, HostID: testHostID, SecurityGeneration: state.DeploymentGeneration, SessionGeneration: session.SessionGeneration, CollectorBootID: testBootID, InventoryRevision: "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", Sources: []protocol.InventorySource{{SourceID: testSourceID, Kind: "runtime", TargetID: stringPtr(testTargetID), CapabilityRevision: "mac-ollama-1", Active: true}}, Targets: []protocol.InventoryTarget{{TargetID: testTargetID, AdapterID: "ollama", LocalSelectorSHA256: "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc", AssociationState: "declared_unverified"}}, Models: []protocol.InventoryModel{{ModelID: testModelID, TargetID: testTargetID, Alias: "model:latest", Digest: &digest, ReportedLoaded: true}}}
	result, err := store.RegisterCollectorInventory(ctx, inventory)
	if err != nil || !result.Durable || !result.Current {
		t.Fatalf("inventory = %#v, %v", result, err)
	}
	return ingestSetup{store, state, session, inventory}
}

func TestCollectorSessionActivationIsIdempotentAndCASFenced(t *testing.T) {
	setup := newIngestSetup(t)
	request := protocol.SessionActivation{Protocol: "1.0", DeploymentID: setup.state.DeploymentID, HostID: testHostID, SecurityGeneration: setup.state.DeploymentGeneration, ActivationRequestID: testActivationID, CollectorBootID: testBootID, ExpectedPreviousGeneration: 0}
	result, err := setup.store.ActivateCollectorSession(context.Background(), request)
	if err != nil || result != setup.session {
		t.Fatalf("idempotent activation = %#v, %v", result, err)
	}
	request.ActivationRequestID = "20000000-0000-4000-8000-000000000001"
	if _, err := setup.store.ActivateCollectorSession(context.Background(), request); !errors.Is(err, ErrGenerationConflict) {
		t.Fatalf("stale CAS error = %v", err)
	}
}

func TestRestoredHostActivationAllocatesAboveRetainedSessionAndReusesInventory(t *testing.T) {
	setup := newIngestSetup(t)
	ctx := context.Background()
	newGeneration := "20000000-0000-4000-8000-000000000011"
	newBoot := "20000000-0000-4000-8000-000000000012"
	newActivation := "20000000-0000-4000-8000-000000000013"
	now := setup.store.clock.Now().UnixMilli()
	statements := []struct {
		query string
		args  []any
	}{
		{`INSERT INTO deployment_generations(deployment_id,generation,reason,activated_ms) VALUES(?,?,'restore_bootstrap',?)`, []any{setup.state.DeploymentID, newGeneration, now}},
		{`UPDATE deployments SET deployment_generation=?,recovery_state='normal',updated_ms=? WHERE id=?`, []any{newGeneration, now, setup.state.DeploymentID}},
		{`UPDATE collector_sessions SET superseded_ms=COALESCE(superseded_ms,?) WHERE deployment_id=? AND host_id=?`, []any{now, setup.state.DeploymentID, testHostID}},
		{`UPDATE hosts SET current_session_generation=0,last_boot_id=NULL,retired_ms=?,updated_ms=? WHERE deployment_id=? AND id=?`, []any{now, now, setup.state.DeploymentID, testHostID}},
	}
	for _, statement := range statements {
		if _, err := setup.store.db.Exec(statement.query, statement.args...); err != nil {
			t.Fatal(err)
		}
	}
	owner := TrustedOwnerContext{DeploymentID: setup.state.DeploymentID, SecurityGeneration: newGeneration, InstallingUID: 501, VerifiedOSOwner: true}
	registration := LocalHostRegistration{HostID: testHostID, InstallationUUID: testInstallID, DisplayName: "Local Mac", CollectorVersion: "0.1.0", Capabilities: map[string]bool{"ollama": true}}
	if err := setup.store.ReEnrollLocalHost(ctx, owner, registration, setup.state.DeploymentGeneration); err != nil {
		t.Fatal(err)
	}
	request := protocol.SessionActivation{Protocol: "1.0", DeploymentID: setup.state.DeploymentID, HostID: testHostID, SecurityGeneration: newGeneration, ActivationRequestID: newActivation, CollectorBootID: newBoot, ExpectedPreviousGeneration: 0}
	session, err := setup.store.ActivateCollectorSession(ctx, request)
	if err != nil || session.SessionGeneration != setup.session.SessionGeneration+1 {
		t.Fatalf("restored activation=%#v err=%v", session, err)
	}
	inventory := setup.inventory
	inventory.SecurityGeneration = newGeneration
	inventory.SessionGeneration = session.SessionGeneration
	inventory.CollectorBootID = newBoot
	inventory.InventoryRevision = strings.Repeat("e", 64)
	result, err := setup.store.RegisterCollectorInventory(ctx, inventory)
	if err != nil || !result.Durable || !result.Current {
		t.Fatalf("retained inventory=%#v err=%v", result, err)
	}
	var sessions, sources, targets, models int
	if err := setup.store.db.QueryRow(`SELECT count(*) FROM collector_sessions WHERE deployment_id=? AND host_id=?`, setup.state.DeploymentID, testHostID).Scan(&sessions); err != nil {
		t.Fatal(err)
	}
	_ = setup.store.db.QueryRow(`SELECT count(*) FROM sources WHERE deployment_id=? AND host_id=? AND id=?`, setup.state.DeploymentID, testHostID, testSourceID).Scan(&sources)
	_ = setup.store.db.QueryRow(`SELECT count(*) FROM targets WHERE deployment_id=? AND host_id=? AND id=?`, setup.state.DeploymentID, testHostID, testTargetID).Scan(&targets)
	_ = setup.store.db.QueryRow(`SELECT count(*) FROM model_revisions WHERE deployment_id=? AND host_id=? AND id=?`, setup.state.DeploymentID, testHostID, testModelID).Scan(&models)
	if sessions != 2 || sources != 1 || targets != 1 || models != 1 {
		t.Fatalf("retained rows changed: sessions=%d sources=%d targets=%d models=%d", sessions, sources, targets, models)
	}
}

func TestInactiveOwnedSourceRetiresTargetWithoutDeletingHistory(t *testing.T) {
	setup := newIngestSetup(t)
	inventory := setup.inventory
	inventory.InventoryRevision = "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"
	inventory.Targets = nil
	inventory.Models = nil
	inventory.Sources[0].Active = false
	result, err := setup.store.RegisterCollectorInventory(context.Background(), inventory)
	if err != nil || !result.Durable || !result.Current {
		t.Fatalf("retirement inventory = %#v, %v", result, err)
	}
	var sourceRetired, targetRetired *int64
	if err := setup.store.db.QueryRow(`SELECT retired_ms FROM sources WHERE id=?`, testSourceID).Scan(&sourceRetired); err != nil || sourceRetired == nil {
		t.Fatalf("source retired = %v, %v", sourceRetired, err)
	}
	if err := setup.store.db.QueryRow(`SELECT retired_ms FROM targets WHERE id=?`, testTargetID).Scan(&targetRetired); err != nil || targetRetired == nil {
		t.Fatalf("target retired = %v, %v", targetRetired, err)
	}
	var modelCount int
	if err := setup.store.db.QueryRow(`SELECT count(*) FROM model_revisions WHERE id=?`, testModelID).Scan(&modelCount); err != nil || modelCount != 1 {
		t.Fatalf("retained model history = %d, %v", modelCount, err)
	}
}

func TestInventoryRetiresOldEndpointBeforeAdmittingReplacement(t *testing.T) {
	setup := newIngestSetup(t)
	ctx := context.Background()
	newTargetID := "10000000-0000-4000-8000-000000000011"
	newSourceID := "10000000-0000-4000-8000-000000000012"

	withHost := setup.inventory
	withHost.InventoryRevision = strings.Repeat("c", 64)
	withHost.Sources = append(withHost.Sources, protocol.InventorySource{
		SourceID: testHostSourceID, Kind: "host", CapabilityRevision: domain.RegistryRevision, Active: true,
	})
	if _, err := setup.store.RegisterCollectorInventory(ctx, withHost); err != nil {
		t.Fatalf("admit host source = %v", err)
	}

	replacement := setup.inventory
	replacement.InventoryRevision = strings.Repeat("d", 64)
	replacement.Targets = []protocol.InventoryTarget{{
		TargetID: newTargetID, AdapterID: "ollama", LocalSelectorSHA256: strings.Repeat("d", 64), AssociationState: "declared_unverified",
	}}
	replacement.Sources = []protocol.InventorySource{
		{SourceID: newSourceID, Kind: "runtime", TargetID: stringPtr(newTargetID), CapabilityRevision: domain.RegistryRevision, Active: true},
		{SourceID: testSourceID, Kind: "runtime", TargetID: stringPtr(testTargetID), CapabilityRevision: domain.RegistryRevision, Active: false},
		{SourceID: testHostSourceID, Kind: "host", CapabilityRevision: domain.RegistryRevision, Active: true},
	}
	replacement.Models = nil
	if _, err := setup.store.RegisterCollectorInventory(ctx, replacement); err != nil {
		t.Fatalf("admit endpoint replacement = %v", err)
	}

	var oldTargetRetired, newTargetRetired, oldSourceRetired, newSourceRetired *int64
	if err := setup.store.db.QueryRow(`SELECT retired_ms FROM targets WHERE id=?`, testTargetID).Scan(&oldTargetRetired); err != nil {
		t.Fatal(err)
	}
	if err := setup.store.db.QueryRow(`SELECT retired_ms FROM targets WHERE id=?`, newTargetID).Scan(&newTargetRetired); err != nil {
		t.Fatal(err)
	}
	if err := setup.store.db.QueryRow(`SELECT retired_ms FROM sources WHERE id=?`, testSourceID).Scan(&oldSourceRetired); err != nil {
		t.Fatal(err)
	}
	if err := setup.store.db.QueryRow(`SELECT retired_ms FROM sources WHERE id=?`, newSourceID).Scan(&newSourceRetired); err != nil {
		t.Fatal(err)
	}
	if oldTargetRetired == nil || newTargetRetired != nil || oldSourceRetired == nil || newSourceRetired != nil {
		t.Fatalf("replacement identities not transitioned: old target=%v new target=%v old source=%v new source=%v", oldTargetRetired, newTargetRetired, oldSourceRetired, newSourceRetired)
	}

	restoredTargetID := "10000000-0000-4000-8000-000000000013"
	restoredSourceID := "10000000-0000-4000-8000-000000000014"
	restored := setup.inventory
	restored.InventoryRevision = strings.Repeat("e", 64)
	restored.Targets = []protocol.InventoryTarget{{
		TargetID: restoredTargetID, AdapterID: "ollama", LocalSelectorSHA256: strings.Repeat("e", 64), AssociationState: "declared_unverified",
	}}
	restored.Sources = []protocol.InventorySource{
		{SourceID: restoredSourceID, Kind: "runtime", TargetID: stringPtr(restoredTargetID), CapabilityRevision: domain.RegistryRevision, Active: true},
		{SourceID: newSourceID, Kind: "runtime", TargetID: stringPtr(newTargetID), CapabilityRevision: domain.RegistryRevision, Active: false},
		{SourceID: testHostSourceID, Kind: "host", CapabilityRevision: domain.RegistryRevision, Active: true},
	}
	restored.Models = nil
	if _, err := setup.store.RegisterCollectorInventory(ctx, restored); err != nil {
		t.Fatalf("admit second endpoint replacement = %v", err)
	}
}

func TestBatchCommitIsAtomicDurableAndHashCheckedOnDedupe(t *testing.T) {
	setup := newIngestSetup(t)
	batch := testBatch(setup)
	ack, err := setup.store.IngestCollectorBatch(context.Background(), batch)
	if err != nil || !ack.Durable || ack.Accepted != 1 || ack.Duplicate != 0 {
		t.Fatalf("first ACK = %#v, %v", ack, err)
	}
	ack, err = setup.store.IngestCollectorBatch(context.Background(), batch)
	if err != nil || ack.Accepted != 0 || ack.Duplicate != 1 {
		t.Fatalf("duplicate ACK = %#v, %v", ack, err)
	}
	batch.Frames[0].Gauges["runtime.reachable"] = protocol.MetricValue{Value: json.RawMessage("false"), Quality: domain.QualityRuntimeReported, Provenance: testProvenance()}
	if _, err := setup.store.IngestCollectorBatch(context.Background(), batch); !errors.Is(err, ErrOwnershipMismatch) {
		t.Fatalf("changed duplicate error = %v", err)
	}
	var count int
	if err := setup.store.db.QueryRow(`SELECT count(*) FROM source_frames`).Scan(&count); err != nil || count != 1 {
		t.Fatalf("frame count = %d, %v", count, err)
	}
}

func TestBulkCapacityFailsClosedButDuplicateAndStatusControlLaneContinue(t *testing.T) {
	setup := newIngestSetup(t)
	ctx := context.Background()
	batch := testBatch(setup)
	if _, err := setup.store.IngestCollectorBatch(ctx, batch); err != nil {
		t.Fatal(err)
	}
	if _, err := setup.store.db.ExecContext(ctx, `UPDATE maintenance SET storage_state='bulk_ingest_paused' WHERE deployment_id=?`, setup.state.DeploymentID); err != nil {
		t.Fatal(err)
	}
	duplicate, err := setup.store.IngestCollectorBatch(ctx, batch)
	if err != nil || duplicate.Duplicate != 1 || duplicate.Accepted != 0 {
		t.Fatalf("duplicate while paused = %#v, %v", duplicate, err)
	}
	batch.BatchID = "20000000-0000-4000-8000-000000000075"
	batch.Frames[0].Sequence++
	if _, err := setup.store.IngestCollectorBatch(ctx, batch); !errors.Is(err, ErrBulkIngestPaused) {
		t.Fatalf("new bulk frame while paused = %v", err)
	}
	status := protocol.SourceStatus{Protocol: "1.0", DeploymentID: setup.state.DeploymentID, HostID: testHostID, SecurityGeneration: setup.state.DeploymentGeneration, SessionGeneration: setup.session.SessionGeneration, CollectorBootID: testBootID, Sequence: 1, ObservedWallMS: setup.store.clock.Now().UnixMilli(), Heartbeat: "fresh", Sources: []protocol.SourceState{{SourceID: testSourceID, State: "fresh"}}, LossIntervals: []protocol.LossInterval{}}
	if result, err := setup.store.IngestSourceStatus(ctx, status); err != nil || !result.Durable {
		t.Fatalf("control status while bulk paused = %#v, %v", result, err)
	}
}

func TestBulkCapacityRejectsMissingOrStaleMeasurement(t *testing.T) {
	setup := newIngestSetup(t)
	ctx := context.Background()
	if _, err := setup.store.db.ExecContext(ctx, `UPDATE maintenance SET evaluator_cursor_json=json_remove(evaluator_cursor_json,'$.capacity_observed_ms') WHERE deployment_id=?`, setup.state.DeploymentID); err != nil {
		t.Fatal(err)
	}
	if _, err := setup.store.IngestCollectorBatch(ctx, testBatch(setup)); !errors.Is(err, ErrCapacityMeasurementUnavailable) {
		t.Fatalf("missing capacity measurement = %v", err)
	}
	staleMS := setup.store.clock.Now().Add(-CapacityMeasurementMaxAge - time.Second).UnixMilli()
	if _, err := setup.store.db.ExecContext(ctx, `UPDATE maintenance SET evaluator_cursor_json=json_set(evaluator_cursor_json,'$.capacity_observed_ms',?) WHERE deployment_id=?`, staleMS, setup.state.DeploymentID); err != nil {
		t.Fatal(err)
	}
	if _, err := setup.store.IngestCollectorBatch(ctx, testBatch(setup)); !errors.Is(err, ErrCapacityMeasurementUnavailable) {
		t.Fatalf("stale capacity measurement = %v", err)
	}
}

func TestBatchRejectsForeignNestedIdentityWithoutPartialWrite(t *testing.T) {
	setup := newIngestSetup(t)
	batch := testBatch(setup)
	batch.Frames = append(batch.Frames, batch.Frames[0])
	batch.Frames[1].Sequence = 2
	batch.Frames[1].ProcessObservations = []domain.ProcessObservation{{HostID: "30000000-0000-4000-8000-000000000001", BootID: testBootID, PID: 1, ProcessStartIdentity: "1", ProcessKey: "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd", Category: domain.ProcessOtherSameUser, AssociationQuality: domain.AssociationNone, Provenance: testProvenance()}}
	if _, err := setup.store.IngestCollectorBatch(context.Background(), batch); !errors.Is(err, ErrOwnershipMismatch) {
		t.Fatalf("foreign owner error = %v", err)
	}
	var count int
	_ = setup.store.db.QueryRow(`SELECT count(*) FROM source_frames`).Scan(&count)
	if count != 0 {
		t.Fatalf("partial rows = %d", count)
	}
}

func TestVerifiedEndpointAssociationCreatesStableIncarnationAndExactExit(t *testing.T) {
	setup := newIngestSetup(t)
	ctx := context.Background()
	inventory := setup.inventory
	inventory.InventoryRevision = strings.Repeat("f", 64)
	inventory.Sources = append(inventory.Sources, protocol.InventorySource{SourceID: testHostSourceID, Kind: "host", CapabilityRevision: domain.RegistryRevision, Active: true})
	if result, err := setup.store.RegisterCollectorInventory(ctx, inventory); err != nil || !result.Durable {
		t.Fatalf("host inventory=%+v err=%v", result, err)
	}

	first := testAssociationFrame(1, setup.store.clock.Now().UnixMilli())
	batch := testConfigBatch(setup, "82000000-0000-4000-8000-000000000001", "current", first)
	if _, err := setup.store.IngestCollectorBatch(ctx, batch); err != nil {
		t.Fatal(err)
	}
	second := testAssociationFrame(2, first.ObservedWallMS+15_000)
	batch.BatchID, batch.Frames = "82000000-0000-4000-8000-000000000002", []protocol.CollectorFrame{second}
	if _, err := setup.store.IngestCollectorBatch(ctx, batch); err != nil {
		t.Fatal(err)
	}
	replayedMS := first.ObservedWallMS - 15_000
	replayed := testAssociationFrame(0, replayedMS)
	batch.BatchID, batch.DeliveryMode, batch.Frames = "82000000-0000-4000-8000-000000000005", "replay", []protocol.CollectorFrame{replayed}
	if _, err := setup.store.IngestCollectorBatch(ctx, batch); err != nil {
		t.Fatalf("older exact replay=%v", err)
	}
	var incarnations, associations, linked int
	var firstSeen, lastSeen int64
	if err := setup.store.db.QueryRowContext(ctx, `SELECT count(*),min(first_seen_ms),max(last_seen_ms) FROM incarnations WHERE deployment_id=? AND host_id=? AND target_id=?`, setup.state.DeploymentID, testHostID, testTargetID).Scan(&incarnations, &firstSeen, &lastSeen); err != nil {
		t.Fatal(err)
	}
	_ = setup.store.db.QueryRowContext(ctx, `SELECT count(*) FROM endpoint_associations WHERE deployment_id=? AND host_id=? AND target_id=?`, setup.state.DeploymentID, testHostID, testTargetID).Scan(&associations)
	_ = setup.store.db.QueryRowContext(ctx, `SELECT count(*) FROM process_observations WHERE deployment_id=? AND host_id=? AND target_id=? AND incarnation_id IS NOT NULL`, setup.state.DeploymentID, testHostID, testTargetID).Scan(&linked)
	if incarnations != 1 || associations != 3 || linked != 3 || firstSeen != replayedMS || lastSeen != second.ObservedWallMS {
		t.Fatalf("incarnations=%d associations=%d linked=%d interval=%d..%d", incarnations, associations, linked, firstSeen, lastSeen)
	}

	exit := second.EndpointAssociation
	exit.Quality = domain.AssociationDeclaredUnverified
	exit.Reason = missingReasonTestPointer(domain.MissingIdentityUnverified)
	exit.VerifiedExit = &domain.VerifiedProcessExit{PID: *exit.PID, ProcessStartIdentity: *exit.ProcessStartIdentity, ProcessKey: *exit.ProcessKey, LastSeenMS: second.ObservedWallMS}
	exit.PID, exit.ProcessStartIdentity, exit.ProcessKey, exit.RuntimeVersion = nil, nil, nil, nil
	exitFrame := testAssociationFrame(3, second.ObservedWallMS+15_000)
	exitFrame.ProcessObservations = []domain.ProcessObservation{}
	exitFrame.ProcessSummary.RetainedProcessCount = 0
	exitFrame.EndpointAssociation = exit
	batch.BatchID, batch.DeliveryMode, batch.Frames = "82000000-0000-4000-8000-000000000003", "current", []protocol.CollectorFrame{exitFrame}
	if _, err := setup.store.IngestCollectorBatch(ctx, batch); err != nil {
		t.Fatal(err)
	}
	var exits int
	_ = setup.store.db.QueryRowContext(ctx, `SELECT count(*) FROM events WHERE deployment_id=? AND host_id=? AND target_id=? AND code='selected_process_exit_verified' AND incarnation_id IS NOT NULL`, setup.state.DeploymentID, testHostID, testTargetID).Scan(&exits)
	if exits != 1 {
		t.Fatalf("verified exit events=%d", exits)
	}
	replayedExit := exitFrame
	replayedExit.Sequence = 4
	batch.BatchID, batch.DeliveryMode, batch.Frames = "82000000-0000-4000-8000-000000000006", "replay", []protocol.CollectorFrame{replayedExit}
	if _, err := setup.store.IngestCollectorBatch(ctx, batch); err != nil {
		t.Fatalf("historical exact exit replay=%v", err)
	}
	_ = setup.store.db.QueryRowContext(ctx, `SELECT count(*) FROM events WHERE deployment_id=? AND host_id=? AND target_id=? AND code='selected_process_exit_verified'`, setup.state.DeploymentID, testHostID, testTargetID).Scan(&exits)
	if exits != 1 {
		t.Fatalf("historical replay emitted a current exit: %d", exits)
	}
}

func TestEndpointAssociationRejectsSelectorMismatchAtomically(t *testing.T) {
	setup := newIngestSetup(t)
	ctx := context.Background()
	inventory := setup.inventory
	inventory.InventoryRevision = strings.Repeat("f", 64)
	inventory.Sources = append(inventory.Sources, protocol.InventorySource{SourceID: testHostSourceID, Kind: "host", CapabilityRevision: domain.RegistryRevision, Active: true})
	if _, err := setup.store.RegisterCollectorInventory(ctx, inventory); err != nil {
		t.Fatal(err)
	}
	frame := testAssociationFrame(1, setup.store.clock.Now().UnixMilli())
	frame.EndpointAssociation.EndpointHash = strings.Repeat("e", 64)
	frame.EndpointAssociation.SelectorSHA256 = strings.Repeat("e", 64)
	batch := testConfigBatch(setup, "82000000-0000-4000-8000-000000000004", "current", frame)
	if _, err := setup.store.IngestCollectorBatch(ctx, batch); !errors.Is(err, ErrOwnershipMismatch) {
		t.Fatalf("selector mismatch=%v", err)
	}
	var frames, incarnations int
	_ = setup.store.db.QueryRowContext(ctx, `SELECT count(*) FROM source_frames`).Scan(&frames)
	_ = setup.store.db.QueryRowContext(ctx, `SELECT count(*) FROM incarnations`).Scan(&incarnations)
	if frames != 0 || incarnations != 0 {
		t.Fatalf("selector mismatch partially persisted frames=%d incarnations=%d", frames, incarnations)
	}
}

func TestConfigEpochsPersistImmutableIdentitiesAndRecurringTransitions(t *testing.T) {
	setup := newIngestSetup(t)
	ctx := context.Background()
	base := setup.store.clock.Now().Add(-2 * time.Minute).UnixMilli()
	versionA, versionB := "0.34.0", "0.35.0"
	frameA1 := testConfigFrame(testSourceID, 1, base, versionA, nil)
	if _, err := setup.store.IngestCollectorBatch(ctx, testConfigBatch(setup, "81000000-0000-4000-8000-000000000001", "current", frameA1)); err != nil {
		t.Fatal(err)
	}
	frameA2 := testConfigFrame(testSourceID, 2, base+30_000, versionA, frameA1.ConfigObservation)
	if _, err := setup.store.IngestCollectorBatch(ctx, testConfigBatch(setup, "81000000-0000-4000-8000-000000000002", "current", frameA2)); err != nil {
		t.Fatal(err)
	}
	frameB := testConfigFrame(testSourceID, 3, base+60_000, versionB, frameA2.ConfigObservation)
	if _, err := setup.store.IngestCollectorBatch(ctx, testConfigBatch(setup, "81000000-0000-4000-8000-000000000003", "current", frameB)); err != nil {
		t.Fatal(err)
	}
	frameA3 := testConfigFrame(testSourceID, 4, base+90_000, versionA, frameB.ConfigObservation)
	if _, err := setup.store.IngestCollectorBatch(ctx, testConfigBatch(setup, "81000000-0000-4000-8000-000000000004", "current", frameA3)); err != nil {
		t.Fatal(err)
	}
	var identities, transitions int
	if err := setup.store.db.QueryRowContext(ctx, `SELECT count(*) FROM config_snapshots WHERE deployment_id=? AND target_id=?`, setup.state.DeploymentID, testTargetID).Scan(&identities); err != nil {
		t.Fatal(err)
	}
	if err := setup.store.db.QueryRowContext(ctx, `SELECT count(*) FROM events WHERE deployment_id=? AND target_id=? AND code='config_change_detected'`, setup.state.DeploymentID, testTargetID).Scan(&transitions); err != nil {
		t.Fatal(err)
	}
	if identities != 2 || transitions != 2 {
		t.Fatalf("config identities=%d transitions=%d", identities, transitions)
	}
	rows, err := setup.store.db.QueryContext(ctx, `SELECT occurred_start_ms,occurred_end_ms,allowlisted_fields_json FROM events WHERE deployment_id=? AND target_id=? AND code='config_change_detected' ORDER BY occurred_start_ms`, setup.state.DeploymentID, testTargetID)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	wantIntervals := [][2]int64{{base + 30_000, base + 60_000}, {base + 60_000, base + 90_000}}
	index := 0
	for rows.Next() {
		var start, end int64
		var fields string
		if err := rows.Scan(&start, &end, &fields); err != nil {
			t.Fatal(err)
		}
		if index >= len(wantIntervals) || start != wantIntervals[index][0] || end != wantIntervals[index][1] || !json.Valid([]byte(fields)) {
			t.Fatalf("transition[%d]=%d..%d %s", index, start, end, fields)
		}
		index++
	}
	if index != 2 {
		t.Fatalf("transition rows=%d", index)
	}
}

func TestConfigReplayRequiresAlreadyAdmittedExactPredecessor(t *testing.T) {
	setup := newIngestSetup(t)
	ctx := context.Background()
	base := setup.store.clock.Now().Add(-time.Hour).UnixMilli()
	first := testConfigFrame(testSourceID, 1, base, "0.34.0", nil)
	second := testConfigFrame(testSourceID, 2, base+30_000, "0.35.0", first.ConfigObservation)
	if _, err := setup.store.IngestCollectorBatch(ctx, testConfigBatch(setup, "82000000-0000-4000-8000-000000000001", "replay", second)); err != nil {
		t.Fatal(err)
	}
	if _, err := setup.store.IngestCollectorBatch(ctx, testConfigBatch(setup, "82000000-0000-4000-8000-000000000002", "replay", first)); err != nil {
		t.Fatal(err)
	}
	var transitions int
	_ = setup.store.db.QueryRowContext(ctx, `SELECT count(*) FROM events WHERE deployment_id=? AND code='config_change_detected'`, setup.state.DeploymentID).Scan(&transitions)
	if transitions != 0 {
		t.Fatalf("out-of-order replay invented %d transition(s)", transitions)
	}

	inOrder := newIngestSetup(t)
	first = testConfigFrame(testSourceID, 1, base, "0.34.0", nil)
	second = testConfigFrame(testSourceID, 2, base+30_000, "0.35.0", first.ConfigObservation)
	batch := testConfigBatch(inOrder, "82000000-0000-4000-8000-000000000003", "replay", first)
	batch.Frames = append(batch.Frames, second)
	if _, err := inOrder.store.IngestCollectorBatch(ctx, batch); err != nil {
		t.Fatal(err)
	}
	_ = inOrder.store.db.QueryRowContext(ctx, `SELECT count(*) FROM events WHERE deployment_id=? AND code='config_change_detected'`, inOrder.state.DeploymentID).Scan(&transitions)
	if transitions != 1 {
		t.Fatalf("in-order replay transitions=%d", transitions)
	}
}

func TestConfigRestartDerivesAlignedPredecessorAndUnalignedRestartIsExplicitlyUnavailable(t *testing.T) {
	t.Run("aligned change", func(t *testing.T) {
		setup := newIngestSetup(t)
		ctx := context.Background()
		base := setup.store.clock.Now().Add(-2 * time.Minute).UnixMilli()
		first := testConfigFrame(testSourceID, 1, base, "0.34.0", nil)
		alignConfigFrame(&first, base+1_000)
		if _, err := setup.store.IngestCollectorBatch(ctx, testConfigBatch(setup, "84000000-0000-4000-8000-000000000001", "current", first)); err != nil {
			t.Fatal(err)
		}
		bootID := "84000000-0000-4000-8000-000000000002"
		session := activateConfigRestart(t, setup, bootID, "84000000-0000-4000-8000-000000000003")
		second := testConfigFrame(testSourceID, 1, base+30_000, "0.35.0", nil)
		alignConfigFrame(&second, base+31_000)
		if _, err := setup.store.IngestCollectorBatch(ctx, testConfigBatchFor(setup, session, bootID, "84000000-0000-4000-8000-000000000004", "current", second)); err != nil {
			t.Fatal(err)
		}
		var start, end int64
		if err := setup.store.db.QueryRowContext(ctx, `SELECT occurred_start_ms,occurred_end_ms FROM events WHERE deployment_id=? AND code='config_change_detected'`, setup.state.DeploymentID).Scan(&start, &end); err != nil {
			t.Fatal(err)
		}
		if start != base+1_000 || end != base+31_000 {
			t.Fatalf("restart transition=%d..%d", start, end)
		}
	})

	t.Run("unaligned comparison", func(t *testing.T) {
		setup := newIngestSetup(t)
		ctx := context.Background()
		base := setup.store.clock.Now().Add(-2 * time.Minute).UnixMilli()
		first := testConfigFrame(testSourceID, 1, base, "0.34.0", nil)
		if _, err := setup.store.IngestCollectorBatch(ctx, testConfigBatch(setup, "85000000-0000-4000-8000-000000000001", "current", first)); err != nil {
			t.Fatal(err)
		}
		bootID := "85000000-0000-4000-8000-000000000002"
		session := activateConfigRestart(t, setup, bootID, "85000000-0000-4000-8000-000000000003")
		second := testConfigFrame(testSourceID, 1, base+30_000, "0.35.0", nil)
		if _, err := setup.store.IngestCollectorBatch(ctx, testConfigBatchFor(setup, session, bootID, "85000000-0000-4000-8000-000000000004", "current", second)); err != nil {
			t.Fatal(err)
		}
		var changed, unavailable int
		_ = setup.store.db.QueryRowContext(ctx, `SELECT count(*) FROM events WHERE deployment_id=? AND code='config_change_detected'`, setup.state.DeploymentID).Scan(&changed)
		_ = setup.store.db.QueryRowContext(ctx, `SELECT count(*) FROM events WHERE deployment_id=? AND code='config_transition_unavailable'`, setup.state.DeploymentID).Scan(&unavailable)
		if changed != 0 || unavailable != 1 {
			t.Fatalf("unaligned restart changed=%d unavailable=%d", changed, unavailable)
		}
	})
}

func TestConfigObservationRejectsForeignTargetAtomically(t *testing.T) {
	setup := newIngestSetup(t)
	frame := testConfigFrame(testSourceID, 1, setup.store.clock.Now().UnixMilli(), "0.34.0", nil)
	frame.ConfigObservation.TargetID = "83000000-0000-4000-8000-000000000001"
	frame.ConfigObservation.ConfigHash = domain.RuntimeConfigHash(frame.ConfigObservation.Fields, frame.ConfigObservation.FieldProvenance)
	if _, err := setup.store.IngestCollectorBatch(context.Background(), testConfigBatch(setup, "83000000-0000-4000-8000-000000000002", "current", frame)); !errors.Is(err, ErrOwnershipMismatch) {
		t.Fatalf("foreign config target error=%v", err)
	}
	var frames, configs int
	_ = setup.store.db.QueryRow(`SELECT count(*) FROM source_frames`).Scan(&frames)
	_ = setup.store.db.QueryRow(`SELECT count(*) FROM config_snapshots`).Scan(&configs)
	if frames != 0 || configs != 0 {
		t.Fatalf("foreign config partial write frames=%d configs=%d", frames, configs)
	}
}

func TestSourceStatusHasIndependentDurableDedupeLane(t *testing.T) {
	setup := newIngestSetup(t)
	status := protocol.SourceStatus{Protocol: "1.0", DeploymentID: setup.state.DeploymentID, HostID: testHostID, SecurityGeneration: setup.state.DeploymentGeneration, SessionGeneration: setup.session.SessionGeneration, CollectorBootID: testBootID, Sequence: 1, ObservedWallMS: setup.store.clock.Now().UnixMilli(), Heartbeat: "fresh", Sources: []protocol.SourceState{{SourceID: testSourceID, State: "fresh", FailureCount: 0}}, LossIntervals: []protocol.LossInterval{}}
	ack, err := setup.store.IngestSourceStatus(context.Background(), status)
	if err != nil || !ack.Durable || ack.Duplicate {
		t.Fatalf("first status = %#v, %v", ack, err)
	}
	ack, err = setup.store.IngestSourceStatus(context.Background(), status)
	if err != nil || !ack.Duplicate {
		t.Fatalf("duplicate status = %#v, %v", ack, err)
	}
}

func TestSourceStatusRejectsStaleNewAndSequenceRegressionButACKsOldDuplicate(t *testing.T) {
	setup := newIngestSetup(t)
	base := time.UnixMilli(setup.store.clock.Now().UnixMilli())
	setup.store.clock = &testClock{now: base}
	status := protocol.SourceStatus{Protocol: "1.0", DeploymentID: setup.state.DeploymentID, HostID: testHostID, SecurityGeneration: setup.state.DeploymentGeneration, SessionGeneration: setup.session.SessionGeneration, CollectorBootID: testBootID, Sequence: 2, ObservedWallMS: base.UnixMilli(), Heartbeat: "fresh", Sources: []protocol.SourceState{{SourceID: testSourceID, State: "fresh", FailureCount: 0}}, LossIntervals: []protocol.LossInterval{}}
	if _, err := setup.store.IngestSourceStatus(context.Background(), status); err != nil {
		t.Fatal(err)
	}
	setup.store.clock = &testClock{now: base.Add(2 * time.Minute)}
	if ack, err := setup.store.IngestSourceStatus(context.Background(), status); err != nil || !ack.Duplicate {
		t.Fatalf("old exact retry = %#v, %v", ack, err)
	}
	status.Sequence = 1
	status.ObservedWallMS = base.Add(2 * time.Minute).UnixMilli()
	if _, err := setup.store.IngestSourceStatus(context.Background(), status); !errors.Is(err, ErrGenerationConflict) {
		t.Fatalf("regressed status sequence = %v", err)
	}
	status.Sequence = 3
	status.ObservedWallMS = base.UnixMilli()
	if _, err := setup.store.IngestSourceStatus(context.Background(), status); !errors.Is(err, ErrStatusObservationExpired) {
		t.Fatalf("stale new status = %v", err)
	}
}

func TestCurrentFramesEnforceSourceKindSequenceAndStartOrder(t *testing.T) {
	setup := newIngestSetup(t)
	first := testBatch(setup)
	first.Frames[0].MonotonicStartNS = "10"
	first.Frames[0].MonotonicEndNS = "100"
	if _, err := setup.store.IngestCollectorBatch(context.Background(), first); err != nil {
		t.Fatal(err)
	}

	// Independent component reads can overlap. Start order advances even though
	// this frame starts before the preceding frame ended.
	overlap := testBatch(setup)
	overlap.BatchID = "20000000-0000-4000-8000-000000000002"
	overlap.Frames[0].Sequence = 2
	overlap.Frames[0].MonotonicStartNS = "50"
	overlap.Frames[0].MonotonicEndNS = "60"
	if _, err := setup.store.IngestCollectorBatch(context.Background(), overlap); err != nil {
		t.Fatalf("overlapping component interval = %v", err)
	}

	regressed := testBatch(setup)
	regressed.BatchID = "20000000-0000-4000-8000-000000000003"
	regressed.Frames[0].Sequence = 3
	regressed.Frames[0].MonotonicStartNS = "49"
	regressed.Frames[0].MonotonicEndNS = "70"
	if _, err := setup.store.IngestCollectorBatch(context.Background(), regressed); !errors.Is(err, ErrGenerationConflict) {
		t.Fatalf("regressed monotonic start = %v", err)
	}

	wrongKind := testBatch(setup)
	wrongKind.BatchID = "20000000-0000-4000-8000-000000000004"
	wrongKind.Frames[0].Sequence = 3
	wrongKind.Frames[0].MonotonicStartNS = "51"
	wrongKind.Frames[0].MonotonicEndNS = "52"
	delete(wrongKind.Frames[0].Gauges, "runtime.reachable")
	wrongKind.Frames[0].Gauges["host.disk.free_bytes"] = protocol.MetricValue{Value: json.RawMessage(`"10"`), Quality: domain.QualityMeasured, Provenance: testProvenance()}
	wrongKind.Frames[0].ModelObservations = nil
	if _, err := setup.store.IngestCollectorBatch(context.Background(), wrongKind); !errors.Is(err, ErrOwnershipMismatch) {
		t.Fatalf("runtime source carrying host metric = %v", err)
	}
}

func TestLateFrameIsHistoryButFutureAlignedFrameIsRejected(t *testing.T) {
	setup := newIngestSetup(t)
	base := time.UnixMilli(setup.store.clock.Now().UnixMilli())
	setup.store.clock = &testClock{now: base}
	late := testBatch(setup)
	old := base.Add(-2 * time.Minute).UnixMilli()
	late.Frames[0].EstimatedUTCMS = &old
	if _, err := setup.store.IngestCollectorBatch(context.Background(), late); err != nil {
		t.Fatalf("late historical frame = %v", err)
	}
	future := testBatch(setup)
	future.BatchID = "20000000-0000-4000-8000-000000000005"
	future.Frames[0].Sequence = 2
	future.Frames[0].MonotonicStartNS = "3"
	future.Frames[0].MonotonicEndNS = "4"
	timestamp := base.Add(61 * time.Second).UnixMilli()
	future.Frames[0].EstimatedUTCMS = &timestamp
	if _, err := setup.store.IngestCollectorBatch(context.Background(), future); !errors.Is(err, ErrGenerationConflict) {
		t.Fatalf("future aligned frame = %v", err)
	}
}

func TestFrameCodecRoundTripAndBound(t *testing.T) {
	setup := newIngestSetup(t)
	codec, err := NewFrameCodecV1()
	if err != nil {
		t.Fatal(err)
	}
	defer codec.Close()
	frame := testBatch(setup).Frames[0]
	payload, hash, err := codec.Encode(frame)
	if err != nil || len(payload) > protocol.MaxFrameBytes || len(hash) != 64 {
		t.Fatalf("encode = %d/%q/%v", len(payload), hash, err)
	}
	decoded, err := codec.Decode(payload)
	if err != nil || decoded.SourceID != frame.SourceID || decoded.Sequence != frame.Sequence {
		t.Fatalf("decode = %#v/%v", decoded, err)
	}
}

func testBatch(setup ingestSetup) protocol.CollectorBatch {
	now := setup.store.clock.Now().UnixMilli()
	estimated := now
	uncertainty := int64(1)
	size := domain.DecimalUint64(10)
	vram := domain.DecimalUint64(0)
	return protocol.CollectorBatch{Protocol: "1.0", DeliveryMode: "current", SecurityGeneration: setup.state.DeploymentGeneration, SessionGeneration: setup.session.SessionGeneration, DeploymentID: setup.state.DeploymentID, HostID: testHostID, CollectorBootID: testBootID, BatchID: testBatchID, Frames: []protocol.CollectorFrame{{SourceID: testSourceID, Sequence: 1, ObservedWallMS: now, EstimatedUTCMS: &estimated, UncertaintyMS: &uncertainty, MonotonicStartNS: "1", MonotonicEndNS: "2", DurationMS: 0, DefinitionRevision: "mac-ollama-1", Quality: domain.QualityRuntimeReported, Provenance: testProvenance(), Gauges: map[string]protocol.MetricValue{"runtime.reachable": {Value: json.RawMessage("true"), Quality: domain.QualityRuntimeReported, Provenance: testProvenance()}}, NetworkObservations: []domain.NetworkObservation{}, ModelObservations: []domain.ModelObservation{{ModelID: testModelID, Digest: *setup.inventory.Models[0].Digest, Loaded: true, ReportedSizeBytes: &size, ReportedSizeVRAMBytes: &vram, Missing: []domain.MissingCapability{}, Provenance: testProvenance()}}, ProcessObservations: []domain.ProcessObservation{}, CapabilitiesMissing: []domain.MissingCapability{}}}}
}
func testProvenance() domain.Provenance {
	return domain.Provenance{Source: domain.ProvenanceRuntimeAPI, MethodRevision: "ollama-bounded-read-v1", Verification: domain.VerificationDirectCapture}
}

func testConfigFrame(source string, sequence, observedMS int64, version string, previous *domain.RuntimeConfigObservation) protocol.CollectorFrame {
	observed := observedMS
	provenance := domain.Provenance{Source: domain.ProvenanceRuntimeAPI, MethodRevision: "ollama-0.34.0-bounded-read-v1", Verification: domain.VerificationDirectCapture, ObservedAtMS: &observed}
	fields := domain.RuntimeConfigFields{ServerVersion: version}
	fieldProvenance := domain.RuntimeConfigFieldProvenance{ServerVersion: provenance}
	observation := &domain.RuntimeConfigObservation{TargetID: testTargetID, ConfigHash: domain.RuntimeConfigHash(fields, fieldProvenance), Fields: fields, FieldProvenance: fieldProvenance}
	if previous != nil {
		previousHash, previousMS := previous.ConfigHash, previous.FieldProvenance.ServerVersion.ObservedAtMS
		observation.PreviousConfigHash = &previousHash
		if previousMS != nil {
			value := *previousMS
			observation.PreviousObservedMS = &value
		}
	}
	start := domain.DecimalUint64(uint64(sequence) * uint64(time.Millisecond))
	return protocol.CollectorFrame{SourceID: source, Sequence: sequence, ObservedWallMS: observedMS, MonotonicStartNS: start, MonotonicEndNS: start, DurationMS: 0, DefinitionRevision: domain.RegistryRevision, Quality: domain.QualityRuntimeReported, Provenance: provenance, Gauges: map[string]protocol.MetricValue{}, NetworkObservations: []domain.NetworkObservation{}, ModelObservations: []domain.ModelObservation{}, ProcessObservations: []domain.ProcessObservation{}, ConfigObservation: observation, CapabilitiesMissing: []domain.MissingCapability{}}
}

func testAssociationFrame(sequence, observedMS int64) protocol.CollectorFrame {
	provenance := domain.Provenance{Source: domain.ProvenanceDarwinAPI, MethodRevision: "darwin-proc-rusage-candidate-1", Verification: domain.VerificationDirectCapture, ObservedAtMS: &observedMS}
	key, selector := strings.Repeat("b", 64), strings.Repeat("c", 64)
	pid, start, version, sourcePin := 700, domain.DecimalUint64(100000000), "0.12.10", "ollama-0.12.10-source"
	target := testTargetID
	process := domain.ProcessObservation{HostID: testHostID, BootID: testBootID, PID: pid, ProcessStartIdentity: start, ProcessKey: key, DisplayBasename: stringPtr("ollama"), Category: domain.ProcessSelectedOllama, TargetID: &target, AssociationQuality: domain.AssociationVerified, Missing: []domain.MissingCapability{}, Provenance: provenance}
	association := &domain.EndpointAssociation{TargetID: target, EndpointHash: selector, TargetRevision: 1, ManifestRevision: 1, ManifestSHA256: strings.Repeat("d", 64), SelectorSHA256: selector, IdentityRevision: strings.Repeat("e", 64), RuntimeVersion: &version, RuntimeSourcePinID: &sourcePin, PID: &pid, ProcessStartIdentity: &start, ProcessKey: &key, Quality: domain.AssociationVerified, Provenance: provenance}
	startNS := domain.DecimalUint64(uint64(sequence) * uint64(time.Second))
	return protocol.CollectorFrame{SourceID: testHostSourceID, Sequence: sequence, ObservedWallMS: observedMS, MonotonicStartNS: startNS, MonotonicEndNS: startNS, DurationMS: 0, DefinitionRevision: domain.RegistryRevision, Quality: domain.QualityMeasured, Provenance: provenance, Gauges: map[string]protocol.MetricValue{}, NetworkObservations: []domain.NetworkObservation{}, ModelObservations: []domain.ModelObservation{}, ProcessObservations: []domain.ProcessObservation{process}, ProcessSummary: &domain.ProcessSummary{EligiblePIDCount: 1, ExaminedPIDCount: 1, RetainedProcessCount: 1, Coverage: "complete", MethodRevision: "darwin-proc-rusage-candidate-1", SampleIntervalMS: 15_000}, EndpointAssociation: association, CapabilitiesMissing: []domain.MissingCapability{}}
}

func missingReasonTestPointer(value domain.MissingReason) *domain.MissingReason { return &value }

func testConfigBatch(setup ingestSetup, id, mode string, frame protocol.CollectorFrame) protocol.CollectorBatch {
	return protocol.CollectorBatch{Protocol: domain.ProtocolVersion, DeliveryMode: mode, SecurityGeneration: setup.state.DeploymentGeneration, SessionGeneration: setup.session.SessionGeneration, DeploymentID: setup.state.DeploymentID, HostID: testHostID, CollectorBootID: testBootID, BatchID: id, Frames: []protocol.CollectorFrame{frame}}
}

func testConfigBatchFor(setup ingestSetup, session protocol.SessionResult, bootID, id, mode string, frame protocol.CollectorFrame) protocol.CollectorBatch {
	return protocol.CollectorBatch{Protocol: domain.ProtocolVersion, DeliveryMode: mode, SecurityGeneration: setup.state.DeploymentGeneration, SessionGeneration: session.SessionGeneration, DeploymentID: setup.state.DeploymentID, HostID: testHostID, CollectorBootID: bootID, BatchID: id, Frames: []protocol.CollectorFrame{frame}}
}

func alignConfigFrame(frame *protocol.CollectorFrame, estimatedMS int64) {
	offset, uncertainty := estimatedMS-frame.ObservedWallMS, int64(1)
	frame.EstimatedUTCMS, frame.OffsetMS, frame.UncertaintyMS = &estimatedMS, &offset, &uncertainty
}

func activateConfigRestart(t *testing.T, setup ingestSetup, bootID, activationID string) protocol.SessionResult {
	t.Helper()
	ctx := context.Background()
	session, err := setup.store.ActivateCollectorSession(ctx, protocol.SessionActivation{Protocol: domain.ProtocolVersion, DeploymentID: setup.state.DeploymentID, HostID: testHostID, SecurityGeneration: setup.state.DeploymentGeneration, ActivationRequestID: activationID, CollectorBootID: bootID, ExpectedPreviousGeneration: setup.session.SessionGeneration})
	if err != nil {
		t.Fatal(err)
	}
	inventory := setup.inventory
	inventory.SessionGeneration, inventory.CollectorBootID, inventory.InventoryRevision = session.SessionGeneration, bootID, strings.Repeat("d", 64)
	if _, err := setup.store.RegisterCollectorInventory(ctx, inventory); err != nil {
		t.Fatal(err)
	}
	return session
}
func stringPtr(value string) *string { return &value }
