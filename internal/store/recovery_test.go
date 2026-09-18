package store

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"testing"
	"time"

	"rmt.local/monitor/internal/domain"
	"rmt.local/monitor/internal/protocol"
)

type recoveryStoreSetup struct {
	store          *Store
	clock          *enrollmentTestClock
	admin          SessionRecord
	oldGeneration  string
	oldBoot        string
	currentBoot    string
	currentSession protocol.SessionResult
	manifest       protocol.RecoveryManifest
	replayFrame    protocol.RecoveryFrame
}

func newRecoveryStoreSetup(t *testing.T) recoveryStoreSetup {
	t.Helper()
	ctx := context.Background()
	st, clock, oldAdmin := newEnrollmentStore(t)
	oldGeneration := oldAdmin.Generation
	oldBoot := "30000000-0000-4000-8000-000000000001"
	currentBoot := "30000000-0000-4000-8000-000000000002"
	registration := LocalHostRegistration{HostID: testHostID, InstallationUUID: testInstallID, DisplayName: "Retained Mac", CollectorVersion: "0.1.0", Capabilities: map[string]bool{"darwin": true}}
	oldOwner := TrustedOwnerContext{DeploymentID: oldAdmin.DeploymentID, SecurityGeneration: oldGeneration, InstallingUID: 501, VerifiedOSOwner: true}
	if err := st.RegisterLocalHost(ctx, oldOwner, registration); err != nil {
		t.Fatal(err)
	}
	oldActivation := protocol.SessionActivation{Protocol: domain.ProtocolVersion, DeploymentID: oldAdmin.DeploymentID, HostID: testHostID, SecurityGeneration: oldGeneration, ActivationRequestID: "30000000-0000-4000-8000-000000000003", CollectorBootID: oldBoot, ExpectedPreviousGeneration: 0}
	oldSession, err := st.ActivateCollectorSession(ctx, oldActivation)
	if err != nil {
		t.Fatal(err)
	}
	oldInventory := protocol.CollectorInventory{Protocol: domain.ProtocolVersion, DeploymentID: oldAdmin.DeploymentID, HostID: testHostID, SecurityGeneration: oldGeneration, SessionGeneration: oldSession.SessionGeneration, CollectorBootID: oldBoot, InventoryRevision: strings.Repeat("a", 64), Sources: []protocol.InventorySource{{SourceID: testSourceID, Kind: "host", CapabilityRevision: domain.RegistryRevision, Active: true}}, Targets: []protocol.InventoryTarget{}, Models: []protocol.InventoryModel{}}
	if _, err := st.RegisterCollectorInventory(ctx, oldInventory); err != nil {
		t.Fatal(err)
	}

	newGeneration := "30000000-0000-4000-8000-000000000004"
	now := clock.Now().UnixMilli()
	for _, statement := range []struct {
		query string
		args  []any
	}{
		{`INSERT INTO deployment_generations(deployment_id,generation,reason,activated_ms) VALUES(?,?,'restore_bootstrap',?)`, []any{oldAdmin.DeploymentID, newGeneration, now}},
		{`UPDATE deployments SET deployment_generation=?,recovery_state='normal',updated_ms=? WHERE id=?`, []any{newGeneration, now, oldAdmin.DeploymentID}},
		{`UPDATE collector_sessions SET superseded_ms=COALESCE(superseded_ms,?) WHERE deployment_id=? AND host_id=?`, []any{now, oldAdmin.DeploymentID, testHostID}},
		{`UPDATE hosts SET current_session_generation=0,last_boot_id=NULL,retired_ms=?,updated_ms=? WHERE deployment_id=? AND id=?`, []any{now, now, oldAdmin.DeploymentID, testHostID}},
	} {
		if _, err := st.db.Exec(statement.query, statement.args...); err != nil {
			t.Fatal(err)
		}
	}
	newAdminID := "30000000-0000-4000-8000-000000000005"
	if _, err := st.db.Exec(`INSERT INTO users(id,deployment_id,name,argon2_hash,role,disabled,trust_generation,historical_restored,version,created_ms,updated_ms) VALUES(?,?,?,'00000000000000000000000000000000','admin',0,?,0,1,?,?)`, newAdminID, oldAdmin.DeploymentID, "recovery-admin", newGeneration, now, now); err != nil {
		t.Fatal(err)
	}
	admin := SessionRecord{User: domain.User{ID: newAdminID, Revision: 1, Name: "recovery-admin", Role: "admin", TrustGeneration: newGeneration}, DeploymentID: oldAdmin.DeploymentID, Generation: newGeneration, ExpiresMS: clock.Now().Add(time.Hour).UnixMilli()}
	newOwner := TrustedOwnerContext{DeploymentID: admin.DeploymentID, SecurityGeneration: newGeneration, InstallingUID: 501, VerifiedOSOwner: true}
	if err := st.ReEnrollLocalHost(ctx, newOwner, registration, oldGeneration); err != nil {
		t.Fatal(err)
	}
	currentActivation := protocol.SessionActivation{Protocol: domain.ProtocolVersion, DeploymentID: admin.DeploymentID, HostID: testHostID, SecurityGeneration: newGeneration, ActivationRequestID: "30000000-0000-4000-8000-000000000006", CollectorBootID: currentBoot, ExpectedPreviousGeneration: 0}
	currentSession, err := st.ActivateCollectorSession(ctx, currentActivation)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := st.MeasureAndRecordCapacity(ctx, admin.DeploymentID, now, ExternalCapacityUsage{}); err != nil {
		t.Fatal(err)
	}

	observed := now - 1_000
	estimated, offset, uncertainty := observed, int64(0), int64(1)
	frame := protocol.CollectorFrame{
		SourceID: testSourceID, Sequence: 9, ObservedWallMS: observed, EstimatedUTCMS: &estimated, OffsetMS: &offset, UncertaintyMS: &uncertainty,
		MonotonicStartNS: "100", MonotonicEndNS: "200", DurationMS: 0, DefinitionRevision: domain.RegistryRevision,
		Quality: domain.QualityMeasured, Provenance: testProvenance(), Gauges: map[string]protocol.MetricValue{
			"host.cpu.busy_ratio": {Value: json.RawMessage("0.25"), Quality: domain.QualityMeasured, Provenance: testProvenance()},
		}, NetworkObservations: []domain.NetworkObservation{}, ModelObservations: []domain.ModelObservation{}, ProcessObservations: []domain.ProcessObservation{}, CapabilitiesMissing: []domain.MissingCapability{},
	}
	payload, payloadHash, err := st.codec.Encode(frame)
	if err != nil {
		t.Fatal(err)
	}
	segmentHasher := sha256.New()
	if err := protocol.WriteRecoveryDescriptor(segmentHasher, protocol.RecoveryDescriptor{SourceID: testSourceID, Sequence: 9, ObservedMS: observed, PayloadSHA256: payloadHash}); err != nil {
		t.Fatal(err)
	}
	manifest := protocol.RecoveryManifest{
		SchemaVersion: domain.SchemaVersion, DeploymentID: admin.DeploymentID, HostID: testHostID, OriginalSecurityGeneration: oldGeneration, OriginalCollectorBootID: oldBoot,
		CreatedMS: now, TotalBytes: int64(len(payload)), TotalFrames: 1, Sources: []string{testSourceID},
		HistoricalDefinitions: protocol.RecoveryDefinitions{HistoricalOnly: true, Sources: []protocol.InventorySource{{SourceID: testSourceID, Kind: "host", CapabilityRevision: domain.RegistryRevision, Active: false}}, Targets: []protocol.InventoryTarget{}, Models: []protocol.InventoryModel{}},
		Segments:              []protocol.RecoverySegment{{SourceID: testSourceID, FromSequence: 9, ToSequence: 9, FirstMS: observed, LastMS: observed, FrameCount: 1, Bytes: int64(len(payload)), SegmentSHA256: hex.EncodeToString(segmentHasher.Sum(nil))}}, LossIntervals: []protocol.RecoveryLoss{},
	}
	manifest.ManifestSHA256, err = protocol.CanonicalRecoveryManifestHash(manifest)
	if err != nil {
		t.Fatal(err)
	}
	return recoveryStoreSetup{store: st, clock: clock, admin: admin, oldGeneration: oldGeneration, oldBoot: oldBoot, currentBoot: currentBoot, currentSession: currentSession, manifest: manifest, replayFrame: protocol.RecoveryFrame{OriginalSourceID: testSourceID, OriginalSequence: 9, OriginalObservedMS: observed, OriginalPayloadSHA256: payloadHash, Frame: frame}}
}

func (setup recoveryStoreSetup) createGrant(t *testing.T) protocol.RecoveryGrant {
	t.Helper()
	grant, err := setup.store.CreateRecoveryGrant(context.Background(), setup.admin, "30000000-0000-4000-8000-000000000007", strings.Repeat("c", 64), setup.manifest)
	if err != nil {
		t.Fatal(err)
	}
	return grant
}

func (setup recoveryStoreSetup) replay(t *testing.T, grant protocol.RecoveryGrant) protocol.RecoveryReplay {
	t.Helper()
	replay := protocol.RecoveryReplay{
		Protocol: domain.ProtocolVersion, GrantID: grant.GrantID, GrantSHA256: grant.GrantSHA256, ReplayRequestID: "30000000-0000-4000-8000-000000000008",
		AdmittingSecurityGeneration: setup.admin.Generation, AdmittingSessionGeneration: setup.currentSession.SessionGeneration, AdmittingCollectorBootID: setup.currentBoot,
		DeploymentID: setup.admin.DeploymentID, HostID: testHostID, OriginalSecurityGeneration: setup.oldGeneration, OriginalCollectorBootID: setup.oldBoot,
		Frames: []protocol.RecoveryFrame{setup.replayFrame},
	}
	var err error
	replay.ScopeSHA256, err = protocol.CanonicalRecoveryScopeHash(replay)
	if err != nil {
		t.Fatal(err)
	}
	return replay
}

func TestRecoveryReplayIsAtomicDurableAndExactlyIdempotent(t *testing.T) {
	setup := newRecoveryStoreSetup(t)
	grant := setup.createGrant(t)
	if _, err := setup.store.CreateRecoveryGrant(context.Background(), setup.admin, "30000000-0000-4000-8000-000000000013", strings.Repeat("1", 64), setup.manifest); !errors.Is(err, ErrRecoveryConflict) {
		t.Fatalf("second active grant for one host admitted: %v", err)
	}
	replay := setup.replay(t, grant)
	ack, err := setup.store.IngestRecoveryReplay(context.Background(), replay)
	if err != nil || !ack.Durable || ack.Accepted != 1 || ack.Duplicate != 0 || !ack.Complete || len(ack.Receipts) != 1 {
		t.Fatalf("first recovery ACK=%#v err=%v", ack, err)
	}
	retry, err := setup.store.IngestRecoveryReplay(context.Background(), replay)
	if err != nil || !reflect.DeepEqual(retry, ack) {
		t.Fatalf("exact retry changed durable ACK: first=%#v retry=%#v err=%v", ack, retry, err)
	}
	redundant := replay
	redundant.ReplayRequestID = "30000000-0000-4000-8000-000000000014"
	redundant.ScopeSHA256, _ = protocol.CanonicalRecoveryScopeHash(redundant)
	if _, err := setup.store.IngestRecoveryReplay(context.Background(), redundant); !errors.Is(err, ErrRecoveryConflict) {
		t.Fatalf("new request identity without new recovery progress admitted: %v", err)
	}
	changed := replay
	changed.Frames = append([]protocol.RecoveryFrame(nil), replay.Frames...)
	changed.Frames[0].Frame.Gauges = map[string]protocol.MetricValue{"host.cpu.busy_ratio": {Value: json.RawMessage("0.5"), Quality: domain.QualityMeasured, Provenance: testProvenance()}}
	_, changedHash, err := setup.store.codec.Encode(changed.Frames[0].Frame)
	if err != nil {
		t.Fatal(err)
	}
	changed.Frames[0].OriginalPayloadSHA256 = changedHash
	changed.ReplayRequestID = "30000000-0000-4000-8000-000000000012"
	changed.ScopeSHA256, _ = protocol.CanonicalRecoveryScopeHash(changed)
	if _, err := setup.store.IngestRecoveryReplay(context.Background(), changed); !errors.Is(err, ErrRecoveryConflict) {
		t.Fatalf("changed payload under original tuple admitted: %v", err)
	}
	var mode, originalGeneration, grantHash string
	if err := setup.store.db.QueryRow(`SELECT delivery_mode,original_security_generation,recovery_grant_hash FROM source_frames WHERE deployment_id=? AND host_id=? AND original_collector_boot_id=? AND original_source_id=? AND original_sequence=9`, setup.admin.DeploymentID, testHostID, setup.oldBoot, testSourceID).Scan(&mode, &originalGeneration, &grantHash); err != nil {
		t.Fatal(err)
	}
	if mode != "restored_replay" || originalGeneration != setup.oldGeneration || grantHash != grant.GrantSHA256 {
		t.Fatalf("restored provenance changed: mode=%s generation=%s grant=%s", mode, originalGeneration, grantHash)
	}
	var liveFrames int
	if err := setup.store.db.QueryRow(`SELECT count(*) FROM source_frames WHERE deployment_id=? AND host_id=? AND recovery_grant_id=? AND delivery_mode='current'`, setup.admin.DeploymentID, testHostID, grant.GrantID).Scan(&liveFrames); err != nil || liveFrames != 0 {
		t.Fatalf("restored replay became live state: count=%d err=%v", liveFrames, err)
	}
	var replayAudits int
	if err := setup.store.db.QueryRow(`SELECT count(*) FROM audit WHERE deployment_id=? AND action='recovery.grant.use' AND resource_id=?`, setup.admin.DeploymentID, grant.GrantID).Scan(&replayAudits); err != nil || replayAudits != 1 {
		t.Fatalf("exact replay retry audit count=%d err=%v", replayAudits, err)
	}
	var reserved int64
	if err := setup.store.db.QueryRow(`SELECT reserved_physical_bytes FROM quota_classes WHERE deployment_id=? AND class='metadata'`, setup.admin.DeploymentID).Scan(&reserved); err != nil || reserved != 0 {
		t.Fatalf("completed grant reservation=%d err=%v", reserved, err)
	}
	var cursorJSON string
	if err := setup.store.db.QueryRow(`SELECT evaluator_cursor_json FROM maintenance WHERE deployment_id=?`, setup.admin.DeploymentID).Scan(&cursorJSON); err != nil {
		t.Fatal(err)
	}
	pending, err := readPendingRecoveryCapacity(cursorJSON)
	if err != nil || pending != grantReservation(t, grant.MaxFrames) {
		t.Fatalf("completed grant pending physical charge=%d err=%v", pending, err)
	}
}

func TestRecoveryReplayRejectsHashConflictGenerationAndExpiryWithoutPartialWrite(t *testing.T) {
	setup := newRecoveryStoreSetup(t)
	grant := setup.createGrant(t)
	replay := setup.replay(t, grant)
	wrongGeneration := replay
	wrongGeneration.AdmittingSecurityGeneration = setup.oldGeneration
	wrongGeneration.ScopeSHA256, _ = protocol.CanonicalRecoveryScopeHash(wrongGeneration)
	if _, err := setup.store.IngestRecoveryReplay(context.Background(), wrongGeneration); !errors.Is(err, ErrGenerationConflict) {
		t.Fatalf("old generation admitted: %v", err)
	}
	setup.clock.now = setup.clock.now.Add(2 * time.Hour)
	if _, err := setup.store.IngestRecoveryReplay(context.Background(), replay); !errors.Is(err, ErrRecoveryGrantExpired) {
		t.Fatalf("expired grant admitted: %v", err)
	}
	var frames, receipts int
	_ = setup.store.db.QueryRow(`SELECT count(*) FROM source_frames WHERE recovery_grant_id=?`, grant.GrantID).Scan(&frames)
	_ = setup.store.db.QueryRow(`SELECT count(*) FROM recovery_grant_receipts WHERE grant_id=?`, grant.GrantID).Scan(&receipts)
	if frames != 0 || receipts != 0 {
		t.Fatalf("failed replay partially persisted frames=%d receipts=%d", frames, receipts)
	}

	ownerSetup := newRecoveryStoreSetup(t)
	cpu := 0.1
	footprint := domain.DecimalUint64(1)
	foreignFrame := ownerSetup.replayFrame
	foreignFrame.Frame.ProcessObservations = []domain.ProcessObservation{{HostID: "40000000-0000-4000-8000-000000000001", BootID: ownerSetup.currentBoot, PID: 1, ProcessStartIdentity: "1", ProcessKey: strings.Repeat("f", 64), Category: domain.ProcessOtherSameUser, AssociationQuality: domain.AssociationNone, CPUBusyRatio: &cpu, PhysicalFootprintBytes: &footprint, Missing: []domain.MissingCapability{}, Provenance: testProvenance()}}
	foreignPayload, foreignHash, err := ownerSetup.store.codec.Encode(foreignFrame.Frame)
	if err != nil {
		t.Fatal(err)
	}
	foreignFrame.OriginalPayloadSHA256 = foreignHash
	setSingleFrameManifest(t, &ownerSetup, foreignFrame, len(foreignPayload))
	ownerGrant := ownerSetup.createGrant(t)
	foreignOwner := ownerSetup.replay(t, ownerGrant)
	foreignOwner.Frames = []protocol.RecoveryFrame{foreignFrame}
	foreignOwner.ReplayRequestID = "40000000-0000-4000-8000-000000000002"
	foreignOwner.ScopeSHA256, _ = protocol.CanonicalRecoveryScopeHash(foreignOwner)
	if _, err := ownerSetup.store.IngestRecoveryReplay(context.Background(), foreignOwner); !errors.Is(err, ErrOwnershipMismatch) {
		t.Fatalf("foreign nested owner was not rejected by ownership validation: %v", err)
	}
}

func setSingleFrameManifest(t *testing.T, setup *recoveryStoreSetup, frame protocol.RecoveryFrame, payloadBytes int) {
	t.Helper()
	hasher := sha256.New()
	if err := protocol.WriteRecoveryDescriptor(hasher, protocol.RecoveryDescriptor{SourceID: frame.OriginalSourceID, Sequence: frame.OriginalSequence, ObservedMS: frame.OriginalObservedMS, PayloadSHA256: frame.OriginalPayloadSHA256}); err != nil {
		t.Fatal(err)
	}
	setup.manifest.TotalBytes = int64(payloadBytes)
	setup.manifest.Segments[0].Bytes = int64(payloadBytes)
	setup.manifest.Segments[0].SegmentSHA256 = hex.EncodeToString(hasher.Sum(nil))
	setup.manifest.ManifestSHA256, _ = protocol.CanonicalRecoveryManifestHash(setup.manifest)
}

func grantReservation(t *testing.T, frames int) int64 {
	t.Helper()
	value, err := RecoveryReceiptReservationBytes(frames)
	if err != nil {
		t.Fatal(err)
	}
	return value
}

func TestRecoveryGrantCapacityFailureRollsBackHistoricalDefinitions(t *testing.T) {
	setup := newRecoveryStoreSetup(t)
	unknownSource := "30000000-0000-4000-8000-000000000009"
	manifest := setup.manifest
	manifest.Sources = []string{unknownSource}
	manifest.HistoricalDefinitions.Sources = []protocol.InventorySource{{SourceID: unknownSource, Kind: "host", CapabilityRevision: domain.RegistryRevision, Active: false}}
	manifest.Segments[0].SourceID = unknownSource
	manifest.ManifestSHA256, _ = protocol.CanonicalRecoveryManifestHash(manifest)
	if _, err := setup.store.db.Exec(`UPDATE quota_classes SET byte_limit=current_physical_bytes WHERE deployment_id=? AND class IN ('metadata','live_total')`, setup.admin.DeploymentID); err != nil {
		t.Fatal(err)
	}
	if _, err := setup.store.CreateRecoveryGrant(context.Background(), setup.admin, "30000000-0000-4000-8000-000000000010", strings.Repeat("d", 64), manifest); !errors.Is(err, ErrRecoveryCapacityBusy) {
		t.Fatalf("capacity failure=%v", err)
	}
	var definitions, grants int
	_ = setup.store.db.QueryRow(`SELECT count(*) FROM sources WHERE id=?`, unknownSource).Scan(&definitions)
	_ = setup.store.db.QueryRow(`SELECT count(*) FROM recovery_grants`).Scan(&grants)
	if definitions != 0 || grants != 0 {
		t.Fatalf("failed grant leaked definitions=%d grants=%d", definitions, grants)
	}
}

func TestRecoveryGrantRejectsExpiredEvidenceBeforeReservation(t *testing.T) {
	setup := newRecoveryStoreSetup(t)
	manifest := setup.manifest
	manifest.Segments[0].FirstMS = setup.clock.Now().Add(-24*time.Hour - time.Millisecond).UnixMilli()
	manifest.ManifestSHA256, _ = protocol.CanonicalRecoveryManifestHash(manifest)
	if _, err := setup.store.CreateRecoveryGrant(context.Background(), setup.admin, "30000000-0000-4000-8000-000000000011", strings.Repeat("e", 64), manifest); !errors.Is(err, ErrRecoveryConflict) {
		t.Fatalf("expired evidence grant=%v", err)
	}
	var reserved int64
	_ = setup.store.db.QueryRow(`SELECT reserved_physical_bytes FROM quota_classes WHERE deployment_id=? AND class='metadata'`, setup.admin.DeploymentID).Scan(&reserved)
	if reserved != 0 {
		t.Fatalf("expired evidence reserved metadata=%d", reserved)
	}
}

func TestRecoveryCompletedGrantKeepsPendingChargeUntilPhysicalRemeasurement(t *testing.T) {
	setup := newRecoveryStoreSetup(t)
	grant := setup.createGrant(t)
	if _, err := setup.store.IngestRecoveryReplay(context.Background(), setup.replay(t, grant)); err != nil {
		t.Fatal(err)
	}
	pending := grantReservation(t, grant.MaxFrames)
	if _, err := setup.store.db.Exec(`UPDATE quota_classes SET current_physical_bytes=byte_limit-? WHERE deployment_id=? AND class IN ('metadata','live_total')`, pending, setup.admin.DeploymentID); err != nil {
		t.Fatal(err)
	}
	if _, err := setup.store.CreateRecoveryGrant(context.Background(), setup.admin, "30000000-0000-4000-8000-000000000015", strings.Repeat("2", 64), setup.manifest); !errors.Is(err, ErrRecoveryCapacityBusy) {
		t.Fatalf("completed grant capacity was reused before measurement: %v", err)
	}
	if _, err := setup.store.MeasureAndRecordCapacity(context.Background(), setup.admin.DeploymentID, setup.clock.Now().UnixMilli(), ExternalCapacityUsage{}); err != nil {
		t.Fatal(err)
	}
	var cursorJSON string
	if err := setup.store.db.QueryRow(`SELECT evaluator_cursor_json FROM maintenance WHERE deployment_id=?`, setup.admin.DeploymentID).Scan(&cursorJSON); err != nil {
		t.Fatal(err)
	}
	if after, err := readPendingRecoveryCapacity(cursorJSON); err != nil || after != 0 {
		t.Fatalf("physical remeasurement did not clear pending recovery charge: %d %v", after, err)
	}
	if _, err := setup.store.CreateRecoveryGrant(context.Background(), setup.admin, "30000000-0000-4000-8000-000000000015", strings.Repeat("2", 64), setup.manifest); err != nil {
		t.Fatalf("remeasured completed grant capacity remained unavailable: %v", err)
	}
}

type recoveryReceiptAllocationFixture struct {
	SchemaVersion string   `json:"schema_version"`
	SQLiteVersion string   `json:"sqlite_version"`
	SQLiteSource  string   `json:"sqlite_source_id"`
	PageSize      int64    `json:"page_size"`
	FixedBytes    int64    `json:"fixed_reservation_bytes"`
	PerFrameBytes int64    `json:"per_frame_reservation_bytes"`
	Included      []string `json:"included_tables"`
	Samples       []struct {
		FrameCount         int   `json:"frame_count"`
		FramesPerRequest   int   `json:"frames_per_request"`
		ObservedDeltaBytes int64 `json:"observed_delta_bytes"`
		ReservationBytes   int64 `json:"reservation_bytes"`
		Calibrated         bool  `json:"calibrated"`
	} `json:"samples"`
}

func TestRecoveryReceiptReservationMatchesPinnedDBStatFixture(t *testing.T) {
	fixturePath := filepath.Join("..", "..", "fixtures", "contracts", "storage", "recovery-receipt-allocation.json")
	file, err := os.Open(fixturePath)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	var fixture recoveryReceiptAllocationFixture
	if err := protocol.DecodeStrictJSON(file, 64<<10, &fixture); err != nil {
		t.Fatal(err)
	}
	included := []string{"recovery_grants", "recovery_grant_tombstones", "recovery_grant_receipts", "idempotency_receipts", "audit"}
	if fixture.SchemaVersion != domain.SchemaVersion || fixture.FixedBytes != recoveryReceiptReservationFixed || fixture.PerFrameBytes != recoveryReceiptReservationPerFrame || !reflect.DeepEqual(fixture.Included, included) || len(fixture.Samples) != 4 {
		t.Fatalf("invalid recovery receipt allocation fixture: %#v", fixture)
	}
	for _, sample := range fixture.Samples {
		sample := sample
		t.Run(strconv.Itoa(sample.FrameCount)+"-by-"+strconv.Itoa(sample.FramesPerRequest), func(t *testing.T) {
			setup := newRecoveryStoreSetup(t)
			var version, source string
			var pageSize int64
			if err := setup.store.db.QueryRow(`SELECT sqlite_version(),sqlite_source_id()`).Scan(&version, &source); err != nil {
				t.Fatal(err)
			}
			if err := setup.store.db.QueryRow(`PRAGMA page_size`).Scan(&pageSize); err != nil {
				t.Fatal(err)
			}
			if version != fixture.SQLiteVersion || source != fixture.SQLiteSource || pageSize != fixture.PageSize {
				t.Fatalf("receipt sizing runtime drift: sqlite=%q source=%q page=%d", version, source, pageSize)
			}
			before, err := recoveryReceiptDBStatBytes(context.Background(), setup.store)
			if err != nil {
				t.Fatal(err)
			}
			if sample.FramesPerRequest < 1 || sample.FramesPerRequest > 64 || sample.FrameCount < 1 || sample.FrameCount%sample.FramesPerRequest != 0 {
				t.Fatalf("invalid sizing sample: %#v", sample)
			}
			setup.manifest.TotalFrames = sample.FrameCount
			setup.manifest.TotalBytes = int64(sample.FrameCount)
			setup.manifest.Segments = []protocol.RecoverySegment{}
			for start := 0; start < sample.FrameCount; start += protocol.MaxRecoverySegmentFrames {
				count := protocol.MaxRecoverySegmentFrames
				if remaining := sample.FrameCount - start; remaining < count {
					count = remaining
				}
				from := int64(9 + start)
				setup.manifest.Segments = append(setup.manifest.Segments, protocol.RecoverySegment{SourceID: testSourceID, FromSequence: from, ToSequence: from + int64(count) - 1, FirstMS: setup.replayFrame.OriginalObservedMS, LastMS: setup.replayFrame.OriginalObservedMS, FrameCount: count, Bytes: int64(count), SegmentSHA256: strings.Repeat("f", 64)})
			}
			setup.manifest.ManifestSHA256, _ = protocol.CanonicalRecoveryManifestHash(setup.manifest)
			grant := setup.createGrant(t)
			tx, err := setup.store.db.BeginTx(context.Background(), nil)
			if err != nil {
				t.Fatal(err)
			}
			defer tx.Rollback()
			statement, err := tx.Prepare(`INSERT INTO recovery_grant_receipts(deployment_id,host_id,grant_id,original_collector_boot_id,original_source_id,original_sequence,original_payload_sha256,disposition,accepted_ms) VALUES(?,?,?,?,?,?,?,'recovered',?)`)
			if err != nil {
				t.Fatal(err)
			}
			for index := 0; index < sample.FrameCount; index++ {
				if _, err := statement.Exec(setup.admin.DeploymentID, testHostID, grant.GrantID, setup.oldBoot, testSourceID, 9+index, strings.Repeat("f", 64), setup.clock.Now().UnixMilli()); err != nil {
					statement.Close()
					tx.Rollback()
					t.Fatal(err)
				}
			}
			for request := 0; request < sample.FrameCount/sample.FramesPerRequest; request++ {
				auditID := fmt.Sprintf("50000000-0000-4000-8000-%012x", request+1)
				replayID := fmt.Sprintf("60000000-0000-4000-8000-%012x", request+1)
				detail := fmt.Sprintf(`{"accepted":%d,"duplicate":0,"replay_request_id":%q,"scope_sha256":%q}`, sample.FramesPerRequest, replayID, strings.Repeat("e", 64))
				if _, err := tx.Exec(`INSERT INTO audit(id,deployment_id,actor_user_id,action,resource_id,time_ms,allowlisted_detail_json) VALUES(?,?,NULL,'recovery.grant.use',?,?,?)`, auditID, setup.admin.DeploymentID, grant.GrantID, setup.clock.Now().UnixMilli(), detail); err != nil {
					t.Fatal(err)
				}
			}
			if err := statement.Close(); err != nil {
				t.Fatal(err)
			}
			if err := tx.Commit(); err != nil {
				t.Fatal(err)
			}
			after, err := recoveryReceiptDBStatBytes(context.Background(), setup.store)
			if err != nil {
				t.Fatal(err)
			}
			observed := after - before
			reserved, err := RecoveryReceiptReservationBytes(sample.FrameCount)
			if err != nil || reserved != sample.ReservationBytes || observed > reserved {
				t.Fatalf("receipt sizing frames=%d observed=%d reserved=%d fixture=%d err=%v", sample.FrameCount, observed, reserved, sample.ReservationBytes, err)
			}
			if !sample.Calibrated {
				t.Logf("CALIBRATE recovery receipt dbstat frames=%d observed_delta_bytes=%d reservation_bytes=%d", sample.FrameCount, observed, reserved)
			} else if observed != sample.ObservedDeltaBytes {
				t.Fatalf("pinned recovery receipt allocation drift: frames=%d got=%d want=%d", sample.FrameCount, observed, sample.ObservedDeltaBytes)
			}
		})
	}
}

func recoveryReceiptDBStatBytes(ctx context.Context, st *Store) (int64, error) {
	const query = `SELECT COALESCE(sum(d.pgsize),0)
		FROM dbstat AS d
		LEFT JOIN sqlite_schema AS m ON m.name=d.name
		WHERE d.aggregate=TRUE AND COALESCE(m.tbl_name,d.name) IN
		('recovery_grants','recovery_grant_tombstones','recovery_grant_receipts','idempotency_receipts','audit')`
	var bytes int64
	err := st.db.QueryRowContext(ctx, query).Scan(&bytes)
	return bytes, err
}
