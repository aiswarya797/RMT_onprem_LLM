package lifecycle

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"rmt.local/monitor/internal/collector/pairing"
	"rmt.local/monitor/internal/domain"
	"rmt.local/monitor/internal/protocol"
	"rmt.local/monitor/internal/store"
)

func TestLocalCollectorSocketPersistsFramesAndRejectsOwnerSpoofing(t *testing.T) {
	paths := testPaths(t)
	manager := NewManager(paths, newFakeRunner(), domain.RealClock{})
	setup, err := manager.SetupLocal(context.Background(), false)
	if err != nil {
		t.Fatal(err)
	}
	st, err := store.OpenExisting(paths.Database, domain.RealClock{})
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	if _, err := st.MeasureAndRecordCapacity(context.Background(), setup.DeploymentID, time.Now().UnixMilli(), store.ExternalCapacityUsage{}); err != nil {
		t.Fatal(err)
	}
	local, err := pairing.Open(paths.Collector, setup.DeploymentID, setup.DeploymentGeneration)
	if err != nil {
		t.Fatal(err)
	}
	identity := local.Snapshot()
	handler := LocalCollectorHandler(st, paths)
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, httptest.NewRequest("POST", "/collector/v1/local-pair", strings.NewReader(`{}`)))
	if response.Code != 403 {
		t.Fatal("handler trusted missing kernel peer identity")
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- ServeOwnerSocketHandler(ctx, paths.HubSocket, handler) }()
	defer func() {
		cancel()
		select {
		case err := <-done:
			if err != nil {
				t.Error(err)
			}
		case <-time.After(4 * time.Second):
			t.Error("owner socket did not stop")
		}
	}()
	transport := &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		return (&net.Dialer{Timeout: time.Second}).DialContext(ctx, "unix", paths.HubSocket)
	}}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: 3 * time.Second}
	for attempt := 0; attempt < 100; attempt++ {
		if _, err := ReadOwnerStatus(ctx, paths.HubSocket); err == nil {
			break
		}
		if attempt == 99 {
			t.Fatal("owner socket did not start")
		}
		time.Sleep(5 * time.Millisecond)
	}
	post := func(path string, value any, wantStatus int, result any) {
		t.Helper()
		data, _ := json.Marshal(value)
		request, _ := http.NewRequestWithContext(ctx, "POST", "http://owner"+path, bytes.NewReader(data))
		request.Header.Set("Content-Type", "application/json")
		response, err := client.Do(request)
		if err != nil {
			t.Fatal(err)
		}
		defer response.Body.Close()
		body, _ := io.ReadAll(io.LimitReader(response.Body, 65536))
		if response.StatusCode != wantStatus {
			t.Fatalf("%s: status=%d body=%s", path, response.StatusCode, body)
		}
		if result != nil {
			if err := json.Unmarshal(body, result); err != nil {
				t.Fatal(err)
			}
		}
	}
	post("/collector/v1/local-pair", map[string]string{"host_id": identity.HostID, "installation_id": identity.InstallationID}, 200, nil)
	boot, _ := domain.NewUUID()
	request, err := local.PrepareActivation(boot)
	if err != nil {
		t.Fatal(err)
	}
	var session protocol.SessionResult
	post("/collector/v1/sessions", request, 200, &session)
	if err := local.CompleteActivation(session); err != nil {
		t.Fatal(err)
	}
	manifest := pairing.TargetManifest{SchemaVersion: "1.0", ManifestID: collectorFixtureUUID(6), ManifestRevision: 1, AdapterID: "ollama", Endpoint: pairing.Endpoint{Scheme: "http", Host: "127.0.0.1", Port: 11434}, IdentityRevision: strings.Repeat("d", 64), DisplayName: "Existing local Ollama"}
	targets, err := pairing.ReadTargets(paths.Collector, identity.Generation)
	if err != nil || len(targets.Targets) != 1 {
		t.Fatalf("read automatically configured target: %+v, %v", targets, err)
	}
	manifest.ManifestID = targets.Targets[0].Manifest.ManifestID
	manifest.ManifestRevision = targets.Targets[0].Manifest.ManifestRevision + 1
	configured, err := pairing.ApplyTarget(paths.Collector, identity.Generation, collectorFixtureUUID(7), "edit", targets.Targets[0].TargetID, targets.Targets[0].Revision, &manifest, strings.Repeat("e", 64))
	if err != nil || configured.ResourceID == nil {
		t.Fatalf("configure target: %+v, %v", configured, err)
	}
	targets, err = pairing.ReadTargets(paths.Collector, identity.Generation)
	if err != nil || len(targets.Targets) != 1 {
		t.Fatalf("read configured target: %+v, %v", targets, err)
	}
	target := targets.Targets[0]
	inventory := protocol.CollectorInventory{
		Protocol: "1.0", DeploymentID: identity.DeploymentID, HostID: identity.HostID, SecurityGeneration: identity.Generation,
		SessionGeneration: session.SessionGeneration, CollectorBootID: boot, InventoryRevision: strings.Repeat("a", 64),
		Sources: []protocol.InventorySource{
			{SourceID: target.SourceID, Kind: "runtime", TargetID: &target.TargetID, CapabilityRevision: domain.RegistryRevision, Active: true},
			{SourceID: identity.HostSourceID, Kind: "host", CapabilityRevision: domain.RegistryRevision, Active: true},
		},
		Targets: []protocol.InventoryTarget{{TargetID: target.TargetID, AdapterID: "ollama", LocalSelectorSHA256: target.SelectorSHA256, AssociationState: "declared_unverified"}},
		Models:  []protocol.InventoryModel{},
	}
	post("/collector/v1/inventory", inventory, 200, nil)
	digestOne, digestTwo := strings.Repeat("1", 64), strings.Repeat("2", 64)
	inventory.InventoryRevision = strings.Repeat("b", 64)
	inventory.Models = []protocol.InventoryModel{
		{ModelID: collectorFixtureUUID(8), TargetID: target.TargetID, Alias: "qwen2.5-coder:7b-instruct", Digest: &digestTwo},
		{ModelID: collectorFixtureUUID(9), TargetID: target.TargetID, Alias: "llama3.2:3b", Digest: &digestOne},
	}
	wire, _ := json.Marshal(inventory)
	decoded, err := protocol.DecodeCollectorInventory(bytes.NewReader(wire))
	if err != nil {
		t.Fatalf("two-model wire rejected before transport: %v", err)
	}
	if !localInventoryMatches(decoded, identity, targets) {
		t.Fatal("two-model inventory rejected by reviewed local target match")
	}
	post("/collector/v1/inventory", inventory, 200, nil)
	wall := time.Now().UnixMilli()
	status := protocol.SourceStatus{Protocol: "1.0", DeploymentID: identity.DeploymentID, HostID: identity.HostID, SecurityGeneration: identity.Generation, SessionGeneration: session.SessionGeneration, CollectorBootID: boot, Sequence: 1, ObservedWallMS: wall - 61000, Heartbeat: "fresh", Sources: []protocol.SourceState{{SourceID: identity.HostSourceID, State: "fresh", FailureCount: 0}}, LossIntervals: []protocol.LossInterval{}}
	post("/collector/v1/status", status, http.StatusGone, nil)
	status.ObservedWallMS = wall
	// A rejected status still spends the control-lane budget. The scheduler
	// retries on its next five-second turn instead of bypassing that limit.
	post("/collector/v1/status", status, http.StatusTooManyRequests, nil)
	if _, err := st.MeasureAndRecordCapacity(ctx, identity.DeploymentID, wall, store.ExternalCapacityUsage{}); err != nil {
		t.Fatal(err)
	}
	zero := int64(0)
	p := domain.Provenance{Source: domain.ProvenanceContractFixture, MethodRevision: "owner-socket-test-v1", Verification: domain.VerificationSyntheticFixture}
	frame := protocol.CollectorFrame{SourceID: identity.HostSourceID, Sequence: 1, ObservedWallMS: wall, EstimatedUTCMS: &wall, OffsetMS: &zero, UncertaintyMS: &zero, MonotonicStartNS: "10", MonotonicEndNS: "20", DefinitionRevision: domain.RegistryRevision, Quality: domain.QualityMeasured, Provenance: p, Gauges: map[string]protocol.MetricValue{"host.memory.pressure_level": {Value: json.RawMessage(`"warning"`), Quality: domain.QualityMeasured, Provenance: p}}, NetworkObservations: []domain.NetworkObservation{}, ModelObservations: []domain.ModelObservation{}, ProcessObservations: []domain.ProcessObservation{}, CapabilitiesMissing: []domain.MissingCapability{}}
	batchID, _ := domain.NewUUID()
	batch := protocol.CollectorBatch{Protocol: "1.0", DeliveryMode: "current", SecurityGeneration: identity.Generation, SessionGeneration: session.SessionGeneration, DeploymentID: identity.DeploymentID, HostID: identity.HostID, CollectorBootID: boot, BatchID: batchID, Frames: []protocol.CollectorFrame{frame}}
	var ack protocol.BatchACK
	post("/collector/v1/batches", batch, 200, &ack)
	if !ack.Durable || ack.Accepted != 1 || ack.Duplicate != 0 {
		t.Fatalf("bad ACK: %+v", ack)
	}
	post("/collector/v1/batches", batch, 200, &ack)
	if ack.Accepted != 0 || ack.Duplicate != 1 {
		t.Fatalf("lost ACK duplicate not idempotent: %+v", ack)
	}
	readURL := &url.URL{Scheme: "file", Path: paths.Database, RawQuery: "mode=ro"}
	db, err := sql.Open("sqlite3", readURL.String())
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	var count int
	if err := db.QueryRow(`SELECT count(*) FROM source_frames WHERE source_id=?`, identity.HostSourceID).Scan(&count); err != nil || count != 1 {
		t.Fatalf("ACK did not persist exactly one frame: count=%d err=%v", count, err)
	}
	if err := db.QueryRow(`SELECT count(*) FROM model_revisions WHERE target_id=?`, target.TargetID).Scan(&count); err != nil || count != 2 {
		t.Fatalf("two-model inventory was not committed: count=%d err=%v", count, err)
	}
	batch.HostID, _ = domain.NewUUID()
	post("/collector/v1/batches", batch, 403, nil)
	spoofedSource, _ := domain.NewUUID()
	inventory.Sources[0].SourceID = spoofedSource
	post("/collector/v1/inventory", inventory, 403, nil)
}

func collectorFixtureUUID(suffix byte) string {
	return "00000000-0000-4000-8000-00000000000" + string('0'+suffix)
}
