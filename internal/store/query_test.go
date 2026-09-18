package store

import (
	"context"
	"fmt"
	"testing"

	"rmt.local/monitor/internal/protocol"
)

func TestQueryReadersFenceLiveStateButRetainHistoricalFrames(t *testing.T) {
	setup := newIngestSetup(t)
	ctx := context.Background()
	batch := testBatch(setup)
	if _, err := setup.store.IngestCollectorBatch(ctx, batch); err != nil {
		t.Fatal(err)
	}
	if collected, err := setup.store.HasCollectedFrames(ctx, setup.state.DeploymentID); err != nil || !collected {
		t.Fatalf("collected frames = %v, %v", collected, err)
	}
	lastSuccess := setup.store.clock.Now().UnixMilli()
	status := protocol.SourceStatus{
		Protocol: "1.0", DeploymentID: setup.state.DeploymentID, HostID: testHostID, SecurityGeneration: setup.state.DeploymentGeneration,
		SessionGeneration: setup.session.SessionGeneration, CollectorBootID: testBootID, Sequence: 1, ObservedWallMS: lastSuccess, Heartbeat: "fresh",
		Sources: []protocol.SourceState{{SourceID: testSourceID, State: "fresh", LastSuccessMS: &lastSuccess}}, LossIntervals: []protocol.LossInterval{},
	}
	if _, err := setup.store.IngestSourceStatus(ctx, status); err != nil {
		t.Fatal(err)
	}
	inventory, err := setup.store.ReadQueryInventory(ctx)
	if err != nil || len(inventory.Hosts) != 1 || len(inventory.Targets) != 1 || len(inventory.Sources) != 1 || len(inventory.Models) != 1 || inventory.HistoryFrameCount != 1 {
		t.Fatalf("query inventory = %#v, %v", inventory, err)
	}
	observationMS := *batch.Frames[0].EstimatedUTCMS
	filter := QueryFrameFilter{DeploymentID: setup.state.DeploymentID, HostID: testHostID, SourceID: testSourceID, StartMS: observationMS - 1, EndMS: observationMS + 1, CurrentOnly: true, Limit: 10}
	frames, err := setup.store.ReadQueryFrames(ctx, filter)
	if err != nil || len(frames) != 1 || frames[0].DeliveryMode != "current" {
		t.Fatalf("current frames = %#v, %v", frames, err)
	}
	statuses, err := setup.store.ReadCurrentSourceStatuses(ctx, setup.state.DeploymentID)
	if err != nil || len(statuses) != 1 || statuses[0].Sequence != 1 {
		t.Fatalf("current statuses = %#v, %v", statuses, err)
	}

	newBoot := "20000000-0000-4000-8000-000000000020"
	activation := protocol.SessionActivation{
		Protocol: "1.0", DeploymentID: setup.state.DeploymentID, HostID: testHostID, SecurityGeneration: setup.state.DeploymentGeneration,
		ActivationRequestID: "20000000-0000-4000-8000-000000000021", CollectorBootID: newBoot, ExpectedPreviousGeneration: setup.session.SessionGeneration,
	}
	if _, err := setup.store.ActivateCollectorSession(ctx, activation); err != nil {
		t.Fatal(err)
	}
	replay := testBatch(setup)
	replay.BatchID = "20000000-0000-4000-8000-000000000022"
	replay.DeliveryMode = "replay"
	replay.Frames[0].Sequence = 2
	replay.Frames[0].MonotonicStartNS = "3"
	replay.Frames[0].MonotonicEndNS = "4"
	replay.Frames[0].ObservedWallMS = batch.Frames[0].ObservedWallMS
	replay.Frames[0].EstimatedUTCMS = batch.Frames[0].EstimatedUTCMS
	if _, err := setup.store.IngestCollectorBatch(ctx, replay); err != nil {
		t.Fatalf("replay ingest = %v", err)
	}
	frames, err = setup.store.ReadQueryFrames(ctx, filter)
	if err != nil || len(frames) != 0 {
		t.Fatalf("superseded session leaked live frames = %#v, %v", frames, err)
	}
	statuses, err = setup.store.ReadCurrentSourceStatuses(ctx, setup.state.DeploymentID)
	if err != nil || len(statuses) != 0 {
		t.Fatalf("superseded status leaked live = %#v, %v", statuses, err)
	}
	filter.CurrentOnly = false
	frames, err = setup.store.ReadQueryFrames(ctx, filter)
	if err != nil || len(frames) != 2 || frames[1].DeliveryMode != "replay" {
		modes := make([]string, 0, len(frames))
		times := make([]int64, 0, len(frames))
		for _, frame := range frames {
			modes = append(modes, frame.DeliveryMode)
			times = append(times, frame.ObservationMS())
		}
		t.Fatalf("historical frame count=%d modes=%v times=%v err=%v", len(frames), modes, times, err)
	}
}

func TestQueryInventoryPrioritizesActiveRowsWithinFleetCaps(t *testing.T) {
	setup := newIngestSetup(t)
	ctx := context.Background()
	for index := range 2 {
		hostID := fmt.Sprintf("30000000-0000-4000-8000-%012d", index+1)
		installationID := fmt.Sprintf("40000000-0000-4000-8000-%012d", index+1)
		if _, err := setup.store.db.ExecContext(ctx, `INSERT INTO hosts(id,deployment_id,display_name,installation_uuid,capabilities_json,retired_ms,created_ms,updated_ms) VALUES(?,?,?,?,?,10,?,?)`, hostID, setup.state.DeploymentID, "Retired Mac", installationID, `{}`, index+1, index+1); err != nil {
			t.Fatal(err)
		}
		targetID := fmt.Sprintf("50000000-0000-4000-8000-%012d", index+1)
		if _, err := setup.store.db.ExecContext(ctx, `INSERT INTO targets(id,deployment_id,host_id,adapter_id,local_selector_hash,display_name,endpoint_alias,retired_ms,created_ms,updated_ms) VALUES(?,?,?,'ollama',?,?,?,10,?,?)`, targetID, setup.state.DeploymentID, testHostID, fmt.Sprintf("%064x", index+1), "Retired Ollama", "retired", index+1, index+1); err != nil {
			t.Fatal(err)
		}
	}
	for index := range 16 {
		sourceID := fmt.Sprintf("60000000-0000-4000-8000-%012d", index+1)
		if _, err := setup.store.db.ExecContext(ctx, `INSERT INTO sources(id,deployment_id,host_id,kind,target_id,admitted_capability_revision,retired_ms,created_ms,updated_ms) VALUES(?,?,?,'runtime',?,'mac-ollama-1',10,?,?)`, sourceID, setup.state.DeploymentID, testHostID, "50000000-0000-4000-8000-000000000001", index+1, index+1); err != nil {
			t.Fatal(err)
		}
	}

	inventory, err := setup.store.ReadQueryInventory(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(inventory.Hosts) != 2 || inventory.Hosts[0].ID != testHostID || inventory.Hosts[0].RetiredMS != nil {
		t.Fatalf("active host was displaced by retired history: %#v", inventory.Hosts)
	}
	if len(inventory.Targets) != 2 || inventory.Targets[0].ID != testTargetID || inventory.Targets[0].RetiredMS != nil {
		t.Fatalf("active target was displaced by retired history: %#v", inventory.Targets)
	}
	foundActiveSource := false
	for _, source := range inventory.Sources {
		foundActiveSource = foundActiveSource || source.ID == testSourceID
	}
	if !foundActiveSource || len(inventory.Sources) != 16 {
		t.Fatalf("active source was displaced by retired history: %#v", inventory.Sources)
	}
}

func TestQueryReadersRejectUnboundedRanges(t *testing.T) {
	setup := newIngestSetup(t)
	if collected, err := setup.store.HasCollectedFrames(context.Background(), setup.state.DeploymentID); err != nil || collected {
		t.Fatalf("registration counted as collection = %v, %v", collected, err)
	}
	if _, err := setup.store.ReadQueryFrames(context.Background(), QueryFrameFilter{DeploymentID: setup.state.DeploymentID, StartMS: 0, EndMS: 1, Limit: MaxQueryFrameRows + 1}); err == nil {
		t.Fatal("unbounded query was accepted")
	}
}
