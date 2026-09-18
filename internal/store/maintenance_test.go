package store

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"rmt.local/monitor/internal/domain"
	"rmt.local/monitor/internal/protocol"
)

func TestMaintenanceFinalizesThenRecomputesLateMinuteAndPreservesOtherCursor(t *testing.T) {
	setup := newIngestSetup(t)
	ctx := context.Background()
	now := time.Now().UTC().Truncate(time.Minute).Add(30 * time.Second)
	setup.store.clock = &testClock{now: now}
	if _, err := setup.store.MeasureAndRecordCapacity(ctx, setup.state.DeploymentID, now.UnixMilli(), ExternalCapacityUsage{}); err != nil {
		t.Fatal(err)
	}
	minute := now.Add(-3 * time.Minute).Truncate(time.Minute)
	batch := replayBatchAt(setup, "20000000-0000-4000-8000-000000000070", 70, minute.Add(5*time.Second))
	if _, err := setup.store.IngestCollectorBatch(ctx, batch); err != nil {
		t.Fatal(err)
	}
	limits := MaintenanceLimits{MinuteIntervals: 1, HourRollups: 1, LateFrames: 64, RetentionRows: 100}
	first, err := setup.store.RunMaintenance(ctx, setup.state.DeploymentID, now.UnixMilli(), limits)
	if err != nil {
		t.Fatal(err)
	}
	if first.MinuteRollupsWritten != 1 || first.LateMinutesRecomputed != 0 || first.WatermarkMS != minute.Add(time.Minute).UnixMilli() || first.SQLiteLogicalBytes == 0 {
		t.Fatalf("first maintenance = %#v", first)
	}
	if _, err := setup.store.db.Exec(`UPDATE maintenance SET evaluator_cursor_json=json_set(evaluator_cursor_json,'$.alert_cursor','keep') WHERE deployment_id=?`, setup.state.DeploymentID); err != nil {
		t.Fatal(err)
	}
	late := replayBatchAt(setup, "20000000-0000-4000-8000-000000000071", 71, minute.Add(40*time.Second))
	if _, err := setup.store.IngestCollectorBatch(ctx, late); err != nil {
		t.Fatal(err)
	}
	second, err := setup.store.RunMaintenance(ctx, setup.state.DeploymentID, now.UnixMilli(), limits)
	if err != nil {
		t.Fatal(err)
	}
	if second.LateMinutesRecomputed != 1 {
		t.Fatalf("late recompute = %#v", second)
	}
	rows, err := setup.store.ReadRollups(ctx, RollupFilter{DeploymentID: setup.state.DeploymentID, HostID: testHostID, SourceID: testSourceID, Resolution: RollupMinute, StartMS: minute.UnixMilli(), EndMS: minute.Add(time.Minute).UnixMilli(), Limit: 2})
	if err != nil || len(rows) != 1 || rows[0].Revision != 2 {
		t.Fatalf("recomputed rollup = %#v, %v", rows, err)
	}
	var cursorJSON string
	if err := setup.store.db.QueryRow(`SELECT evaluator_cursor_json FROM maintenance WHERE deployment_id=?`, setup.state.DeploymentID).Scan(&cursorJSON); err != nil {
		t.Fatal(err)
	}
	var cursor map[string]json.RawMessage
	if json.Unmarshal([]byte(cursorJSON), &cursor) != nil || string(cursor["alert_cursor"]) != `"keep"` || len(cursor["rollup_frame_rowid"]) == 0 {
		t.Fatalf("maintenance overwrote another cursor: %s", cursorJSON)
	}
}

func TestMaintenanceRediscoversHoursBeyondPerTickLimit(t *testing.T) {
	setup := newIngestSetup(t)
	ctx := context.Background()
	now := time.Now().UTC().Truncate(time.Hour)
	firstHour := now.Add(-3 * time.Hour)
	for minute := 0; minute < 120; minute++ {
		minuteMS := firstHour.Add(time.Duration(minute) * time.Minute).UnixMilli()
		payload, err := BuildRollupPayload(RollupMinute, minuteMS, nil)
		if err != nil {
			t.Fatal(err)
		}
		if err := setup.store.PutRollup(ctx, RollupRecord{DeploymentID: setup.state.DeploymentID, HostID: testHostID, SourceID: testSourceID, IntervalMS: minuteMS, Revision: 1, Payload: payload}); err != nil {
			t.Fatal(err)
		}
	}
	limits := MaintenanceLimits{MinuteIntervals: 1, HourRollups: 1, LateFrames: 1, RetentionRows: 1}
	first, err := setup.store.RunMaintenance(ctx, setup.state.DeploymentID, now.UnixMilli(), limits)
	if err != nil || first.HourRollupsWritten != 1 {
		t.Fatalf("first bounded hour pass = %#v, %v", first, err)
	}
	second, err := setup.store.RunMaintenance(ctx, setup.state.DeploymentID, now.UnixMilli(), limits)
	if err != nil || second.HourRollupsWritten != 1 {
		t.Fatalf("second bounded hour pass = %#v, %v", second, err)
	}
	var hours int
	if err := setup.store.db.QueryRowContext(ctx, `SELECT count(*) FROM rollup_hours WHERE deployment_id=?`, setup.state.DeploymentID).Scan(&hours); err != nil || hours != 2 {
		t.Fatalf("durably rediscovered hours = %d, %v", hours, err)
	}

	// A later minute revision invalidates the derived hour transactionally;
	// the next bounded pass rediscovers it without a volatile work queue.
	minuteMS := firstHour.UnixMilli()
	payload, err := BuildRollupPayload(RollupMinute, minuteMS, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := setup.store.PutRollup(ctx, RollupRecord{DeploymentID: setup.state.DeploymentID, HostID: testHostID, SourceID: testSourceID, IntervalMS: minuteMS, Revision: 2, Payload: payload}); err != nil {
		t.Fatal(err)
	}
	if err := setup.store.db.QueryRowContext(ctx, `SELECT count(*) FROM rollup_hours WHERE deployment_id=? AND hour_ms=?`, setup.state.DeploymentID, firstHour.UnixMilli()).Scan(&hours); err != nil || hours != 0 {
		t.Fatalf("stale hour remained after minute revision = %d, %v", hours, err)
	}
	third, err := setup.store.RunMaintenance(ctx, setup.state.DeploymentID, now.UnixMilli(), limits)
	if err != nil || third.HourRollupsWritten != 1 {
		t.Fatalf("rebuild invalidated hour = %#v, %v", third, err)
	}
}

func TestRetentionKeepsRowIDHighWaterForLateFrameCursor(t *testing.T) {
	setup := newIngestSetup(t)
	ctx := context.Background()
	now := time.Now().UTC().Truncate(time.Minute)
	oldMinute := now.Add(-80 * time.Hour)
	newerObservation := replayBatchAt(setup, "20000000-0000-4000-8000-000000000072", 72, oldMinute.Add(40*time.Second))
	if _, err := setup.store.IngestCollectorBatch(ctx, newerObservation); err != nil {
		t.Fatal(err)
	}
	lateOlderObservation := replayBatchAt(setup, "20000000-0000-4000-8000-000000000073", 73, oldMinute.Add(5*time.Second))
	if _, err := setup.store.IngestCollectorBatch(ctx, lateOlderObservation); err != nil {
		t.Fatal(err)
	}
	if _, err := setup.store.BuildAndPutMinuteRollup(ctx, setup.state.DeploymentID, testHostID, testSourceID, oldMinute.UnixMilli(), 1); err != nil {
		t.Fatal(err)
	}
	_, cursor, _, err := setup.store.readDirtyRollups(ctx, setup.state.DeploymentID, 0, 0, now.UnixMilli(), 8)
	if err != nil || cursor != 2 {
		t.Fatalf("initial high-water cursor = %d, %v", cursor, err)
	}
	if _, err := setup.store.PruneObservationRetention(ctx, setup.state.DeploymentID, now.UnixMilli(), 8); err != nil {
		t.Fatal(err)
	}
	var retained int
	if err := setup.store.db.QueryRowContext(ctx, `SELECT count(*) FROM source_frames WHERE rowid=?`, cursor).Scan(&retained); err != nil || retained != 1 {
		t.Fatalf("rowid high-water sentinel = %d, %v", retained, err)
	}
	recent := replayBatchAt(setup, "20000000-0000-4000-8000-000000000074", 74, now.Add(-time.Hour))
	if _, err := setup.store.IngestCollectorBatch(ctx, recent); err != nil {
		t.Fatal(err)
	}
	dirty, next, _, err := setup.store.readDirtyRollups(ctx, setup.state.DeploymentID, cursor, now.UnixMilli(), now.UnixMilli(), 8)
	if err != nil || next <= cursor || len(dirty) != 1 {
		t.Fatalf("new frame after retained cursor = dirty:%#v next:%d err:%v", dirty, next, err)
	}
}

func replayBatchAt(setup ingestSetup, batchID string, sequence int64, observed time.Time) protocol.CollectorBatch {
	batch := testBatch(setup)
	batch.BatchID = batchID
	batch.DeliveryMode = "replay"
	batch.Frames[0].Sequence = sequence
	batch.Frames[0].ObservedWallMS = observed.UnixMilli()
	aligned := observed.UnixMilli()
	batch.Frames[0].EstimatedUTCMS = &aligned
	batch.Frames[0].MonotonicStartNS = domain.DecimalUint64(uint64(sequence * 10))
	batch.Frames[0].MonotonicEndNS = domain.DecimalUint64(uint64(sequence*10 + 1))
	return batch
}
