package store

import (
	"context"
	"encoding/json"
	"math"
	"strconv"
	"testing"
	"time"

	"rmt.local/monitor/internal/domain"
)

func TestBuildRollupPreservesCoverageMissingAndExactCounterDelta(t *testing.T) {
	start := int64(1_800_000_000_000 / 60_000 * 60_000)
	gaugeHash := RollupSeriesHash("host.cpu.busy_ratio", testHostID)
	missing := domain.MissingSourceTimeout
	payload, err := BuildRollupPayload(RollupMinute, start, []RollupObservation{
		rollupObservation(gaugeHash, "", "gauge", "number", start, start+10_000, `0.5`, nil),
		rollupObservation(gaugeHash, "", "gauge", "number", start+10_000, start+20_000, `1`, nil),
		rollupObservation(gaugeHash, "", "gauge", "number", start+20_000, start+30_000, `null`, &missing),
	})
	if err != nil {
		t.Fatal(err)
	}
	segment := payload.Series[gaugeHash][0]
	if !payload.Complete || segment.ValidDurationMS != 20_000 || segment.MissingDurationMS[missing] != 10_000 || segment.WeightMS != 20_000 || math.Abs(segment.WeightedSum-15_000) > 0.001 || string(segment.Min) != "0.5" || string(segment.Max) != "1" {
		t.Fatalf("gauge rollup lost semantics: %#v", segment)
	}

	counterHash := RollupSeriesHash("host.network.received_bytes_total", "interface-a")
	payload, err = BuildRollupPayload(RollupMinute, start, []RollupObservation{
		rollupObservation(counterHash, "10000000-0000-4000-8000-000000000099", "cumulative_counter", "uint64", start, start+5_000, `"18446744073709551610"`, nil),
		rollupObservation(counterHash, "10000000-0000-4000-8000-000000000099", "cumulative_counter", "uint64", start+5_000, start+10_000, `"18446744073709551615"`, nil),
	})
	if err != nil {
		t.Fatal(err)
	}
	delta := payload.Series[counterHash][0].CounterDelta
	if delta == nil || *delta != "5" {
		t.Fatalf("counter delta = %v", delta)
	}
}

func TestBuildRollupMarksMoreThanEightEpochsIncomplete(t *testing.T) {
	start := int64(1_800_000_000_000 / 60_000 * 60_000)
	hash := RollupSeriesHash("host.network.sent_bytes_total", "interface-a")
	observations := make([]RollupObservation, 0, 9)
	for index := range 9 {
		epoch := string(rune('a' + index))
		observations = append(observations, rollupObservation(hash, epoch, "cumulative_counter", "uint64", start+int64(index*1000), start+int64((index+1)*1000), `"1"`, nil))
	}
	payload, err := BuildRollupPayload(RollupMinute, start, observations)
	if err != nil {
		t.Fatal(err)
	}
	if payload.Complete || len(payload.Series[hash]) != maxRollupEpochs {
		t.Fatalf("epoch cap = complete %v segments %d", payload.Complete, len(payload.Series[hash]))
	}
}

func TestHourRollupMergesOnlySixtyCompatibleCompleteMinutes(t *testing.T) {
	hour := int64(1_800_000_000_000 / 3_600_000 * 3_600_000)
	hash := RollupSeriesHash("host.cpu.busy_ratio", testHostID)
	minutes := make([]RollupPayload, 0, 60)
	for index := range 60 {
		start := hour + int64(index)*60_000
		minute, err := BuildRollupPayload(RollupMinute, start, []RollupObservation{rollupObservation(hash, "", "gauge", "number", start, start+60_000, `0.5`, nil)})
		if err != nil {
			t.Fatal(err)
		}
		minutes = append(minutes, minute)
	}
	merged, err := MergeHourRollups(hour, minutes)
	if err != nil {
		t.Fatal(err)
	}
	segment := merged.Series[hash][0]
	if !merged.Complete || segment.SampleCount != 60 || segment.ValidDurationMS != 3_600_000 || segment.WeightMS != 3_600_000 || segment.WeightedSum != 1_800_000 {
		t.Fatalf("hour merge = %#v", segment)
	}
	minutes[10].Complete = false
	if _, err := MergeHourRollups(hour, minutes); err == nil {
		t.Fatal("incomplete minute was used to build an hour")
	}
}

func TestRollupPersistenceIsBoundedAndRevisioned(t *testing.T) {
	setup := newIngestSetup(t)
	start := int64(1_800_000_000_000 / 60_000 * 60_000)
	hash := RollupSeriesHash("runtime.reachable", testTargetID)
	payload, err := BuildRollupPayload(RollupMinute, start, []RollupObservation{rollupObservation(hash, "", "gauge", "boolean", start, start+10_000, `true`, nil)})
	if err != nil {
		t.Fatal(err)
	}
	record := RollupRecord{DeploymentID: setup.state.DeploymentID, HostID: testHostID, SourceID: testSourceID, IntervalMS: start, Revision: 1, Payload: payload}
	if err := setup.store.PutRollup(context.Background(), record); err != nil {
		t.Fatal(err)
	}
	record.Payload.Series[hash][0].Last = json.RawMessage("false")
	if err := setup.store.PutRollup(context.Background(), record); err != nil {
		t.Fatal(err)
	}
	rows, err := setup.store.ReadRollups(context.Background(), RollupFilter{DeploymentID: setup.state.DeploymentID, HostID: testHostID, SourceID: testSourceID, Resolution: RollupMinute, StartMS: start, EndMS: start + 60_000, Limit: 2})
	if err != nil || len(rows) != 1 || rows[0].Revision != 1 || string(rows[0].Payload.Series[hash][0].Last) != "true" {
		t.Fatalf("rollup rows = %#v, %v", rows, err)
	}
}

func rollupObservation(hash, epoch, kind, valueType string, observed, validUntil int64, value string, missing *domain.MissingReason) RollupObservation {
	return RollupObservation{SeriesHash: hash, EpochID: epoch, Kind: kind, ValueType: valueType, ObservedMS: observed, ValidUntilMS: validUntil, Value: json.RawMessage(value), MissingReason: missing, Quality: domain.QualityMeasured, MethodRevision: "fixture-v1"}
}

func TestObservationRetentionRequiresCompleteRollupAndKeepsPredecessor(t *testing.T) {
	setup := newIngestSetup(t)
	now := time.Now().UTC().Truncate(time.Minute)
	times := []time.Time{now.Add(-74 * time.Hour), now.Add(-73*time.Hour - 50*time.Minute), now.Add(-73*time.Hour - 40*time.Minute), now.Add(-73*time.Hour - 30*time.Minute), now.Add(-time.Hour)}
	batch := testBatch(setup)
	batch.DeliveryMode = "replay"
	batch.Frames = nil
	for index, observed := range times {
		frame := testBatch(setup).Frames[0]
		frame.Sequence = int64(index + 10)
		frame.ObservedWallMS = observed.UnixMilli()
		aligned := observed.UnixMilli()
		frame.EstimatedUTCMS = &aligned
		frame.MonotonicStartNS = domain.Uint64Decimal(strconv.Itoa(index + 1))
		frame.MonotonicEndNS = domain.Uint64Decimal(strconv.Itoa(index + 7))
		batch.Frames = append(batch.Frames, frame)
	}
	if _, err := setup.store.IngestCollectorBatch(context.Background(), batch); err != nil {
		t.Fatal(err)
	}
	hash := RollupSeriesHash("runtime.reachable", testTargetID)
	for index, observed := range times[:4] {
		start := observed.Truncate(time.Minute).UnixMilli()
		payload, err := BuildRollupPayload(RollupMinute, start, []RollupObservation{rollupObservation(hash, "", "gauge", "boolean", start, start+1000, `true`, nil)})
		if err != nil {
			t.Fatal(err)
		}
		if index == 2 {
			payload.Complete = false
		}
		if err := setup.store.PutRollup(context.Background(), RollupRecord{DeploymentID: setup.state.DeploymentID, HostID: testHostID, SourceID: testSourceID, IntervalMS: start, Revision: 1, Payload: payload}); err != nil {
			t.Fatal(err)
		}
	}
	result, err := setup.store.PruneObservationRetention(context.Background(), setup.state.DeploymentID, now.UnixMilli(), 100)
	if err != nil {
		t.Fatal(err)
	}
	if result.RawFramesDeleted != 2 {
		t.Fatalf("deleted raw = %d, want 2", result.RawFramesDeleted)
	}
	var remaining int
	if err := setup.store.db.QueryRow(`SELECT count(*) FROM source_frames`).Scan(&remaining); err != nil || remaining != 3 {
		t.Fatalf("remaining raw = %d, %v", remaining, err)
	}
}
