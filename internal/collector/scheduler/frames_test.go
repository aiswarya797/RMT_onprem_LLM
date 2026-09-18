package scheduler

import (
	"testing"
	"time"

	"rmt.local/monitor/internal/domain"
)

func TestHostFramesRetainIndependentTimingAndUnavailableValues(t *testing.T) {
	now := time.Unix(1700000000, 0)
	p := domain.Provenance{Source: domain.ProvenanceDarwinAPI, MethodRevision: "test-method-v1", Verification: domain.VerificationSyntheticFixture}
	timing := domain.NewComponentTiming(now, 100, 1000100)
	later := domain.NewComponentTiming(now.Add(time.Millisecond), 200, 2000200)
	host := domain.HostObservation{
		ComponentTimings: domain.HostComponentTimings{CPU: later, Pressure: timing, Compressed: timing, Swap: timing, Disk: timing, Network: timing},
		Gauges:           domain.HostGauges{CPUBusyRatio: domain.Measured(0.25, p), PressureLevel: domain.Unavailable[domain.PressureLevel](domain.MissingPermissionDenied, p), CompressedBytes: domain.Measured(domain.DecimalUint64(123), p), SwapUsedBytes: domain.Measured(domain.DecimalUint64(456), p), DiskFreeBytes: domain.Measured(domain.DecimalUint64(789), p)},
	}
	frames := HostFrames("11111111-1111-4111-8111-111111111111", host, nil, Alignment{OffsetMS: 10, UncertaintyMS: 2, MeasuredAt: now, Valid: true}, now)
	if len(frames) != 6 {
		t.Fatal("component frames lost")
	}
	for i, frame := range frames {
		frame.Sequence = int64(i)
		if err := frame.Validate(); err != nil {
			t.Fatalf("invalid normalized frame: %v", err)
		}
		if metric, ok := frame.Gauges["host.cpu.busy_ratio"]; ok {
			if string(metric.Value) != "0.25" || frame.ObservedWallMS != later.ObservedWallMS || frame.DurationMS != later.DurationMS {
				t.Fatal("CPU timing replaced by whole-host timing")
			}
		}
		if metric, ok := frame.Gauges["host.memory.pressure_level"]; ok {
			if string(metric.Value) != "null" || metric.MissingReason == nil || *metric.MissingReason != domain.MissingPermissionDenied {
				t.Fatal("unavailable pressure became a value")
			}
		}
	}
	if frames[len(frames)-1].MonotonicStartNS != later.MonotonicStartNS {
		t.Fatal("independent frame starts not ordered")
	}
}

func TestUncertainAlignmentKeepsOriginalTime(t *testing.T) {
	now := time.Unix(1700000000, 0)
	if TimeExchange(now, now.Add(3*time.Second), now.UnixMilli()).Valid {
		t.Fatal("slow exchange considered aligned")
	}
	alignment := TimeExchange(now, now.Add(100*time.Millisecond), now.Add(70*time.Millisecond).UnixMilli())
	if !alignment.Valid || alignment.OffsetMS != 20 || alignment.UncertaintyMS != 50 {
		t.Fatalf("midpoint calculation incorrect: %+v", alignment)
	}
	frame := baseFrame("source", domain.NewComponentTiming(now, 0, 1), domain.Provenance{}, alignment, now.Add(3*time.Minute))
	if frame.EstimatedUTCMS != nil || frame.ObservedWallMS != now.UnixMilli() || len(frame.CapabilitiesMissing) != 1 {
		t.Fatal("stale exchange claimed alignment or erased local time")
	}
}

func TestEmptyLoadedSnapshotIsDistinctFromFailedRead(t *testing.T) {
	now := time.Unix(1700000000, 0)
	timing := domain.NewComponentTiming(now, 0, 1)
	runtime := domain.RuntimeObservation{ComponentTimings: domain.RuntimeComponentTimings{LoadedModels: &timing}}
	valid := RuntimeFrames("source", runtime, false, true, Alignment{}, now)
	if len(valid) != 1 || valid[0].Provenance.MethodRevision != "ollama-0.34.0-bounded-ps-v1" || valid[0].ModelObservations == nil {
		t.Fatal("observed-empty inventory is ambiguous")
	}
	runtime.CapabilitiesMissing = []domain.MissingCapability{{ID: "runtime.model.loaded", Reason: domain.MissingSourceTimeout}}
	failed := RuntimeFrames("source", runtime, false, true, Alignment{}, now)
	if failed[0].Provenance.MethodRevision == valid[0].Provenance.MethodRevision {
		t.Fatal("failed inventory presented as observed empty")
	}
	for _, id := range []string{"runtime.model.digest", "runtime.model.identity"} {
		runtime.CapabilitiesMissing = []domain.MissingCapability{{ID: id, Reason: domain.MissingIdentityUnverified}}
		partial := RuntimeFrames("source", runtime, false, true, Alignment{}, now)
		if partial[0].Provenance.MethodRevision == valid[0].Provenance.MethodRevision {
			t.Fatalf("%s failure presented as observed empty", id)
		}
	}
}

func TestRuntimeConfigUsesIndependentComponentFrame(t *testing.T) {
	now := time.Unix(1700000000, 0)
	versionTiming := domain.NewComponentTiming(now, 10, 1_000_010)
	configTiming := domain.NewComponentTiming(now.Add(time.Second), 2_000_000, 3_000_000)
	provenance := domain.Provenance{Source: domain.ProvenanceRuntimeAPI, MethodRevision: "ollama-0.34.0-bounded-read-v1", Verification: domain.VerificationDirectCapture}
	fields := domain.RuntimeConfigFields{ServerVersion: "0.34.0"}
	fieldProvenance := domain.RuntimeConfigFieldProvenance{ServerVersion: provenance}
	config := &domain.RuntimeConfigObservation{TargetID: "22222222-2222-4222-8222-222222222222", ConfigHash: domain.RuntimeConfigHash(fields, fieldProvenance), Fields: fields, FieldProvenance: fieldProvenance}
	runtime := domain.RuntimeObservation{ComponentTimings: domain.RuntimeComponentTimings{Version: &versionTiming, Config: &configTiming}, Config: config}
	frames := RuntimeFrames("11111111-1111-4111-8111-111111111111", runtime, false, true, Alignment{}, now)
	if len(frames) != 1 || frames[0].ConfigObservation == nil || frames[0].ObservedWallMS != configTiming.ObservedWallMS || len(frames[0].Gauges) != 0 || len(frames[0].ModelObservations) != 0 {
		t.Fatalf("config frames=%#v", frames)
	}
	frames[0].Sequence = 1
	if err := frames[0].Validate(); err != nil {
		t.Fatalf("config frame validation: %v", err)
	}
}
