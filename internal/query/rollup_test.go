package query

import (
	"encoding/json"
	"testing"
	"time"

	"rmt.local/monitor/internal/domain"
	"rmt.local/monitor/internal/store"
)

func TestBuildMinuteSeriesUsesWeightedValueAndExplicitCoverage(t *testing.T) {
	start := int64(1_800_000_000_000 / 60_000 * 60_000)
	hash := store.RollupSeriesHash("host.cpu.busy_ratio", queryHostID)
	missing := domain.MissingSourceTimeout
	payload, err := store.BuildRollupPayload(store.RollupMinute, start, []store.RollupObservation{
		{SeriesHash: hash, Kind: "gauge", ValueType: "number", ObservedMS: start, ValidUntilMS: start + 30_000, Value: json.RawMessage(`0.5`), Quality: domain.QualityMeasured, MethodRevision: "darwin-host-cpu-candidate-1", Aligned: true},
		{SeriesHash: hash, Kind: "gauge", ValueType: "number", ObservedMS: start + 30_000, ValidUntilMS: start + 60_000, Value: json.RawMessage(`null`), MissingReason: &missing, Quality: domain.QualityUnavailable, MethodRevision: "darwin-host-cpu-candidate-1", Aligned: true},
	})
	if err != nil {
		t.Fatal(err)
	}
	series, err := buildRollupSeries(SeriesParameters{Scope: queryHostID, Metric: "host.cpu.busy_ratio", Resolution: store.RollupMinute, Start: start, End: start + 60_000}, metricDefinitions["host.cpu.busy_ratio"], querySourceID, queryHostID, []store.QueryRollup{{HostID: queryHostID, SourceID: querySourceID, IntervalMS: start, Revision: 1, Complete: true, Payload: payload}})
	if err != nil {
		t.Fatal(err)
	}
	if len(series.Points) != 2 || series.CoverageRatio == nil || *series.CoverageRatio != 0.5 || string(series.Points[0].Value) != "0.5" || series.Points[1].MissingReason == nil || *series.Points[1].MissingReason != missing || len(series.Gaps) != 1 || series.ClockMethod == nil || *series.ClockMethod != "single_host_monotonic_aligned" {
		t.Fatalf("minute series lost rollup semantics: %#v", series)
	}
}

func TestPartialRollupBoundaryDoesNotClaimWholeBucketCoverage(t *testing.T) {
	start := int64(1_800_000_000_000 / 60_000 * 60_000)
	hash := store.RollupSeriesHash("host.cpu.busy_ratio", queryHostID)
	missing := domain.MissingSourceTimeout
	cases := []struct {
		name         string
		observations []store.RollupObservation
		queryStart   int64
		queryEnd     int64
	}{
		{
			name: "valid first missing last query last",
			observations: []store.RollupObservation{
				{SeriesHash: hash, Kind: "gauge", ValueType: "number", ObservedMS: start, ValidUntilMS: start + 30_000, Value: json.RawMessage(`0.5`), Quality: domain.QualityMeasured, MethodRevision: "darwin-host-cpu-candidate-1", Aligned: true},
				{SeriesHash: hash, Kind: "gauge", ValueType: "number", ObservedMS: start + 30_000, ValidUntilMS: start + 60_000, Value: json.RawMessage(`null`), MissingReason: &missing, Quality: domain.QualityUnavailable, MethodRevision: "darwin-host-cpu-candidate-1", Aligned: true},
			},
			queryStart: start + 50_000, queryEnd: start + 60_000,
		},
		{
			name: "missing first valid last query last",
			observations: []store.RollupObservation{
				{SeriesHash: hash, Kind: "gauge", ValueType: "number", ObservedMS: start, ValidUntilMS: start + 30_000, Value: json.RawMessage(`null`), MissingReason: &missing, Quality: domain.QualityUnavailable, MethodRevision: "darwin-host-cpu-candidate-1", Aligned: true},
				{SeriesHash: hash, Kind: "gauge", ValueType: "number", ObservedMS: start + 30_000, ValidUntilMS: start + 60_000, Value: json.RawMessage(`0.5`), Quality: domain.QualityMeasured, MethodRevision: "darwin-host-cpu-candidate-1", Aligned: true},
			},
			queryStart: start + 50_000, queryEnd: start + 60_000,
		},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			payload, err := store.BuildRollupPayload(store.RollupMinute, start, test.observations)
			if err != nil {
				t.Fatal(err)
			}
			series, err := buildRollupSeries(SeriesParameters{Scope: queryHostID, Metric: "host.cpu.busy_ratio", Resolution: store.RollupMinute, Start: test.queryStart, End: test.queryEnd}, metricDefinitions["host.cpu.busy_ratio"], querySourceID, queryHostID, []store.QueryRollup{{HostID: queryHostID, SourceID: querySourceID, IntervalMS: start, Revision: 1, Complete: true, Payload: payload}})
			if err != nil {
				t.Fatal(err)
			}
			if series.CoverageRatio == nil || *series.CoverageRatio != 0 || len(series.Points) != 0 || len(series.Gaps) != 1 || series.Gaps[0].StartMS != test.queryStart || series.Gaps[0].EndMS != test.queryEnd || series.EffectiveRange != nil {
				t.Fatalf("partial boundary inferred unavailable detail: %#v", series)
			}
		})
	}
}

func TestSeriesRangeSelectsOnlyNormativeTier(t *testing.T) {
	now := time.Now().UnixMilli()
	cases := []struct {
		resolution string
		start, end int64
		valid      bool
	}{
		{"raw", now - int64(6*time.Hour/time.Millisecond), now, true},
		{"raw", now - int64(6*time.Hour/time.Millisecond) - 1, now, false},
		{store.RollupMinute, now - int64(8*time.Hour/time.Millisecond), now, true},
		{store.RollupMinute, now - int64(time.Hour/time.Millisecond), now, false},
		{store.RollupMinute, now - store.RawFrameRetention.Milliseconds() - int64(time.Hour/time.Millisecond), now - store.RawFrameRetention.Milliseconds(), true},
		{store.RollupHour, now - int64(25*time.Hour/time.Millisecond), now, true},
		{store.RollupHour, now - store.RollupRetention.Milliseconds() - 1, now, false},
	}
	for _, test := range cases {
		parameters := SeriesParameters{Resolution: test.resolution, Start: test.start, End: test.end}
		if got := validSeriesRange(parameters, now); got != test.valid {
			t.Errorf("resolution=%s range=%d valid=%v want=%v", test.resolution, test.end-test.start, got, test.valid)
		}
	}
}

func TestAutomaticSeriesResolutionUsesAgeAndRangeWithoutFrontendMath(t *testing.T) {
	now := time.Now().UnixMilli()
	cases := []struct {
		start, end int64
		want       string
	}{
		{now - int64(time.Hour/time.Millisecond), now, "raw"},
		{now - int64(6*time.Hour/time.Millisecond), now, store.RollupMinute},
		{now - int64(7*time.Hour/time.Millisecond), now, store.RollupMinute},
		{now - int64(7*24*time.Hour/time.Millisecond), now, store.RollupHour},
		{now - store.RawFrameRetention.Milliseconds() - int64(time.Hour/time.Millisecond), now - store.RawFrameRetention.Milliseconds(), store.RollupMinute},
	}
	for _, test := range cases {
		parameters := SeriesParameters{Start: test.start, End: test.end, Resolution: ResolutionAuto}
		if got := automaticSeriesResolution(parameters, now); got != test.want {
			t.Errorf("range %d..%d resolved %q, want %q", test.start, test.end, got, test.want)
		}
	}
}
