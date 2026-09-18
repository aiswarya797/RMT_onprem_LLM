package query

import (
	"encoding/json"
	"testing"
	"time"

	"rmt.local/monitor/internal/domain"
	"rmt.local/monitor/internal/protocol"
	"rmt.local/monitor/internal/store"
)

const (
	queryHostID   = "10000000-0000-4000-8000-000000000001"
	querySourceID = "10000000-0000-4000-8000-000000000002"
	queryBootID   = "10000000-0000-4000-8000-000000000003"
)

func TestSparseFramesKeepIndependentHostComponentsAndTimes(t *testing.T) {
	now := int64(1_800_000_000_000)
	frames := []protocol.CollectorFrame{
		{Gauges: map[string]protocol.MetricValue{"host.cpu.busy_ratio": metricValue(json.RawMessage(`0.25`), "darwin-host-cpu-candidate-1")}},
		{Provenance: provenance("darwin-net-rt-iflist2-ifdata64-candidate-1"), NetworkObservations: []domain.NetworkObservation{}},
		{Gauges: map[string]protocol.MetricValue{"host.memory.pressure_level": metricValue(json.RawMessage(`"warning"`), "xnu-11417.121.6-pressure-flags")}},
		{ProcessSummary: &domain.ProcessSummary{EligiblePIDCount: 2, ExaminedPIDCount: 1, PermissionDeniedCount: 1, Coverage: "partial", MethodRevision: "darwin-proc-list-candidate-1", SampleIntervalMS: 1000}},
	}
	rows := []store.QueryFrame{{OriginalWallMS: now - 1_000}, {OriginalWallMS: now - 2_000}, {OriginalWallMS: now - 3_000}, {OriginalWallMS: now - 4_000}}
	readings := latestGaugeReadings(frames, rows, []string{"host.cpu.busy_ratio", "host.memory.pressure_level"}, querySourceID, queryHostID, now)
	if len(readings) != 2 || readings[0].AgeMS == nil || *readings[0].AgeMS != 1_000 || string(readings[1].Value) != `"warning"` || readings[1].AgeMS == nil || *readings[1].AgeMS != 3_000 {
		t.Fatalf("sparse readings = %#v", readings)
	}
	networkMS, networkAge, networks := latestNetwork(frames, rows, now)
	if networkMS == nil || *networkMS != now-2_000 || networkAge == nil || *networkAge != 2_000 || networks == nil || len(networks) != 0 {
		t.Fatalf("empty successful network = %v/%v/%#v", networkMS, networkAge, networks)
	}
	processMS, processAge, summary, processes := latestProcess(frames, rows, now)
	if processMS == nil || *processMS != now-4_000 || processAge == nil || *processAge != 4_000 || summary == nil || summary.Coverage != "partial" || processes == nil {
		t.Fatalf("process component = %v/%v/%#v/%#v", processMS, processAge, summary, processes)
	}
}

func TestFailedNetworkAttemptIsNotObservedEmpty(t *testing.T) {
	now := int64(1_800_000_000_000)
	missing := domain.MissingCapability{ID: "host.network.received_bytes_total", Reason: domain.MissingSourceTimeout}
	frames := []protocol.CollectorFrame{
		{Provenance: provenance("darwin-net-rt-iflist2-ifdata64-candidate-1"), NetworkObservations: []domain.NetworkObservation{}, CapabilitiesMissing: []domain.MissingCapability{missing}},
		{Provenance: provenance("darwin-net-rt-iflist2-ifdata64-candidate-1"), NetworkObservations: []domain.NetworkObservation{{InterfaceID: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}}},
	}
	rows := []store.QueryFrame{{OriginalWallMS: now - 1_000}, {OriginalWallMS: now - 2_000}}
	observedMS, _, observations := latestNetwork(frames, rows, now)
	capabilities := latestCapabilities(frames)
	if observedMS == nil || *observedMS != now-1_000 || len(observations) != 0 || len(capabilities) != 1 || capabilities[0].Reason != domain.MissingSourceTimeout {
		t.Fatalf("failed network attempt = observed:%v values:%#v missing:%#v", observedMS, observations, capabilities)
	}
}

func TestNetworkCapabilityMakesHostPartialWithAndWithoutUsableCounters(t *testing.T) {
	now := int64(1_800_000_000_000)
	host := Host{NetworkObservedMS: &now, ProcessObservedMS: &now, Metrics: []MetricReading{{Quality: domain.QualityMeasured}}, NetworkObservations: []domain.NetworkObservation{}}
	if hostObservationPartial(host) {
		t.Fatal("complete observed-empty network was marked partial")
	}
	host.CapabilitiesMissing = []domain.MissingCapability{{ID: "host.network.received_bytes_total", Reason: domain.MissingSourceTimeout}}
	if !hostObservationPartial(host) {
		t.Fatal("network-only total failure left host fresh")
	}
	host.NetworkObservations = []domain.NetworkObservation{{InterfaceID: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}}
	host.CapabilitiesMissing[0].Reason = domain.MissingLimitExceeded
	if !hostObservationPartial(host) {
		t.Fatal("usable truncated network population left host fresh")
	}
	host.CapabilitiesMissing = []domain.MissingCapability{}
	if hostObservationPartial(host) {
		t.Fatal("successful network recovery remained partial")
	}
}

func TestHostStateIgnoresUnrelatedSourceFailuresAndBoundsFreshness(t *testing.T) {
	now := int64(1_800_000_000_000)
	last := now - 1_000
	host := store.QueryHost{CurrentSessionGeneration: 1, LastBootID: pointer(queryBootID)}
	status := protocol.SourceStatus{ObservedWallMS: now - 1_000, Heartbeat: "fresh", Sources: []protocol.SourceState{
		{SourceID: querySourceID, State: "fresh", LastSuccessMS: &last},
		{SourceID: "10000000-0000-4000-8000-000000000004", State: "incompatible"},
	}}
	if got := hostSourceState(host, status, true, now, map[string]bool{querySourceID: true}); got != SourceFresh {
		t.Fatalf("host state = %q", got)
	}
	last = now - 15_001
	if got := hostSourceState(host, status, true, now, map[string]bool{querySourceID: true}); got != SourceStale {
		t.Fatalf("stale host state = %q", got)
	}
	if got := hostSourceState(host, status, true, now+61_000, map[string]bool{querySourceID: true}); got != SourceDisconnected {
		t.Fatalf("disconnected host state = %q", got)
	}
}

func TestSuccessfulEmptyRuntimeInventoryDiffersFromFailure(t *testing.T) {
	now := int64(1_800_000_000_000)
	rows := []store.QueryFrame{{OriginalWallMS: now - 1_000}}
	empty := protocol.CollectorFrame{Provenance: provenance("ollama-0.34.0-bounded-ps-v1"), ModelObservations: []domain.ModelObservation{}}
	state, observed, age, models := latestModels([]protocol.CollectorFrame{empty}, rows, now)
	if state != SourceFresh || observed == nil || age == nil || len(models) != 0 {
		t.Fatalf("empty inventory = %q/%v/%v/%#v", state, observed, age, models)
	}
	failure := empty
	failure.Provenance.MethodRevision = "ollama-0.34.0-bounded-read-v1"
	failure.CapabilitiesMissing = []domain.MissingCapability{{ID: "runtime.model.loaded", Reason: domain.MissingSourceUnreachable}}
	state, _, _, models = latestModels([]protocol.CollectorFrame{failure}, rows, now)
	if state != SourceUnavailable || len(models) != 0 {
		t.Fatalf("failed inventory = %q/%#v", state, models)
	}
	failure.Provenance.MethodRevision = "ollama-0.34.0-bounded-ps-v1"
	failure.CapabilitiesMissing = []domain.MissingCapability{{ID: "runtime.model.digest", Reason: domain.MissingIdentityUnverified}}
	state, _, _, models = latestModels([]protocol.CollectorFrame{failure}, rows, now)
	if state != SourceUnavailable || len(models) != 0 {
		t.Fatalf("unresolved model identity looked empty = %q/%#v", state, models)
	}
}

func TestSeriesCoverageUsesFreshIntervalsAndExplicitGaps(t *testing.T) {
	missing := domain.MissingSourceTimeout
	points := []SeriesPoint{
		{TimeMS: 1_000, Value: json.RawMessage(`0.2`), Quality: domain.QualityMeasured},
		{TimeMS: 7_000, Value: nil, Quality: domain.QualityUnavailable, MissingReason: &missing},
	}
	coverage, gaps := coverageAndGaps(points, 0, 15_000, 5*time.Second)
	if coverage != float64(5_000)/float64(15_000) {
		t.Fatalf("coverage = %v", coverage)
	}
	if len(gaps) != 4 || gaps[0].StartMS != 0 || gaps[0].EndMS != 1_000 || gaps[1].Reason != domain.MissingCollectionGap || gaps[2].Reason != domain.MissingSourceTimeout || gaps[3].Reason != domain.MissingCollectionGap {
		t.Fatalf("gaps = %#v", gaps)
	}
}

func TestHistoricalReplayIsLabeledAndCannotBecomeLiveState(t *testing.T) {
	definition := metricDefinitions["host.cpu.busy_ratio"]
	series, err := buildSeries(SeriesParameters{Scope: queryHostID, Metric: "host.cpu.busy_ratio", Resolution: "raw", Start: 1_000, End: 10_000}, definition, querySourceID, queryHostID, []seriesValue{{point: SeriesPoint{TimeMS: 2_000, Value: json.RawMessage(`0.5`), Quality: domain.QualityMeasured}, method: definition.method}}, true)
	if err != nil || len(series.Warnings) != 1 || series.SourceID == nil || *series.SourceID != querySourceID {
		t.Fatalf("replay series = %#v, %v", series, err)
	}
}

func metricValue(value json.RawMessage, method string) protocol.MetricValue {
	return protocol.MetricValue{Value: value, Quality: domain.QualityMeasured, Provenance: provenance(method)}
}

func provenance(method string) domain.Provenance {
	return domain.Provenance{Source: domain.ProvenanceDarwinAPI, MethodRevision: method, Verification: domain.VerificationDirectCapture}
}
