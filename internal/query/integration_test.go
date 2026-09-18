package query

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"testing"
	"time"

	"rmt.local/monitor/internal/alertruntime"
	"rmt.local/monitor/internal/domain"
	"rmt.local/monitor/internal/protocol"
	"rmt.local/monitor/internal/store"
)

const (
	integrationTargetID  = "20000000-0000-4000-8000-000000000001"
	integrationHostSrcID = "20000000-0000-4000-8000-000000000002"
	integrationRunSrcID  = "20000000-0000-4000-8000-000000000003"
	integrationModelID   = "20000000-0000-4000-8000-000000000004"
)

type fixedClock struct{ now time.Time }

func (c fixedClock) Now() time.Time { return c.now }

func TestOverviewAndSeriesReadPersistedCurrentComponents(t *testing.T) {
	ctx := context.Background()
	now := time.UnixMilli(1_800_000_000_000)
	clock := fixedClock{now: now}
	st, err := store.Open(filepath.Join(t.TempDir(), "monitor.db"), clock)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	state, _, err := st.EnsureDeployment(ctx, "query-test")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := st.MeasureAndRecordCapacity(ctx, state.DeploymentID, now.UnixMilli(), store.ExternalCapacityUsage{}); err != nil {
		t.Fatal(err)
	}
	if err := st.RegisterLocalHost(ctx, store.TrustedOwnerContext{DeploymentID: state.DeploymentID, SecurityGeneration: state.DeploymentGeneration, InstallingUID: 501, VerifiedOSOwner: true}, store.LocalHostRegistration{HostID: queryHostID, InstallationUUID: "20000000-0000-4000-8000-000000000005", DisplayName: "Local Mac", CollectorVersion: "0.1.0"}); err != nil {
		t.Fatal(err)
	}
	activation := protocol.SessionActivation{Protocol: domain.ProtocolVersion, DeploymentID: state.DeploymentID, HostID: queryHostID, SecurityGeneration: state.DeploymentGeneration, ActivationRequestID: "20000000-0000-4000-8000-000000000006", CollectorBootID: queryBootID}
	session, err := st.ActivateCollectorSession(ctx, activation)
	if err != nil {
		t.Fatal(err)
	}
	digest := "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	inventory := protocol.CollectorInventory{
		Protocol: domain.ProtocolVersion, DeploymentID: state.DeploymentID, HostID: queryHostID, SecurityGeneration: state.DeploymentGeneration, SessionGeneration: session.SessionGeneration, CollectorBootID: queryBootID,
		InventoryRevision: "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
		Sources:           []protocol.InventorySource{{SourceID: integrationHostSrcID, Kind: "host", CapabilityRevision: domain.RegistryRevision, Active: true}, {SourceID: integrationRunSrcID, Kind: "runtime", TargetID: pointer(integrationTargetID), CapabilityRevision: domain.RegistryRevision, Active: true}},
		Targets:           []protocol.InventoryTarget{{TargetID: integrationTargetID, AdapterID: "ollama", LocalSelectorSHA256: "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc", AssociationState: "verified"}},
		Models:            []protocol.InventoryModel{{ModelID: integrationModelID, TargetID: integrationTargetID, Alias: "model:latest", Digest: &digest, ReportedLoaded: true}},
	}
	if _, err := st.RegisterCollectorInventory(ctx, inventory); err != nil {
		t.Fatal(err)
	}
	processName := "ollama"
	processKey := "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"
	footprint := domain.DecimalUint64(4096)
	hostFrames := []protocol.CollectorFrame{
		integrationFrame(integrationHostSrcID, 1, now.Add(-3*time.Second), "darwin-host-cpu-candidate-1", map[string]protocol.MetricValue{
			"host.cpu.busy_ratio":          metricValue(json.RawMessage(`0.25`), "darwin-host-cpu-candidate-1"),
			"host.memory.pressure_level":   metricValue(json.RawMessage(`"normal"`), "xnu-11417.121.6-pressure-flags"),
			"host.memory.compressed_bytes": metricValue(json.RawMessage(`"4096"`), "darwin-vm-candidate-1"),
			"host.memory.swap_used_bytes":  metricValue(json.RawMessage(`"0"`), "darwin-swap-candidate-1"),
			"host.disk.free_bytes":         metricValue(json.RawMessage(`"1048576"`), "darwin-statfs-candidate-1"),
		}),
		integrationFrame(integrationHostSrcID, 2, now.Add(-2*time.Second), "darwin-proc-list-candidate-1", map[string]protocol.MetricValue{}),
	}
	hostFrames[1].ProcessObservations = []domain.ProcessObservation{{HostID: queryHostID, BootID: queryBootID, PID: 42, ProcessStartIdentity: "100", ProcessKey: processKey, DisplayBasename: &processName, Category: domain.ProcessSelectedOllama, TargetID: pointer(integrationTargetID), AssociationQuality: domain.AssociationVerified, CPUBusyRatio: pointer(0.1), PhysicalFootprintBytes: &footprint, Missing: []domain.MissingCapability{}, Provenance: provenance("darwin-proc-rusage-candidate-1")}}
	hostFrames[1].ProcessSummary = &domain.ProcessSummary{EligiblePIDCount: 1, ExaminedPIDCount: 1, RetainedProcessCount: 1, Coverage: "complete", MethodRevision: "darwin-proc-list-candidate-1", SampleIntervalMS: 1000, ScanDurationMS: 5}
	if _, err := st.IngestCollectorBatch(ctx, integrationBatch(state, session, integrationHostSrcID, "20000000-0000-4000-8000-000000000007", hostFrames)); err != nil {
		t.Fatal(err)
	}
	runtimeFrames := []protocol.CollectorFrame{
		integrationFrame(integrationRunSrcID, 1, now.Add(-3*time.Second), "ollama-0.34.0-bounded-read-v1", map[string]protocol.MetricValue{"runtime.reachable": {Value: json.RawMessage(`true`), Quality: domain.QualityRuntimeReported, Provenance: domain.Provenance{Source: domain.ProvenanceRuntimeAPI, MethodRevision: "ollama-0.34.0-bounded-read-v1", Verification: domain.VerificationDirectCapture}}}),
		integrationFrame(integrationRunSrcID, 2, now.Add(-2*time.Second), "ollama-0.34.0-bounded-ps-v1", map[string]protocol.MetricValue{}),
	}
	runtimeFrames[1].Quality = domain.QualityRuntimeReported
	runtimeFrames[1].Provenance = domain.Provenance{Source: domain.ProvenanceRuntimeAPI, MethodRevision: "ollama-0.34.0-bounded-ps-v1", Verification: domain.VerificationDirectCapture}
	runtimeFrames[1].ModelObservations = []domain.ModelObservation{{ModelID: integrationModelID, Digest: digest, Loaded: true, ReportedSizeBytes: &footprint, Missing: []domain.MissingCapability{}, Provenance: runtimeFrames[1].Provenance}}
	if _, err := st.IngestCollectorBatch(ctx, integrationBatch(state, session, integrationRunSrcID, "20000000-0000-4000-8000-000000000008", runtimeFrames)); err != nil {
		t.Fatal(err)
	}
	lastSuccess := now.Add(-time.Second).UnixMilli()
	status := protocol.SourceStatus{Protocol: domain.ProtocolVersion, DeploymentID: state.DeploymentID, HostID: queryHostID, SecurityGeneration: state.DeploymentGeneration, SessionGeneration: session.SessionGeneration, CollectorBootID: queryBootID, Sequence: 1, ObservedWallMS: lastSuccess, Heartbeat: "fresh", Sources: []protocol.SourceState{{SourceID: integrationHostSrcID, State: "fresh", LastSuccessMS: &lastSuccess}, {SourceID: integrationRunSrcID, State: "fresh", LastSuccessMS: &lastSuccess}}, LossIntervals: []protocol.LossInterval{}}
	if _, err := st.IngestSourceStatus(ctx, status); err != nil {
		t.Fatal(err)
	}

	service := New(st, clock)
	overview, err := service.Overview(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if overview.State != SourcePartial || len(overview.Hosts) != 1 || len(overview.Targets) != 1 || overview.Hosts[0].ProcessSummary == nil || overview.Targets[0].AssociationState != "verified" || len(overview.Targets[0].Models) != 1 || overview.Targets[0].Reachable.Value == nil {
		t.Fatalf("overview = %#v", overview)
	}
	if overview.Hosts[0].Metrics[0].ObservedMS == nil || *overview.Hosts[0].Metrics[0].ObservedMS != now.Add(-3*time.Second).UnixMilli() {
		t.Fatalf("CPU timing = %#v", overview.Hosts[0].Metrics[0])
	}
	assertResponseContractKeys(t, overview, "overview")
	assertResponseContractKeys(t, overview.Hosts[0], "host")
	assertResponseContractKeys(t, overview.Targets[0], "target")
	health, err := service.MonitorHealth(ctx)
	if err != nil || health.StorageState != store.StorageNormal || len(health.CollectorStates) != 1 || health.Gaps != 0 {
		t.Fatalf("monitor health = %#v, %v", health, err)
	}
	// The HTTP boundary adds live evaluator status to the persisted query result.
	assertResponseContractKeys(t, struct {
		MonitorHealth
		Evaluator alertruntime.Status `json:"evaluator"`
	}{health, alertruntime.Status{}}, "monitorHealth")
	forecast, err := service.StorageForecast(ctx)
	if err != nil || forecast.PhysicalBytes <= 0 || forecast.LiveLimitBytes != store.LiveDataLimitBytes || forecast.EstimatedDaysRemaining != nil {
		t.Fatalf("storage forecast = %#v, %v", forecast, err)
	}
	assertResponseContractKeys(t, forecast, "storageForecast")
	series, err := service.Series(ctx, SeriesParameters{Scope: queryHostID, Metric: "host.cpu.busy_ratio", Resolution: "raw", Start: now.Add(-time.Minute).UnixMilli(), End: now.Add(time.Millisecond).UnixMilli()})
	if err != nil || len(series.Points) != 1 || string(series.Points[0].Value) != "0.25" || series.CoverageRatio == nil {
		t.Fatalf("host series = %#v, %v", series, err)
	}
	assertSeriesContractKeys(t, series)
	autoSeries, err := service.Series(ctx, SeriesParameters{Scope: queryHostID, Metric: "host.cpu.busy_ratio", Resolution: ResolutionAuto, Start: now.Add(-time.Minute).UnixMilli(), End: now.Add(time.Millisecond).UnixMilli()})
	if err != nil || autoSeries.ResolutionTier == nil || *autoSeries.ResolutionTier != "raw" || len(autoSeries.Points) != 1 {
		t.Fatalf("automatic host series = %#v, %v", autoSeries, err)
	}
	sixHourStart := now.Add(-6 * time.Hour).UnixMilli()
	seriesHash := store.RollupSeriesHash("host.cpu.busy_ratio", queryHostID)
	for index := range 360 {
		minuteMS := sixHourStart + int64(index)*60_000
		payload, buildErr := store.BuildRollupPayload(store.RollupMinute, minuteMS, []store.RollupObservation{{
			SeriesHash: seriesHash, Kind: "gauge", ValueType: "number", ObservedMS: minuteMS, ValidUntilMS: minuteMS + 60_000,
			Value: json.RawMessage(`0.5`), Quality: domain.QualityMeasured, MethodRevision: "darwin-host-cpu-candidate-1", Aligned: true,
		}})
		if buildErr != nil {
			t.Fatal(buildErr)
		}
		if putErr := st.PutRollup(ctx, store.RollupRecord{DeploymentID: state.DeploymentID, HostID: queryHostID, SourceID: integrationHostSrcID, IntervalMS: minuteMS, Revision: 1, Payload: payload}); putErr != nil {
			t.Fatal(putErr)
		}
	}
	sixHourSeries, err := service.Series(ctx, SeriesParameters{Scope: queryHostID, Metric: "host.cpu.busy_ratio", Resolution: ResolutionAuto, Start: sixHourStart, End: now.UnixMilli()})
	if err != nil || sixHourSeries.ResolutionTier == nil || *sixHourSeries.ResolutionTier != store.RollupMinute || len(sixHourSeries.Points) != 360 || sixHourSeries.CoverageRatio == nil || *sixHourSeries.CoverageRatio != 1 {
		t.Fatalf("bounded six-hour series = %#v, %v", sixHourSeries, err)
	}
	processSeries, err := service.Series(ctx, SeriesParameters{Scope: processKey, Metric: "process.physical_footprint_bytes", Resolution: "raw", Start: now.Add(-time.Minute).UnixMilli(), End: now.Add(time.Millisecond).UnixMilli()})
	if err != nil || len(processSeries.Points) != 1 || string(processSeries.Points[0].Value) != `"4096"` {
		t.Fatalf("process series = %#v, %v", processSeries, err)
	}
	catalog, err := service.HistoryCatalog(ctx)
	if err != nil || len(catalog.Scopes) != 4 || catalog.EarliestRetainedMS == nil || catalog.LatestRetainedMS == nil || catalog.Truncated {
		t.Fatalf("history catalog = %#v, %v", catalog, err)
	}
	if catalog.Scopes[3].Kind != "process" || catalog.Scopes[3].DisplayName != "Observed process dddddddddddd" || catalog.Scopes[3].ID != processKey {
		t.Fatalf("privacy-preserving process scope = %#v", catalog.Scopes[3])
	}
	assertResponseContractKeys(t, catalog, "historyCatalog")
	for _, scope := range catalog.Scopes {
		assertResponseContractKeys(t, scope, "historyScope")
	}

	networkFailure := integrationFrame(integrationHostSrcID, 3, now.Add(-1500*time.Millisecond), "darwin-net-rt-iflist2-ifdata64-candidate-1", map[string]protocol.MetricValue{})
	networkFailure.CapabilitiesMissing = []domain.MissingCapability{{ID: "host.network.received_bytes_total", Reason: domain.MissingSourceTimeout}}
	if _, err := st.IngestCollectorBatch(ctx, integrationBatch(state, session, integrationHostSrcID, "20000000-0000-4000-8000-000000000009", []protocol.CollectorFrame{networkFailure})); err != nil {
		t.Fatal(err)
	}
	overview, err = service.Overview(ctx)
	if err != nil || overview.Hosts[0].SourceState != SourcePartial || len(overview.Hosts[0].NetworkObservations) != 0 || !hasNetworkCapability(overview.Hosts[0].CapabilitiesMissing) {
		t.Fatalf("network failure overview = %#v, %v", overview.Hosts[0], err)
	}

	received, sent := domain.DecimalUint64(1024), domain.DecimalUint64(2048)
	detail := "interface_cap"
	network := domain.NetworkObservation{
		InterfaceID: "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee", BootID: queryBootID, CounterEpochID: "20000000-0000-4000-8000-000000000010",
		ReceivedBytesTotal: &received, SentBytesTotal: &sent, Missing: []domain.MissingCapability{}, Provenance: provenance("darwin-net-rt-iflist2-ifdata64-candidate-1"),
	}
	partialNetwork := integrationFrame(integrationHostSrcID, 4, now.Add(-time.Second), "darwin-net-rt-iflist2-ifdata64-candidate-1", map[string]protocol.MetricValue{})
	partialNetwork.NetworkObservations = []domain.NetworkObservation{network}
	partialNetwork.CapabilitiesMissing = []domain.MissingCapability{{ID: "host.network.received_bytes_total", Reason: domain.MissingLimitExceeded, DetailCode: &detail}}
	if _, err := st.IngestCollectorBatch(ctx, integrationBatch(state, session, integrationHostSrcID, "20000000-0000-4000-8000-000000000011", []protocol.CollectorFrame{partialNetwork})); err != nil {
		t.Fatal(err)
	}
	overview, err = service.Overview(ctx)
	if err != nil || overview.Hosts[0].SourceState != SourcePartial || len(overview.Hosts[0].NetworkObservations) != 1 || !hasNetworkCapability(overview.Hosts[0].CapabilitiesMissing) {
		t.Fatalf("partial network overview = %#v, %v", overview.Hosts[0], err)
	}

	recoveredNetwork := integrationFrame(integrationHostSrcID, 5, now.Add(-500*time.Millisecond), "darwin-net-rt-iflist2-ifdata64-candidate-1", map[string]protocol.MetricValue{})
	recoveredNetwork.NetworkObservations = []domain.NetworkObservation{network}
	if _, err := st.IngestCollectorBatch(ctx, integrationBatch(state, session, integrationHostSrcID, "20000000-0000-4000-8000-000000000012", []protocol.CollectorFrame{recoveredNetwork})); err != nil {
		t.Fatal(err)
	}
	overview, err = service.Overview(ctx)
	if err != nil || overview.Hosts[0].SourceState != SourceFresh || len(overview.Hosts[0].NetworkObservations) != 1 || hasNetworkCapability(overview.Hosts[0].CapabilitiesMissing) {
		t.Fatalf("recovered network overview = %#v, %v", overview.Hosts[0], err)
	}
	retiredInventory := inventory
	retiredInventory.InventoryRevision = "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
	retiredInventory.Sources = []protocol.InventorySource{{SourceID: integrationHostSrcID, Kind: "host", CapabilityRevision: domain.RegistryRevision, Active: false}, {SourceID: integrationRunSrcID, Kind: "runtime", TargetID: pointer(integrationTargetID), CapabilityRevision: domain.RegistryRevision, Active: false}}
	retiredInventory.Targets = nil
	retiredInventory.Models = nil
	if _, err := st.RegisterCollectorInventory(ctx, retiredInventory); err != nil {
		t.Fatal(err)
	}
	retiredSeries, err := service.Series(ctx, SeriesParameters{Scope: queryHostID, Metric: "host.cpu.busy_ratio", Resolution: "raw", Start: now.Add(-time.Minute).UnixMilli(), End: now.Add(time.Millisecond).UnixMilli()})
	if err != nil || len(retiredSeries.Points) != 1 {
		t.Fatalf("retired host history = %#v, %v", retiredSeries, err)
	}
	retiredCatalog, err := service.HistoryCatalog(ctx)
	if err != nil || !retiredCatalog.Scopes[0].Retired {
		t.Fatalf("retired catalog = %#v, %v", retiredCatalog, err)
	}
	// A retained process identity stays valid before its first observation and
	// after exit. No samples is an explicit gap, not an unsupported scope.
	for _, start := range []time.Time{now.Add(-2 * time.Hour), now.Add(2 * time.Hour)} {
		for _, resolution := range []string{"raw", store.RollupMinute} {
			request := SeriesParameters{Scope: processKey, Metric: "process.physical_footprint_bytes", Resolution: resolution, Start: start.UnixMilli(), End: start.Add(6 * time.Hour).UnixMilli()}
			if resolution == "raw" {
				request.End = start.Add(time.Minute).UnixMilli()
			} else if start.Before(now) {
				request.Start = now.Add(-8 * time.Hour).UnixMilli()
				request.End = now.Add(-2 * time.Hour).UnixMilli()
			}
			empty, err := service.Series(ctx, request)
			if err != nil || len(empty.Points) != 0 || len(empty.Gaps) == 0 || empty.EffectiveRange != nil {
				t.Fatalf("known process empty window (%s, %v) = %#v, %v", resolution, start, empty, err)
			}
			request.Scope = "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"
			if _, err := service.Series(ctx, request); !errors.Is(err, ErrUnsupportedMetric) {
				t.Fatalf("unknown process accepted (%s): %v", resolution, err)
			}
		}
	}
}

func assertResponseContractKeys(t *testing.T, value any, definition string) {
	t.Helper()
	var contract struct {
		Definitions map[string]struct {
			Required []string `json:"required"`
		} `json:"$defs"`
	}
	decodeContract(t, filepath.Join("contracts", "api", "v1", "response.schema.json"), &contract)
	assertJSONKeys(t, value, contract.Definitions[definition].Required)
}

func assertSeriesContractKeys(t *testing.T, value any) {
	t.Helper()
	var contract struct {
		Required []string `json:"required"`
	}
	decodeContract(t, filepath.Join("contracts", "api", "v1", "query.schema.json"), &contract)
	assertJSONKeys(t, value, contract.Required)
}

func decodeContract(t *testing.T, relative string, destination any) {
	t.Helper()
	_, source, _, _ := runtime.Caller(0)
	repository := filepath.Clean(filepath.Join(filepath.Dir(source), "..", ".."))
	payload, err := os.ReadFile(filepath.Join(repository, relative))
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(payload, destination); err != nil {
		t.Fatal(err)
	}
}

func assertJSONKeys(t *testing.T, value any, required []string) {
	t.Helper()
	payload, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	var object map[string]json.RawMessage
	if err := json.Unmarshal(payload, &object); err != nil {
		t.Fatal(err)
	}
	actual := make([]string, 0, len(object))
	for key := range object {
		actual = append(actual, key)
	}
	sort.Strings(actual)
	sort.Strings(required)
	if string(mustJSON(actual)) != string(mustJSON(required)) {
		t.Fatalf("actual JSON keys %v do not match required contract keys %v", actual, required)
	}
}

func mustJSON(value any) []byte {
	payload, _ := json.Marshal(value)
	return payload
}

func integrationFrame(sourceID string, sequence int64, observed time.Time, method string, gauges map[string]protocol.MetricValue) protocol.CollectorFrame {
	return protocol.CollectorFrame{SourceID: sourceID, Sequence: sequence, ObservedWallMS: observed.UnixMilli(), MonotonicStartNS: domain.DecimalUint64(uint64(sequence * 10)), MonotonicEndNS: domain.DecimalUint64(uint64(sequence*10 + 1)), DefinitionRevision: domain.RegistryRevision, Quality: domain.QualityMeasured, Provenance: provenance(method), Gauges: gauges, NetworkObservations: []domain.NetworkObservation{}, ModelObservations: []domain.ModelObservation{}, ProcessObservations: []domain.ProcessObservation{}, CapabilitiesMissing: []domain.MissingCapability{}}
}

func integrationBatch(state domain.DeploymentState, session protocol.SessionResult, _ string, batchID string, frames []protocol.CollectorFrame) protocol.CollectorBatch {
	return protocol.CollectorBatch{Protocol: domain.ProtocolVersion, DeliveryMode: "current", SecurityGeneration: state.DeploymentGeneration, SessionGeneration: session.SessionGeneration, DeploymentID: state.DeploymentID, HostID: queryHostID, CollectorBootID: queryBootID, BatchID: batchID, Frames: frames}
}
