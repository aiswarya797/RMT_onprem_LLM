package query

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"sort"
	"time"

	"rmt.local/monitor/internal/domain"
	"rmt.local/monitor/internal/protocol"
	"rmt.local/monitor/internal/store"
)

const (
	maxSeriesPoints = 2000
	ResolutionAuto  = "auto"
)

var (
	queryUUIDPattern  = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$`)
	processKeyPattern = regexp.MustCompile(`^[0-9a-f]{64}$`)
)

type metricDefinition struct {
	unit, population, kind, method string
	source                         string
	freshness                      time.Duration
}

var metricDefinitions = map[string]metricDefinition{
	"host.cpu.busy_ratio":                    {"ratio", "host", "host", "darwin-host-cpu-candidate-1", domain.ProvenanceDarwinAPI, 15 * time.Second},
	"host.memory.pressure_level":             {"state", "host", "host", "xnu-11417.121.6-pressure-flags", domain.ProvenanceDarwinAPI, 15 * time.Second},
	"host.memory.compressed_bytes":           {"bytes", "host", "host", "darwin-vm-candidate-1", domain.ProvenanceDarwinAPI, 15 * time.Second},
	"host.memory.swap_used_bytes":            {"bytes", "host", "host", "darwin-swap-candidate-1", domain.ProvenanceDarwinAPI, 15 * time.Second},
	"host.disk.free_bytes":                   {"bytes", "host", "host", "darwin-statfs-candidate-1", domain.ProvenanceDarwinAPI, 15 * time.Second},
	"runtime.reachable":                      {"boolean", "runtime", "runtime", "ollama-0.34.0-bounded-read-v1", domain.ProvenanceRuntimeAPI, 15 * time.Second},
	"runtime.model.loaded":                   {"boolean", "runtime", "model", "ollama-0.34.0-bounded-ps-v1", domain.ProvenanceRuntimeAPI, 45 * time.Second},
	"runtime.model.reported_size_bytes":      {"bytes", "runtime", "model", "ollama-0.34.0-bounded-ps-v1", domain.ProvenanceRuntimeAPI, 45 * time.Second},
	"runtime.model.reported_size_vram_bytes": {"bytes", "runtime", "model", "ollama-0.34.0-bounded-ps-v1", domain.ProvenanceRuntimeAPI, 45 * time.Second},
	"process.cpu.busy_ratio":                 {"ratio", "process", "process", "darwin-proc-rusage-candidate-1", domain.ProvenanceDarwinAPI, 45 * time.Second},
	"process.physical_footprint_bytes":       {"bytes", "process", "process", "darwin-proc-footprint-candidate-1", domain.ProvenanceDarwinAPI, 45 * time.Second},
}

func (s *Service) Series(ctx context.Context, parameters SeriesParameters) (Series, error) {
	definition, ok := metricDefinitions[parameters.Metric]
	if !ok {
		return Series{}, ErrUnsupportedMetric
	}
	if parameters.Resolution != ResolutionAuto && parameters.Resolution != "raw" && parameters.Resolution != store.RollupMinute && parameters.Resolution != store.RollupHour {
		return Series{}, ErrUnsupportedResolution
	}
	if !validSeriesScope(parameters.Scope, definition.kind) || parameters.Start < 0 || parameters.End <= parameters.Start || parameters.End-parameters.Start > store.RollupRetention.Milliseconds() {
		return Series{}, ErrInvalidQuery
	}
	nowMS := s.clock.Now().UnixMilli()
	if parameters.Resolution == ResolutionAuto {
		parameters.Resolution = automaticSeriesResolution(parameters, nowMS)
	}
	if !validSeriesRange(parameters, nowMS) {
		return Series{}, ErrUnsupportedResolution
	}
	if parameters.Resolution != "raw" {
		return s.rollupSeries(ctx, parameters, definition)
	}
	inventory, err := s.store.ReadQueryInventory(ctx)
	if err != nil {
		return Series{}, err
	}
	source, err := s.store.ResolveHistorySource(ctx, inventory.Deployment.DeploymentID, parameters.Scope, definition.kind, parameters.Start, parameters.End)
	hostID := source.HostID
	var rows []store.QueryFrame
	if err == nil {
		rows, err = s.store.ReadQueryFrames(ctx, store.QueryFrameFilter{
			DeploymentID: inventory.Deployment.DeploymentID, HostID: hostID, SourceID: source.ID,
			StartMS: parameters.Start, EndMS: parameters.End, Limit: store.MaxQueryFrameRows,
		})
	}
	if err != nil {
		if errors.Is(err, store.ErrQueryLimit) {
			return Series{}, ErrPointLimit
		}
		if errors.Is(err, store.ErrHistoryScopeNotFound) {
			return Series{}, ErrUnsupportedMetric
		}
		return Series{}, err
	}
	if len(rows) == store.MaxQueryFrameRows {
		return Series{}, ErrPointLimit
	}
	codec, err := store.NewFrameCodecV1()
	if err != nil {
		return Series{}, err
	}
	defer codec.Close()
	points := make([]seriesValue, 0, min(len(rows), maxSeriesPoints))
	replayed := false
	for _, row := range rows {
		if err := row.ValidateCodec(); err != nil {
			return Series{}, err
		}
		frame, err := codec.Decode(row.Payload)
		if err != nil {
			return Series{}, fmt.Errorf("decode persisted series frame: %w", err)
		}
		value, found := metricFromFrame(frame, parameters.Metric, parameters.Scope, definition.kind)
		if !found {
			continue
		}
		if len(points) == maxSeriesPoints {
			return Series{}, ErrPointLimit
		}
		if row.DeliveryMode != "current" {
			replayed = true
		}
		points = append(points, seriesValue{point: SeriesPoint{TimeMS: row.ObservationMS(), Value: cloneRaw(value.Value), Quality: value.Quality, MissingReason: value.MissingReason, EpochID: row.IncarnationID}, method: value.Provenance.MethodRevision, aligned: row.AlignedMS != nil})
	}
	return buildSeries(parameters, definition, source.ID, hostID, points, replayed)
}

func automaticSeriesResolution(parameters SeriesParameters, nowMS int64) string {
	rangeMS := parameters.End - parameters.Start
	if rangeMS > int64(24*time.Hour/time.Millisecond) {
		return store.RollupHour
	}
	if rangeMS >= int64(6*time.Hour/time.Millisecond) || parameters.End <= nowMS-store.RawFrameRetention.Milliseconds() {
		return store.RollupMinute
	}
	return "raw"
}

func validSeriesRange(parameters SeriesParameters, nowMS int64) bool {
	rangeMS := parameters.End - parameters.Start
	switch parameters.Resolution {
	case "raw":
		return rangeMS <= int64(6*time.Hour/time.Millisecond)
	case store.RollupMinute:
		return rangeMS <= int64(24*time.Hour/time.Millisecond) && (rangeMS >= int64(6*time.Hour/time.Millisecond) || parameters.End <= nowMS-store.RawFrameRetention.Milliseconds())
	case store.RollupHour:
		return rangeMS > int64(24*time.Hour/time.Millisecond) && rangeMS <= store.RollupRetention.Milliseconds()
	default:
		return false
	}
}

func validSeriesScope(scope, kind string) bool {
	if kind == "process" {
		return processKeyPattern.MatchString(scope)
	}
	return queryUUIDPattern.MatchString(scope)
}

func (s *Service) resolveProcessSeries(ctx context.Context, inventory store.QueryInventory, parameters SeriesParameters) (store.QuerySource, string, []store.QueryFrame, error) {
	codec, err := store.NewFrameCodecV1()
	if err != nil {
		return store.QuerySource{}, "", nil, err
	}
	defer codec.Close()
	for _, source := range inventory.Sources {
		if source.Kind != "host" {
			continue
		}
		rows, err := s.store.ReadQueryFrames(ctx, store.QueryFrameFilter{
			DeploymentID: inventory.Deployment.DeploymentID, HostID: source.HostID, SourceID: source.ID,
			StartMS: parameters.Start, EndMS: parameters.End, Limit: store.MaxQueryFrameRows,
		})
		if err != nil {
			return store.QuerySource{}, "", nil, err
		}
		for _, row := range rows {
			if err := row.ValidateCodec(); err != nil {
				return store.QuerySource{}, "", nil, err
			}
			frame, err := codec.Decode(row.Payload)
			if err != nil {
				return store.QuerySource{}, "", nil, fmt.Errorf("decode persisted process series frame: %w", err)
			}
			if _, found := metricFromFrame(frame, parameters.Metric, parameters.Scope, "process"); found {
				return source, source.HostID, rows, nil
			}
		}
	}
	return store.QuerySource{}, "", nil, ErrUnsupportedMetric
}

type seriesValue struct {
	point   SeriesPoint
	method  string
	aligned bool
}

func metricFromFrame(frame protocol.CollectorFrame, metric, scope, kind string) (protocol.MetricValue, bool) {
	if kind == "host" || kind == "runtime" {
		value, ok := frame.Gauges[metric]
		if ok {
			return value, true
		}
		for _, missing := range frame.CapabilitiesMissing {
			if missing.ID == metric {
				return protocol.MetricValue{Value: nil, Quality: domain.QualityUnavailable, MissingReason: &missing.Reason, Provenance: frame.Provenance}, true
			}
		}
		return protocol.MetricValue{}, false
	}
	if kind == "model" {
		for _, model := range frame.ModelObservations {
			if model.ModelID != scope {
				continue
			}
			return modelMetric(model, metric)
		}
		return protocol.MetricValue{}, false
	}
	if kind == "process" {
		for _, process := range frame.ProcessObservations {
			if process.ProcessKey != scope {
				continue
			}
			return processMetric(process, metric)
		}
	}
	return protocol.MetricValue{}, false
}

func modelMetric(model domain.ModelObservation, metric string) (protocol.MetricValue, bool) {
	value := protocol.MetricValue{Quality: domain.QualityRuntimeReported, Provenance: model.Provenance}
	switch metric {
	case "runtime.model.loaded":
		value.Value = rawJSON(model.Loaded)
	case "runtime.model.reported_size_bytes":
		if model.ReportedSizeBytes == nil {
			return missingMetric(model.Missing, metric, model.Provenance)
		}
		value.Value = rawJSON(*model.ReportedSizeBytes)
	case "runtime.model.reported_size_vram_bytes":
		if model.ReportedSizeVRAMBytes == nil {
			return missingMetric(model.Missing, metric, model.Provenance)
		}
		value.Value = rawJSON(*model.ReportedSizeVRAMBytes)
	default:
		return protocol.MetricValue{}, false
	}
	return value, true
}

func processMetric(process domain.ProcessObservation, metric string) (protocol.MetricValue, bool) {
	value := protocol.MetricValue{Quality: domain.QualityMeasured, Provenance: process.Provenance}
	switch metric {
	case "process.cpu.busy_ratio":
		if process.CPUBusyRatio == nil {
			return missingMetric(process.Missing, metric, process.Provenance)
		}
		value.Value = rawJSON(*process.CPUBusyRatio)
	case "process.physical_footprint_bytes":
		if process.PhysicalFootprintBytes == nil {
			return missingMetric(process.Missing, metric, process.Provenance)
		}
		value.Value = rawJSON(*process.PhysicalFootprintBytes)
	default:
		return protocol.MetricValue{}, false
	}
	return value, true
}

func missingMetric(values []domain.MissingCapability, metric string, provenance domain.Provenance) (protocol.MetricValue, bool) {
	for _, missing := range values {
		if missing.ID == metric {
			return protocol.MetricValue{Quality: domain.QualityUnavailable, MissingReason: &missing.Reason, Provenance: provenance}, true
		}
	}
	return protocol.MetricValue{}, false
}

func buildSeries(parameters SeriesParameters, definition metricDefinition, sourceID, hostID string, values []seriesValue, replayed bool) (Series, error) {
	requested := makeRange(parameters.Start, parameters.End)
	resolution, clockMethod := "raw", "monotonic"
	result := Series{
		SchemaVersion: domain.SchemaVersion, Metric: parameters.Metric, DefinitionRevision: domain.RegistryRevision, Unit: definition.unit,
		RequestedRange: requested, Population: definition.population, HostID: pointer(hostID), SourceID: pointer(sourceID), ResolutionTier: &resolution,
		PopulationKey: nil, Summary: nil, Points: []SeriesPoint{}, Gaps: []Gap{}, Warnings: []string{},
	}
	if len(values) == 0 {
		result.Gaps = []Gap{{StartMS: parameters.Start, EndMS: parameters.End, Reason: domain.MissingPopulationNotObserved}}
		return result, nil
	}
	sort.SliceStable(values, func(i, j int) bool { return values[i].point.TimeMS < values[j].point.TimeMS })
	method := values[0].method
	for _, value := range values {
		if value.method != method {
			return Series{}, fmt.Errorf("%w: multiple method revisions in range", ErrUnsupportedMetric)
		}
		if value.aligned {
			clockMethod = "single_host_monotonic_aligned"
		}
		result.Points = append(result.Points, value.point)
	}
	result.MethodRevision, result.ClockMethod = pointer(method), pointer(clockMethod)
	first, last := result.Points[0].TimeMS, result.Points[len(result.Points)-1].TimeMS
	effectiveEnd := min(parameters.End, last+1)
	effective := makeRange(first, effectiveEnd)
	result.EffectiveRange = &effective
	coverage, gaps := coverageAndGaps(result.Points, parameters.Start, parameters.End, definition.freshness)
	result.CoverageRatio, result.Gaps = &coverage, gaps
	if replayed {
		result.Warnings = append(result.Warnings, "Historical replay is included in this range and does not establish current freshness.")
	}
	return result, nil
}

func coverageAndGaps(points []SeriesPoint, start, end int64, freshness time.Duration) (float64, []Gap) {
	freshMS := freshness.Milliseconds()
	validDuration := int64(0)
	gaps := make([]Gap, 0)
	if points[0].TimeMS > start {
		gaps = appendGap(gaps, start, points[0].TimeMS, domain.MissingCollectionGap)
	}
	for index, point := range points {
		intervalEnd := end
		if index+1 < len(points) {
			intervalEnd = min(end, points[index+1].TimeMS)
		}
		validEnd := min(intervalEnd, point.TimeMS+freshMS)
		if point.Value != nil && point.Quality != domain.QualityUnavailable && validEnd > max(start, point.TimeMS) {
			validDuration += validEnd - max(start, point.TimeMS)
		} else if validEnd > point.TimeMS {
			reason := domain.MissingCollectionGap
			if point.MissingReason != nil {
				reason = *point.MissingReason
			}
			gaps = appendGap(gaps, max(start, point.TimeMS), validEnd, reason)
		}
		if intervalEnd > validEnd {
			gaps = appendGap(gaps, max(start, validEnd), intervalEnd, domain.MissingCollectionGap)
		}
	}
	requested := end - start
	if requested <= 0 {
		return 0, gaps
	}
	return min(1, float64(validDuration)/float64(requested)), gaps
}

func appendGap(gaps []Gap, start, end int64, reason domain.MissingReason) []Gap {
	if end <= start {
		return gaps
	}
	if len(gaps) > 0 && gaps[len(gaps)-1].EndMS == start && gaps[len(gaps)-1].Reason == reason {
		gaps[len(gaps)-1].EndMS = end
		return gaps
	}
	return append(gaps, Gap{StartMS: start, EndMS: end, Reason: reason})
}

func resolveSeriesSource(inventory store.QueryInventory, scope, kind string) (store.QuerySource, string, error) {
	for _, source := range inventory.Sources {
		if source.Kind != sourceKind(kind) {
			continue
		}
		matches := (kind == "host" && source.HostID == scope) || (kind == "runtime" && source.TargetID != nil && *source.TargetID == scope) || (kind == "model" && source.TargetID != nil && modelBelongsTo(inventory.Models, scope, *source.TargetID))
		if matches {
			return source, source.HostID, nil
		}
	}
	return store.QuerySource{}, "", ErrUnsupportedMetric
}

func sourceKind(kind string) string {
	if kind == "runtime" || kind == "model" {
		return "runtime"
	}
	return "host"
}

func modelBelongsTo(models []store.QueryModel, modelID, targetID string) bool {
	for _, model := range models {
		if model.ID == modelID && model.TargetID == targetID {
			return true
		}
	}
	return false
}

func makeRange(start, end int64) Range {
	return Range{Start: time.UnixMilli(start).UTC().Format(time.RFC3339Nano), End: time.UnixMilli(end).UTC().Format(time.RFC3339Nano), StartMS: start, EndMS: end, InclusiveStartExclusiveEnd: true}
}

func rawJSON(value any) []byte {
	encoded, _ := json.Marshal(value)
	return encoded
}
