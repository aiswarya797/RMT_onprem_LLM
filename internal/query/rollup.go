package query

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"sort"

	"rmt.local/monitor/internal/domain"
	"rmt.local/monitor/internal/store"
)

func (s *Service) rollupSeries(ctx context.Context, parameters SeriesParameters, definition metricDefinition) (Series, error) {
	inventory, err := s.store.ReadQueryInventory(ctx)
	if err != nil {
		return Series{}, err
	}
	source, err := s.store.ResolveHistorySource(ctx, inventory.Deployment.DeploymentID, parameters.Scope, definition.kind, parameters.Start, parameters.End)
	hostID := source.HostID
	var rows []store.QueryRollup
	if err == nil {
		rows, err = s.store.ReadRollups(ctx, rollupFilter(inventory.Deployment.DeploymentID, hostID, source.ID, parameters))
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
	if len(rows) == store.MaxRollupRows {
		return Series{}, ErrPointLimit
	}
	return buildRollupSeries(parameters, definition, source.ID, hostID, rows)
}

func rollupFilter(deploymentID, hostID, sourceID string, parameters SeriesParameters) store.RollupFilter {
	duration := int64(60_000)
	if parameters.Resolution == store.RollupHour {
		duration = 3_600_000
	}
	return store.RollupFilter{DeploymentID: deploymentID, HostID: hostID, SourceID: sourceID, Resolution: parameters.Resolution, StartMS: parameters.Start / duration * duration, EndMS: parameters.End, Limit: store.MaxRollupRows}
}

func (s *Service) resolveProcessRollups(ctx context.Context, inventory store.QueryInventory, parameters SeriesParameters) (store.QuerySource, string, []store.QueryRollup, error) {
	hash := store.RollupSeriesHash(parameters.Metric, parameters.Scope)
	for _, source := range inventory.Sources {
		if source.Kind != "host" {
			continue
		}
		rows, err := s.store.ReadRollups(ctx, rollupFilter(inventory.Deployment.DeploymentID, source.HostID, source.ID, parameters))
		if err != nil {
			return store.QuerySource{}, "", nil, err
		}
		for _, row := range rows {
			if _, found := row.Payload.Series[hash]; found {
				return source, source.HostID, rows, nil
			}
		}
	}
	return store.QuerySource{}, "", nil, ErrUnsupportedMetric
}

func buildRollupSeries(parameters SeriesParameters, definition metricDefinition, sourceID, hostID string, rows []store.QueryRollup) (Series, error) {
	resolution := parameters.Resolution
	result := Series{
		SchemaVersion: domain.SchemaVersion, Metric: parameters.Metric, DefinitionRevision: domain.RegistryRevision, Unit: definition.unit,
		RequestedRange: makeRange(parameters.Start, parameters.End), Population: definition.population, HostID: pointer(hostID), SourceID: pointer(sourceID), ResolutionTier: &resolution,
		PopulationKey: nil, Summary: nil, Points: []SeriesPoint{}, Gaps: []Gap{}, Warnings: []string{},
	}
	if len(rows) == 0 {
		result.Gaps = []Gap{{StartMS: parameters.Start, EndMS: parameters.End, Reason: domain.MissingPopulationNotObserved}}
		return result, nil
	}
	hash := store.RollupSeriesHash(parameters.Metric, parameters.Scope)
	methods := make(map[string]bool)
	clockAligned := true
	validDuration := int64(0)
	first, last := int64(0), int64(0)
	for _, row := range rows {
		intervalStart := max(parameters.Start, row.Payload.StartMS)
		intervalEnd := min(parameters.End, row.Payload.EndMS)
		if intervalEnd <= intervalStart {
			continue
		}
		// A retained rollup summarizes its complete aligned bucket. It cannot
		// locate valid and missing dwell inside a clipped boundary, so using its
		// whole-bucket aggregate would fabricate boundary coverage and values.
		if intervalStart != row.Payload.StartMS || intervalEnd != row.Payload.EndMS {
			result.Gaps = appendGap(result.Gaps, intervalStart, intervalEnd, domain.MissingCollectionGap)
			appendWarning(&result.Warnings, "A partial retained-rollup boundary cannot be reconstructed without raw observations.")
			continue
		}
		if row.Payload.IncludesReplay {
			appendWarning(&result.Warnings, "Historical replay contributes to this rollup and does not establish current freshness.")
		}
		segments := row.Payload.Series[hash]
		if !row.Complete || !row.Payload.Complete {
			result.Gaps = appendGap(result.Gaps, intervalStart, intervalEnd, domain.MissingCollectionGap)
			appendWarning(&result.Warnings, "An interval exceeded the supported epoch transitions or could not be completely reconstructed.")
			continue
		}
		if len(segments) == 0 {
			result.Gaps = appendGap(result.Gaps, intervalStart, intervalEnd, domain.MissingPopulationNotObserved)
			continue
		}
		// Source buckets can contain other populations. Only the requested
		// series establishes an effective observation range.
		if first == 0 || intervalStart < first {
			first = intervalStart
		}
		last = max(last, intervalEnd)
		intervalValid := int64(0)
		for _, segment := range segments {
			methods[segment.MethodRevision] = true
			clockAligned = clockAligned && segment.Aligned
			point, ok, err := rollupPoint(row.IntervalMS, segment)
			if err != nil {
				return Series{}, err
			}
			if ok {
				if len(result.Points) == maxSeriesPoints {
					return Series{}, ErrPointLimit
				}
				result.Points = append(result.Points, point)
			}
			intervalValid += segment.ValidDurationMS
		}
		overlap := intervalEnd - intervalStart
		intervalValid = min(overlap, intervalValid)
		validDuration += intervalValid
		if intervalValid < overlap {
			reason := dominantMissingReason(segments)
			result.Gaps = appendGap(result.Gaps, intervalStart, intervalEnd, reason)
		}
	}
	requestedDuration := parameters.End - parameters.Start
	coverage := math.Min(1, float64(validDuration)/float64(requestedDuration))
	result.CoverageRatio = &coverage
	if first != 0 && last > first {
		effective := makeRange(first, last)
		result.EffectiveRange = &effective
	}
	if len(methods) == 1 {
		for method := range methods {
			result.MethodRevision = pointer(method)
		}
	} else if len(methods) > 1 {
		appendWarning(&result.Warnings, "Multiple compatible method epochs are retained in this range.")
	}
	clockMethod := "monotonic"
	if clockAligned {
		clockMethod = "single_host_monotonic_aligned"
	}
	if len(methods) > 0 {
		result.ClockMethod = &clockMethod
	}
	sort.SliceStable(result.Points, func(i, j int) bool { return result.Points[i].TimeMS < result.Points[j].TimeMS })
	return result, nil
}

func rollupPoint(timeMS int64, segment store.RollupSegment) (SeriesPoint, bool, error) {
	point := SeriesPoint{TimeMS: timeMS, Quality: domain.QualityDerived}
	if segment.EpochID != "" {
		point.EpochID = pointer(segment.EpochID)
	}
	if segment.ValidDurationMS == 0 {
		reason := dominantMissingReason([]store.RollupSegment{segment})
		point.Quality = domain.QualityUnavailable
		point.MissingReason = &reason
		point.Value = nil
		return point, true, nil
	}
	switch segment.Kind {
	case "cumulative_counter":
		if segment.CounterDelta == nil {
			return SeriesPoint{}, false, nil
		}
		point.Value = rawJSON(*segment.CounterDelta)
	case "gauge":
		switch segment.ValueType {
		case "number":
			if segment.WeightMS == 0 {
				return SeriesPoint{}, false, nil
			}
			point.Value = rawJSON(segment.WeightedSum / float64(segment.WeightMS))
		case "uint64":
			if segment.WeightMS == 0 {
				return SeriesPoint{}, false, nil
			}
			point.Value = rawJSON(domain.DecimalUint64(uint64(math.Round(segment.WeightedSum / float64(segment.WeightMS)))))
		case "enum", "boolean":
			point.Value = append(json.RawMessage(nil), segment.Last...)
		default:
			return SeriesPoint{}, false, fmt.Errorf("unsupported rollup value type %q", segment.ValueType)
		}
	default:
		return SeriesPoint{}, false, fmt.Errorf("unsupported rollup kind %q", segment.Kind)
	}
	return point, true, nil
}

func dominantMissingReason(segments []store.RollupSegment) domain.MissingReason {
	reason := domain.MissingCollectionGap
	longest := int64(0)
	for _, segment := range segments {
		for candidate, duration := range segment.MissingDurationMS {
			if duration > longest {
				reason, longest = candidate, duration
			}
		}
	}
	return reason
}

func appendWarning(values *[]string, warning string) {
	for _, existing := range *values {
		if existing == warning {
			return
		}
	}
	*values = append(*values, warning)
}
