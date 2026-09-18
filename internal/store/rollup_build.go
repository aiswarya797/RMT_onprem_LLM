package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"rmt.local/monitor/internal/domain"
	"rmt.local/monitor/internal/protocol"
)

const rollupPredecessorWindow = 45 * time.Second

type rollupMetricSpec struct {
	kind, valueType string
	freshness       time.Duration
}

var rollupMetricSpecs = map[string]rollupMetricSpec{
	"host.cpu.busy_ratio":                    {"gauge", "number", 15 * time.Second},
	"host.memory.pressure_level":             {"gauge", "enum", 15 * time.Second},
	"host.memory.compressed_bytes":           {"gauge", "uint64", 15 * time.Second},
	"host.memory.swap_used_bytes":            {"gauge", "uint64", 15 * time.Second},
	"host.disk.free_bytes":                   {"gauge", "uint64", 15 * time.Second},
	"host.network.received_bytes_total":      {"cumulative_counter", "uint64", 15 * time.Second},
	"host.network.sent_bytes_total":          {"cumulative_counter", "uint64", 15 * time.Second},
	"process.cpu.busy_ratio":                 {"gauge", "number", 45 * time.Second},
	"process.physical_footprint_bytes":       {"gauge", "uint64", 45 * time.Second},
	"runtime.reachable":                      {"gauge", "boolean", 15 * time.Second},
	"runtime.model.loaded":                   {"gauge", "boolean", 45 * time.Second},
	"runtime.model.reported_size_bytes":      {"gauge", "uint64", 45 * time.Second},
	"runtime.model.reported_size_vram_bytes": {"gauge", "uint64", 45 * time.Second},
}

// BuildAndPutMinuteRollup derives one revision from retained canonical frames.
// The bounded predecessor window is the longest metric freshness interval and
// supplies the first interval value/counter delta without crossing identities.
func (s *Store) BuildAndPutMinuteRollup(ctx context.Context, deploymentID, hostID, sourceID string, minuteMS, revision int64) (RollupRecord, error) {
	if deploymentID == "" || hostID == "" || sourceID == "" || minuteMS < 0 || minuteMS%60_000 != 0 || revision < 1 {
		return RollupRecord{}, errors.New("invalid minute rollup request")
	}
	targetID, err := s.rollupSourceTarget(ctx, deploymentID, hostID, sourceID)
	if err != nil {
		return RollupRecord{}, err
	}
	start := max(int64(0), minuteMS-rollupPredecessorWindow.Milliseconds())
	rows, err := s.ReadQueryFrames(ctx, QueryFrameFilter{DeploymentID: deploymentID, HostID: hostID, SourceID: sourceID, StartMS: start, EndMS: minuteMS + 60_000, Limit: MaxQueryFrameRows})
	if err != nil {
		return RollupRecord{}, err
	}
	if len(rows) == MaxQueryFrameRows {
		return RollupRecord{}, ErrQueryLimit
	}
	observations := make([]RollupObservation, 0, len(rows)*4)
	for _, row := range rows {
		if err := row.ValidateCodec(); err != nil {
			return RollupRecord{}, err
		}
		frame, err := s.codec.Decode(row.Payload)
		if err != nil {
			return RollupRecord{}, fmt.Errorf("decode rollup input frame: %w", err)
		}
		observations = append(observations, observationsFromFrame(frame, row, hostID, targetID, minuteMS, minuteMS+60_000)...)
	}
	payload, err := BuildRollupPayload(RollupMinute, minuteMS, observations)
	if err != nil {
		return RollupRecord{}, err
	}
	record := RollupRecord{DeploymentID: deploymentID, HostID: hostID, SourceID: sourceID, IntervalMS: minuteMS, Revision: revision, Payload: payload}
	if err := s.PutRollup(ctx, record); err != nil {
		return RollupRecord{}, err
	}
	return record, nil
}

func (s *Store) BuildAndPutHourRollup(ctx context.Context, deploymentID, hostID, sourceID string, hourMS, revision int64) (RollupRecord, error) {
	if deploymentID == "" || hostID == "" || sourceID == "" || hourMS < 0 || hourMS%3_600_000 != 0 || revision < 1 {
		return RollupRecord{}, errors.New("invalid hour rollup request")
	}
	rows, err := s.ReadRollups(ctx, RollupFilter{DeploymentID: deploymentID, HostID: hostID, SourceID: sourceID, Resolution: RollupMinute, StartMS: hourMS, EndMS: hourMS + 3_600_000, Limit: 61})
	if err != nil {
		return RollupRecord{}, err
	}
	minutes := make([]RollupPayload, 0, len(rows))
	for _, row := range rows {
		minutes = append(minutes, row.Payload)
	}
	payload, err := MergeHourRollups(hourMS, minutes)
	if err != nil {
		return RollupRecord{}, err
	}
	record := RollupRecord{DeploymentID: deploymentID, HostID: hostID, SourceID: sourceID, IntervalMS: hourMS, Revision: revision, Payload: payload}
	if err := s.PutRollup(ctx, record); err != nil {
		return RollupRecord{}, err
	}
	return record, nil
}

func (s *Store) rollupSourceTarget(ctx context.Context, deploymentID, hostID, sourceID string) (*string, error) {
	var targetID sql.NullString
	if err := s.db.QueryRowContext(ctx, `SELECT target_id FROM sources WHERE deployment_id=? AND host_id=? AND id=?`, deploymentID, hostID, sourceID).Scan(&targetID); err != nil {
		return nil, err
	}
	return nullableStringPointer(targetID), nil
}

func observationsFromFrame(frame protocol.CollectorFrame, row QueryFrame, hostID string, targetID *string, intervalStart, intervalEnd int64) []RollupObservation {
	observed := row.ObservationMS()
	aligned := row.AlignedMS != nil
	replayed := row.DeliveryMode != "current"
	result := make([]RollupObservation, 0, len(frame.Gauges)+len(frame.ModelObservations)*3+len(frame.ProcessObservations)*2+len(frame.NetworkObservations)*2)
	appendValue := func(metric, scope, epoch string, value json.RawMessage, missing *domain.MissingReason, quality domain.Quality, method string) {
		spec, ok := rollupMetricSpecs[metric]
		if !ok || scope == "" {
			return
		}
		validUntil := min(intervalEnd, observed+spec.freshness.Milliseconds())
		if validUntil <= intervalStart {
			return
		}
		result = append(result, RollupObservation{SeriesHash: RollupSeriesHash(metric, scope), EpochID: epoch, Kind: spec.kind, ValueType: spec.valueType, ObservedMS: observed, ValidUntilMS: validUntil, Value: cloneJSON(value), MissingReason: missing, Quality: quality, MethodRevision: method, Aligned: aligned, Replayed: replayed})
	}
	for metric, value := range frame.Gauges {
		scope := hostID
		if metric == "runtime.reachable" && targetID != nil {
			scope = *targetID
		}
		appendValue(metric, scope, "", value.Value, value.MissingReason, value.Quality, value.Provenance.MethodRevision)
	}
	for _, missing := range frame.CapabilitiesMissing {
		scope := hostID
		if missing.ID == "runtime.reachable" && targetID != nil {
			scope = *targetID
		}
		appendValue(missing.ID, scope, "", json.RawMessage("null"), &missing.Reason, domain.QualityUnavailable, frame.Provenance.MethodRevision)
	}
	for _, network := range frame.NetworkObservations {
		appendOptionalDecimal := func(metric string, value *domain.Uint64Decimal) {
			if value != nil {
				appendValue(metric, network.InterfaceID, network.CounterEpochID, mustJSON(*value), nil, domain.QualityMeasured, network.Provenance.MethodRevision)
				return
			}
			if reason := missingReasonFor(network.Missing, metric); reason != nil {
				appendValue(metric, network.InterfaceID, network.CounterEpochID, json.RawMessage("null"), reason, domain.QualityUnavailable, network.Provenance.MethodRevision)
			}
		}
		appendOptionalDecimal("host.network.received_bytes_total", network.ReceivedBytesTotal)
		appendOptionalDecimal("host.network.sent_bytes_total", network.SentBytesTotal)
	}
	for _, process := range frame.ProcessObservations {
		if process.CPUBusyRatio != nil {
			appendValue("process.cpu.busy_ratio", process.ProcessKey, "", mustJSON(*process.CPUBusyRatio), nil, domain.QualityMeasured, process.Provenance.MethodRevision)
		} else if reason := missingReasonFor(process.Missing, "process.cpu.busy_ratio"); reason != nil {
			appendValue("process.cpu.busy_ratio", process.ProcessKey, "", json.RawMessage("null"), reason, domain.QualityUnavailable, process.Provenance.MethodRevision)
		}
		if process.PhysicalFootprintBytes != nil {
			appendValue("process.physical_footprint_bytes", process.ProcessKey, "", mustJSON(*process.PhysicalFootprintBytes), nil, domain.QualityMeasured, process.Provenance.MethodRevision)
		} else if reason := missingReasonFor(process.Missing, "process.physical_footprint_bytes"); reason != nil {
			appendValue("process.physical_footprint_bytes", process.ProcessKey, "", json.RawMessage("null"), reason, domain.QualityUnavailable, process.Provenance.MethodRevision)
		}
	}
	for _, model := range frame.ModelObservations {
		appendValue("runtime.model.loaded", model.ModelID, "", mustJSON(model.Loaded), nil, domain.QualityRuntimeReported, model.Provenance.MethodRevision)
		for _, item := range []struct {
			metric string
			value  *domain.Uint64Decimal
		}{{"runtime.model.reported_size_bytes", model.ReportedSizeBytes}, {"runtime.model.reported_size_vram_bytes", model.ReportedSizeVRAMBytes}} {
			if item.value != nil {
				appendValue(item.metric, model.ModelID, "", mustJSON(*item.value), nil, domain.QualityRuntimeReported, model.Provenance.MethodRevision)
			} else if reason := missingReasonFor(model.Missing, item.metric); reason != nil {
				appendValue(item.metric, model.ModelID, "", json.RawMessage("null"), reason, domain.QualityUnavailable, model.Provenance.MethodRevision)
			}
		}
	}
	return result
}

func missingReasonFor(values []domain.MissingCapability, metric string) *domain.MissingReason {
	for _, missing := range values {
		if missing.ID == metric {
			reason := missing.Reason
			return &reason
		}
	}
	return nil
}

func mustJSON(value any) json.RawMessage {
	encoded, _ := json.Marshal(value)
	return encoded
}
