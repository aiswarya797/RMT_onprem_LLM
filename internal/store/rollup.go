package store

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"math/big"
	"sort"
	"strconv"
	"time"

	"github.com/fxamacker/cbor/v2"
	"github.com/klauspost/compress/zstd"

	"rmt.local/monitor/internal/domain"
)

const (
	RollupMinute          = "minute"
	RollupHour            = "hour"
	MaxRollupRows         = 2001
	maxRollupPayloadBytes = 256 << 10
	maxRollupSeries       = 1024
	maxRollupEpochs       = 8
)

var ErrRollupIncomplete = errors.New("rollup inputs are incomplete or incompatible")

type RollupObservation struct {
	SeriesHash     string
	EpochID        string
	Kind           string
	ValueType      string
	ObservedMS     int64
	ValidUntilMS   int64
	Value          json.RawMessage
	MissingReason  *domain.MissingReason
	Quality        domain.Quality
	MethodRevision string
	Aligned        bool
	Replayed       bool
}

// RollupPayload is the compact internal storage value. Series identity is a
// deterministic hash of metric and scope; those strings are not repeated in
// every interval. Epoch segments are never merged across method, identity, or
// counter-reset boundaries.
type RollupPayload struct {
	SchemaVersion      string                     `cbor:"schema_version"`
	DefinitionRevision string                     `cbor:"definition_revision"`
	Resolution         string                     `cbor:"resolution"`
	StartMS            int64                      `cbor:"start_ms"`
	EndMS              int64                      `cbor:"end_ms"`
	Complete           bool                       `cbor:"complete"`
	IncludesReplay     bool                       `cbor:"includes_replay"`
	Series             map[string][]RollupSegment `cbor:"series"`
}

type RollupSegment struct {
	EpochID           string                         `cbor:"epoch_id,omitempty"`
	Kind              string                         `cbor:"kind"`
	ValueType         string                         `cbor:"value_type"`
	MethodRevision    string                         `cbor:"method_revision"`
	Quality           domain.Quality                 `cbor:"quality"`
	Aligned           bool                           `cbor:"aligned"`
	ObservedStartMS   int64                          `cbor:"observed_start_ms"`
	ObservedEndMS     int64                          `cbor:"observed_end_ms"`
	ValidDurationMS   int64                          `cbor:"valid_duration_ms"`
	SampleCount       int                            `cbor:"sample_count"`
	TransitionCount   int                            `cbor:"transition_count"`
	Min               json.RawMessage                `cbor:"min,omitempty"`
	Max               json.RawMessage                `cbor:"max,omitempty"`
	Last              json.RawMessage                `cbor:"last,omitempty"`
	WeightedSum       float64                        `cbor:"weighted_sum,omitempty"`
	WeightMS          int64                          `cbor:"weight_ms,omitempty"`
	StateDurationMS   map[string]int64               `cbor:"state_duration_ms,omitempty"`
	MissingDurationMS map[domain.MissingReason]int64 `cbor:"missing_duration_ms,omitempty"`
	CounterDelta      *domain.Uint64Decimal          `cbor:"counter_delta,omitempty"`
}

type RollupRecord struct {
	DeploymentID, HostID, SourceID string
	IntervalMS                     int64
	Revision                       int64
	Payload                        RollupPayload
}

type RollupFilter struct {
	DeploymentID, HostID, SourceID string
	Resolution                     string
	StartMS, EndMS                 int64
	Limit                          int
}

type QueryRollup struct {
	HostID, SourceID string
	IntervalMS       int64
	Revision         int64
	Complete         bool
	Payload          RollupPayload
}

func RollupSeriesHash(metricID, scopeID string) string {
	sum := sha256.Sum256([]byte(metricID + "\x00" + scopeID))
	return hex.EncodeToString(sum[:])
}

func BuildRollupPayload(resolution string, startMS int64, observations []RollupObservation) (RollupPayload, error) {
	duration, err := rollupDuration(resolution)
	if err != nil || startMS < 0 || startMS%duration != 0 {
		return RollupPayload{}, errors.New("invalid aligned rollup interval")
	}
	payload := RollupPayload{SchemaVersion: domain.SchemaVersion, DefinitionRevision: domain.RegistryRevision, Resolution: resolution, StartMS: startMS, EndMS: startMS + duration, Complete: true, Series: make(map[string][]RollupSegment)}
	grouped := make(map[string][]RollupObservation)
	for _, observation := range observations {
		if err := validateRollupObservation(observation, payload.StartMS, payload.EndMS); err != nil {
			return RollupPayload{}, err
		}
		grouped[observation.SeriesHash] = append(grouped[observation.SeriesHash], observation)
		payload.IncludesReplay = payload.IncludesReplay || observation.Replayed
	}
	if len(grouped) > maxRollupSeries {
		return RollupPayload{}, errors.New("rollup series limit exceeded")
	}
	for seriesHash, samples := range grouped {
		sort.SliceStable(samples, func(i, j int) bool { return samples[i].ObservedMS < samples[j].ObservedMS })
		segments, complete, err := aggregateRollupSeries(payload.StartMS, payload.EndMS, samples)
		if err != nil {
			return RollupPayload{}, err
		}
		if !complete {
			payload.Complete = false
		}
		payload.Series[seriesHash] = segments
	}
	return payload, nil
}

func aggregateRollupSeries(startMS, endMS int64, samples []RollupObservation) ([]RollupSegment, bool, error) {
	segments := make([]RollupSegment, 0, min(len(samples), maxRollupEpochs))
	complete := true
	for index, sample := range samples {
		segmentIndex := -1
		if len(segments) > 0 && sameRollupEpoch(segments[len(segments)-1], sample) {
			segmentIndex = len(segments) - 1
		} else if len(segments) < maxRollupEpochs {
			segments = append(segments, newRollupSegment(sample))
			segmentIndex = len(segments) - 1
		} else {
			complete = false
			continue
		}
		segment := &segments[segmentIndex]
		segment.ObservedStartMS = max(startMS, segment.ObservedStartMS)
		segment.SampleCount++
		segment.ObservedEndMS = max(startMS, sample.ObservedMS)
		if index > 0 && !sameObservationEpoch(samples[index-1], sample) {
			segment.TransitionCount++
		}

		validEnd := min(endMS, sample.ValidUntilMS)
		if index+1 < len(samples) {
			validEnd = min(validEnd, samples[index+1].ObservedMS)
		}
		validStart := max(startMS, sample.ObservedMS)
		duration := max(int64(0), validEnd-validStart)
		if sample.MissingReason != nil || bytes.Equal(sample.Value, []byte("null")) {
			if sample.MissingReason == nil {
				return nil, false, errors.New("null rollup observation needs a missing reason")
			}
			if segment.MissingDurationMS == nil {
				segment.MissingDurationMS = make(map[domain.MissingReason]int64)
			}
			segment.MissingDurationMS[*sample.MissingReason] += duration
			continue
		}
		segment.ValidDurationMS += duration
		segment.Last = cloneJSON(sample.Value)
		switch sample.Kind {
		case "gauge":
			if sample.ValueType == "enum" || sample.ValueType == "boolean" {
				if segment.StateDurationMS == nil {
					segment.StateDurationMS = make(map[string]int64)
				}
				state, err := rollupState(sample.Value, sample.ValueType)
				if err != nil {
					return nil, false, err
				}
				segment.StateDurationMS[state] += duration
				continue
			}
			number, err := rollupNumber(sample.Value)
			if err != nil {
				return nil, false, err
			}
			updateRollupBounds(segment, sample.Value, number)
			segment.WeightedSum += number * float64(duration)
			segment.WeightMS += duration
		case "cumulative_counter":
			if index == 0 || !sameObservationEpoch(samples[index-1], sample) || samples[index-1].MissingReason != nil {
				continue
			}
			delta, ok, err := counterDifference(samples[index-1].Value, sample.Value)
			if err != nil {
				return nil, false, err
			}
			if !ok {
				complete = false
				continue
			}
			current := new(big.Int)
			if segment.CounterDelta != nil {
				current.SetString(string(*segment.CounterDelta), 10)
			}
			current.Add(current, delta)
			encoded := domain.Uint64Decimal(current.String())
			segment.CounterDelta = &encoded
		default:
			return nil, false, fmt.Errorf("unsupported rollup kind %q", sample.Kind)
		}
	}
	return segments, complete, nil
}

// MergeHourRollups accepts exactly the 60 complete minute records in one hour.
// It never rebuilds an hour from raw frames, and it refuses incompatible or
// partial minutes rather than replacing a previously valid hour.
func MergeHourRollups(hourStartMS int64, minutes []RollupPayload) (RollupPayload, error) {
	if hourStartMS < 0 || hourStartMS%int64(time.Hour/time.Millisecond) != 0 || len(minutes) != 60 {
		return RollupPayload{}, fmt.Errorf("%w: hour requires 60 aligned minutes", ErrRollupIncomplete)
	}
	sort.SliceStable(minutes, func(i, j int) bool { return minutes[i].StartMS < minutes[j].StartMS })
	result := RollupPayload{SchemaVersion: domain.SchemaVersion, DefinitionRevision: domain.RegistryRevision, Resolution: RollupHour, StartMS: hourStartMS, EndMS: hourStartMS + int64(time.Hour/time.Millisecond), Complete: true, Series: make(map[string][]RollupSegment)}
	for index, minute := range minutes {
		if err := validateRollupPayload(minute); err != nil || minute.Resolution != RollupMinute || !minute.Complete || minute.StartMS != hourStartMS+int64(index)*int64(time.Minute/time.Millisecond) {
			return RollupPayload{}, fmt.Errorf("%w: minute missing or incomplete", ErrRollupIncomplete)
		}
		result.IncludesReplay = result.IncludesReplay || minute.IncludesReplay
		for hash, minuteSegments := range minute.Series {
			for _, incoming := range minuteSegments {
				segments := result.Series[hash]
				if len(segments) > 0 && compatibleRollupSegments(segments[len(segments)-1], incoming) {
					if err := mergeRollupSegment(&segments[len(segments)-1], incoming); err != nil {
						return RollupPayload{}, err
					}
					result.Series[hash] = segments
					continue
				}
				if len(segments) == maxRollupEpochs {
					result.Complete = false
					continue
				}
				segments = append(segments, incoming)
				if len(segments) > 1 {
					segments[len(segments)-1].TransitionCount++
				}
				result.Series[hash] = segments
			}
		}
	}
	return result, nil
}

func compatibleRollupSegments(left, right RollupSegment) bool {
	return left.EpochID == right.EpochID && left.Kind == right.Kind && left.ValueType == right.ValueType && left.MethodRevision == right.MethodRevision && left.Quality == right.Quality && left.Aligned == right.Aligned
}

func mergeRollupSegment(target *RollupSegment, incoming RollupSegment) error {
	target.ObservedStartMS = min(target.ObservedStartMS, incoming.ObservedStartMS)
	if incoming.ObservedEndMS >= target.ObservedEndMS {
		target.ObservedEndMS = incoming.ObservedEndMS
		if incoming.Last != nil {
			target.Last = cloneJSON(incoming.Last)
		}
	}
	target.ValidDurationMS += incoming.ValidDurationMS
	target.SampleCount += incoming.SampleCount
	target.TransitionCount += incoming.TransitionCount
	target.WeightedSum += incoming.WeightedSum
	target.WeightMS += incoming.WeightMS
	if incoming.Min != nil {
		value, err := rollupNumber(incoming.Min)
		if err != nil {
			return err
		}
		updateRollupBounds(target, incoming.Min, value)
		value, err = rollupNumber(incoming.Max)
		if err != nil {
			return err
		}
		updateRollupBounds(target, incoming.Max, value)
	}
	for state, duration := range incoming.StateDurationMS {
		if target.StateDurationMS == nil {
			target.StateDurationMS = make(map[string]int64)
		}
		target.StateDurationMS[state] += duration
	}
	for reason, duration := range incoming.MissingDurationMS {
		if target.MissingDurationMS == nil {
			target.MissingDurationMS = make(map[domain.MissingReason]int64)
		}
		target.MissingDurationMS[reason] += duration
	}
	if incoming.CounterDelta != nil {
		left := new(big.Int)
		if target.CounterDelta != nil {
			if _, ok := left.SetString(string(*target.CounterDelta), 10); !ok {
				return errors.New("invalid stored counter delta")
			}
		}
		right := new(big.Int)
		if _, ok := right.SetString(string(*incoming.CounterDelta), 10); !ok {
			return errors.New("invalid incoming counter delta")
		}
		left.Add(left, right)
		encoded := domain.Uint64Decimal(left.String())
		target.CounterDelta = &encoded
	}
	return nil
}

func rollupState(raw json.RawMessage, valueType string) (string, error) {
	if valueType == "boolean" {
		var value bool
		if err := json.Unmarshal(raw, &value); err != nil {
			return "", errors.New("invalid boolean rollup value")
		}
		return strconv.FormatBool(value), nil
	}
	var value string
	if err := json.Unmarshal(raw, &value); err != nil || value == "" {
		return "", errors.New("invalid enum rollup value")
	}
	return value, nil
}

func newRollupSegment(sample RollupObservation) RollupSegment {
	return RollupSegment{EpochID: sample.EpochID, Kind: sample.Kind, ValueType: sample.ValueType, MethodRevision: sample.MethodRevision, Quality: sample.Quality, Aligned: sample.Aligned, ObservedStartMS: sample.ObservedMS, ObservedEndMS: sample.ObservedMS}
}

func sameRollupEpoch(segment RollupSegment, sample RollupObservation) bool {
	return segment.EpochID == sample.EpochID && segment.Kind == sample.Kind && segment.ValueType == sample.ValueType && segment.MethodRevision == sample.MethodRevision && segment.Quality == sample.Quality && segment.Aligned == sample.Aligned
}

func sameObservationEpoch(left, right RollupObservation) bool {
	return left.SeriesHash == right.SeriesHash && left.EpochID == right.EpochID && left.Kind == right.Kind && left.ValueType == right.ValueType && left.MethodRevision == right.MethodRevision && left.Quality == right.Quality && left.Aligned == right.Aligned
}

func updateRollupBounds(segment *RollupSegment, raw json.RawMessage, number float64) {
	if segment.Min == nil {
		segment.Min, segment.Max = cloneJSON(raw), cloneJSON(raw)
		return
	}
	minimum, _ := rollupNumber(segment.Min)
	maximum, _ := rollupNumber(segment.Max)
	if number < minimum {
		segment.Min = cloneJSON(raw)
	}
	if number > maximum {
		segment.Max = cloneJSON(raw)
	}
}

func rollupNumber(raw json.RawMessage) (float64, error) {
	var number float64
	if len(raw) > 0 && raw[0] == '"' {
		var decimal string
		if err := json.Unmarshal(raw, &decimal); err != nil {
			return 0, errors.New("invalid decimal rollup value")
		}
		value, err := strconv.ParseUint(decimal, 10, 64)
		if err != nil {
			return 0, errors.New("invalid uint64 rollup value")
		}
		number = float64(value)
	} else if err := json.Unmarshal(raw, &number); err != nil {
		return 0, errors.New("invalid numeric rollup value")
	}
	if math.IsNaN(number) || math.IsInf(number, 0) {
		return 0, errors.New("non-finite rollup value")
	}
	return number, nil
}

func counterDifference(previous, current json.RawMessage) (*big.Int, bool, error) {
	parse := func(raw json.RawMessage) (*big.Int, error) {
		var decimal string
		if err := json.Unmarshal(raw, &decimal); err != nil {
			return nil, errors.New("counter must use decimal-string encoding")
		}
		value := new(big.Int)
		if _, ok := value.SetString(decimal, 10); !ok || value.Sign() < 0 || value.BitLen() > 64 {
			return nil, errors.New("invalid uint64 counter")
		}
		return value, nil
	}
	left, err := parse(previous)
	if err != nil {
		return nil, false, err
	}
	right, err := parse(current)
	if err != nil {
		return nil, false, err
	}
	if right.Cmp(left) < 0 {
		return nil, false, nil
	}
	return new(big.Int).Sub(right, left), true, nil
}

func validateRollupObservation(value RollupObservation, startMS, endMS int64) error {
	if !validSHA256(value.SeriesHash) || value.ObservedMS >= endMS || value.ValidUntilMS <= startMS || value.ValidUntilMS < value.ObservedMS || value.ValidUntilMS > endMS || value.MethodRevision == "" {
		return errors.New("invalid rollup observation boundary")
	}
	if value.Kind != "gauge" && value.Kind != "cumulative_counter" {
		return errors.New("invalid rollup observation kind")
	}
	if value.ValueType != "number" && value.ValueType != "uint64" && value.ValueType != "boolean" && value.ValueType != "enum" {
		return errors.New("invalid rollup value type")
	}
	if len(value.Value) == 0 || !json.Valid(value.Value) {
		return errors.New("invalid rollup JSON value")
	}
	return nil
}

func (s *Store) PutRollup(ctx context.Context, record RollupRecord) error {
	if record.DeploymentID == "" || record.HostID == "" || record.SourceID == "" || record.Revision < 1 || record.IntervalMS != record.Payload.StartMS {
		return errors.New("invalid rollup identity")
	}
	if err := validateRollupPayload(record.Payload); err != nil {
		return err
	}
	encoded, digest, err := encodeRollupPayload(record.Payload)
	if err != nil {
		return err
	}
	release, err := s.acquireWrite(ctx)
	if err != nil {
		return err
	}
	defer release()
	table, err := rollupTable(record.Payload.Resolution)
	if err != nil {
		return err
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	currentQuery := fmt.Sprintf(`SELECT revision FROM %s WHERE deployment_id=? AND host_id=? AND source_id=? AND %s=?`, table.name, table.timeColumn)
	var currentRevision int64
	if err := tx.QueryRowContext(ctx, currentQuery, record.DeploymentID, record.HostID, record.SourceID, record.IntervalMS).Scan(&currentRevision); err == nil && currentRevision >= record.Revision {
		return tx.Commit()
	} else if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return err
	}
	for hash, segments := range record.Payload.Series {
		for _, segment := range segments {
			if segment.Kind != "cumulative_counter" || segment.EpochID == "" {
				continue
			}
			if _, err := tx.ExecContext(ctx, `INSERT INTO counter_epochs(deployment_id,host_id,source_id,series_hash,epoch_id,definition_revision,layout_hash,first_ms,last_ms,reason) VALUES(?,?,?,?,?,?,NULL,?,?,?) ON CONFLICT(deployment_id,host_id,source_id,series_hash,epoch_id) DO UPDATE SET first_ms=min(first_ms,excluded.first_ms),last_ms=max(last_ms,excluded.last_ms)`, record.DeploymentID, record.HostID, record.SourceID, hash, segment.EpochID, domain.RegistryRevision, segment.ObservedStartMS, segment.ObservedEndMS, "first_observation"); err != nil {
				return fmt.Errorf("persist counter epoch: %w", err)
			}
		}
	}
	query := fmt.Sprintf(`INSERT INTO %s(deployment_id,host_id,source_id,%s,revision,definition_revision,codec,payload,payload_sha256,complete) VALUES(?,?,?,?,?,?,?,?,?,?) ON CONFLICT(deployment_id,host_id,source_id,%s) DO UPDATE SET revision=excluded.revision,definition_revision=excluded.definition_revision,codec=excluded.codec,payload=excluded.payload,payload_sha256=excluded.payload_sha256,complete=excluded.complete WHERE excluded.revision>%s.revision`, table.name, table.timeColumn, table.timeColumn, table.name)
	if _, err = tx.ExecContext(ctx, query, record.DeploymentID, record.HostID, record.SourceID, record.IntervalMS, record.Revision, domain.RegistryRevision, FrameCodec, encoded, digest, boolToInt(record.Payload.Complete)); err != nil {
		return err
	}
	if record.Payload.Resolution == RollupMinute {
		// An hour is derived from the exact current minute revisions. Remove a
		// prior hour in this same transaction so bounded maintenance can
		// durably rediscover and rebuild it after a late minute changes.
		hourMS := record.IntervalMS / int64(time.Hour/time.Millisecond) * int64(time.Hour/time.Millisecond)
		if _, err := tx.ExecContext(ctx, `DELETE FROM rollup_hours WHERE deployment_id=? AND host_id=? AND source_id=? AND hour_ms=?`, record.DeploymentID, record.HostID, record.SourceID, hourMS); err != nil {
			return err
		}
	}
	return tx.Commit()
}

func (s *Store) ReadRollups(ctx context.Context, filter RollupFilter) ([]QueryRollup, error) {
	if filter.DeploymentID == "" || filter.SourceID == "" || filter.StartMS < 0 || filter.EndMS <= filter.StartMS || filter.Limit < 1 || filter.Limit > MaxRollupRows {
		return nil, errors.New("invalid bounded rollup query")
	}
	table, err := rollupTable(filter.Resolution)
	if err != nil {
		return nil, err
	}
	query := fmt.Sprintf(`SELECT host_id,source_id,%s,revision,definition_revision,codec,payload,payload_sha256,complete FROM %s WHERE deployment_id=? AND source_id=? AND %s>=? AND %s<?`, table.timeColumn, table.name, table.timeColumn, table.timeColumn)
	args := []any{filter.DeploymentID, filter.SourceID, filter.StartMS, filter.EndMS}
	if filter.HostID != "" {
		query += ` AND host_id=?`
		args = append(args, filter.HostID)
	}
	query += ` ORDER BY ` + table.timeColumn + ` LIMIT ?`
	args = append(args, filter.Limit)
	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	result := make([]QueryRollup, 0)
	totalBytes := 0
	for rows.Next() {
		var value QueryRollup
		var definitionRevision, codec, expectedHash string
		var encoded []byte
		var complete int
		if err := rows.Scan(&value.HostID, &value.SourceID, &value.IntervalMS, &value.Revision, &definitionRevision, &codec, &encoded, &expectedHash, &complete); err != nil {
			return nil, err
		}
		if definitionRevision != domain.RegistryRevision || codec != FrameCodec {
			return nil, errors.New("unsupported rollup definition or codec")
		}
		digest := sha256.Sum256(encoded)
		if hex.EncodeToString(digest[:]) != expectedHash {
			return nil, errors.New("rollup payload hash mismatch")
		}
		totalBytes += len(encoded)
		if totalBytes > maxQueryPayloadBytes {
			return nil, ErrQueryLimit
		}
		value.Complete = complete == 1
		value.Payload, err = decodeRollupPayload(encoded)
		if err != nil {
			return nil, err
		}
		if value.Payload.Resolution != filter.Resolution || value.Payload.StartMS != value.IntervalMS || value.Payload.Complete != value.Complete {
			return nil, errors.New("rollup row identity mismatch")
		}
		result = append(result, value)
	}
	return result, rows.Err()
}

type rollupTableName struct{ name, timeColumn string }

func rollupTable(resolution string) (rollupTableName, error) {
	switch resolution {
	case RollupMinute:
		return rollupTableName{"rollup_minutes", "minute_ms"}, nil
	case RollupHour:
		return rollupTableName{"rollup_hours", "hour_ms"}, nil
	default:
		return rollupTableName{}, errors.New("invalid rollup resolution")
	}
}

func rollupDuration(resolution string) (int64, error) {
	switch resolution {
	case RollupMinute:
		return int64(time.Minute / time.Millisecond), nil
	case RollupHour:
		return int64(time.Hour / time.Millisecond), nil
	default:
		return 0, errors.New("invalid rollup resolution")
	}
}

func validateRollupPayload(payload RollupPayload) error {
	duration, err := rollupDuration(payload.Resolution)
	if err != nil || payload.SchemaVersion != domain.SchemaVersion || payload.DefinitionRevision != domain.RegistryRevision || payload.StartMS < 0 || payload.StartMS%duration != 0 || payload.EndMS != payload.StartMS+duration || len(payload.Series) > maxRollupSeries {
		return errors.New("invalid rollup payload")
	}
	for hash, segments := range payload.Series {
		if !validSHA256(hash) || len(segments) > maxRollupEpochs {
			return errors.New("invalid rollup series")
		}
		for _, segment := range segments {
			if segment.SampleCount < 1 || segment.ObservedStartMS < payload.StartMS || segment.ObservedEndMS < segment.ObservedStartMS || segment.ObservedEndMS >= payload.EndMS || segment.ValidDurationMS < 0 || segment.ValidDurationMS > duration || segment.MethodRevision == "" {
				return errors.New("invalid rollup segment")
			}
		}
	}
	return nil
}

func encodeRollupPayload(payload RollupPayload) ([]byte, string, error) {
	if err := validateRollupPayload(payload); err != nil {
		return nil, "", err
	}
	mode, err := cbor.CanonicalEncOptions().EncMode()
	if err != nil {
		return nil, "", err
	}
	plain, err := mode.Marshal(payload)
	if err != nil {
		return nil, "", err
	}
	encoder, err := zstd.NewWriter(nil, zstd.WithEncoderConcurrency(1), zstd.WithEncoderLevel(zstd.SpeedFastest), zstd.WithWindowSize(1<<20))
	if err != nil {
		return nil, "", err
	}
	encoded := encoder.EncodeAll(plain, make([]byte, 0, len(plain)))
	encoder.Close()
	if len(encoded) > maxRollupPayloadBytes {
		return nil, "", errors.New("rollup payload exceeds storage limit")
	}
	sum := sha256.Sum256(encoded)
	return encoded, hex.EncodeToString(sum[:]), nil
}

func decodeRollupPayload(encoded []byte) (RollupPayload, error) {
	var payload RollupPayload
	if len(encoded) > maxRollupPayloadBytes {
		return payload, errors.New("rollup payload exceeds storage limit")
	}
	decoder, err := zstd.NewReader(bytes.NewReader(encoded), zstd.WithDecoderConcurrency(1), zstd.WithDecoderMaxMemory(2<<20))
	if err != nil {
		return payload, err
	}
	defer decoder.Close()
	plain, err := io.ReadAll(io.LimitReader(decoder, maxRollupPayloadBytes+1))
	if err != nil || len(plain) > maxRollupPayloadBytes {
		return payload, errors.New("invalid bounded rollup payload")
	}
	mode, err := cbor.DecOptions{MaxNestedLevels: 16, MaxArrayElements: maxRollupSeries * maxRollupEpochs, MaxMapPairs: maxRollupSeries * 4, DupMapKey: cbor.DupMapKeyEnforcedAPF, IndefLength: cbor.IndefLengthForbidden}.DecMode()
	if err != nil {
		return payload, err
	}
	if err := mode.Unmarshal(plain, &payload); err != nil {
		return payload, err
	}
	return payload, validateRollupPayload(payload)
}

func validSHA256(value string) bool {
	if len(value) != 64 {
		return false
	}
	_, err := hex.DecodeString(value)
	return err == nil
}

func cloneJSON(value json.RawMessage) json.RawMessage {
	return append(json.RawMessage(nil), value...)
}

func boolToInt(value bool) int {
	if value {
		return 1
	}
	return 0
}
