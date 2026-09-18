package query

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"sort"
	"time"

	"rmt.local/monitor/internal/alertruntime"
	"rmt.local/monitor/internal/alerts"
	"rmt.local/monitor/internal/domain"
	"rmt.local/monitor/internal/protocol"
	"rmt.local/monitor/internal/store"
)

const alertEvidenceSampleLimit = 16

// EvaluateCurrent builds one bounded current-state input for every enabled
// rule and commits it through the Store's fenced durable evaluator boundary.
// Historical and restored replay frames remain queryable but are never used.
func (s *Service) EvaluateCurrent(ctx context.Context, cycle alertruntime.Cycle) error {
	deployment, err := s.store.DeploymentState(ctx)
	if err != nil {
		return err
	}
	plan, err := s.store.ReadAlertRuntimePlan(ctx, deployment.DeploymentID, deployment.DeploymentGeneration)
	if err != nil {
		return err
	}
	if len(plan.Rules) == 0 {
		return nil
	}
	nowMS := cycle.EventTime.UnixMilli()
	snapshot, err := s.live(ctx, nowMS)
	if err != nil {
		return err
	}
	if snapshot.inventory.Deployment.DeploymentID != plan.DeploymentID || snapshot.inventory.Deployment.DeploymentGeneration != plan.DeploymentGeneration {
		return store.ErrAlertCursorConflict
	}
	writes, err := buildAlertWrites(plan, snapshot, cycle)
	if err != nil {
		return err
	}
	for _, write := range writes {
		if _, err := s.store.ApplyAlertEvaluation(ctx, write); err != nil {
			return err
		}
	}
	return nil
}

func buildAlertWrites(plan store.AlertRuntimePlan, snapshot liveSnapshot, cycle alertruntime.Cycle) ([]store.AlertEvaluationWrite, error) {
	if cycle.EventTime.IsZero() || cycle.Elapsed < 0 || cycle.Lag < 0 {
		return nil, store.ErrAlertInvalid
	}
	nowMS := cycle.EventTime.UnixMilli()
	result := make([]store.AlertEvaluationWrite, 0, len(plan.Rules))
	episodeTargets := make(map[string]bool)
	for _, planned := range plan.Rules {
		write, err := buildAlertWrite(plan, snapshot, planned, cycle, nowMS)
		if err != nil {
			return nil, fmt.Errorf("build current alert input for rule %s: %w", planned.Rule.ID, err)
		}
		if write.Episode != nil {
			if episodeTargets[write.Episode.Target.TargetID] {
				write.Episode = nil
			} else {
				episodeTargets[write.Episode.Target.TargetID] = true
			}
		}
		result = append(result, write)
	}
	return result, nil
}

func buildAlertWrite(plan store.AlertRuntimePlan, snapshot liveSnapshot, planned store.AlertRuntimeRulePlan, cycle alertruntime.Cycle, nowMS int64) (store.AlertEvaluationWrite, error) {
	write := store.AlertEvaluationWrite{
		DeploymentID: plan.DeploymentID, DeploymentGeneration: plan.DeploymentGeneration,
		RuleID: planned.Rule.ID, RuleVersion: planned.Rule.Revision, EventMS: nowMS,
		ElapsedMS: cycle.Elapsed.Milliseconds(), HubRestarted: cycle.Restarted, CurrentLive: true,
	}
	ordinal := int64(1)
	if planned.Cursor != nil {
		if planned.Cursor.InputOrdinal >= protocol.MaxUint53 {
			return write, store.ErrAlertCursorConflict
		}
		ordinal = planned.Cursor.InputOrdinal + 1
	}
	write.Cursor.InputOrdinal, write.Cursor.ObservedThroughMS = ordinal, nowMS

	host, target, err := alertRuleFences(plan, planned.Rule)
	if err != nil {
		return write, err
	}
	write.Fence.Host, write.Fence.Target = host, target

	switch planned.Rule.Definition.EvaluatorType {
	case alerts.RuleHostNotReporting:
		write.Input, write.Evidence = heartbeatAlertInput(host, nowMS)
	case alerts.RuleSourceMissing:
		write.Input, write.Evidence = sourceAlertInput(snapshot, host, target, nowMS)
	case alerts.RuleHeavyCPU:
		write.Input, write.Evidence = hostMetricAlertInput(snapshot, host, "host.cpu.busy_ratio", nowMS)
	case alerts.RuleMemoryPressure:
		write.Input, write.Evidence = hostMetricAlertInput(snapshot, host, "host.memory.pressure_level", nowMS)
	case alerts.RuleOllamaUnreachable:
		var episode *store.AlertReachabilityEpisode
		for index := range plan.Episodes {
			if plan.Episodes[index].TargetID == target.TargetID && plan.Episodes[index].HostID == target.HostID {
				episode = &plan.Episodes[index]
				break
			}
		}
		write.Input, write.Evidence = reachabilityAlertInput(snapshot, host, target, episode, nowMS)
		write.Episode = &store.AlertReachabilityEpisodeWrite{Target: *target, Expected: episode, ObservedMS: nowMS}
		if write.Input.Reachability != nil {
			write.Episode.Reachable = write.Input.Reachability.Reachable
		}
	case alerts.RuleDiskMonitorHealth:
		write.Input, write.Evidence = monitorAlertInput(plan.Monitor, cycle, nowMS)
	case alerts.RuleObservedRequestDuration:
		// U08 owns the exact frozen request-population query. Generic series and
		// passive runtime traffic cannot establish this rule's population.
		write.Input = alerts.Input{DataState: alerts.DataUnknown}
	default:
		return write, store.ErrAlertInvalid
	}

	write.ObservedDwellMS = alertObservedDwell(planned, write.Input, cycle)
	if write.Evidence != nil {
		finalizeAlertEvidence(write.Evidence, snapshot, planned.Rule, write.ObservedDwellMS, nowMS)
	}
	hash, err := hashAlertWrite(write)
	if err != nil {
		return write, err
	}
	write.Cursor.InputSHA256 = hash
	return write, nil
}

func alertRuleFences(plan store.AlertRuntimePlan, rule store.RuleRecord) (*store.AlertRuntimeHostFence, *store.AlertRuntimeTargetFence, error) {
	var host *store.AlertRuntimeHostFence
	var target *store.AlertRuntimeTargetFence
	needsTarget := false
	switch rule.Definition.EvaluatorType {
	case alerts.RuleHostNotReporting, alerts.RuleMemoryPressure, alerts.RuleHeavyCPU:
		for index := range plan.Hosts {
			if plan.Hosts[index].HostID == rule.Definition.ScopeID {
				host = &plan.Hosts[index]
				break
			}
		}
	case alerts.RuleOllamaUnreachable, alerts.RuleSourceMissing, alerts.RuleObservedRequestDuration:
		needsTarget = true
		for index := range plan.Targets {
			if plan.Targets[index].TargetID == rule.Definition.ScopeID {
				target = &plan.Targets[index]
				break
			}
		}
		if target != nil {
			for index := range plan.Hosts {
				if plan.Hosts[index].HostID == target.HostID {
					host = &plan.Hosts[index]
					break
				}
			}
		}
	case alerts.RuleDiskMonitorHealth:
		return nil, nil, nil
	}
	if host == nil || needsTarget && target == nil {
		return nil, nil, store.ErrAlertCursorConflict
	}
	return host, target, nil
}

func heartbeatAlertInput(host *store.AlertRuntimeHostFence, nowMS int64) (alerts.Input, *store.AlertCapsuleEvidence) {
	if host == nil {
		return alerts.Input{DataState: alerts.DataUnknown}, nil
	}
	if host.Status == nil {
		if host.CreatedMS < 0 || host.CreatedMS > nowMS || (host.CollectorBootID == nil) != (host.SessionGeneration == 0) {
			return alerts.Input{DataState: alerts.DataUnknown}, nil
		}
		age := nowMS - host.CreatedMS
		input := alerts.Input{DataState: alerts.DataValid, Heartbeat: &alerts.HeartbeatInput{AgeMS: age}}
		value := float64(age)
		evidence := baseAlertEvidence("collector.heartbeat_age_ms", "milliseconds", nowMS, domain.QualityDerived, "collector-source-status-v1")
		evidence.NumberValue = &value
		evidence.StatusAbsence = &store.AlertStatusAbsence{HostID: host.HostID, CollectorBootID: host.CollectorBootID, SessionGeneration: host.SessionGeneration, CheckedMS: nowMS}
		return input, evidence
	}
	if host.CollectorBootID == nil || host.Status.AdmittedMS > nowMS {
		return alerts.Input{DataState: alerts.DataUnknown}, nil
	}
	age := nowMS - host.Status.AdmittedMS
	input := alerts.Input{DataState: alerts.DataValid, Heartbeat: &alerts.HeartbeatInput{AgeMS: age}}
	value := float64(age)
	evidence := statusEvidence(host, "collector.heartbeat_age_ms", "milliseconds", nowMS, domain.QualityDerived)
	evidence.NumberValue = &value
	return input, evidence
}

func sourceAlertInput(snapshot liveSnapshot, host *store.AlertRuntimeHostFence, target *store.AlertRuntimeTargetFence, nowMS int64) (alerts.Input, *store.AlertCapsuleEvidence) {
	input := alerts.Input{DataState: alerts.DataUnknown, Source: &alerts.SourceInput{}}
	if host == nil || target == nil || host.Status == nil || host.CollectorBootID == nil || host.Status.AdmittedMS > nowMS {
		return input, nil
	}
	hostAge := nowMS - host.Status.AdmittedMS
	input.Source.HostFresh = hostAge <= int64(60*time.Second/time.Millisecond)
	if !input.Source.HostFresh {
		input.DataState = alerts.DataStale
		return input, nil
	}
	sourceID := alertRuntimeSourceID(snapshot.inventory.Sources, target.TargetID)
	var source *protocol.SourceState
	for index := range host.Status.Sources {
		if host.Status.Sources[index].SourceID == sourceID {
			source = &host.Status.Sources[index]
			break
		}
	}
	available := false
	input.Source.Available = &available
	input.DataState = alerts.DataValid
	if source != nil {
		switch sourceStateFromStatus(*source, nowMS, 45*time.Second) {
		case SourceFresh:
			available = true
		case SourceStale:
			input.DataState = alerts.DataStale
		case SourceIncompatible:
			input.DataState, input.Source.Incompatible = alerts.DataIncompatible, true
		case SourceUnavailable:
			// A fresh host explicitly reporting an unavailable expected source is
			// the source-missing predicate, not an observed zero.
		default:
			input.DataState = alerts.DataUnknown
		}
	}
	if input.DataState != alerts.DataValid && input.DataState != alerts.DataIncompatible {
		return input, nil
	}
	evidence := statusEvidence(host, "runtime.source.available", "boolean", nowMS, domain.QualityDeclared)
	evidence.BooleanValue = &available
	return input, evidence
}

func hostMetricAlertInput(snapshot liveSnapshot, host *store.AlertRuntimeHostFence, metric string, nowMS int64) (alerts.Input, *store.AlertCapsuleEvidence) {
	input := alerts.Input{DataState: alerts.DataUnknown}
	if host == nil {
		return input, nil
	}
	source := alertSource(snapshot.inventory.Sources, host.HostID, nil, "host")
	sourceState := alertStatusDataState(host, source, nowMS, 15*time.Second)
	sample, ok := latestAlertMetric(snapshot, source, metric, host.HostID, nowMS)
	if !ok {
		return input, nil
	}
	input.DataState = worseAlertDataState(sample.state, sourceState)
	if sample.state != alerts.DataValid {
		return input, nil
	}
	evidence := metricEvidence(metric, sample, nowMS)
	switch metric {
	case "host.cpu.busy_ratio":
		var value float64
		if json.Unmarshal(sample.value.Value, &value) != nil || math.IsNaN(value) || math.IsInf(value, 0) || value < 0 || value > 1 {
			return alerts.Input{DataState: alerts.DataUnknown}, nil
		}
		input.CPU = &alerts.CPUInput{BusyRatio: &value}
		evidence.NumberValue = &value
	case "host.memory.pressure_level":
		var value string
		if json.Unmarshal(sample.value.Value, &value) != nil {
			return alerts.Input{DataState: alerts.DataUnknown}, nil
		}
		certified := sample.value.Provenance.Verification == domain.VerificationDirectCapture && sample.value.Provenance.MethodRevision == metricDefinitions[metric].method
		input.MemoryPressure = &alerts.MemoryPressureInput{Level: value, Certified: certified}
		if !certified {
			input.DataState = alerts.DataUnknown
			return input, nil
		}
		evidence.StateValue = &value
	}
	return input, evidence
}

func reachabilityAlertInput(snapshot liveSnapshot, host *store.AlertRuntimeHostFence, target *store.AlertRuntimeTargetFence, episode *store.AlertReachabilityEpisode, nowMS int64) (alerts.Input, *store.AlertCapsuleEvidence) {
	input := alerts.Input{DataState: alerts.DataUnknown, Reachability: &alerts.ReachabilityInput{}}
	if host == nil || target == nil {
		return input, nil
	}
	if host.Status != nil && host.Status.AdmittedMS <= nowMS && nowMS-host.Status.AdmittedMS <= int64(60*time.Second/time.Millisecond) {
		input.Reachability.CollectorFresh = true
	}
	source := alertSource(snapshot.inventory.Sources, host.HostID, &target.TargetID, "runtime")
	sourceState := alertStatusDataState(host, source, nowMS, 15*time.Second)
	sample, ok := latestAlertMetric(snapshot, source, "runtime.reachable", target.TargetID, nowMS)
	if ok {
		input.DataState = worseAlertDataState(sample.state, sourceState)
		if sample.state == alerts.DataValid {
			var reachable bool
			if json.Unmarshal(sample.value.Value, &reachable) == nil {
				input.Reachability.Reachable = &reachable
				graceDeadline := target.CreatedMS + store.AlertStartupGrace.Milliseconds()
				everReachable := false
				if episode != nil {
					graceDeadline, everReachable = episode.StartupDeadlineMS, episode.EverReachable
				}
				input.Reachability.StartupGraceOpen = !reachable && !everReachable && nowMS < graceDeadline
				evidence := metricEvidence("runtime.reachable", sample, nowMS)
				evidence.BooleanValue = &reachable
				return input, evidence
			}
		}
	}
	if status := alertStatusSource(host, source); status != nil && status.State == "incompatible" {
		input.DataState, input.Reachability.Incompatible = alerts.DataIncompatible, true
	}
	return input, nil
}

func monitorAlertInput(facts store.AlertRuntimeMonitorFacts, cycle alertruntime.Cycle, nowMS int64) (alerts.Input, *store.AlertCapsuleEvidence) {
	lagMS := cycle.Lag.Milliseconds()
	failed := facts.FinalDeliveryFailed
	var pressure *bool
	if facts.CapacityObservedMS != nil && *facts.CapacityObservedMS <= nowMS && nowMS-*facts.CapacityObservedMS <= store.CapacityMeasurementMaxAge.Milliseconds() {
		value := facts.StorageState != store.StorageNormal
		pressure = &value
	}
	input := alerts.Input{DataState: alerts.DataValid, MonitorHealth: &alerts.MonitorHealthInput{StoragePressure: pressure, EvaluatorLagMS: &lagMS, FinalDeliveryFailed: &failed}}
	if pressure == nil && !failed && lagMS <= 15_000 {
		input.DataState = alerts.DataUnknown
		return input, nil
	}
	evidence := baseAlertEvidence("monitor.evaluator_lag_ms", "milliseconds", nowMS, domain.QualityDerived, "hub-alert-evaluator-v1")
	value := float64(lagMS)
	evidence.NumberValue = &value
	if failed {
		evidence.MetricID, evidence.Unit, evidence.NumberValue = "monitor.final_delivery_failed", "boolean", nil
		evidence.BooleanValue = &failed
	} else if pressure != nil && *pressure {
		evidence.MetricID, evidence.Unit, evidence.NumberValue = "monitor.storage_pressure", "boolean", nil
		evidence.BooleanValue = pressure
	}
	return input, evidence
}

type alertMetricSample struct {
	value protocol.MetricValue
	row   store.QueryFrame
	state alerts.DataState
}

func latestAlertMetric(snapshot liveSnapshot, source *store.QuerySource, metric, scopeID string, nowMS int64) (alertMetricSample, bool) {
	if source == nil {
		return alertMetricSample{}, false
	}
	frames, rows := snapshot.frames[source.ID], snapshot.rows[source.ID]
	definition, ok := metricDefinitions[metric]
	if !ok {
		return alertMetricSample{}, false
	}
	for index, frame := range frames {
		if index >= len(rows) {
			break
		}
		if rows[index].DeliveryMode != "current" {
			continue
		}
		value, found := metricFromFrame(frame, metric, scopeID, definition.kind)
		if !found {
			continue
		}
		state := alerts.DataValid
		observed := rows[index].ObservationMS()
		if observed > nowMS || nowMS-observed > definition.freshness.Milliseconds() {
			state = alerts.DataStale
		} else if value.Value == nil || value.Quality == domain.QualityUnavailable || value.MissingReason != nil {
			state = alerts.DataUnknown
		} else if value.Provenance.MethodRevision != definition.method || value.Provenance.Source != definition.source {
			state = alerts.DataIncompatible
		}
		return alertMetricSample{value: value, row: rows[index], state: state}, true
	}
	return alertMetricSample{}, false
}

func metricEvidence(metric string, sample alertMetricSample, nowMS int64) *store.AlertCapsuleEvidence {
	definition := metricDefinitions[metric]
	result := baseAlertEvidence(metric, definition.unit, nowMS, sample.value.Quality, sample.value.Provenance.MethodRevision)
	result.ObservedMS = sample.row.ObservationMS()
	return result
}

func baseAlertEvidence(metric, unit string, nowMS int64, quality domain.Quality, method string) *store.AlertCapsuleEvidence {
	return &store.AlertCapsuleEvidence{
		MetricID: metric, Unit: unit, WindowStartMS: nowMS, WindowEndMS: nowMS + 1, ObservedMS: nowMS, Quality: string(quality),
		SourceSamples: []store.AlertSourceSample{}, RequestSampleIDs: []string{}, DefinitionRevision: domain.RegistryRevision, MethodRevision: method,
		Gaps: []store.AlertEvidenceGap{}, UnavailableReasons: []string{},
	}
}

func statusEvidence(host *store.AlertRuntimeHostFence, metric, unit string, nowMS int64, quality domain.Quality) *store.AlertCapsuleEvidence {
	result := baseAlertEvidence(metric, unit, nowMS, quality, "collector-source-status-v1")
	result.ObservedMS = host.Status.AdmittedMS
	result.StatusSample = &store.AlertStatusSample{HostID: host.HostID, CollectorBootID: *host.CollectorBootID, SessionGeneration: host.SessionGeneration, Sequence: host.Status.Sequence, PayloadSHA256: host.Status.PayloadSHA256, ObservedMS: host.Status.ObservedMS, AdmittedMS: host.Status.AdmittedMS}
	return result
}

func finalizeAlertEvidence(evidence *store.AlertCapsuleEvidence, snapshot liveSnapshot, rule store.RuleRecord, dwellMS, nowMS int64) {
	start := max(int64(0), nowMS-dwellMS)
	if evidence.ObservedMS < start {
		start = evidence.ObservedMS
	}
	evidence.WindowStartMS, evidence.WindowEndMS = start, nowMS+1
	if evidence.StatusSample != nil || evidence.StatusAbsence != nil || evidence.MetricID == "monitor.storage_pressure" || evidence.MetricID == "monitor.evaluator_lag_ms" || evidence.MetricID == "monitor.final_delivery_failed" {
		return
	}
	definition, ok := metricDefinitions[evidence.MetricID]
	if !ok {
		return
	}
	var source *store.QuerySource
	if definition.kind == "host" {
		for index := range snapshot.inventory.Sources {
			candidate := &snapshot.inventory.Sources[index]
			if candidate.Kind == "host" && candidate.HostID == rule.Definition.ScopeID && candidate.RetiredMS == nil {
				source = candidate
				break
			}
		}
	} else {
		for index := range snapshot.inventory.Sources {
			candidate := &snapshot.inventory.Sources[index]
			if candidate.Kind == "runtime" && candidate.TargetID != nil && *candidate.TargetID == rule.Definition.ScopeID && candidate.RetiredMS == nil {
				source = candidate
				break
			}
		}
	}
	if source == nil {
		return
	}
	frames, rows := snapshot.frames[source.ID], snapshot.rows[source.ID]
	points := make([]SeriesPoint, 0, len(rows))
	samples := make([]store.AlertSourceSample, 0, min(alertEvidenceSampleLimit, len(rows)))
	for index, frame := range frames {
		if index >= len(rows) {
			break
		}
		row := rows[index]
		observed := row.ObservationMS()
		if row.DeliveryMode != "current" || observed < start || observed >= nowMS+1 {
			continue
		}
		value, found := metricFromFrame(frame, evidence.MetricID, rule.Definition.ScopeID, definition.kind)
		if !found || value.Provenance.MethodRevision != evidence.MethodRevision {
			continue
		}
		points = append(points, SeriesPoint{TimeMS: observed, Value: cloneRaw(value.Value), Quality: value.Quality, MissingReason: value.MissingReason})
		if value.Value != nil && value.Quality != domain.QualityUnavailable && value.MissingReason == nil {
			evidence.SourceSampleCount++
			if len(samples) < alertEvidenceSampleLimit {
				samples = append(samples, store.AlertSourceSample{CollectorBootID: row.CollectorBootID, SourceID: row.SourceID, Sequence: row.Sequence, ConfigIDs: []string{}})
			}
		}
	}
	sort.SliceStable(points, func(i, j int) bool { return points[i].TimeMS < points[j].TimeMS })
	evidence.SourceSamples = samples
	evidence.SourceSamplesTruncated = evidence.SourceSampleCount > len(samples)
	if len(points) > 0 {
		_, gaps := coverageAndGaps(points, start, nowMS+1, definition.freshness)
		for _, gap := range gaps {
			evidence.Gaps = append(evidence.Gaps, store.AlertEvidenceGap{StartMS: gap.StartMS, EndMS: gap.EndMS, Reason: string(gap.Reason)})
		}
	}
}

func alertObservedDwell(planned store.AlertRuntimeRulePlan, input alerts.Input, cycle alertruntime.Cycle) int64 {
	if planned.Rule.Definition.EvaluatorType == alerts.RuleHostNotReporting && input.Heartbeat != nil {
		return input.Heartbeat.AgeMS
	}
	value := int64(0)
	if planned.Snapshot != nil && !cycle.Restarted {
		value = planned.Snapshot.DwellMS
		elapsed := cycle.Elapsed.Milliseconds()
		if elapsed > math.MaxInt64-value {
			value = math.MaxInt64
		} else {
			value += elapsed
		}
	}
	if decision, err := evaluatePlannedInput(planned.Rule, input); err == nil && decision.Immediate {
		return 0
	}
	return value
}

func evaluatePlannedInput(rule store.RuleRecord, input alerts.Input) (alerts.Decision, error) {
	const placeholderScopeFingerprint = "0000000000000000000000000000000000000000000000000000000000000000"
	spec, err := alerts.DefaultSpec(rule.ID, rule.Revision, rule.Definition.EvaluatorType, placeholderScopeFingerprint)
	if err != nil {
		return alerts.Decision{}, err
	}
	if rule.Definition.EvaluatorType == alerts.RuleObservedRequestDuration {
		return alerts.Decision{}, errors.New("request population evaluator is pending")
	}
	return alerts.Evaluate(spec, input)
}

func hashAlertWrite(write store.AlertEvaluationWrite) (string, error) {
	payload := struct {
		RuleID          string                               `json:"rule_id"`
		RuleVersion     int64                                `json:"rule_version"`
		Ordinal         int64                                `json:"ordinal"`
		EventMS         int64                                `json:"event_ms"`
		ElapsedMS       int64                                `json:"elapsed_ms"`
		HubRestarted    bool                                 `json:"hub_restarted"`
		ObservedDwellMS int64                                `json:"observed_dwell_ms"`
		Input           alerts.Input                         `json:"input"`
		Fence           store.AlertEvaluationFence           `json:"fence"`
		Episode         *store.AlertReachabilityEpisodeWrite `json:"episode"`
		Evidence        *store.AlertCapsuleEvidence          `json:"evidence"`
	}{
		RuleID: write.RuleID, RuleVersion: write.RuleVersion, Ordinal: write.Cursor.InputOrdinal,
		EventMS: write.EventMS, ElapsedMS: write.ElapsedMS, HubRestarted: write.HubRestarted,
		ObservedDwellMS: write.ObservedDwellMS, Input: write.Input, Fence: write.Fence,
		Episode: write.Episode, Evidence: write.Evidence,
	}
	encoded, err := json.Marshal(payload)
	if err != nil {
		return "", err
	}
	digest := sha256.Sum256(encoded)
	return hex.EncodeToString(digest[:]), nil
}

func alertSource(sources []store.QuerySource, hostID string, targetID *string, kind string) *store.QuerySource {
	for index := range sources {
		if sources[index].HostID != hostID || sources[index].Kind != kind || sources[index].RetiredMS != nil {
			continue
		}
		if targetID == nil && sources[index].TargetID == nil || targetID != nil && sources[index].TargetID != nil && *targetID == *sources[index].TargetID {
			return &sources[index]
		}
	}
	return nil
}

func alertRuntimeSourceID(sources []store.QuerySource, targetID string) string {
	for _, source := range sources {
		if source.Kind == "runtime" && source.RetiredMS == nil && source.TargetID != nil && *source.TargetID == targetID {
			return source.ID
		}
	}
	return ""
}

func alertStatusSource(host *store.AlertRuntimeHostFence, source *store.QuerySource) *protocol.SourceState {
	if host == nil || host.Status == nil || source == nil {
		return nil
	}
	for index := range host.Status.Sources {
		if host.Status.Sources[index].SourceID == source.ID {
			return &host.Status.Sources[index]
		}
	}
	return nil
}

func alertStatusDataState(host *store.AlertRuntimeHostFence, source *store.QuerySource, nowMS int64, freshness time.Duration) alerts.DataState {
	if host == nil || host.Status == nil || source == nil || host.Status.AdmittedMS > nowMS {
		return alerts.DataUnknown
	}
	if nowMS-host.Status.AdmittedMS > int64(60*time.Second/time.Millisecond) {
		return alerts.DataStale
	}
	status := alertStatusSource(host, source)
	if status == nil {
		return alerts.DataUnknown
	}
	switch sourceStateFromStatus(*status, nowMS, freshness) {
	case SourceFresh:
		return alerts.DataValid
	case SourceStale:
		return alerts.DataStale
	case SourceIncompatible:
		return alerts.DataIncompatible
	default:
		return alerts.DataUnknown
	}
}

func worseAlertDataState(left, right alerts.DataState) alerts.DataState {
	order := map[alerts.DataState]int{alerts.DataValid: 0, alerts.DataUnknown: 1, alerts.DataStale: 2, alerts.DataIncompatible: 3}
	if order[right] > order[left] {
		return right
	}
	return left
}
