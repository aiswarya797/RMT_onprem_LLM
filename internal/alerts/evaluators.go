package alerts

import (
	"math"
	"regexp"
)

const (
	warningPressureDwellMS = int64(30_000)
	cpuDwellMS             = int64(60_000)
	standardRecoveryMS     = int64(30_000)
)

var (
	uuidPattern            = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)
	hashPattern            = regexp.MustCompile(`^[0-9a-f]{64}$`)
	requestDurationMetrics = map[string]bool{
		"request.client.first_byte_ms":            true,
		"request.client.first_content_ms":         true,
		"request.client.total_ms":                 true,
		"request.runtime.eval_duration_ms":        true,
		"request.runtime.load_duration_ms":        true,
		"request.runtime.prompt_eval_duration_ms": true,
		"request.runtime.total_duration_ms":       true,
	}
)

// DefaultSpec returns the fixed first-release dwell and incarnation policy for
// one shipped Mac evaluator. Observed-request duration remains invalid until a
// caller supplies a reviewed RequestDuration specification.
func DefaultSpec(ruleID string, version int64, ruleType RuleType, scopeFingerprint string) (Spec, error) {
	spec := Spec{RuleID: ruleID, Version: version, Type: ruleType, ScopeFingerprint: scopeFingerprint, IncarnationPolicy: IncarnationStableScope}
	switch ruleType {
	case RuleOllamaUnreachable:
		spec.IncarnationPolicy, spec.TriggerDwellMS, spec.RecoveryDwellMS = IncarnationTargetEpisode, 30_000, standardRecoveryMS
	case RuleHostNotReporting:
		spec.TriggerDwellMS, spec.RecoveryDwellMS = 0, standardRecoveryMS
	case RuleSourceMissing:
		spec.IncarnationPolicy, spec.TriggerDwellMS, spec.RecoveryDwellMS = IncarnationSource, 30_000, standardRecoveryMS
	case RuleMemoryPressure:
		spec.TriggerDwellMS, spec.RecoveryDwellMS = warningPressureDwellMS, 60_000
	case RuleHeavyCPU:
		spec.TriggerDwellMS, spec.RecoveryDwellMS = cpuDwellMS, cpuDwellMS
	case RuleObservedRequestDuration:
		spec.IncarnationPolicy = IncarnationPopulation
	case RuleDiskMonitorHealth:
		spec.TriggerDwellMS, spec.RecoveryDwellMS = 30_000, standardRecoveryMS
	default:
		return Spec{}, ErrInvalidSpec
	}
	return spec, nil
}

func (s Spec) Validate() error {
	if !uuidPattern.MatchString(s.RuleID) || s.Version < 1 || !hashPattern.MatchString(s.ScopeFingerprint) || s.TriggerDwellMS < 0 || s.RecoveryDwellMS < 0 {
		return ErrInvalidSpec
	}
	base, err := DefaultSpec(s.RuleID, s.Version, s.Type, s.ScopeFingerprint)
	if err != nil || s.IncarnationPolicy != base.IncarnationPolicy || s.TriggerDwellMS != base.TriggerDwellMS || s.RecoveryDwellMS != base.RecoveryDwellMS {
		return ErrInvalidSpec
	}
	if s.Type != RuleObservedRequestDuration {
		if s.RequestDuration != nil {
			return ErrInvalidSpec
		}
		return nil
	}
	request := s.RequestDuration
	if request == nil || !requestDurationMetrics[request.MetricID] || (request.Statistic != "median" && request.Statistic != "p95") || math.IsNaN(request.ThresholdMS) || math.IsInf(request.ThresholdMS, 0) || request.ThresholdMS < 0 || request.ThresholdMS > 120_000 {
		return ErrInvalidSpec
	}
	return nil
}

// Evaluate converts only shipped Mac inputs into a reducer decision. Missing,
// stale or unqualified evidence returns a non-evaluable decision rather than a
// synthetic clear value.
func Evaluate(spec Spec, input Input) (Decision, error) {
	if err := spec.Validate(); err != nil {
		return Decision{}, err
	}
	quality := input.DataState
	if quality == "" {
		quality = DataUnknown
	}
	if !validDataState(quality) {
		return Decision{}, ErrInvalidInput
	}
	if quality != DataValid && spec.Type != RuleSourceMissing {
		return unavailable(quality, "input_"+string(quality)), nil
	}
	switch spec.Type {
	case RuleOllamaUnreachable:
		return evaluateReachability(input.Reachability, quality), nil
	case RuleHostNotReporting:
		return evaluateHeartbeat(input.Heartbeat, quality)
	case RuleSourceMissing:
		return evaluateSource(input.Source, quality), nil
	case RuleMemoryPressure:
		return evaluateMemoryPressure(input.MemoryPressure, quality), nil
	case RuleHeavyCPU:
		return evaluateCPU(input.CPU, quality)
	case RuleObservedRequestDuration:
		return evaluateRequest(*spec.RequestDuration, input.Request, quality)
	case RuleDiskMonitorHealth:
		return evaluateMonitorHealth(input.MonitorHealth, quality)
	default:
		return Decision{}, ErrInvalidSpec
	}
}

func evaluateReachability(input *ReachabilityInput, quality DataState) Decision {
	if input == nil || !input.CollectorFresh || input.Reachable == nil {
		return unavailable(DataUnknown, "reachability_not_observed")
	}
	if input.Incompatible {
		return unavailable(DataIncompatible, "runtime_incompatible")
	}
	if *input.Reachable {
		return known(PredicateClear, quality, "runtime_reachable", false)
	}
	if input.StartupGraceOpen {
		return known(PredicateHold, quality, "startup_grace_open", false)
	}
	return known(PredicateMatch, quality, "runtime_unreachable", false)
}

func evaluateHeartbeat(input *HeartbeatInput, quality DataState) (Decision, error) {
	if input == nil {
		return unavailable(DataUnknown, "heartbeat_not_observed"), nil
	}
	if input.AgeMS < 0 {
		return Decision{}, ErrInvalidInput
	}
	if input.AgeMS >= 60_000 {
		return known(PredicateMatch, quality, "heartbeat_age_60s", false), nil
	}
	return known(PredicateClear, quality, "heartbeat_fresh", false), nil
}

func evaluateSource(input *SourceInput, quality DataState) Decision {
	if input == nil || !input.HostFresh || input.Available == nil {
		return unavailable(DataUnknown, "source_not_observed")
	}
	if input.Incompatible || quality == DataIncompatible {
		return known(PredicateMatch, DataIncompatible, "source_incompatible", false)
	}
	if quality != DataValid {
		return unavailable(quality, "source_"+string(quality))
	}
	if *input.Available {
		return known(PredicateClear, quality, "source_available", false)
	}
	return known(PredicateMatch, quality, "source_missing", false)
}

func evaluateMemoryPressure(input *MemoryPressureInput, quality DataState) Decision {
	if input == nil || !input.Certified {
		return unavailable(DataUnknown, "pressure_uncertified")
	}
	switch input.Level {
	case "normal":
		return known(PredicateClear, quality, "pressure_normal", false)
	case "warning":
		return known(PredicateMatch, quality, "pressure_warning", false)
	case "critical":
		return known(PredicateMatch, quality, "pressure_critical", true)
	default:
		return unavailable(DataUnknown, "pressure_not_observed")
	}
}

func evaluateCPU(input *CPUInput, quality DataState) (Decision, error) {
	if input == nil || input.BusyRatio == nil {
		return unavailable(DataUnknown, "cpu_not_observed"), nil
	}
	value := *input.BusyRatio
	if math.IsNaN(value) || math.IsInf(value, 0) || value < 0 || value > 1 {
		return Decision{}, ErrInvalidInput
	}
	if value >= 0.90 {
		return known(PredicateMatch, quality, "cpu_at_least_90_percent", false), nil
	}
	if value < 0.80 {
		return known(PredicateClear, quality, "cpu_below_80_percent", false), nil
	}
	return known(PredicateHold, quality, "cpu_hysteresis", false), nil
}

func evaluateRequest(spec RequestDurationSpec, input *RequestDurationInput, quality DataState) (Decision, error) {
	if input == nil || input.MetricID != spec.MetricID || !input.ExactCompletedPopulation || input.CompletedN < 0 || input.ValidN < 0 || input.ValidN > input.CompletedN {
		return unavailable(DataUnknown, "request_population_unavailable"), nil
	}
	var value *float64
	if spec.Statistic == "p95" {
		if input.ValidN < 100 {
			return unavailable(DataUnknown, "request_p95_valid_n_below_100"), nil
		}
		value = input.P95MS
	} else {
		if input.ValidN < 1 {
			return unavailable(DataUnknown, "request_valid_n_zero"), nil
		}
		value = input.MedianMS
	}
	if value == nil {
		return unavailable(DataUnknown, "request_statistic_unavailable"), nil
	}
	if math.IsNaN(*value) || math.IsInf(*value, 0) || *value < 0 || *value > 120_000 {
		return Decision{}, ErrInvalidInput
	}
	if *value >= spec.ThresholdMS {
		return known(PredicateMatch, quality, "request_threshold_met", true), nil
	}
	return known(PredicateClear, quality, "request_threshold_clear", true), nil
}

func evaluateMonitorHealth(input *MonitorHealthInput, quality DataState) (Decision, error) {
	if input == nil {
		return unavailable(DataUnknown, "monitor_health_not_observed"), nil
	}
	if input.EvaluatorLagMS != nil && *input.EvaluatorLagMS < 0 {
		return Decision{}, ErrInvalidInput
	}
	if input.FinalDeliveryFailed != nil && *input.FinalDeliveryFailed {
		return known(PredicateMatch, quality, "final_delivery_failed", true), nil
	}
	if input.StoragePressure != nil && *input.StoragePressure {
		return known(PredicateMatch, quality, "storage_pressure", true), nil
	}
	if input.EvaluatorLagMS != nil && *input.EvaluatorLagMS > 15_000 {
		return known(PredicateMatch, quality, "evaluator_lag_over_15s", false), nil
	}
	if input.StoragePressure == nil || input.EvaluatorLagMS == nil || input.FinalDeliveryFailed == nil {
		return unavailable(DataUnknown, "monitor_health_partial"), nil
	}
	return known(PredicateClear, quality, "monitor_health_clear", false), nil
}

func unavailable(state DataState, reason string) Decision {
	return Decision{Predicate: PredicateHold, Evaluable: false, DataState: state, Reason: reason}
}

func known(predicate Predicate, state DataState, reason string, immediate bool) Decision {
	return Decision{Predicate: predicate, Evaluable: true, DataState: state, Reason: reason, Immediate: immediate}
}
