package alerts

import (
	"errors"
	"testing"
)

const (
	testRuleID = "11111111-1111-4111-8111-111111111111"
	testScope  = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	testHash   = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
)

func TestDefaultSpecsAreClosed(t *testing.T) {
	want := map[RuleType]struct {
		trigger  int64
		recovery int64
		policy   IncarnationPolicy
	}{
		RuleOllamaUnreachable:       {30_000, 30_000, IncarnationTargetEpisode},
		RuleHostNotReporting:        {0, 30_000, IncarnationStableScope},
		RuleSourceMissing:           {30_000, 30_000, IncarnationSource},
		RuleMemoryPressure:          {30_000, 60_000, IncarnationStableScope},
		RuleHeavyCPU:                {60_000, 60_000, IncarnationStableScope},
		RuleObservedRequestDuration: {0, 0, IncarnationPopulation},
		RuleDiskMonitorHealth:       {30_000, 30_000, IncarnationStableScope},
	}
	for ruleType, expected := range want {
		spec := mustSpec(t, ruleType)
		if spec.TriggerDwellMS != expected.trigger || spec.RecoveryDwellMS != expected.recovery || spec.IncarnationPolicy != expected.policy {
			t.Fatalf("%s: got dwell %d/%d policy %s", ruleType, spec.TriggerDwellMS, spec.RecoveryDwellMS, spec.IncarnationPolicy)
		}
		changed := spec
		changed.TriggerDwellMS++
		if !errors.Is(changed.Validate(), ErrInvalidSpec) {
			t.Fatalf("%s: customized dwell was accepted", ruleType)
		}
	}
}

func TestReachabilityAndSourceQuality(t *testing.T) {
	unreachable := mustSpec(t, RuleOllamaUnreachable)
	falseValue, trueValue := false, true
	cases := []struct {
		name  string
		input Input
		want  Decision
	}{
		{"missing", Input{DataState: DataValid}, unavailable(DataUnknown, "reachability_not_observed")},
		{"stale collector", Input{DataState: DataValid, Reachability: &ReachabilityInput{Reachable: &falseValue}}, unavailable(DataUnknown, "reachability_not_observed")},
		{"startup grace", Input{DataState: DataValid, Reachability: &ReachabilityInput{CollectorFresh: true, Reachable: &falseValue, StartupGraceOpen: true}}, known(PredicateHold, DataValid, "startup_grace_open", false)},
		{"unreachable", Input{DataState: DataValid, Reachability: &ReachabilityInput{CollectorFresh: true, Reachable: &falseValue}}, known(PredicateMatch, DataValid, "runtime_unreachable", false)},
		{"reachable", Input{DataState: DataValid, Reachability: &ReachabilityInput{CollectorFresh: true, Reachable: &trueValue}}, known(PredicateClear, DataValid, "runtime_reachable", false)},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := Evaluate(unreachable, tc.input)
			if err != nil || got != tc.want {
				t.Fatalf("got %#v, %v; want %#v", got, err, tc.want)
			}
		})
	}

	source := mustSpec(t, RuleSourceMissing)
	got, err := Evaluate(source, Input{DataState: DataIncompatible, Source: &SourceInput{HostFresh: true, Available: &falseValue, Incompatible: true}})
	if err != nil || !got.Evaluable || got.Predicate != PredicateMatch || got.DataState != DataIncompatible {
		t.Fatalf("incompatible source must be a known condition with incompatible quality: %#v, %v", got, err)
	}
	got, err = Evaluate(source, Input{DataState: DataStale, Source: &SourceInput{HostFresh: true, Available: &falseValue}})
	if err != nil || got.Evaluable || got.DataState != DataStale {
		t.Fatalf("stale source must remain unavailable: %#v, %v", got, err)
	}
}

func TestPressureCPUAndHealthEvaluators(t *testing.T) {
	pressure := mustSpec(t, RuleMemoryPressure)
	for _, tc := range []struct {
		input     *MemoryPressureInput
		predicate Predicate
		immediate bool
		evaluable bool
	}{
		{&MemoryPressureInput{Level: "normal", Certified: true}, PredicateClear, false, true},
		{&MemoryPressureInput{Level: "warning", Certified: true}, PredicateMatch, false, true},
		{&MemoryPressureInput{Level: "critical", Certified: true}, PredicateMatch, true, true},
		{&MemoryPressureInput{Level: "warning", Certified: false}, PredicateHold, false, false},
	} {
		got, err := Evaluate(pressure, Input{DataState: DataValid, MemoryPressure: tc.input})
		if err != nil || got.Predicate != tc.predicate || got.Immediate != tc.immediate || got.Evaluable != tc.evaluable {
			t.Fatalf("pressure %#v: got %#v, %v", tc.input, got, err)
		}
	}

	cpu := mustSpec(t, RuleHeavyCPU)
	for value, predicate := range map[float64]Predicate{0.79: PredicateClear, 0.80: PredicateHold, 0.89: PredicateHold, 0.90: PredicateMatch} {
		value := value
		got, err := Evaluate(cpu, Input{DataState: DataValid, CPU: &CPUInput{BusyRatio: &value}})
		if err != nil || got.Predicate != predicate {
			t.Fatalf("cpu %f: got %#v, %v", value, got, err)
		}
	}

	health := mustSpec(t, RuleDiskMonitorHealth)
	falseValue, trueValue := false, true
	lagAt, lagOver := int64(15_000), int64(15_001)
	clearInput := &MonitorHealthInput{StoragePressure: &falseValue, EvaluatorLagMS: &lagAt, FinalDeliveryFailed: &falseValue}
	got, err := Evaluate(health, Input{DataState: DataValid, MonitorHealth: clearInput})
	if err != nil || got.Predicate != PredicateClear {
		t.Fatalf("clear monitor health: %#v, %v", got, err)
	}
	got, err = Evaluate(health, Input{DataState: DataValid, MonitorHealth: &MonitorHealthInput{StoragePressure: &falseValue, EvaluatorLagMS: &lagOver, FinalDeliveryFailed: &falseValue}})
	if err != nil || got.Predicate != PredicateMatch || got.Immediate {
		t.Fatalf("lag alert: %#v, %v", got, err)
	}
	veryOld := int64(30 * 24 * 60 * 60 * 1000)
	got, err = Evaluate(health, Input{DataState: DataValid, MonitorHealth: &MonitorHealthInput{StoragePressure: &falseValue, EvaluatorLagMS: &veryOld, FinalDeliveryFailed: &falseValue}})
	if err != nil || got.Predicate != PredicateMatch {
		t.Fatalf("long evaluator lag must remain alertable: %#v, %v", got, err)
	}
	got, err = Evaluate(health, Input{DataState: DataValid, MonitorHealth: &MonitorHealthInput{FinalDeliveryFailed: &trueValue}})
	if err != nil || got.Predicate != PredicateMatch || !got.Immediate {
		t.Fatalf("final delivery failure: %#v, %v", got, err)
	}
}

func TestHeartbeatAgeDoesNotAgeOutOfAlertability(t *testing.T) {
	spec := mustSpec(t, RuleHostNotReporting)
	got, err := Evaluate(spec, Input{DataState: DataValid, Heartbeat: &HeartbeatInput{AgeMS: 30 * 24 * 60 * 60 * 1000}})
	if err != nil || got.Predicate != PredicateMatch || !got.Evaluable {
		t.Fatalf("long-missing host must remain a known alert: %#v, %v", got, err)
	}
}

func TestObservedRequestUsesExactCompletedPopulationAndSelectedFieldN(t *testing.T) {
	spec := mustSpec(t, RuleObservedRequestDuration)
	spec.RequestDuration = &RequestDurationSpec{MetricID: "request.client.total_ms", Statistic: "p95", ThresholdMS: 500}
	p95 := 600.0
	input := &RequestDurationInput{MetricID: "request.client.total_ms", ExactCompletedPopulation: true, CompletedN: 100, ValidN: 99, P95MS: &p95}
	got, err := Evaluate(spec, Input{DataState: DataValid, Request: input})
	if err != nil || got.Evaluable || got.Reason != "request_p95_valid_n_below_100" {
		t.Fatalf("99 valid p95 samples must be unknown: %#v, %v", got, err)
	}
	input.ValidN = 100
	got, err = Evaluate(spec, Input{DataState: DataValid, Request: input})
	if err != nil || got.Predicate != PredicateMatch || !got.Evaluable {
		t.Fatalf("100 valid p95 samples must evaluate: %#v, %v", got, err)
	}
	input.ExactCompletedPopulation = false
	got, err = Evaluate(spec, Input{DataState: DataValid, Request: input})
	if err != nil || got.Evaluable {
		t.Fatalf("mixed request population must be unknown: %#v, %v", got, err)
	}
	input.ExactCompletedPopulation = true
	input.MetricID = "request.client.first_byte_ms"
	got, err = Evaluate(spec, Input{DataState: DataValid, Request: input})
	if err != nil || got.Evaluable {
		t.Fatalf("wrong metric population must be unknown: %#v, %v", got, err)
	}
}

func mustSpec(t *testing.T, ruleType RuleType) Spec {
	t.Helper()
	spec, err := DefaultSpec(testRuleID, 1, ruleType, testScope)
	if err != nil {
		t.Fatal(err)
	}
	return spec
}
