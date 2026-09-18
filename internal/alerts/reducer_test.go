package alerts

import "testing"

func TestReducerRequiresConsecutiveValidDwellAndRecovery(t *testing.T) {
	spec := mustSpec(t, RuleMemoryPressure)
	snapshot, err := NewSnapshot(spec, 7)
	if err != nil {
		t.Fatal(err)
	}
	warning := known(PredicateMatch, DataValid, "pressure_warning", false)
	normal := known(PredicateClear, DataValid, "pressure_normal", false)
	unknown := unavailable(DataUnknown, "pressure_not_observed")

	snapshot = reduceState(t, spec, snapshot, 1_000, 0, false, warning, StatePending)
	snapshot = reduceState(t, spec, snapshot, 11_000, 10_000, false, warning, StatePending)
	if snapshot.DwellMS != 10_000 {
		t.Fatalf("pending dwell=%d", snapshot.DwellMS)
	}
	snapshot = reduceState(t, spec, snapshot, 16_000, 5_000, false, unknown, StateOK)
	if snapshot.DwellMS != 0 || snapshot.DataState != DataUnknown {
		t.Fatalf("gap did not reset pending: %#v", snapshot)
	}
	snapshot = reduceState(t, spec, snapshot, 20_000, 0, false, warning, StatePending)
	snapshot = reduceState(t, spec, snapshot, 50_000, 30_000, false, warning, StateFiring)
	if snapshot.OpenedMS == nil || *snapshot.OpenedMS != 50_000 {
		t.Fatalf("unexpected opening time: %#v", snapshot.OpenedMS)
	}
	snapshot = reduceState(t, spec, snapshot, 51_000, 1_000, false, normal, StateRecovering)
	snapshot = reduceState(t, spec, snapshot, 81_000, 30_000, false, normal, StateRecovering)
	snapshot = reduceState(t, spec, snapshot, 111_000, 30_000, false, normal, StateResolved)
	if snapshot.ResolvedMS == nil || *snapshot.ResolvedMS != 111_000 {
		t.Fatalf("unexpected resolution: %#v", snapshot)
	}
}

func TestFiringUnknownStaysOpenAndRecoveringGapReturnsFiring(t *testing.T) {
	spec := mustSpec(t, RuleHeavyCPU)
	snapshot := firingSnapshot(t, spec)
	unknown := unavailable(DataStale, "input_stale")
	result := reduceResult(t, spec, snapshot, 2_000, 10_000, false, unknown)
	if result.Snapshot.State != StateFiring || result.Transition != nil || result.Snapshot.DataState != DataStale {
		t.Fatalf("firing unknown must stay open: %#v", result)
	}
	clear := known(PredicateClear, DataValid, "cpu_below_80_percent", false)
	snapshot = reduceState(t, spec, result.Snapshot, 3_000, 1_000, false, clear, StateRecovering)
	snapshot = reduceState(t, spec, snapshot, 4_000, 1_000, false, unknown, StateFiring)
	if snapshot.ResolvedMS != nil {
		t.Fatalf("gap must not resolve firing alert")
	}
}

func TestRestartDiscardsUnprovenPendingAndRecoveryElapsed(t *testing.T) {
	spec := mustSpec(t, RuleMemoryPressure)
	pending, _ := NewSnapshot(spec, 1)
	pending.State, pending.DwellMS = StatePending, 25_000
	match := known(PredicateMatch, DataValid, "pressure_warning", false)
	pending = reduceState(t, spec, pending, 100_000, 5_000, true, match, StatePending)
	if pending.DwellMS != 0 {
		t.Fatalf("restart counted unproven pending interval: %d", pending.DwellMS)
	}

	recovering := firingSnapshot(t, spec)
	recovering.State, recovering.DwellMS = StateRecovering, 55_000
	clear := known(PredicateClear, DataValid, "pressure_normal", false)
	recovering = reduceState(t, spec, recovering, 100_000, 5_000, true, clear, StateRecovering)
	if recovering.DwellMS != 0 {
		t.Fatalf("restart counted unproven recovery interval: %d", recovering.DwellMS)
	}

	firing := firingSnapshot(t, spec)
	firing = reduceState(t, spec, firing, 100_000, 5_000, true, unavailable(DataUnknown, "pressure_not_observed"), StateFiring)
	if firing.OpenedMS == nil {
		t.Fatal("restart closed firing alert")
	}
}

func TestCriticalPressureFiresImmediately(t *testing.T) {
	spec := mustSpec(t, RuleMemoryPressure)
	decision, err := Evaluate(spec, Input{DataState: DataValid, MemoryPressure: &MemoryPressureInput{Level: "critical", Certified: true}})
	if err != nil {
		t.Fatal(err)
	}
	snapshot, _ := NewSnapshot(spec, 1)
	snapshot = reduceState(t, spec, snapshot, 1_000, 0, false, decision, StateFiring)
	if snapshot.DwellMS != 0 {
		t.Fatalf("critical pressure used dwell: %d", snapshot.DwellMS)
	}
}

func TestCPUHysteresisDoesNotAdvanceWrongDwell(t *testing.T) {
	spec := mustSpec(t, RuleHeavyCPU)
	snapshot, _ := NewSnapshot(spec, 1)
	match := known(PredicateMatch, DataValid, "cpu_at_least_90_percent", false)
	hold := known(PredicateHold, DataValid, "cpu_hysteresis", false)
	clear := known(PredicateClear, DataValid, "cpu_below_80_percent", false)
	snapshot = reduceState(t, spec, snapshot, 1_000, 0, false, match, StatePending)
	snapshot = reduceState(t, spec, snapshot, 61_000, 60_000, false, match, StateFiring)
	result := reduceResult(t, spec, snapshot, 62_000, 1_000, false, hold)
	if result.Snapshot.State != StateFiring || result.Transition != nil {
		t.Fatalf("hysteresis changed firing state: %#v", result)
	}
	snapshot = reduceState(t, spec, result.Snapshot, 63_000, 1_000, false, clear, StateRecovering)
	snapshot = reduceState(t, spec, snapshot, 64_000, 1_000, false, hold, StateFiring)
	snapshot = reduceState(t, spec, snapshot, 65_000, 1_000, false, clear, StateRecovering)
	snapshot = reduceState(t, spec, snapshot, 125_000, 60_000, false, clear, StateResolved)
}

func TestAcknowledgementAndMuteNeverAffectEvaluation(t *testing.T) {
	spec := mustSpec(t, RuleMemoryPressure)
	snapshot, _ := NewSnapshot(spec, 1)
	actor, acknowledged, muted := "22222222-2222-4222-8222-222222222222", int64(10), int64(999_999)
	snapshot.AcknowledgedBy, snapshot.AcknowledgedMS, snapshot.MutedUntilMS = &actor, &acknowledged, &muted
	match := known(PredicateMatch, DataValid, "pressure_warning", false)
	snapshot = reduceState(t, spec, snapshot, 20, 0, false, match, StatePending)
	snapshot = reduceState(t, spec, snapshot, 30_020, 30_000, false, match, StateFiring)
	if snapshot.AcknowledgedBy == nil || *snapshot.AcknowledgedBy != actor || snapshot.AcknowledgedMS == nil || *snapshot.AcknowledgedMS != acknowledged || snapshot.MutedUntilMS == nil || *snapshot.MutedUntilMS != muted {
		t.Fatalf("ack/mute changed evaluation state: %#v", snapshot)
	}
}

func TestSupersedeIsNotRecovery(t *testing.T) {
	spec := mustSpec(t, RuleMemoryPressure)
	current := firingSnapshot(t, spec)
	current.DataState = DataUnknown
	result, err := Supersede(spec, current, 10_000, testHash)
	if err != nil || result.Snapshot.State != StateSuperseded || result.Snapshot.DataState != DataUnknown || result.Snapshot.ResolvedMS != nil || result.Transition == nil || result.Transition.NewState != StateSuperseded {
		t.Fatalf("supersede result: %#v, %v", result, err)
	}
	resolved := current
	resolved.State = StateResolved
	resolvedAt := int64(9_000)
	resolved.ResolvedMS = &resolvedAt
	if _, err := Supersede(spec, resolved, 10_000, testHash); err != ErrTerminalState {
		t.Fatalf("resolved instance supersede error=%v", err)
	}
	newSpec := spec
	newSpec.Version++
	if _, err := Reduce(newSpec, current, Evaluation{EventMS: 11_000, Decision: known(PredicateClear, DataValid, "pressure_normal", false), EvidenceHash: testHash}); err != ErrInvalidSnapshot {
		t.Fatalf("old state crossed rule versions: %v", err)
	}
}

func TestWallClockDoesNotDriveDwell(t *testing.T) {
	spec := mustSpec(t, RuleMemoryPressure)
	snapshot, _ := NewSnapshot(spec, 1)
	match := known(PredicateMatch, DataValid, "pressure_warning", false)
	snapshot = reduceState(t, spec, snapshot, 100_000, 0, false, match, StatePending)
	snapshot = reduceState(t, spec, snapshot, 90_000, 10_000, false, match, StatePending)
	if snapshot.DwellMS != 10_000 || snapshot.LastEvalMS != 90_000 {
		t.Fatalf("wall clock altered monotonic dwell: %#v", snapshot)
	}
}

func reduceState(t *testing.T, spec Spec, current Snapshot, eventMS, elapsedMS int64, restarted bool, decision Decision, want State) Snapshot {
	t.Helper()
	result := reduceResult(t, spec, current, eventMS, elapsedMS, restarted, decision)
	if result.Snapshot.State != want {
		t.Fatalf("state=%s, want %s; result=%#v", result.Snapshot.State, want, result)
	}
	return result.Snapshot
}

func reduceResult(t *testing.T, spec Spec, current Snapshot, eventMS, elapsedMS int64, restarted bool, decision Decision) Result {
	t.Helper()
	result, err := Reduce(spec, current, Evaluation{EventMS: eventMS, ElapsedMS: elapsedMS, HubRestarted: restarted, Decision: decision, EvidenceHash: testHash})
	if err != nil {
		t.Fatal(err)
	}
	return result
}

func firingSnapshot(t *testing.T, spec Spec) Snapshot {
	t.Helper()
	snapshot, err := NewSnapshot(spec, 1)
	if err != nil {
		t.Fatal(err)
	}
	opened := int64(1_000)
	snapshot.State, snapshot.DataState, snapshot.OpenedMS = StateFiring, DataValid, &opened
	return snapshot
}
