package alerts

import "math"

func NewSnapshot(spec Spec, activeGeneration int64) (Snapshot, error) {
	if err := spec.Validate(); err != nil || activeGeneration < 1 {
		return Snapshot{}, ErrInvalidSpec
	}
	return Snapshot{
		RuleID:            spec.RuleID,
		RuleVersion:       spec.Version,
		ScopeFingerprint:  spec.ScopeFingerprint,
		IncarnationPolicy: spec.IncarnationPolicy,
		ActiveGeneration:  activeGeneration,
		State:             StateOK,
		DataState:         DataUnknown,
	}, nil
}

func Reduce(spec Spec, current Snapshot, evaluation Evaluation) (Result, error) {
	if err := spec.Validate(); err != nil {
		return Result{}, err
	}
	if err := validateSnapshot(spec, current); err != nil {
		return Result{}, err
	}
	if current.State == StateResolved || current.State == StateSuperseded {
		return Result{}, ErrTerminalState
	}
	if err := validateEvaluation(evaluation); err != nil {
		return Result{}, err
	}
	next := current
	elapsedMS := evaluation.ElapsedMS
	next.LastEvalMS = evaluation.EventMS
	next.DataState = evaluation.Decision.DataState
	if evaluation.Decision.Evaluable && evaluation.Decision.DataState == DataValid {
		observed := evaluation.EventMS
		next.LastValidMS = &observed
	}
	if evaluation.HubRestarted {
		// The first post-restart sample cannot prove how much of the supplied
		// interval was continuously observed by this hub process.
		elapsedMS = 0
		switch next.State {
		case StatePending, StateRecovering:
			next.DwellMS = 0
		}
	}
	if !evaluation.Decision.Evaluable {
		switch next.State {
		case StatePending:
			return transition(current, resetToOK(next), evaluation), nil
		case StateRecovering:
			return transition(current, resetToFiring(next), evaluation), nil
		default:
			next.DwellMS = 0
			return Result{Snapshot: next}, nil
		}
	}

	switch next.State {
	case StateOK:
		if evaluation.Decision.Predicate != PredicateMatch {
			next.DwellMS = 0
			return Result{Snapshot: next}, nil
		}
		if evaluation.Decision.Immediate || spec.TriggerDwellMS == 0 {
			return transition(current, openFiring(next, evaluation.EventMS), evaluation), nil
		}
		next.State, next.DwellMS = StatePending, 0
		return transition(current, next, evaluation), nil
	case StatePending:
		if evaluation.Decision.Predicate != PredicateMatch {
			return transition(current, resetToOK(next), evaluation), nil
		}
		next.DwellMS = addElapsed(next.DwellMS, elapsedMS)
		if evaluation.Decision.Immediate || next.DwellMS >= spec.TriggerDwellMS {
			return transition(current, openFiring(next, evaluation.EventMS), evaluation), nil
		}
		return Result{Snapshot: next}, nil
	case StateFiring:
		if evaluation.Decision.Predicate != PredicateClear {
			next.DwellMS = 0
			return Result{Snapshot: next}, nil
		}
		if evaluation.Decision.Immediate || spec.RecoveryDwellMS == 0 {
			return transition(current, resolve(next, evaluation.EventMS), evaluation), nil
		}
		next.State, next.DwellMS = StateRecovering, 0
		return transition(current, next, evaluation), nil
	case StateRecovering:
		if evaluation.Decision.Predicate != PredicateClear {
			return transition(current, resetToFiring(next), evaluation), nil
		}
		next.DwellMS = addElapsed(next.DwellMS, elapsedMS)
		if evaluation.Decision.Immediate || next.DwellMS >= spec.RecoveryDwellMS {
			return transition(current, resolve(next, evaluation.EventMS), evaluation), nil
		}
		return Result{Snapshot: next}, nil
	default:
		return Result{}, ErrInvalidSnapshot
	}
}

func Supersede(spec Spec, current Snapshot, eventMS int64, evidenceHash string) (Result, error) {
	if err := spec.Validate(); err != nil {
		return Result{}, err
	}
	if err := validateSnapshot(spec, current); err != nil {
		return Result{}, err
	}
	if current.State == StateResolved || current.State == StateSuperseded {
		return Result{}, ErrTerminalState
	}
	// Supersession is a rule lifecycle transition, not a condition evaluation.
	// Validate its event envelope independently of the instance's current
	// (possibly unknown) evidence quality, while retaining that quality below.
	evaluation := Evaluation{EventMS: eventMS, EvidenceHash: evidenceHash, Decision: known(PredicateHold, DataValid, "rule_superseded", true)}
	if err := validateEvaluation(evaluation); err != nil {
		return Result{}, err
	}
	next := current
	next.State, next.DwellMS, next.LastEvalMS = StateSuperseded, 0, eventMS
	return transition(current, next, evaluation), nil
}

func transition(previous, next Snapshot, evaluation Evaluation) Result {
	next.TransitionSeq = previous.TransitionSeq + 1
	return Result{
		Snapshot: next,
		Transition: &Transition{
			Sequence:      next.TransitionSeq,
			PreviousState: previous.State,
			NewState:      next.State,
			EventMS:       evaluation.EventMS,
			EvidenceHash:  evaluation.EvidenceHash,
		},
	}
}

func openFiring(value Snapshot, eventMS int64) Snapshot {
	value.State, value.DwellMS = StateFiring, 0
	if value.OpenedMS == nil {
		opened := eventMS
		value.OpenedMS = &opened
	}
	value.ResolvedMS = nil
	return value
}

func resetToOK(value Snapshot) Snapshot {
	value.State, value.DwellMS = StateOK, 0
	return value
}

func resetToFiring(value Snapshot) Snapshot {
	value.State, value.DwellMS = StateFiring, 0
	return value
}

func resolve(value Snapshot, eventMS int64) Snapshot {
	value.State, value.DwellMS = StateResolved, 0
	resolved := eventMS
	value.ResolvedMS = &resolved
	return value
}

func addElapsed(current, elapsed int64) int64 {
	if elapsed > math.MaxInt64-current {
		return math.MaxInt64
	}
	return current + elapsed
}

func validateSnapshot(spec Spec, value Snapshot) error {
	if value.RuleID != spec.RuleID || value.RuleVersion != spec.Version || value.ScopeFingerprint != spec.ScopeFingerprint || value.IncarnationPolicy != spec.IncarnationPolicy || value.ActiveGeneration < 1 || !validState(value.State) || !validDataState(value.DataState) || value.DwellMS < 0 || value.LastEvalMS < 0 || value.TransitionSeq < 0 {
		return ErrInvalidSnapshot
	}
	if (value.State != StatePending && value.State != StateRecovering) && value.DwellMS != 0 {
		return ErrInvalidSnapshot
	}
	if (value.State == StateFiring || value.State == StateRecovering || value.State == StateResolved) && value.OpenedMS == nil {
		return ErrInvalidSnapshot
	}
	if value.State == StateResolved && value.ResolvedMS == nil || value.State != StateResolved && value.ResolvedMS != nil {
		return ErrInvalidSnapshot
	}
	if (value.AcknowledgedBy == nil) != (value.AcknowledgedMS == nil) {
		return ErrInvalidSnapshot
	}
	for _, timeValue := range []*int64{value.LastValidMS, value.OpenedMS, value.ResolvedMS, value.AcknowledgedMS, value.MutedUntilMS} {
		if timeValue != nil && *timeValue < 0 {
			return ErrInvalidSnapshot
		}
	}
	return nil
}

func validateEvaluation(value Evaluation) error {
	decision := value.Decision
	if value.EventMS < 0 || value.ElapsedMS < 0 || !validDataState(decision.DataState) || !validPredicate(decision.Predicate) || !safeReason(decision.Reason) || !hashPattern.MatchString(value.EvidenceHash) {
		return ErrInvalidInput
	}
	if !decision.Evaluable && decision.Predicate != PredicateHold || decision.Evaluable && decision.DataState != DataValid && decision.DataState != DataIncompatible {
		return ErrInvalidInput
	}
	return nil
}

func validState(value State) bool {
	switch value {
	case StateOK, StatePending, StateFiring, StateRecovering, StateResolved, StateSuperseded:
		return true
	default:
		return false
	}
}

func validDataState(value DataState) bool {
	switch value {
	case DataValid, DataUnknown, DataStale, DataIncompatible:
		return true
	default:
		return false
	}
}

func validPredicate(value Predicate) bool {
	return value == PredicateMatch || value == PredicateClear || value == PredicateHold
}

func safeReason(value string) bool {
	if len(value) < 1 || len(value) > 128 || value[0] < 'a' || value[0] > 'z' {
		return false
	}
	for _, char := range value {
		if !(char >= 'a' && char <= 'z' || char >= '0' && char <= '9' || char == '_') {
			return false
		}
	}
	return true
}
