// Package alerts contains the deterministic, storage-independent alert
// predicate and state reducers. Callers own persistence, scheduling and
// notification delivery.
package alerts

import "errors"

type State string

const (
	StateOK         State = "OK"
	StatePending    State = "PENDING"
	StateFiring     State = "FIRING"
	StateRecovering State = "RECOVERING"
	StateResolved   State = "RESOLVED"
	StateSuperseded State = "superseded"
)

type DataState string

const (
	DataValid        DataState = "valid"
	DataUnknown      DataState = "unknown"
	DataStale        DataState = "stale"
	DataIncompatible DataState = "incompatible"
)

type Predicate string

const (
	PredicateMatch Predicate = "match"
	PredicateClear Predicate = "clear"
	PredicateHold  Predicate = "hold"
)

type RuleType string

const (
	RuleOllamaUnreachable       RuleType = "ollama_unreachable"
	RuleHostNotReporting        RuleType = "host_not_reporting"
	RuleSourceMissing           RuleType = "source_missing"
	RuleMemoryPressure          RuleType = "memory_pressure"
	RuleHeavyCPU                RuleType = "heavy_cpu"
	RuleObservedRequestDuration RuleType = "observed_request_duration"
	RuleDiskMonitorHealth       RuleType = "disk_monitor_health"
)

type IncarnationPolicy string

const (
	IncarnationStableScope   IncarnationPolicy = "stable_scope"
	IncarnationTargetEpisode IncarnationPolicy = "target_reachability_episode"
	IncarnationSource        IncarnationPolicy = "source_incarnation"
	IncarnationPopulation    IncarnationPolicy = "request_population"
)

type Spec struct {
	RuleID            string
	Version           int64
	Type              RuleType
	ScopeFingerprint  string
	IncarnationPolicy IncarnationPolicy
	TriggerDwellMS    int64
	RecoveryDwellMS   int64
	RequestDuration   *RequestDurationSpec
}

type RequestDurationSpec struct {
	MetricID    string
	Statistic   string
	ThresholdMS float64
}

type Input struct {
	DataState      DataState
	Reachability   *ReachabilityInput
	Heartbeat      *HeartbeatInput
	Source         *SourceInput
	MemoryPressure *MemoryPressureInput
	CPU            *CPUInput
	Request        *RequestDurationInput
	MonitorHealth  *MonitorHealthInput
}

type ReachabilityInput struct {
	CollectorFresh   bool
	Reachable        *bool
	StartupGraceOpen bool
	Incompatible     bool
}

type HeartbeatInput struct {
	AgeMS int64
}

type SourceInput struct {
	HostFresh    bool
	Available    *bool
	Incompatible bool
}

type MemoryPressureInput struct {
	Level     string
	Certified bool
}

type CPUInput struct {
	BusyRatio *float64
}

type RequestDurationInput struct {
	MetricID                 string
	ExactCompletedPopulation bool
	CompletedN               int
	ValidN                   int
	MedianMS                 *float64
	P95MS                    *float64
}

type MonitorHealthInput struct {
	StoragePressure     *bool
	EvaluatorLagMS      *int64
	FinalDeliveryFailed *bool
}

// Snapshot maps directly to alert_instances columns. IncarnationPolicy is
// part of the reducer identity and is retained with the rule/scope contract;
// it is not a fluctuating evidence value.
type Snapshot struct {
	RuleID            string
	RuleVersion       int64
	ScopeFingerprint  string
	IncarnationPolicy IncarnationPolicy
	ActiveGeneration  int64
	State             State
	DataState         DataState
	DwellMS           int64
	LastEvalMS        int64
	LastValidMS       *int64
	OpenedMS          *int64
	ResolvedMS        *int64
	AcknowledgedBy    *string
	AcknowledgedMS    *int64
	MutedUntilMS      *int64
	TransitionSeq     int64
}

type Decision struct {
	Predicate Predicate
	Evaluable bool
	DataState DataState
	Reason    string
	Immediate bool
}

// Evaluation carries a wall timestamp only for persisted event fields. Dwell
// is advanced solely by ElapsedMS, supplied from the hub monotonic clock.
type Evaluation struct {
	EventMS      int64
	ElapsedMS    int64
	HubRestarted bool
	Decision     Decision
	EvidenceHash string
}

type Transition struct {
	Sequence      int64
	PreviousState State
	NewState      State
	EventMS       int64
	EvidenceHash  string
}

type Result struct {
	Snapshot   Snapshot
	Transition *Transition
}

var (
	ErrInvalidSpec     = errors.New("invalid alert rule specification")
	ErrInvalidSnapshot = errors.New("invalid alert state snapshot")
	ErrInvalidInput    = errors.New("invalid alert evaluation")
	ErrTerminalState   = errors.New("alert state is terminal")
)
