package query

import (
	"encoding/json"

	"rmt.local/monitor/internal/domain"
)

type SourceState string

const (
	SourceNotObserved  SourceState = "not_observed"
	SourceFresh        SourceState = "fresh"
	SourceStale        SourceState = "stale"
	SourceDisconnected SourceState = "disconnected"
	SourceUnavailable  SourceState = "unavailable"
	SourceIncompatible SourceState = "incompatible"
	SourcePartial      SourceState = "partial"
)

type MetricReading struct {
	Metric         string                `json:"metric"`
	Unit           string                `json:"unit"`
	ScopeID        string                `json:"scope_id"`
	SourceID       *string               `json:"source_id"`
	ObservedMS     *int64                `json:"observed_ms"`
	AgeMS          *int64                `json:"age_ms"`
	Value          json.RawMessage       `json:"value"`
	Quality        domain.Quality        `json:"quality"`
	MissingReason  *domain.MissingReason `json:"missing_reason"`
	MethodRevision string                `json:"method_revision"`
	Provenance     domain.Provenance     `json:"provenance"`
}

type Host struct {
	ID                       string                      `json:"id"`
	DisplayName              string                      `json:"display_name"`
	Local                    bool                        `json:"local"`
	State                    string                      `json:"state"`
	SourceState              SourceState                 `json:"source_state"`
	CollectorVersion         *string                     `json:"collector_version"`
	CurrentSessionGeneration int64                       `json:"current_session_generation"`
	UpdatedMS                int64                       `json:"updated_ms"`
	HeartbeatMS              *int64                      `json:"heartbeat_ms"`
	HeartbeatAgeMS           *int64                      `json:"heartbeat_age_ms"`
	Metrics                  []MetricReading             `json:"metrics"`
	NetworkObservedMS        *int64                      `json:"network_observed_ms"`
	NetworkAgeMS             *int64                      `json:"network_age_ms"`
	NetworkObservations      []domain.NetworkObservation `json:"network_observations"`
	ProcessObservedMS        *int64                      `json:"process_observed_ms"`
	ProcessAgeMS             *int64                      `json:"process_age_ms"`
	ProcessSummary           *domain.ProcessSummary      `json:"process_summary"`
	Processes                []domain.ProcessObservation `json:"process_observations"`
	CapabilitiesMissing      []domain.MissingCapability  `json:"capabilities_missing"`
}

type Model struct {
	ID                    string                `json:"id"`
	Alias                 *string               `json:"alias"`
	Digest                *string               `json:"digest"`
	Loaded                bool                  `json:"loaded"`
	LoadState             string                `json:"load_state"`
	ReportedSizeBytes     *domain.Uint64Decimal `json:"reported_size_bytes"`
	ReportedSizeVRAMBytes *domain.Uint64Decimal `json:"reported_size_vram_bytes"`
	Provenance            domain.Provenance     `json:"provenance"`
}

type Target struct {
	ID                  string                     `json:"id"`
	HostID              string                     `json:"host_id"`
	HostLocal           bool                       `json:"host_local"`
	DisplayName         string                     `json:"display_name"`
	AdapterID           string                     `json:"adapter_id"`
	AssociationState    string                     `json:"association_state"`
	Retired             bool                       `json:"retired"`
	SourceState         SourceState                `json:"source_state"`
	Reachable           MetricReading              `json:"reachable"`
	ModelsState         SourceState                `json:"models_state"`
	ModelsObservedMS    *int64                     `json:"models_observed_ms"`
	ModelsAgeMS         *int64                     `json:"models_age_ms"`
	Models              []Model                    `json:"models"`
	CapabilitiesMissing []domain.MissingCapability `json:"capabilities_missing"`
}

type Overview struct {
	GeneratedMS               int64                      `json:"generated_ms"`
	DeploymentState           domain.DeploymentState     `json:"deployment_state"`
	State                     SourceState                `json:"state"`
	HostCount                 int                        `json:"host_count"`
	TargetCount               int                        `json:"target_count"`
	OpenIncidentCount         int                        `json:"open_incident_count"`
	ObservedRequestPopulation string                     `json:"observed_request_population"`
	HistoryAvailable          bool                       `json:"history_available"`
	Hosts                     []Host                     `json:"hosts"`
	Targets                   []Target                   `json:"targets"`
	CapabilitiesMissing       []domain.MissingCapability `json:"capabilities_missing"`
}

type MonitorHealth struct {
	GeneratedMS     int64  `json:"generated_ms"`
	StorageState    string `json:"storage_state"`
	CollectorStates []Host `json:"collector_states"`
	Gaps            int    `json:"gaps"`
	ClockWarnings   int    `json:"clock_warnings"`
}

type StorageForecast struct {
	PhysicalBytes          int64    `json:"physical_bytes"`
	ReservedBytes          int64    `json:"reserved_bytes"`
	LiveLimitBytes         int64    `json:"live_limit_bytes"`
	State                  string   `json:"state"`
	EstimatedDaysRemaining *float64 `json:"estimated_days_remaining"`
}

type Range struct {
	Start                      string `json:"start"`
	End                        string `json:"end"`
	StartMS                    int64  `json:"start_ms"`
	EndMS                      int64  `json:"end_ms"`
	InclusiveStartExclusiveEnd bool   `json:"inclusive_start_exclusive_end"`
}

type SeriesPoint struct {
	TimeMS        int64                 `json:"time_ms"`
	Value         json.RawMessage       `json:"value"`
	Quality       domain.Quality        `json:"quality"`
	MissingReason *domain.MissingReason `json:"missing_reason"`
	EpochID       *string               `json:"epoch_id"`
}

type Gap struct {
	StartMS int64                `json:"start_ms"`
	EndMS   int64                `json:"end_ms"`
	Reason  domain.MissingReason `json:"reason"`
}

type Series struct {
	SchemaVersion      string        `json:"schema_version"`
	Metric             string        `json:"metric"`
	DefinitionRevision string        `json:"definition_revision"`
	Unit               string        `json:"unit"`
	RequestedRange     Range         `json:"requested_range"`
	EffectiveRange     *Range        `json:"effective_range"`
	Population         string        `json:"population"`
	HostID             *string       `json:"host_id"`
	SourceID           *string       `json:"source_id"`
	ResolutionTier     *string       `json:"resolution_tier"`
	MethodRevision     *string       `json:"method_revision"`
	EpochID            *string       `json:"epoch_id"`
	ClockMethod        *string       `json:"clock_method"`
	CoverageRatio      *float64      `json:"coverage_ratio"`
	PopulationKey      any           `json:"population_key"`
	CompletedCount     int           `json:"completed_count"`
	CancelledCount     int           `json:"cancelled_count"`
	FailedCount        int           `json:"failed_count"`
	IncompleteCount    int           `json:"incomplete_count"`
	Summary            any           `json:"summary"`
	Points             []SeriesPoint `json:"points"`
	Gaps               []Gap         `json:"gaps"`
	Warnings           []string      `json:"warnings"`
}

type SeriesParameters struct {
	Scope, Metric, Resolution string
	Start, End                int64
}
