package domain

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"strconv"
	"time"
)

type Quality string

const (
	QualityMeasured                   Quality = "measured"
	QualityRuntimeReported            Quality = "runtime_reported"
	QualityOperatorImportedUnverified Quality = "operator_imported_unverified"
	QualityDerived                    Quality = "derived"
	QualityEstimated                  Quality = "estimated"
	QualityDeclared                   Quality = "declared"
	QualityInferred                   Quality = "inferred"
	QualityUnavailable                Quality = "unavailable"
)

type MissingReason string

const (
	MissingUnsupportedPlatform   MissingReason = "unsupported_platform_contract"
	MissingRuntimeUnverified     MissingReason = "runtime_version_unverified"
	MissingPermissionDenied      MissingReason = "permission_denied"
	MissingSourceTimeout         MissingReason = "source_timeout"
	MissingSourceUnreachable     MissingReason = "source_unreachable"
	MissingParseRejected         MissingReason = "parse_rejected"
	MissingLimitExceeded         MissingReason = "limit_exceeded"
	MissingIdentityUnverified    MissingReason = "identity_unverified"
	MissingAlignmentUnavailable  MissingReason = "alignment_unavailable"
	MissingPopulationNotObserved MissingReason = "population_not_observed"
	MissingNotApplicable         MissingReason = "not_applicable"
	MissingPopulationPartial     MissingReason = "population_expired_or_partial"
	MissingMethodUncertified     MissingReason = "method_uncertified"
	MissingFieldOmitted          MissingReason = "field_omitted"
	MissingCollectionGap         MissingReason = "collection_gap"
)

type Verification string

const (
	VerificationDirectCapture              Verification = "direct_capture"
	VerificationOperatorImportedUnverified Verification = "operator_imported_unverified"
	VerificationDeclaredUnverified         Verification = "declared_unverified"
	VerificationSyntheticFixture           Verification = "synthetic_fixture"
)

type Provenance struct {
	Source               string       `json:"source"`
	MethodRevision       string       `json:"method_revision"`
	Verification         Verification `json:"verification"`
	ObservedAtMS         *int64       `json:"observed_at_ms,omitempty"`
	SourceArtifactSHA256 *string      `json:"source_artifact_sha256,omitempty"`
}

const (
	ProvenanceDarwinAPI           = "darwin_api"
	ProvenanceRuntimeAPI          = "runtime_api"
	ProvenanceDirectClient        = "direct_client"
	ProvenanceOperatorImport      = "operator_import"
	ProvenanceOperatorDeclaration = "operator_declaration"
	ProvenanceContractFixture     = "contract_fixture"
)

type MissingCapability struct {
	ID         string        `json:"id"`
	Reason     MissingReason `json:"reason"`
	DetailCode *string       `json:"detail_code"`
}

type Uint64Decimal string

func DecimalUint64(value uint64) Uint64Decimal { return Uint64Decimal(strconv.FormatUint(value, 10)) }

type MetricObservation[T any] struct {
	Value         *T             `json:"value"`
	Quality       Quality        `json:"quality"`
	MissingReason *MissingReason `json:"missing_reason"`
	Provenance    Provenance     `json:"provenance"`
}

func Measured[T any](value T, provenance Provenance) MetricObservation[T] {
	return MetricObservation[T]{Value: &value, Quality: QualityMeasured, Provenance: provenance}
}

func RuntimeReported[T any](value T, provenance Provenance) MetricObservation[T] {
	return MetricObservation[T]{Value: &value, Quality: QualityRuntimeReported, Provenance: provenance}
}

func Unavailable[T any](reason MissingReason, provenance Provenance) MetricObservation[T] {
	return MetricObservation[T]{Quality: QualityUnavailable, MissingReason: &reason, Provenance: provenance}
}

type PressureLevel string

const (
	PressureNormal   PressureLevel = "normal"
	PressureWarning  PressureLevel = "warning"
	PressureCritical PressureLevel = "critical"
)

type ComponentTiming struct {
	ObservedWallMS   int64         `json:"observed_wall_ms"`
	MonotonicStartNS Uint64Decimal `json:"monotonic_start_ns"`
	MonotonicEndNS   Uint64Decimal `json:"monotonic_end_ns"`
	DurationMS       int64         `json:"duration_ms"`
}

func NewComponentTiming(wall time.Time, startNS, endNS uint64) ComponentTiming {
	duration := int64(0)
	if endNS >= startNS {
		duration = int64((endNS - startNS) / uint64(time.Millisecond))
	}
	return ComponentTiming{ObservedWallMS: wall.UnixMilli(), MonotonicStartNS: DecimalUint64(startNS), MonotonicEndNS: DecimalUint64(endNS), DurationMS: duration}
}

type HostGauges struct {
	CPUBusyRatio    MetricObservation[float64]       `json:"host.cpu.busy_ratio"`
	PressureLevel   MetricObservation[PressureLevel] `json:"host.memory.pressure_level"`
	CompressedBytes MetricObservation[Uint64Decimal] `json:"host.memory.compressed_bytes"`
	SwapUsedBytes   MetricObservation[Uint64Decimal] `json:"host.memory.swap_used_bytes"`
	DiskFreeBytes   MetricObservation[Uint64Decimal] `json:"host.disk.free_bytes"`
}

type HostObservation struct {
	ComponentTimings    HostComponentTimings `json:"component_timings"`
	Gauges              HostGauges           `json:"gauges"`
	NetworkObservations []NetworkObservation `json:"network_observations"`
	CapabilitiesMissing []MissingCapability  `json:"capabilities_missing"`
}

type HostComponentTimings struct {
	CPU        ComponentTiming `json:"cpu"`
	Pressure   ComponentTiming `json:"pressure"`
	Compressed ComponentTiming `json:"compressed"`
	Swap       ComponentTiming `json:"swap"`
	Disk       ComponentTiming `json:"disk"`
	Network    ComponentTiming `json:"network"`
}

type NetworkObservation struct {
	InterfaceID        string              `json:"interface_id"`
	BootID             string              `json:"boot_id"`
	CounterEpochID     string              `json:"counter_epoch_id"`
	Loopback           bool                `json:"loopback"`
	ReceivedBytesTotal *Uint64Decimal      `json:"received_bytes_total"`
	SentBytesTotal     *Uint64Decimal      `json:"sent_bytes_total"`
	Missing            []MissingCapability `json:"missing"`
	Provenance         Provenance          `json:"provenance"`
}

type ProcessCategory string

const (
	ProcessSelectedOllama ProcessCategory = "selected_ollama"
	ProcessRMT            ProcessCategory = "rmt"
	ProcessOtherSameUser  ProcessCategory = "other_same_user"
)

type AssociationQuality string

const (
	AssociationVerified           AssociationQuality = "verified"
	AssociationDeclaredUnverified AssociationQuality = "declared_unverified"
	AssociationAmbiguous          AssociationQuality = "ambiguous"
	AssociationNone               AssociationQuality = "none"
)

type ProcessObservation struct {
	HostID                 string              `json:"host_id"`
	BootID                 string              `json:"boot_id"`
	PID                    int                 `json:"pid"`
	ProcessStartIdentity   Uint64Decimal       `json:"process_start_identity"`
	ProcessKey             string              `json:"process_key"`
	DisplayBasename        *string             `json:"display_basename"`
	Category               ProcessCategory     `json:"category"`
	TargetID               *string             `json:"target_id"`
	AssociationQuality     AssociationQuality  `json:"association_quality"`
	CPUBusyRatio           *float64            `json:"cpu_busy_ratio"`
	PhysicalFootprintBytes *Uint64Decimal      `json:"physical_footprint_bytes"`
	Missing                []MissingCapability `json:"missing"`
	Provenance             Provenance          `json:"provenance"`
}

type ProcessSummary struct {
	EligiblePIDCount      int    `json:"eligible_pid_count"`
	ExaminedPIDCount      int    `json:"examined_pid_count"`
	PermissionDeniedCount int    `json:"permission_denied_count"`
	RetainedProcessCount  int    `json:"retained_process_count"`
	EnumerationTruncated  bool   `json:"enumeration_truncated"`
	Coverage              string `json:"coverage"`
	MethodRevision        string `json:"method_revision"`
	SampleIntervalMS      int64  `json:"sample_interval_ms"`
	ScanDurationMS        int64  `json:"scan_duration_ms"`
}

type ProcessCollection struct {
	Timing      ComponentTiming      `json:"timing"`
	Processes   []ProcessObservation `json:"process_observations"`
	Summary     ProcessSummary       `json:"process_summary"`
	Association EndpointAssociation  `json:"endpoint_association"`
}

type EndpointAssociation struct {
	TargetID             string               `json:"target_id"`
	EndpointHash         string               `json:"endpoint_hash"`
	TargetRevision       int                  `json:"target_revision"`
	ManifestRevision     int                  `json:"manifest_revision"`
	ManifestSHA256       string               `json:"manifest_sha256"`
	SelectorSHA256       string               `json:"selector_sha256"`
	IdentityRevision     string               `json:"identity_revision"`
	RuntimeVersion       *string              `json:"runtime_version"`
	RuntimeSourcePinID   *string              `json:"runtime_source_pin_id"`
	PID                  *int                 `json:"pid"`
	ProcessStartIdentity *Uint64Decimal       `json:"process_start_identity"`
	ProcessKey           *string              `json:"process_key"`
	Quality              AssociationQuality   `json:"quality"`
	Reason               *MissingReason       `json:"reason"`
	VerifiedExit         *VerifiedProcessExit `json:"verified_exit"`
	Provenance           Provenance           `json:"provenance"`
}

type VerifiedProcessExit struct {
	PID                  int           `json:"pid"`
	ProcessStartIdentity Uint64Decimal `json:"process_start_identity"`
	ProcessKey           string        `json:"process_key"`
	LastSeenMS           int64         `json:"last_seen_ms"`
}

type ModelObservation struct {
	ModelID               string              `json:"model_id"`
	Digest                string              `json:"digest"`
	Loaded                bool                `json:"loaded"`
	ReportedSizeBytes     *Uint64Decimal      `json:"reported_size_bytes"`
	ReportedSizeVRAMBytes *Uint64Decimal      `json:"reported_size_vram_bytes"`
	Missing               []MissingCapability `json:"missing"`
	Provenance            Provenance          `json:"provenance"`
}

type RuntimeObservation struct {
	ComponentTimings    RuntimeComponentTimings   `json:"component_timings"`
	Reachable           MetricObservation[bool]   `json:"runtime.reachable"`
	Version             *string                   `json:"version"`
	Build               *string                   `json:"build"`
	Config              *RuntimeConfigObservation `json:"config_observation,omitempty"`
	Models              []ModelObservation        `json:"model_observations"`
	CapabilitiesMissing []MissingCapability       `json:"capabilities_missing"`
}

type RuntimeComponentTimings struct {
	Reachability ComponentTiming  `json:"reachability"`
	Version      *ComponentTiming `json:"version,omitempty"`
	LoadedModels *ComponentTiming `json:"loaded_models,omitempty"`
	Tags         *ComponentTiming `json:"tags,omitempty"`
	SelectedShow *ComponentTiming `json:"selected_show,omitempty"`
	Config       *ComponentTiming `json:"config,omitempty"`
}

// RuntimeConfigObservation is a closed passive snapshot. It deliberately
// excludes arbitrary runtime metadata, process arguments, environment, model
// templates and request content. Previous* is collector evidence only; the
// hub validates it against an already-admitted config frame before recording
// a transition.
type RuntimeConfigObservation struct {
	TargetID           string                       `json:"target_id"`
	ConfigHash         string                       `json:"config_hash"`
	PreviousConfigHash *string                      `json:"previous_config_hash"`
	PreviousObservedMS *int64                       `json:"previous_observed_ms"`
	Fields             RuntimeConfigFields          `json:"fields"`
	FieldProvenance    RuntimeConfigFieldProvenance `json:"field_provenance"`
}

type RuntimeConfigFields struct {
	ServerVersion string                      `json:"server_version"`
	ServerBuild   *string                     `json:"server_build"`
	SelectedModel *RuntimeSelectedModelConfig `json:"selected_model"`
}

type RuntimeSelectedModelConfig struct {
	Alias         string  `json:"alias"`
	Digest        *string `json:"digest"`
	Format        *string `json:"format"`
	Family        *string `json:"family"`
	Quantization  *string `json:"quantization"`
	ContextLength *uint64 `json:"context_length"`
}

type RuntimeConfigFieldProvenance struct {
	ServerVersion Provenance                           `json:"server_version"`
	ServerBuild   *Provenance                          `json:"server_build"`
	SelectedModel *RuntimeSelectedModelFieldProvenance `json:"selected_model"`
}

type RuntimeSelectedModelFieldProvenance struct {
	Alias         Provenance  `json:"alias"`
	Digest        *Provenance `json:"digest"`
	Format        *Provenance `json:"format"`
	Family        *Provenance `json:"family"`
	Quantization  *Provenance `json:"quantization"`
	ContextLength *Provenance `json:"context_length"`
}

// RuntimeConfigHash hashes only admitted values and their declared source.
// Observation times and missing reasons cannot create configuration epochs.
func RuntimeConfigHash(fields RuntimeConfigFields, provenance RuntimeConfigFieldProvenance) string {
	type sourcedString struct {
		Value  string `json:"value"`
		Source string `json:"source"`
	}
	type sourcedUint struct {
		Value  uint64 `json:"value"`
		Source string `json:"source"`
	}
	type selected struct {
		Alias         sourcedString  `json:"alias"`
		Digest        *sourcedString `json:"digest"`
		Format        *sourcedString `json:"format"`
		Family        *sourcedString `json:"family"`
		Quantization  *sourcedString `json:"quantization"`
		ContextLength *sourcedUint   `json:"context_length"`
	}
	type canonical struct {
		ServerVersion sourcedString  `json:"server_version"`
		ServerBuild   *sourcedString `json:"server_build"`
		SelectedModel *selected      `json:"selected_model"`
	}
	value := canonical{ServerVersion: sourcedString{Value: fields.ServerVersion, Source: provenance.ServerVersion.Source}}
	if fields.ServerBuild != nil && provenance.ServerBuild != nil {
		value.ServerBuild = &sourcedString{Value: *fields.ServerBuild, Source: provenance.ServerBuild.Source}
	}
	if fields.SelectedModel != nil && provenance.SelectedModel != nil {
		model, sources := fields.SelectedModel, provenance.SelectedModel
		item := &selected{Alias: sourcedString{Value: model.Alias, Source: sources.Alias.Source}}
		if model.Digest != nil && sources.Digest != nil {
			item.Digest = &sourcedString{Value: *model.Digest, Source: sources.Digest.Source}
		}
		if model.Format != nil && sources.Format != nil {
			item.Format = &sourcedString{Value: *model.Format, Source: sources.Format.Source}
		}
		if model.Family != nil && sources.Family != nil {
			item.Family = &sourcedString{Value: *model.Family, Source: sources.Family.Source}
		}
		if model.Quantization != nil && sources.Quantization != nil {
			item.Quantization = &sourcedString{Value: *model.Quantization, Source: sources.Quantization.Source}
		}
		if model.ContextLength != nil && sources.ContextLength != nil {
			item.ContextLength = &sourcedUint{Value: *model.ContextLength, Source: sources.ContextLength.Source}
		}
		value.SelectedModel = item
	}
	encoded, _ := json.Marshal(value)
	digest := sha256.Sum256(encoded)
	return hex.EncodeToString(digest[:])
}
