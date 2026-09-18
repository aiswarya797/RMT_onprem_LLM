package protocol

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"regexp"
	"strconv"
	"time"
	"unicode/utf8"

	"rmt.local/monitor/internal/domain"
)

const (
	MaxBatchBytes     int64 = 4 << 20
	MaxInventoryBytes int64 = 1 << 20
	MaxStatusBytes    int64 = 4 << 10
	MaxFrameBytes           = 256 << 10
	MaxProtocolDepth        = 32
	MaxUint53         int64 = 9007199254740991
)

var (
	uuidPattern         = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$`)
	sha256Pattern       = regexp.MustCompile(`^[0-9a-f]{64}$`)
	runtimePinPattern   = regexp.MustCompile(`^(ollama-[0-9]+\.[0-9]+\.[0-9]+-source|runtime-version-unverified)$`)
	collectorDecodeSlot = make(chan struct{}, 1)
	ErrDecoderBusy      = errors.New("collector decoder busy")
)

type MetricValue struct {
	Value         json.RawMessage       `json:"value"`
	Quality       domain.Quality        `json:"quality"`
	MissingReason *domain.MissingReason `json:"missing_reason"`
	Provenance    domain.Provenance     `json:"provenance"`
}

type CollectorFrame struct {
	SourceID            string                           `json:"source_id"`
	Sequence            int64                            `json:"sequence"`
	ObservedWallMS      int64                            `json:"observed_wall_ms"`
	EstimatedUTCMS      *int64                           `json:"estimated_utc_ms"`
	OffsetMS            *int64                           `json:"offset_ms"`
	UncertaintyMS       *int64                           `json:"uncertainty_ms"`
	MonotonicStartNS    domain.Uint64Decimal             `json:"monotonic_start_ns"`
	MonotonicEndNS      domain.Uint64Decimal             `json:"monotonic_end_ns"`
	DurationMS          int64                            `json:"duration_ms"`
	DefinitionRevision  string                           `json:"definition_revision"`
	IncarnationID       *string                          `json:"incarnation_id"`
	Quality             domain.Quality                   `json:"quality"`
	Provenance          domain.Provenance                `json:"provenance"`
	Gauges              map[string]MetricValue           `json:"gauges"`
	NetworkObservations []domain.NetworkObservation      `json:"network_observations"`
	ModelObservations   []domain.ModelObservation        `json:"model_observations"`
	ProcessObservations []domain.ProcessObservation      `json:"process_observations"`
	ProcessSummary      *domain.ProcessSummary           `json:"process_summary"`
	EndpointAssociation *domain.EndpointAssociation      `json:"endpoint_association,omitempty"`
	ConfigObservation   *domain.RuntimeConfigObservation `json:"config_observation,omitempty"`
	CapabilitiesMissing []domain.MissingCapability       `json:"capabilities_missing"`
}

type CollectorBatch struct {
	Protocol           string           `json:"protocol"`
	DeliveryMode       string           `json:"delivery_mode"`
	SecurityGeneration string           `json:"security_generation"`
	SessionGeneration  int64            `json:"session_generation"`
	DeploymentID       string           `json:"deployment_id"`
	HostID             string           `json:"host_id"`
	CollectorBootID    string           `json:"collector_boot_id"`
	BatchID            string           `json:"batch_id"`
	Frames             []CollectorFrame `json:"frames"`
}

type ControlRequest struct {
	RequestID string `json:"request_id"`
	HostID    string `json:"host_id"`
	TargetID  string `json:"target_id"`
	Operation string `json:"operation"`
	ExpiresMS int64  `json:"expires_ms"`
}

type BatchACK struct {
	BatchID         string           `json:"batch_id"`
	Durable         bool             `json:"durable"`
	Accepted        int              `json:"accepted"`
	Duplicate       int              `json:"duplicate"`
	HubTimeMS       int64            `json:"hub_time_ms"`
	NextSendAfterMS int              `json:"next_send_after_ms"`
	ControlRequests []ControlRequest `json:"control_requests"`
}

type SessionActivation struct {
	Protocol                   string `json:"protocol"`
	DeploymentID               string `json:"deployment_id"`
	HostID                     string `json:"host_id"`
	SecurityGeneration         string `json:"security_generation"`
	ActivationRequestID        string `json:"activation_request_id"`
	CollectorBootID            string `json:"collector_boot_id"`
	ExpectedPreviousGeneration int64  `json:"expected_previous_generation"`
}

type SessionResult struct {
	ActivationRequestID string `json:"activation_request_id"`
	SecurityGeneration  string `json:"security_generation"`
	SessionGeneration   int64  `json:"session_generation"`
	CollectorBootID     string `json:"collector_boot_id"`
	ActivatedMS         int64  `json:"activated_ms"`
	Current             bool   `json:"current"`
}

type InventorySource struct {
	SourceID           string  `json:"source_id"`
	Kind               string  `json:"kind"`
	TargetID           *string `json:"target_id"`
	CapabilityRevision string  `json:"capability_revision"`
	Active             bool    `json:"active"`
}

type InventoryTarget struct {
	TargetID            string `json:"target_id"`
	AdapterID           string `json:"adapter_id"`
	LocalSelectorSHA256 string `json:"local_selector_sha256"`
	AssociationState    string `json:"association_state"`
}

type InventoryModel struct {
	ModelID        string  `json:"model_id"`
	TargetID       string  `json:"target_id"`
	Alias          string  `json:"alias"`
	Digest         *string `json:"digest"`
	ReportedLoaded bool    `json:"reported_loaded"`
}

type CollectorInventory struct {
	Protocol           string            `json:"protocol"`
	DeploymentID       string            `json:"deployment_id"`
	HostID             string            `json:"host_id"`
	SecurityGeneration string            `json:"security_generation"`
	SessionGeneration  int64             `json:"session_generation"`
	CollectorBootID    string            `json:"collector_boot_id"`
	InventoryRevision  string            `json:"inventory_revision"`
	Sources            []InventorySource `json:"sources"`
	Targets            []InventoryTarget `json:"targets"`
	Models             []InventoryModel  `json:"models"`
}

type InventoryResult struct {
	InventoryRevision string           `json:"inventory_revision"`
	Durable           bool             `json:"durable"`
	Current           bool             `json:"current"`
	HubTimeMS         int64            `json:"hub_time_ms"`
	ControlRequests   []ControlRequest `json:"control_requests"`
}

type SourceState struct {
	SourceID       string                `json:"source_id"`
	State          string                `json:"state"`
	LastSuccessMS  *int64                `json:"last_success_ms"`
	FailureReason  *domain.MissingReason `json:"failure_reason"`
	FirstFailureMS *int64                `json:"first_failure_ms"`
	FailureCount   int64                 `json:"failure_count"`
}

type LossInterval struct {
	SourceID  string `json:"source_id"`
	StartMS   int64  `json:"start_ms"`
	EndMS     int64  `json:"end_ms"`
	LostCount int64  `json:"lost_count"`
	Reason    string `json:"reason"`
}

type SourceStatus struct {
	Protocol           string         `json:"protocol"`
	DeploymentID       string         `json:"deployment_id"`
	HostID             string         `json:"host_id"`
	SecurityGeneration string         `json:"security_generation"`
	SessionGeneration  int64          `json:"session_generation"`
	CollectorBootID    string         `json:"collector_boot_id"`
	Sequence           int64          `json:"sequence"`
	ObservedWallMS     int64          `json:"observed_wall_ms"`
	Heartbeat          string         `json:"heartbeat"`
	Sources            []SourceState  `json:"sources"`
	LossIntervals      []LossInterval `json:"loss_intervals"`
}

type StatusACK struct {
	CollectorBootID string           `json:"collector_boot_id"`
	Sequence        int64            `json:"sequence"`
	Durable         bool             `json:"durable"`
	Duplicate       bool             `json:"duplicate"`
	HubTimeMS       int64            `json:"hub_time_ms"`
	ControlRequests []ControlRequest `json:"control_requests"`
}

func DecodeCollectorBatch(reader io.Reader) (CollectorBatch, error) {
	var value CollectorBatch
	data, err := decodeStrictJSON(reader, MaxBatchBytes, &value)
	if err != nil {
		return value, err
	}
	if err := validateBatchShape(data); err != nil {
		return value, err
	}
	return value, value.Validate()
}
func DecodeCollectorInventory(reader io.Reader) (CollectorInventory, error) {
	var value CollectorInventory
	data, err := decodeStrictJSON(reader, MaxInventoryBytes, &value)
	if err != nil {
		return value, err
	}
	if err := validateInventoryShape(data); err != nil {
		return value, err
	}
	return value, value.Validate()
}
func DecodeSessionActivation(reader io.Reader) (SessionActivation, error) {
	var value SessionActivation
	data, err := decodeStrictJSON(reader, MaxInventoryBytes, &value)
	if err != nil {
		return value, err
	}
	if _, err := requireObject(data, []string{"protocol", "deployment_id", "host_id", "security_generation", "activation_request_id", "collector_boot_id", "expected_previous_generation"}); err != nil {
		return value, err
	}
	return value, value.Validate()
}
func DecodeSourceStatus(reader io.Reader) (SourceStatus, error) {
	var value SourceStatus
	data, err := decodeStrictJSON(reader, MaxStatusBytes, &value)
	if err != nil {
		return value, err
	}
	if err := validateStatusShape(data); err != nil {
		return value, err
	}
	return value, value.Validate()
}

func (b CollectorBatch) Validate() error {
	if b.Protocol != domain.ProtocolVersion || !validUUIDs(b.SecurityGeneration, b.DeploymentID, b.HostID, b.CollectorBootID, b.BatchID) {
		return errors.New("invalid batch identity or protocol")
	}
	if b.DeliveryMode != "current" && b.DeliveryMode != "replay" {
		return errors.New("invalid delivery_mode")
	}
	if b.SessionGeneration < 1 || b.SessionGeneration > MaxUint53 || len(b.Frames) < 1 || len(b.Frames) > 64 {
		return errors.New("invalid session generation or frame count")
	}
	seen := map[string]bool{}
	for i := range b.Frames {
		if err := b.Frames[i].Validate(); err != nil {
			return fmt.Errorf("frame[%d]: %w", i, err)
		}
		key := b.Frames[i].SourceID + "/" + strconv.FormatInt(b.Frames[i].Sequence, 10)
		if seen[key] {
			return errors.New("duplicate frame key in batch")
		}
		seen[key] = true
	}
	return nil
}

func (f CollectorFrame) Validate() error {
	if !validUUID(f.SourceID) || f.Sequence < 0 || f.Sequence > MaxUint53 || f.ObservedWallMS < 0 || f.ObservedWallMS > MaxUint53 || f.DurationMS < 0 || f.DurationMS > 5000 || f.DefinitionRevision != domain.RegistryRevision {
		return errors.New("invalid frame identity, time, or definition")
	}
	start, err := parseDecimal(f.MonotonicStartNS)
	if err != nil {
		return err
	}
	end, err := parseDecimal(f.MonotonicEndNS)
	if err != nil || end < start {
		return errors.New("invalid monotonic boundary")
	}
	elapsedNS := end - start
	claimedNS := uint64(f.DurationMS) * uint64(time.Millisecond)
	if elapsedNS > claimedNS+uint64(time.Millisecond) || claimedNS > elapsedNS+uint64(time.Millisecond) {
		return errors.New("duration contradicts monotonic boundary")
	}
	if f.EstimatedUTCMS != nil && (*f.EstimatedUTCMS < 0 || *f.EstimatedUTCMS > MaxUint53) {
		return errors.New("invalid estimated UTC")
	}
	if f.OffsetMS != nil && (*f.OffsetMS < -86400000 || *f.OffsetMS > 86400000) {
		return errors.New("invalid clock offset")
	}
	if f.UncertaintyMS != nil && (*f.UncertaintyMS < 0 || *f.UncertaintyMS > 60000) {
		return errors.New("invalid uncertainty")
	}
	if f.IncarnationID != nil && !validUUID(*f.IncarnationID) {
		return errors.New("invalid incarnation")
	}
	if !validQuality(f.Quality) || validateProvenance(f.Provenance) != nil {
		return errors.New("invalid frame quality or provenance")
	}
	if len(f.Gauges) > 6 || len(f.NetworkObservations) > 8 || len(f.ModelObservations) > 2 || len(f.ProcessObservations) > 32 || len(f.CapabilitiesMissing) > 32 {
		return errors.New("frame cardinality exceeded")
	}
	allowed := map[string]bool{"host.cpu.busy_ratio": true, "host.memory.pressure_level": true, "host.memory.compressed_bytes": true, "host.memory.swap_used_bytes": true, "host.disk.free_bytes": true, "runtime.reachable": true}
	for id, value := range f.Gauges {
		if !allowed[id] || validateMetricValue(id, value) != nil {
			return fmt.Errorf("invalid gauge %q", id)
		}
	}
	for _, v := range f.NetworkObservations {
		if !sha256Pattern.MatchString(v.InterfaceID) || !validUUIDs(v.BootID, v.CounterEpochID) || len(v.Missing) > 2 || validateOptionalDecimal(v.ReceivedBytesTotal) != nil || validateOptionalDecimal(v.SentBytesTotal) != nil || validateProvenance(v.Provenance) != nil {
			return errors.New("invalid network observation")
		}
		for _, missing := range v.Missing {
			if validateMissing(missing) != nil {
				return errors.New("invalid network missing capability")
			}
		}
	}
	networkKeys := make(map[string]struct{}, len(f.NetworkObservations))
	for _, v := range f.NetworkObservations {
		key := v.InterfaceID + "/" + v.BootID + "/" + v.CounterEpochID
		if _, exists := networkKeys[key]; exists {
			return errors.New("duplicate network observation")
		}
		networkKeys[key] = struct{}{}
	}
	modelIDs := make(map[string]struct{}, len(f.ModelObservations))
	for _, v := range f.ModelObservations {
		if !validUUID(v.ModelID) || !sha256Pattern.MatchString(v.Digest) || len(v.Missing) > 2 || validateOptionalDecimal(v.ReportedSizeBytes) != nil || validateOptionalDecimal(v.ReportedSizeVRAMBytes) != nil || validateProvenance(v.Provenance) != nil {
			return errors.New("invalid model observation")
		}
		if _, exists := modelIDs[v.ModelID]; exists {
			return errors.New("duplicate model observation")
		}
		modelIDs[v.ModelID] = struct{}{}
		for _, missing := range v.Missing {
			if validateMissing(missing) != nil {
				return errors.New("invalid model missing capability")
			}
		}
	}
	processKeys := make(map[string]struct{}, len(f.ProcessObservations))
	processesByKey := make(map[string]domain.ProcessObservation, len(f.ProcessObservations))
	for _, v := range f.ProcessObservations {
		validCategory := v.Category == domain.ProcessSelectedOllama || v.Category == domain.ProcessRMT || v.Category == domain.ProcessOtherSameUser
		validAssociation := v.AssociationQuality == domain.AssociationVerified || v.AssociationQuality == domain.AssociationDeclaredUnverified || v.AssociationQuality == domain.AssociationNone
		validName := v.DisplayBasename == nil || *v.DisplayBasename == "ollama" || *v.DisplayBasename == "llm-monitor" || *v.DisplayBasename == "llm-monitor-collector"
		if !validUUIDs(v.HostID, v.BootID) || v.PID < 1 || v.PID > 2147483647 || !validDecimal(v.ProcessStartIdentity) || !sha256Pattern.MatchString(v.ProcessKey) || !validCategory || !validAssociation || !validName || len(v.Missing) > 2 || (v.TargetID != nil && !validUUID(*v.TargetID)) || (v.CPUBusyRatio != nil && (*v.CPUBusyRatio < 0 || *v.CPUBusyRatio > 1 || math.IsNaN(*v.CPUBusyRatio) || math.IsInf(*v.CPUBusyRatio, 0))) || validateOptionalDecimal(v.PhysicalFootprintBytes) != nil || validateProvenance(v.Provenance) != nil {
			return errors.New("invalid process observation owner")
		}
		if v.AssociationQuality == domain.AssociationNone && v.TargetID != nil {
			return errors.New("unassociated process has target")
		}
		if (v.AssociationQuality == domain.AssociationVerified || v.AssociationQuality == domain.AssociationDeclaredUnverified) && v.TargetID == nil {
			return errors.New("associated process has no target")
		}
		if _, exists := processKeys[v.ProcessKey]; exists {
			return errors.New("duplicate process observation")
		}
		processKeys[v.ProcessKey] = struct{}{}
		processesByKey[v.ProcessKey] = v
		for _, missing := range v.Missing {
			if validateMissing(missing) != nil {
				return errors.New("invalid process missing capability")
			}
		}
	}
	if f.ProcessSummary != nil {
		s := f.ProcessSummary
		if s.EligiblePIDCount < 0 || s.EligiblePIDCount > 512 || s.ExaminedPIDCount < 0 || s.ExaminedPIDCount > 512 || s.PermissionDeniedCount < 0 || s.PermissionDeniedCount > 512 || s.RetainedProcessCount < 0 || s.RetainedProcessCount > 32 || s.RetainedProcessCount != len(f.ProcessObservations) || s.ExaminedPIDCount > s.EligiblePIDCount || s.PermissionDeniedCount > s.ExaminedPIDCount || (s.Coverage != "complete" && s.Coverage != "partial") || len(s.MethodRevision) < 1 || len(s.MethodRevision) > 256 || !safeString(s.MethodRevision) || s.SampleIntervalMS < 1000 || s.SampleIntervalMS > 60000 || s.ScanDurationMS < 0 || s.ScanDurationMS > 2000 {
			return errors.New("invalid process summary")
		}
	}
	if f.EndpointAssociation != nil {
		if err := validateEndpointAssociation(*f.EndpointAssociation, f.ObservedWallMS, processesByKey); err != nil {
			return err
		}
		if f.ProcessSummary == nil || len(f.Gauges) != 0 || len(f.NetworkObservations) != 0 || len(f.ModelObservations) != 0 || f.ConfigObservation != nil {
			return errors.New("endpoint association must have a process component frame")
		}
	}
	if f.ConfigObservation != nil {
		if err := validateRuntimeConfigObservation(*f.ConfigObservation, f.ObservedWallMS); err != nil {
			return err
		}
		if len(f.Gauges) != 0 || len(f.NetworkObservations) != 0 || len(f.ModelObservations) != 0 || len(f.ProcessObservations) != 0 || f.ProcessSummary != nil {
			return errors.New("config observation must have an independent component frame")
		}
	}
	for _, v := range f.CapabilitiesMissing {
		if err := validateMissing(v); err != nil {
			return err
		}
	}
	return nil
}

func validateEndpointAssociation(association domain.EndpointAssociation, observedMS int64, processesByKey map[string]domain.ProcessObservation) error {
	if !validUUID(association.TargetID) || !sha256Pattern.MatchString(association.EndpointHash) || association.TargetRevision < 1 || association.TargetRevision > 1_000_000 || association.ManifestRevision < 1 || association.ManifestRevision > 1_000_000 || !sha256Pattern.MatchString(association.ManifestSHA256) || !sha256Pattern.MatchString(association.SelectorSHA256) || !sha256Pattern.MatchString(association.IdentityRevision) || validateProvenance(association.Provenance) != nil || association.Provenance.Source != domain.ProvenanceDarwinAPI || association.Provenance.Verification != domain.VerificationDirectCapture {
		return errors.New("invalid endpoint association identity or provenance")
	}
	if association.RuntimeVersion != nil && !safeString(*association.RuntimeVersion) {
		return errors.New("invalid endpoint association runtime version")
	}
	if association.RuntimeSourcePinID != nil && !runtimePinPattern.MatchString(*association.RuntimeSourcePinID) {
		return errors.New("invalid endpoint association runtime source pin")
	}
	validQuality := association.Quality == domain.AssociationVerified || association.Quality == domain.AssociationDeclaredUnverified || association.Quality == domain.AssociationAmbiguous
	if !validQuality {
		return errors.New("invalid endpoint association quality")
	}
	hasIdentity := association.PID != nil || association.ProcessStartIdentity != nil || association.ProcessKey != nil
	if association.Quality == domain.AssociationVerified {
		if association.Reason != nil || association.RuntimeVersion == nil || association.RuntimeSourcePinID == nil || association.PID == nil || *association.PID < 1 || *association.PID > 2147483647 || association.ProcessStartIdentity == nil || !validDecimal(*association.ProcessStartIdentity) || association.ProcessKey == nil || !sha256Pattern.MatchString(*association.ProcessKey) || association.EndpointHash != association.SelectorSHA256 {
			return errors.New("incomplete verified endpoint association")
		}
		process, ok := processesByKey[*association.ProcessKey]
		if !ok || process.PID != *association.PID || process.ProcessStartIdentity != *association.ProcessStartIdentity || process.TargetID == nil || *process.TargetID != association.TargetID || process.AssociationQuality != domain.AssociationVerified {
			return errors.New("verified endpoint process is not retained in frame")
		}
	} else if hasIdentity || association.Reason == nil || !validMissingReason(*association.Reason) {
		return errors.New("unverified endpoint association carries identity or lacks reason")
	}
	if association.VerifiedExit != nil {
		exit := association.VerifiedExit
		if exit.PID < 1 || exit.PID > 2147483647 || !validDecimal(exit.ProcessStartIdentity) || !sha256Pattern.MatchString(exit.ProcessKey) || exit.LastSeenMS < 0 || exit.LastSeenMS > observedMS || exit.LastSeenMS > MaxUint53 {
			return errors.New("invalid verified endpoint exit")
		}
	}
	return nil
}

func validateRuntimeConfigObservation(observation domain.RuntimeConfigObservation, observedMS int64) error {
	if !validUUID(observation.TargetID) || !sha256Pattern.MatchString(observation.ConfigHash) || !safeString(observation.Fields.ServerVersion) {
		return errors.New("invalid runtime config identity")
	}
	if (observation.PreviousConfigHash == nil) != (observation.PreviousObservedMS == nil) {
		return errors.New("runtime config predecessor must be complete")
	}
	if observation.PreviousConfigHash != nil && (!sha256Pattern.MatchString(*observation.PreviousConfigHash) || *observation.PreviousObservedMS < 0 || *observation.PreviousObservedMS >= observedMS) {
		return errors.New("invalid runtime config predecessor")
	}
	if !runtimeAPIProvenance(observation.FieldProvenance.ServerVersion) {
		return errors.New("invalid server version provenance")
	}
	if (observation.Fields.ServerBuild == nil) != (observation.FieldProvenance.ServerBuild == nil) {
		return errors.New("server build provenance mismatch")
	}
	if observation.Fields.ServerBuild != nil && (!safeString(*observation.Fields.ServerBuild) || !runtimeAPIProvenance(*observation.FieldProvenance.ServerBuild)) {
		return errors.New("invalid server build field")
	}
	if (observation.Fields.SelectedModel == nil) != (observation.FieldProvenance.SelectedModel == nil) {
		return errors.New("selected model provenance mismatch")
	}
	if observation.Fields.SelectedModel != nil {
		model, provenance := observation.Fields.SelectedModel, observation.FieldProvenance.SelectedModel
		if !safeString(model.Alias) || !runtimeAPIProvenance(provenance.Alias) || !optionalConfigString(model.Digest, provenance.Digest, true) || !optionalConfigString(model.Format, provenance.Format, false) || !optionalConfigString(model.Family, provenance.Family, false) || !optionalConfigString(model.Quantization, provenance.Quantization, false) || (model.ContextLength == nil) != (provenance.ContextLength == nil) || (model.ContextLength != nil && (*model.ContextLength < 1 || *model.ContextLength > 131072 || !runtimeAPIProvenance(*provenance.ContextLength))) {
			return errors.New("invalid selected model config")
		}
	}
	if domain.RuntimeConfigHash(observation.Fields, observation.FieldProvenance) != observation.ConfigHash {
		return errors.New("runtime config hash mismatch")
	}
	return nil
}

func optionalConfigString(value *string, provenance *domain.Provenance, digest bool) bool {
	if (value == nil) != (provenance == nil) {
		return false
	}
	if value == nil {
		return true
	}
	if (digest && !sha256Pattern.MatchString(*value)) || (!digest && !safeString(*value)) {
		return false
	}
	return runtimeAPIProvenance(*provenance)
}

func runtimeAPIProvenance(value domain.Provenance) bool {
	return value.Source == domain.ProvenanceRuntimeAPI && value.Verification == domain.VerificationDirectCapture && validateProvenance(value) == nil
}

func (s SessionActivation) Validate() error {
	if s.Protocol != domain.ProtocolVersion || !validUUIDs(s.DeploymentID, s.HostID, s.SecurityGeneration, s.ActivationRequestID, s.CollectorBootID) || s.ExpectedPreviousGeneration < 0 || s.ExpectedPreviousGeneration >= MaxUint53 {
		return errors.New("invalid session activation")
	}
	return nil
}
func (i CollectorInventory) Validate() error {
	if i.Protocol != domain.ProtocolVersion || !validUUIDs(i.DeploymentID, i.HostID, i.SecurityGeneration, i.CollectorBootID) || i.SessionGeneration < 1 || i.SessionGeneration > MaxUint53 || !sha256Pattern.MatchString(i.InventoryRevision) || len(i.Sources) < 1 || len(i.Sources) > 8 || len(i.Targets) > 1 || len(i.Models) > 64 {
		return errors.New("invalid inventory envelope")
	}
	targets := map[string]bool{}
	for _, v := range i.Targets {
		if !validUUID(v.TargetID) || v.AdapterID != "ollama" || !sha256Pattern.MatchString(v.LocalSelectorSHA256) || (v.AssociationState != "verified" && v.AssociationState != "declared_unverified" && v.AssociationState != "ambiguous") {
			return errors.New("invalid inventory target")
		}
		targets[v.TargetID] = true
	}
	seenSources := map[string]bool{}
	for _, v := range i.Sources {
		if !validUUID(v.SourceID) || seenSources[v.SourceID] || v.CapabilityRevision != domain.RegistryRevision {
			return errors.New("invalid inventory source")
		}
		seenSources[v.SourceID] = true
		if v.Kind == "host" {
			if v.TargetID != nil {
				return errors.New("host source has target")
			}
		} else if v.Kind == "runtime" || v.Kind == "observed_request" {
			if v.TargetID == nil || (v.Active && !targets[*v.TargetID]) {
				return errors.New("runtime source target is absent")
			}
		} else {
			return errors.New("invalid source kind")
		}
	}
	seenModels := map[string]bool{}
	for _, v := range i.Models {
		if !validUUIDs(v.ModelID, v.TargetID) || !targets[v.TargetID] || seenModels[v.ModelID] || !safeString(v.Alias) || (v.Digest != nil && !sha256Pattern.MatchString(*v.Digest)) {
			return errors.New("invalid inventory model")
		}
		seenModels[v.ModelID] = true
	}
	return nil
}
func (s SourceStatus) Validate() error {
	if s.Protocol != domain.ProtocolVersion || !validUUIDs(s.DeploymentID, s.HostID, s.SecurityGeneration, s.CollectorBootID) || s.SessionGeneration < 1 || s.SessionGeneration > MaxUint53 || s.Sequence < 0 || s.Sequence > MaxUint53 || s.ObservedWallMS < 0 || s.ObservedWallMS > MaxUint53 || (s.Heartbeat != "fresh" && s.Heartbeat != "degraded") || len(s.Sources) > 8 || len(s.LossIntervals) > 16 {
		return errors.New("invalid source status envelope")
	}
	seenSources := make(map[string]struct{}, len(s.Sources))
	for _, v := range s.Sources {
		if !validUUID(v.SourceID) || v.FailureCount < 0 || v.FailureCount > 1_000_000 || (v.State != "fresh" && v.State != "stale" && v.State != "unavailable" && v.State != "incompatible") || (v.LastSuccessMS != nil && (*v.LastSuccessMS < 0 || *v.LastSuccessMS > MaxUint53)) || (v.FirstFailureMS != nil && (*v.FirstFailureMS < 0 || *v.FirstFailureMS > MaxUint53)) || (v.FailureReason != nil && !validMissingReason(*v.FailureReason)) {
			return errors.New("invalid source state")
		}
		if _, exists := seenSources[v.SourceID]; exists {
			return errors.New("duplicate source state")
		}
		seenSources[v.SourceID] = struct{}{}
	}
	for _, v := range s.LossIntervals {
		if !validUUID(v.SourceID) || v.StartMS < 0 || v.EndMS < v.StartMS || v.LostCount < 1 || v.LostCount > MaxUint53 || (v.Reason != "spool_capacity" && v.Reason != "spool_age" && v.Reason != "oversized_frame" && v.Reason != "corrupt_record") {
			return errors.New("invalid loss interval")
		}
	}
	return nil
}

func validateMetricValue(id string, v MetricValue) error {
	if len(v.Value) == 0 || !validQuality(v.Quality) || validateProvenance(v.Provenance) != nil {
		return errors.New("invalid metric observation")
	}
	if bytes.Equal(v.Value, []byte("null")) {
		if v.Quality != domain.QualityUnavailable || v.MissingReason == nil {
			return errors.New("null metric missing reason")
		}
	} else if v.MissingReason != nil {
		return errors.New("present metric has missing reason")
	}
	if bytes.Equal(v.Value, []byte("null")) {
		return nil
	}
	switch id {
	case "host.cpu.busy_ratio":
		var n float64
		if json.Unmarshal(v.Value, &n) != nil || math.IsNaN(n) || math.IsInf(n, 0) || n < 0 || n > 1 {
			return errors.New("invalid ratio")
		}
	case "host.memory.pressure_level":
		var level string
		if json.Unmarshal(v.Value, &level) != nil || (level != "normal" && level != "warning" && level != "critical") {
			return errors.New("invalid pressure")
		}
	case "host.memory.compressed_bytes", "host.memory.swap_used_bytes", "host.disk.free_bytes":
		var raw string
		if json.Unmarshal(v.Value, &raw) != nil {
			return errors.New("invalid decimal metric")
		}
		decimal := domain.Uint64Decimal(raw)
		if _, err := parseDecimal(decimal); err != nil {
			return err
		}
	case "runtime.reachable":
		var reachable bool
		if json.Unmarshal(v.Value, &reachable) != nil {
			return errors.New("invalid reachability")
		}
	}
	return nil
}
func validateProvenance(v domain.Provenance) error {
	validSource := v.Source == domain.ProvenanceDarwinAPI || v.Source == domain.ProvenanceRuntimeAPI || v.Source == domain.ProvenanceDirectClient || v.Source == domain.ProvenanceOperatorImport || v.Source == domain.ProvenanceOperatorDeclaration || v.Source == domain.ProvenanceContractFixture
	validVerification := v.Verification == domain.VerificationDirectCapture || v.Verification == domain.VerificationDeclaredUnverified || v.Verification == domain.VerificationSyntheticFixture || v.Verification == "operator_imported_unverified"
	if !validSource || !safeString(v.MethodRevision) || !validVerification || (v.ObservedAtMS != nil && (*v.ObservedAtMS < 0 || *v.ObservedAtMS > MaxUint53)) || (v.SourceArtifactSHA256 != nil && !sha256Pattern.MatchString(*v.SourceArtifactSHA256)) {
		return errors.New("invalid provenance")
	}
	return nil
}
func validateMissing(v domain.MissingCapability) error {
	if len(v.ID) < 3 || len(v.ID) > 96 || !validMetricID(v.ID) || !validMissingReason(v.Reason) {
		return errors.New("invalid missing capability")
	}
	if v.DetailCode != nil && (len(*v.DetailCode) < 1 || len(*v.DetailCode) > 64 || !validSafeCode(*v.DetailCode)) {
		return errors.New("invalid detail code")
	}
	return nil
}
func validQuality(v domain.Quality) bool {
	switch v {
	case domain.QualityMeasured, domain.QualityRuntimeReported, domain.QualityOperatorImportedUnverified, domain.QualityDerived, domain.QualityEstimated, domain.QualityDeclared, domain.QualityInferred, domain.QualityUnavailable:
		return true
	}
	return false
}
func validUUID(v string) bool { return uuidPattern.MatchString(v) }
func validUUIDs(values ...string) bool {
	for _, v := range values {
		if !validUUID(v) {
			return false
		}
	}
	return true
}
func parseDecimal(v domain.Uint64Decimal) (uint64, error) {
	raw := string(v)
	if raw == "" || (len(raw) > 1 && raw[0] == '0') {
		return 0, errors.New("invalid decimal uint64")
	}
	return strconv.ParseUint(raw, 10, 64)
}
func validateOptionalDecimal(v *domain.Uint64Decimal) error {
	if v == nil {
		return nil
	}
	_, err := parseDecimal(*v)
	return err
}
func validDecimal(v domain.Uint64Decimal) bool { _, err := parseDecimal(v); return err == nil }
func validMissingReason(v domain.MissingReason) bool {
	switch v {
	case domain.MissingUnsupportedPlatform, domain.MissingRuntimeUnverified, domain.MissingPermissionDenied, domain.MissingSourceTimeout, domain.MissingSourceUnreachable, domain.MissingParseRejected, domain.MissingLimitExceeded, domain.MissingIdentityUnverified, domain.MissingAlignmentUnavailable, domain.MissingPopulationNotObserved, domain.MissingNotApplicable, domain.MissingPopulationPartial, domain.MissingMethodUncertified, domain.MissingFieldOmitted, domain.MissingCollectionGap:
		return true
	}
	return false
}
func validMetricID(v string) bool {
	parts := bytes.Split([]byte(v), []byte{'.'})
	if len(parts) < 2 {
		return false
	}
	for _, part := range parts {
		if len(part) == 0 || part[0] < 'a' || part[0] > 'z' {
			return false
		}
		for _, c := range part {
			if !((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '_') {
				return false
			}
		}
	}
	return true
}
func validSafeCode(v string) bool {
	if len(v) == 0 || v[0] < 'a' || v[0] > 'z' {
		return false
	}
	for _, c := range v {
		if !((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '_') {
			return false
		}
	}
	return true
}

func safeString(v string) bool {
	if len(v) == 0 || len(v) > 256 || !utf8.ValidString(v) {
		return false
	}
	for _, r := range v {
		if r <= 0x1f || r == 0x7f {
			return false
		}
	}
	return true
}

// DecodeStrictJSON applies the collector contract's shared bounded JSON rules:
// one admitted decoder, a caller-owned byte limit, UTF-8, finite depth,
// duplicate-key rejection, closed typed fields and no trailing value.
func DecodeStrictJSON(reader io.Reader, limit int64, target any) error {
	_, err := decodeStrictJSON(reader, limit, target)
	return err
}

// DecodeStrictJSONWithCeiling is the same closed, duplicate-key rejecting
// decoder with an explicitly reviewed ceiling for non-collector envelopes.
// Callers still choose a smaller per-request limit.
func DecodeStrictJSONWithCeiling(reader io.Reader, limit, ceiling int64, target any) error {
	_, err := decodeStrictJSONWithCeiling(reader, limit, ceiling, target)
	return err
}

func decodeStrictJSON(reader io.Reader, limit int64, target any) ([]byte, error) {
	return decodeStrictJSONWithCeiling(reader, limit, MaxBatchBytes, target)
}

func decodeStrictJSONWithCeiling(reader io.Reader, limit, ceiling int64, target any) ([]byte, error) {
	if reader == nil || target == nil || limit < 1 || limit > ceiling {
		return nil, errors.New("invalid strict JSON decode request")
	}
	select {
	case collectorDecodeSlot <- struct{}{}:
		defer func() { <-collectorDecodeSlot }()
	default:
		return nil, ErrDecoderBusy
	}
	data, err := io.ReadAll(io.LimitReader(reader, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > limit {
		return nil, errors.New("collector body exceeds limit")
	}
	if !utf8.Valid(data) {
		return nil, errors.New("collector body is not UTF-8")
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber()
	if err := validateNoDuplicates(dec, 0); err != nil {
		return nil, err
	}
	if _, err := dec.Token(); err != io.EOF {
		return nil, errors.New("trailing JSON value")
	}
	dec = json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(target); err != nil {
		return nil, err
	}
	return data, nil
}

func requireObject(data []byte, required []string) (map[string]json.RawMessage, error) {
	var object map[string]json.RawMessage
	if err := json.Unmarshal(data, &object); err != nil || object == nil {
		return nil, errors.New("required JSON object is absent")
	}
	for _, key := range required {
		if _, ok := object[key]; !ok {
			return nil, fmt.Errorf("required property %q is absent", key)
		}
	}
	return object, nil
}

func requireArray(raw json.RawMessage, name string) ([]json.RawMessage, error) {
	if bytes.Equal(bytes.TrimSpace(raw), []byte("null")) {
		return nil, fmt.Errorf("required array %q is null", name)
	}
	var values []json.RawMessage
	if err := json.Unmarshal(raw, &values); err != nil || values == nil {
		return nil, fmt.Errorf("required array %q is invalid", name)
	}
	return values, nil
}

func requireNestedObject(raw json.RawMessage, name string, required []string) (map[string]json.RawMessage, error) {
	object, err := requireObject(raw, required)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", name, err)
	}
	return object, nil
}

func validateProvenanceShape(raw json.RawMessage, name string) error {
	_, err := requireNestedObject(raw, name, []string{"source", "method_revision", "verification"})
	return err
}

func validateMissingArray(raw json.RawMessage, name string) error {
	values, err := requireArray(raw, name)
	if err != nil {
		return err
	}
	for index, value := range values {
		if _, err := requireNestedObject(value, fmt.Sprintf("%s[%d]", name, index), []string{"id", "reason"}); err != nil {
			return err
		}
	}
	return nil
}

func validateBatchShape(data []byte) error {
	top, err := requireObject(data, []string{"protocol", "delivery_mode", "security_generation", "session_generation", "deployment_id", "host_id", "collector_boot_id", "batch_id", "frames"})
	if err != nil {
		return err
	}
	frames, err := requireArray(top["frames"], "frames")
	if err != nil {
		return err
	}
	frameKeys := []string{"source_id", "sequence", "observed_wall_ms", "estimated_utc_ms", "offset_ms", "uncertainty_ms", "monotonic_start_ns", "monotonic_end_ns", "duration_ms", "definition_revision", "incarnation_id", "quality", "provenance", "gauges", "network_observations", "model_observations", "process_observations", "process_summary", "capabilities_missing"}
	for index, raw := range frames {
		name := fmt.Sprintf("frames[%d]", index)
		frame, err := requireNestedObject(raw, name, frameKeys)
		if err != nil {
			return err
		}
		if err := validateProvenanceShape(frame["provenance"], name+".provenance"); err != nil {
			return err
		}
		var gauges map[string]json.RawMessage
		if err := json.Unmarshal(frame["gauges"], &gauges); err != nil || gauges == nil {
			return fmt.Errorf("%s.gauges must be an object", name)
		}
		for id, rawMetric := range gauges {
			metric, err := requireNestedObject(rawMetric, name+".gauges."+id, []string{"value", "quality", "missing_reason", "provenance"})
			if err != nil {
				return err
			}
			if err := validateProvenanceShape(metric["provenance"], name+".gauges."+id+".provenance"); err != nil {
				return err
			}
		}
		if err := validateObservationArray(frame["network_observations"], name+".network_observations", []string{"interface_id", "boot_id", "counter_epoch_id", "loopback", "received_bytes_total", "sent_bytes_total", "missing", "provenance"}); err != nil {
			return err
		}
		if err := validateObservationArray(frame["model_observations"], name+".model_observations", []string{"model_id", "digest", "loaded", "reported_size_bytes", "reported_size_vram_bytes", "missing", "provenance"}); err != nil {
			return err
		}
		if err := validateObservationArray(frame["process_observations"], name+".process_observations", []string{"host_id", "boot_id", "pid", "process_start_identity", "process_key", "display_basename", "category", "target_id", "association_quality", "cpu_busy_ratio", "physical_footprint_bytes", "missing", "provenance"}); err != nil {
			return err
		}
		if !bytes.Equal(bytes.TrimSpace(frame["process_summary"]), []byte("null")) {
			if _, err := requireNestedObject(frame["process_summary"], name+".process_summary", []string{"eligible_pid_count", "examined_pid_count", "permission_denied_count", "retained_process_count", "enumeration_truncated", "coverage", "method_revision", "sample_interval_ms", "scan_duration_ms"}); err != nil {
				return err
			}
		}
		if rawAssociation, ok := frame["endpoint_association"]; ok {
			association, err := requireNestedObject(rawAssociation, name+".endpoint_association", []string{"target_id", "endpoint_hash", "target_revision", "manifest_revision", "manifest_sha256", "selector_sha256", "identity_revision", "runtime_version", "runtime_source_pin_id", "pid", "process_start_identity", "process_key", "quality", "reason", "verified_exit", "provenance"})
			if err != nil {
				return err
			}
			if err := validateProvenanceShape(association["provenance"], name+".endpoint_association.provenance"); err != nil {
				return err
			}
			if !bytes.Equal(bytes.TrimSpace(association["verified_exit"]), []byte("null")) {
				if _, err := requireNestedObject(association["verified_exit"], name+".endpoint_association.verified_exit", []string{"pid", "process_start_identity", "process_key", "last_seen_ms"}); err != nil {
					return err
				}
			}
		}
		if rawConfig, ok := frame["config_observation"]; ok {
			config, err := requireNestedObject(rawConfig, name+".config_observation", []string{"target_id", "config_hash", "previous_config_hash", "previous_observed_ms", "fields", "field_provenance"})
			if err != nil {
				return err
			}
			fields, err := requireNestedObject(config["fields"], name+".config_observation.fields", []string{"server_version", "server_build", "selected_model"})
			if err != nil {
				return err
			}
			provenance, err := requireNestedObject(config["field_provenance"], name+".config_observation.field_provenance", []string{"server_version", "server_build", "selected_model"})
			if err != nil {
				return err
			}
			if err := validateProvenanceShape(provenance["server_version"], name+".config_observation.field_provenance.server_version"); err != nil {
				return err
			}
			if !bytes.Equal(bytes.TrimSpace(fields["selected_model"]), []byte("null")) {
				if _, err := requireNestedObject(fields["selected_model"], name+".config_observation.fields.selected_model", []string{"alias", "digest", "format", "family", "quantization", "context_length"}); err != nil {
					return err
				}
			}
			if !bytes.Equal(bytes.TrimSpace(provenance["selected_model"]), []byte("null")) {
				selected, err := requireNestedObject(provenance["selected_model"], name+".config_observation.field_provenance.selected_model", []string{"alias", "digest", "format", "family", "quantization", "context_length"})
				if err != nil {
					return err
				}
				if err := validateProvenanceShape(selected["alias"], name+".config_observation.field_provenance.selected_model.alias"); err != nil {
					return err
				}
			}
		}
		if err := validateMissingArray(frame["capabilities_missing"], name+".capabilities_missing"); err != nil {
			return err
		}
	}
	return nil
}

func validateObservationArray(raw json.RawMessage, name string, required []string) error {
	values, err := requireArray(raw, name)
	if err != nil {
		return err
	}
	for index, value := range values {
		itemName := fmt.Sprintf("%s[%d]", name, index)
		item, err := requireNestedObject(value, itemName, required)
		if err != nil {
			return err
		}
		if err := validateMissingArray(item["missing"], itemName+".missing"); err != nil {
			return err
		}
		if err := validateProvenanceShape(item["provenance"], itemName+".provenance"); err != nil {
			return err
		}
	}
	return nil
}

func validateInventoryShape(data []byte) error {
	top, err := requireObject(data, []string{"protocol", "deployment_id", "host_id", "security_generation", "session_generation", "collector_boot_id", "inventory_revision", "sources", "targets", "models"})
	if err != nil {
		return err
	}
	for name, required := range map[string][]string{
		"sources": {"source_id", "kind", "target_id", "capability_revision", "active"},
		"targets": {"target_id", "adapter_id", "local_selector_sha256", "association_state"},
		"models":  {"model_id", "target_id", "alias", "digest", "reported_loaded"},
	} {
		values, err := requireArray(top[name], name)
		if err != nil {
			return err
		}
		for index, value := range values {
			if _, err := requireNestedObject(value, fmt.Sprintf("%s[%d]", name, index), required); err != nil {
				return err
			}
		}
	}
	return nil
}

func validateStatusShape(data []byte) error {
	top, err := requireObject(data, []string{"protocol", "deployment_id", "host_id", "security_generation", "session_generation", "collector_boot_id", "sequence", "observed_wall_ms", "heartbeat", "sources", "loss_intervals"})
	if err != nil {
		return err
	}
	for name, required := range map[string][]string{
		"sources":        {"source_id", "state", "last_success_ms", "failure_reason", "first_failure_ms", "failure_count"},
		"loss_intervals": {"source_id", "start_ms", "end_ms", "lost_count", "reason"},
	} {
		values, err := requireArray(top[name], name)
		if err != nil {
			return err
		}
		for index, value := range values {
			if _, err := requireNestedObject(value, fmt.Sprintf("%s[%d]", name, index), required); err != nil {
				return err
			}
		}
	}
	return nil
}
func validateNoDuplicates(dec *json.Decoder, depth int) error {
	if depth > MaxProtocolDepth {
		return errors.New("collector JSON depth exceeded")
	}
	token, err := dec.Token()
	if err != nil {
		return err
	}
	delimiter, ok := token.(json.Delim)
	if !ok {
		return nil
	}
	switch delimiter {
	case '{':
		seen := map[string]bool{}
		for dec.More() {
			k, err := dec.Token()
			if err != nil {
				return err
			}
			key := k.(string)
			if seen[key] {
				return fmt.Errorf("duplicate key %q", key)
			}
			seen[key] = true
			if err := validateNoDuplicates(dec, depth+1); err != nil {
				return err
			}
		}
		_, err = dec.Token()
		return err
	case '[':
		for dec.More() {
			if err := validateNoDuplicates(dec, depth+1); err != nil {
				return err
			}
		}
		_, err = dec.Token()
		return err
	}
	return errors.New("invalid JSON delimiter")
}

func NewSessionResult(request SessionActivation, generation, activatedMS int64) SessionResult {
	return SessionResult{request.ActivationRequestID, request.SecurityGeneration, generation, request.CollectorBootID, activatedMS, true}
}
func NowMS(now time.Time) int64 { return now.UnixMilli() }
