package store

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"math"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"rmt.local/monitor/internal/domain"
)

const (
	probeImportMaximumBytes       int64 = 8 << 20
	probeImportMaximumSamples           = 10000
	comparisonRequestMaximumBytes       = 64 << 10
	comparisonResultMaximumBytes        = 512 << 10
	comparisonMaximumResults            = 256
	comparisonRetention                 = 30 * 24 * time.Hour
	probeImportMinimumInterval          = time.Minute
)

var (
	ErrProbeImportInvalid   = errors.New("invalid probe import")
	ErrProbeImportConflict  = errors.New("probe import request conflict")
	ErrProbeImportBusy      = errors.New("probe import busy")
	ErrProbeImportRate      = errors.New("probe import rate limited")
	ErrProbeImportCapacity  = errors.New("probe import capacity exhausted")
	ErrComparisonInvalid    = errors.New("invalid comparison")
	ErrComparisonNotFound   = errors.New("comparison not found")
	ErrComparisonExpired    = errors.New("comparison expired")
	ErrComparisonConflict   = errors.New("comparison request conflict")
	ErrComparisonIneligible = errors.New("comparison is not eligible")
	ErrComparisonCapacity   = errors.New("comparison capacity exhausted")
	ErrComparisonAttachment = errors.New("comparison attachment failed")
)

// RequestPopulationKey and RequestGenerationOptions are shared with the
// alert rule contract. The aliases keep comparison and alert population
// identity byte-compatible without adding a second representation.
type RequestPopulationKey = RuleRequestPopulation
type RequestGenerationOptions = RuleGenerationOptions

type RequestOffsets struct {
	Submit        string  `json:"submit"`
	Headers       *string `json:"headers"`
	FirstByte     *string `json:"first_byte"`
	FirstThinking *string `json:"first_thinking"`
	FirstContent  *string `json:"first_content"`
	End           string  `json:"end"`
}

type RequestMetrics struct {
	ClientFirstByteMS      *float64 `json:"request.client.first_byte_ms"`
	ClientFirstContentMS   *float64 `json:"request.client.first_content_ms"`
	ClientTotalMS          *float64 `json:"request.client.total_ms"`
	RuntimeTotalDurationMS *float64 `json:"request.runtime.total_duration_ms"`
	RuntimeLoadDurationMS  *float64 `json:"request.runtime.load_duration_ms"`
	RuntimePromptEvalMS    *float64 `json:"request.runtime.prompt_eval_duration_ms"`
	RuntimeEvalMS          *float64 `json:"request.runtime.eval_duration_ms"`
	RuntimePromptTokens    *int64   `json:"request.runtime.prompt_tokens"`
	RuntimeOutputTokens    *int64   `json:"request.runtime.output_tokens"`
}

type RequestFieldProvenance struct {
	Source        string  `json:"source"`
	Verification  string  `json:"verification"`
	MissingReason *string `json:"missing_reason"`
}

type RequestSample struct {
	SchemaVersion          string                            `json:"schema_version"`
	SampleID               string                            `json:"sample_id"`
	RunID                  string                            `json:"run_id"`
	SourceKind             string                            `json:"source_kind"`
	VerificationState      string                            `json:"verification_state"`
	ObservationScope       string                            `json:"observation_scope"`
	DeploymentID           string                            `json:"deployment_id"`
	HostID                 string                            `json:"host_id"`
	SourceID               string                            `json:"source_id"`
	TargetID               string                            `json:"target_id"`
	ModelID                string                            `json:"model_id"`
	ConfigSnapshotID       string                            `json:"config_snapshot_id"`
	PopulationKey          RequestPopulationKey              `json:"population_key"`
	RuntimeSourcePinID     string                            `json:"runtime_source_pin_id"`
	RuntimeOperation       string                            `json:"runtime_operation"`
	TerminalRecordObserved bool                              `json:"terminal_record_observed"`
	SubmittedAtMS          int64                             `json:"submitted_at_ms"`
	OffsetsNS              RequestOffsets                    `json:"offsets_ns"`
	HTTPStatus             *int                              `json:"http_status"`
	TerminalStatus         string                            `json:"terminal_status"`
	DoneReason             *string                           `json:"done_reason"`
	SafeErrorCategory      *string                           `json:"safe_error_category"`
	Metrics                RequestMetrics                    `json:"metrics"`
	FieldProvenance        map[string]RequestFieldProvenance `json:"field_provenance"`
	ContentPersistence     string                            `json:"content_persistence"`
}

type RequestRun struct {
	SchemaVersion      string               `json:"schema_version"`
	RunID              string               `json:"run_id"`
	DeploymentID       string               `json:"deployment_id"`
	HostID             string               `json:"host_id"`
	SourceID           string               `json:"source_id"`
	TargetID           string               `json:"target_id"`
	ModelID            string               `json:"model_id"`
	ConfigSnapshotID   string               `json:"config_snapshot_id"`
	SourceKind         string               `json:"source_kind"`
	VerificationState  string               `json:"verification_state"`
	PopulationKey      RequestPopulationKey `json:"population_key"`
	ExpectedCount      int                  `json:"expected_count"`
	SubmittedCount     int                  `json:"submitted_count"`
	CompletedCount     int                  `json:"completed_count"`
	FailedCount        int                  `json:"failed_count"`
	CancelledCount     int                  `json:"cancelled_count"`
	IncompleteCount    int                  `json:"incomplete_count"`
	DecodedSizeBytes   int64                `json:"decoded_size_bytes"`
	FinalizationState  string               `json:"finalization_state"`
	PartialReason      *string              `json:"partial_reason"`
	ContentPersistence string               `json:"content_persistence"`
	Samples            []RequestSample      `json:"samples"`
}

type ProbeImport struct {
	OriginalArtifactSHA256 string     `json:"original_artifact_sha256"`
	NormalizationRevision  string     `json:"normalization_revision"`
	Run                    RequestRun `json:"run"`
}

type DeclaredIntervention struct {
	Type              string `json:"type"`
	Field             string `json:"field"`
	BeforeValueSHA256 string `json:"before_value_sha256"`
	AfterValueSHA256  string `json:"after_value_sha256"`
	DeclarationID     string `json:"declaration_id"`
	DeclaredTimeMS    int64  `json:"declared_time_ms"`
}

type RequestComparison struct {
	ComparisonKind       string                `json:"comparison_kind"`
	ScopeID              string                `json:"scope_id"`
	MetricID             string                `json:"metric_id"`
	BeforeRunID          string                `json:"before_run_id"`
	AfterRunID           string                `json:"after_run_id"`
	DeclaredIntervention *DeclaredIntervention `json:"declared_intervention"`
}

type RequestSummaryStats struct {
	ValidN    int      `json:"valid_n"`
	Minimum   float64  `json:"minimum"`
	Median    float64  `json:"median"`
	Maximum   float64  `json:"maximum"`
	P95       *float64 `json:"p95"`
	Algorithm string   `json:"algorithm"`
}

type RequestSummary struct {
	SchemaVersion       string               `json:"schema_version"`
	AggregationRevision string               `json:"aggregation_revision"`
	PopulationKey       RequestPopulationKey `json:"population_key"`
	PopulationStatus    string               `json:"population_status"`
	RunIDs              []string             `json:"run_ids"`
	MetricID            string               `json:"metric_id"`
	CompletedCount      int                  `json:"completed_count"`
	ValidCount          int                  `json:"valid_count"`
	FailedCount         int                  `json:"failed_count"`
	CancelledCount      int                  `json:"cancelled_count"`
	IncompleteCount     int                  `json:"incomplete_count"`
	ProvenanceKey       map[string]string    `json:"provenance_key"`
	Summary             *RequestSummaryStats `json:"summary"`
	Warnings            []string             `json:"warnings"`
}

type ComparisonResult struct {
	SchemaVersion        string                `json:"schema_version"`
	ComparisonKind       string                `json:"comparison_kind"`
	ResultID             *string               `json:"result_id"`
	Persisted            bool                  `json:"persisted"`
	Status               string                `json:"status"`
	MetricID             string                `json:"metric_id"`
	Before               RequestSummary        `json:"before"`
	After                RequestSummary        `json:"after"`
	DeclaredIntervention *DeclaredIntervention `json:"declared_intervention"`
	Confounds            []string              `json:"confounds"`
	BlockedReasons       []string              `json:"blocked_reasons"`
	ClaimScope           string                `json:"claim_scope"`
}

type ComparisonReference struct {
	ComparisonID string `json:"comparison_id"`
	MetricID     string `json:"metric_id"`
	Status       string `json:"status"`
	BeforeRunID  string `json:"before_run_id"`
	AfterRunID   string `json:"after_run_id"`
	CreatedMS    int64  `json:"created_ms"`
	ExpiresMS    int64  `json:"expires_ms"`
}

type JobResult struct {
	ResourceID        string `json:"resource_id"`
	ResourceType      string `json:"resource_type"`
	DownloadExpiresMS *int64 `json:"download_expires_ms"`
}

type JobRecord struct {
	ID                   string     `json:"job_id"`
	DeploymentGeneration string     `json:"deployment_generation"`
	Type                 string     `json:"type"`
	State                string     `json:"state"`
	ProgressRatio        float64    `json:"progress_ratio"`
	CreatedMS            int64      `json:"created_ms"`
	UpdatedMS            int64      `json:"updated_ms"`
	Result               *JobResult `json:"result"`
	ErrorCode            *string    `json:"error_code"`
	CancelState          string     `json:"cancel_state"`
}

var requestMetricIDs = []string{
	"request.client.first_byte_ms",
	"request.client.first_content_ms",
	"request.client.total_ms",
	"request.runtime.total_duration_ms",
	"request.runtime.load_duration_ms",
	"request.runtime.prompt_eval_duration_ms",
	"request.runtime.eval_duration_ms",
	"request.runtime.prompt_tokens",
	"request.runtime.output_tokens",
}

func validRequestMetricID(value string) bool {
	for _, item := range requestMetricIDs {
		if value == item {
			return true
		}
	}
	return false
}

func validateProbeImport(input ProbeImport) error {
	if !sha256HexPattern.MatchString(input.OriginalArtifactSHA256) || input.NormalizationRevision != "probe-import-1" {
		return ErrProbeImportInvalid
	}
	run := input.Run
	if run.SchemaVersion != domain.SchemaVersion || run.SourceKind != "imported_test" || run.VerificationState != "operator_imported_unverified" || run.ContentPersistence != "none" || !validUUIDText(run.RunID) || !validUUIDText(run.DeploymentID) || !validUUIDText(run.HostID) || !validUUIDText(run.SourceID) || !validUUIDText(run.TargetID) || !validUUIDText(run.ModelID) || !validUUIDText(run.ConfigSnapshotID) || run.ExpectedCount < 1 || run.ExpectedCount > probeImportMaximumSamples || run.SubmittedCount < 0 || run.SubmittedCount > run.ExpectedCount || run.CompletedCount < 0 || run.FailedCount < 0 || run.CancelledCount < 0 || run.IncompleteCount < 0 || run.DecodedSizeBytes < 1 || run.DecodedSizeBytes > probeImportMaximumBytes || len(run.Samples) > probeImportMaximumSamples || len(run.Samples) > run.SubmittedCount || !validFinalization(run.FinalizationState, run.PartialReason) {
		return ErrProbeImportInvalid
	}
	if !validRulePopulation(run.PopulationKey) || run.PopulationKey.SourceKind != run.SourceKind || run.PopulationKey.VerificationState != run.VerificationState || run.PopulationKey.TargetID != run.TargetID {
		return ErrProbeImportInvalid
	}
	if run.CompletedCount+run.FailedCount+run.CancelledCount+run.IncompleteCount != run.SubmittedCount {
		return ErrProbeImportInvalid
	}
	seen := make(map[string]struct{}, len(run.Samples))
	actualCompleted, actualFailed, actualCancelled, actualIncomplete := 0, 0, 0, 0
	for _, sample := range run.Samples {
		if err := validateImportedSample(run, sample, input.OriginalArtifactSHA256); err != nil {
			return err
		}
		if _, ok := seen[sample.SampleID]; ok {
			return ErrProbeImportInvalid
		}
		seen[sample.SampleID] = struct{}{}
		switch sample.TerminalStatus {
		case "completed":
			actualCompleted++
		case "failed":
			actualFailed++
		case "cancelled":
			actualCancelled++
		case "incomplete":
			actualIncomplete++
		}
	}
	if actualCompleted != run.CompletedCount || actualFailed != run.FailedCount || actualCancelled != run.CancelledCount || actualIncomplete > run.IncompleteCount {
		return ErrProbeImportInvalid
	}
	if len(run.Samples) == run.SubmittedCount && actualIncomplete != run.IncompleteCount {
		return ErrProbeImportInvalid
	}
	return nil
}

func validFinalization(state string, reason *string) bool {
	switch state {
	case "active", "finalized":
		return reason == nil
	case "partial":
		return reason != nil && (*reason == "source_loss" || *reason == "import_interrupted" || *reason == "population_expired_or_partial")
	default:
		return false
	}
}

func validateImportedSample(run RequestRun, sample RequestSample, artifactSHA string) error {
	if sample.SchemaVersion != domain.SchemaVersion || !validUUIDText(sample.SampleID) || sample.RunID != run.RunID || sample.SourceKind != "imported_test" || sample.VerificationState != "operator_imported_unverified" || sample.ObservationScope != "explicit_observed_request" || sample.DeploymentID != run.DeploymentID || sample.HostID != run.HostID || sample.SourceID != run.SourceID || sample.TargetID != run.TargetID || sample.ModelID != run.ModelID || sample.ConfigSnapshotID != run.ConfigSnapshotID || sample.RuntimeSourcePinID != "operator-import-unverified" || sample.RuntimeOperation != "generate" || sample.ContentPersistence != "none" || !validRulePopulation(sample.PopulationKey) || sample.SubmittedAtMS < 0 || sample.OffsetsNS.Submit != "0" || sample.OffsetsNS.End == "" || sample.TerminalStatus == "" {
		return ErrProbeImportInvalid
	}
	samplePopulationHash, err := populationKeyHash(sample.PopulationKey)
	runPopulationHash, hashErr := populationKeyHash(run.PopulationKey)
	if err != nil || hashErr != nil || samplePopulationHash != runPopulationHash || sample.PopulationKey.SourceKind != "imported_test" || sample.PopulationKey.VerificationState != "operator_imported_unverified" {
		return ErrProbeImportInvalid
	}
	if err := validateOffsets(sample.OffsetsNS, sample.Metrics); err != nil {
		return err
	}
	if err := validateSampleHTTPAndTerminal(sample); err != nil {
		return err
	}
	if len(sample.FieldProvenance) != len(requestMetricIDs) {
		return ErrProbeImportInvalid
	}
	for _, metric := range requestMetricIDs {
		provenance, ok := sample.FieldProvenance[metric]
		if !ok || provenance.Source != "operator_import" || provenance.Verification != "operator_imported_unverified" || provenance.MissingReason != nil && !validMissingReason(*provenance.MissingReason) {
			return ErrProbeImportInvalid
		}
	}
	_ = artifactSHA // The envelope hash is retained at run metadata, not copied into every field.
	return nil
}

func validMissingReason(value string) bool {
	switch value {
	case "field_omitted", "not_reached", "cancelled", "failed", "incomplete", "not_applicable":
		return true
	default:
		return false
	}
}

func validateOffsets(offsets RequestOffsets, metrics RequestMetrics) error {
	values := map[string]*string{"headers": offsets.Headers, "first_byte": offsets.FirstByte, "first_thinking": offsets.FirstThinking, "first_content": offsets.FirstContent, "end": &offsets.End}
	var previous uint64
	for _, name := range []string{"headers", "first_byte", "first_thinking", "first_content", "end"} {
		value := values[name]
		if value == nil {
			continue
		}
		parsed, err := parseUint64Decimal(*value)
		if err != nil || parsed < previous {
			return ErrProbeImportInvalid
		}
		previous = parsed
	}
	if offsets.Submit != "0" {
		return ErrProbeImportInvalid
	}
	for _, item := range []*struct {
		metric string
		value  *float64
		offset *string
	}{
		{"request.client.first_byte_ms", metrics.ClientFirstByteMS, offsets.FirstByte},
		{"request.client.first_content_ms", metrics.ClientFirstContentMS, offsets.FirstContent},
		{"request.client.total_ms", metrics.ClientTotalMS, &offsets.End},
	} {
		if item.value != nil {
			if item.offset == nil {
				return ErrProbeImportInvalid
			}
			offset, _ := parseUint64Decimal(*item.offset)
			if math.IsNaN(*item.value) || math.IsInf(*item.value, 0) || *item.value < 0 || *item.value > 120000 || math.Abs(*item.value-float64(offset)/1e6) > 0.001 {
				return ErrProbeImportInvalid
			}
		}
	}
	for _, value := range []*float64{metrics.RuntimeTotalDurationMS, metrics.RuntimeLoadDurationMS, metrics.RuntimePromptEvalMS, metrics.RuntimeEvalMS} {
		if value != nil && (math.IsNaN(*value) || math.IsInf(*value, 0) || *value < 0 || *value > 120000) {
			return ErrProbeImportInvalid
		}
	}
	for _, value := range []*int64{metrics.RuntimePromptTokens, metrics.RuntimeOutputTokens} {
		if value != nil && (*value < 0 || *value > 1000000) {
			return ErrProbeImportInvalid
		}
	}
	return nil
}

func validateSampleHTTPAndTerminal(sample RequestSample) error {
	if sample.HTTPStatus != nil && (*sample.HTTPStatus < 100 || *sample.HTTPStatus > 599) {
		return ErrProbeImportInvalid
	}
	switch sample.TerminalStatus {
	case "completed":
		if !sample.TerminalRecordObserved || sample.HTTPStatus == nil || *sample.HTTPStatus < 200 || *sample.HTTPStatus > 299 || sample.DoneReason == nil || (*sample.DoneReason != "stop" && *sample.DoneReason != "length") || sample.SafeErrorCategory != nil || sample.Metrics.ClientTotalMS == nil {
			return ErrProbeImportInvalid
		}
	case "cancelled", "failed", "incomplete":
		if sample.SafeErrorCategory == nil || !validSafeErrorCategory(*sample.SafeErrorCategory) {
			return ErrProbeImportInvalid
		}
	default:
		return ErrProbeImportInvalid
	}
	if sample.DoneReason != nil && (*sample.DoneReason == "load" || *sample.DoneReason == "unload" || *sample.DoneReason == "error") && sample.TerminalStatus == "completed" {
		return ErrProbeImportInvalid
	}
	if !sample.TerminalRecordObserved && (sample.DoneReason != nil || sample.Metrics.RuntimeTotalDurationMS != nil || sample.Metrics.RuntimeLoadDurationMS != nil || sample.Metrics.RuntimePromptEvalMS != nil || sample.Metrics.RuntimeEvalMS != nil || sample.Metrics.RuntimePromptTokens != nil || sample.Metrics.RuntimeOutputTokens != nil) {
		return ErrProbeImportInvalid
	}
	return nil
}

func validSafeErrorCategory(value string) bool {
	switch value {
	case "cancelled", "deadline", "connection", "http_error", "runtime_error", "malformed_stream", "incomplete_stream", "limit_exceeded", "identity_unverified":
		return true
	default:
		return false
	}
}

func parseUint64Decimal(value string) (uint64, error) {
	if value == "" || len(value) > 20 || (len(value) > 1 && value[0] == '0') {
		return 0, ErrProbeImportInvalid
	}
	for _, r := range value {
		if r < '0' || r > '9' {
			return 0, ErrProbeImportInvalid
		}
	}
	parsed, err := strconv.ParseUint(value, 10, 64)
	if err != nil {
		return 0, ErrProbeImportInvalid
	}
	return parsed, nil
}

func canonicalJSON(value any) ([]byte, error) { return json.Marshal(value) }

func validSafeValue(value string, maximum int) bool {
	return len(value) >= 1 && len(value) <= maximum && utf8.ValidString(value) && strings.IndexFunc(value, func(r rune) bool { return r < 0x20 || r == 0x7f || unicode.IsControl(r) }) < 0
}

func populationKeyHash(value RequestPopulationKey) (string, error) {
	encoded, err := canonicalJSON(value)
	if err != nil {
		return "", err
	}
	return sha256Text(string(encoded)), nil
}

// ImportProbe validates the whole normalized envelope before acquiring a
// write transaction. The transaction then performs all identity, quota and
// row writes together, so a rejected sample can never leave a partial run.
func (s *Store) ImportProbe(ctx context.Context, actor SessionRecord, idempotencyKey, requestHash string, input ProbeImport) (JobRecord, error) {
	if !validMutationReceipt(idempotencyKey, requestHash) {
		return JobRecord{}, ErrProbeImportInvalid
	}
	if err := validateProbeImport(input); err != nil {
		return JobRecord{}, err
	}
	release, err := s.acquireWrite(ctx)
	if err != nil {
		return JobRecord{}, err
	}
	defer release()
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return JobRecord{}, err
	}
	defer tx.Rollback()
	role, _, err := validateAPITokenActor(ctx, tx, actor)
	if err != nil {
		return JobRecord{}, err
	}
	if role != "admin" {
		return JobRecord{}, ErrOwnershipMismatch
	}
	now := s.clock.Now().UnixMilli()
	if job, found, err := readGenericJobReceiptTx(ctx, tx, actor, idempotencyKey, requestHash, now); err != nil {
		return JobRecord{}, err
	} else if found {
		return job, nil
	}
	if input.Run.DeploymentID != actor.DeploymentID {
		return JobRecord{}, ErrOwnershipMismatch
	}
	if err := validateImportReferencesTx(ctx, tx, input.Run); err != nil {
		return JobRecord{}, err
	}
	var recent int
	if err := tx.QueryRowContext(ctx, `SELECT count(*) FROM jobs WHERE deployment_id=? AND type='probe_import' AND created_ms>?`, actor.DeploymentID, now-probeImportMinimumInterval.Milliseconds()).Scan(&recent); err != nil {
		return JobRecord{}, err
	}
	if recent != 0 {
		return JobRecord{}, ErrProbeImportRate
	}
	var active int
	if err := tx.QueryRowContext(ctx, `SELECT count(*) FROM jobs WHERE deployment_id=? AND type='probe_import' AND state IN ('queued','running')`, actor.DeploymentID).Scan(&active); err != nil {
		return JobRecord{}, err
	}
	if active != 0 {
		return JobRecord{}, ErrProbeImportBusy
	}
	var existing int
	if err := tx.QueryRowContext(ctx, `SELECT count(*) FROM request_runs WHERE deployment_id=? AND id=?`, actor.DeploymentID, input.Run.RunID).Scan(&existing); err != nil {
		return JobRecord{}, err
	}
	if existing != 0 {
		return JobRecord{}, ErrProbeImportConflict
	}
	encoded, err := canonicalJSON(input)
	if err != nil || int64(len(encoded)) > probeImportMaximumBytes {
		return JobRecord{}, ErrProbeImportInvalid
	}
	reserved, err := batchCapacityBytes(len(encoded), len(input.Run.Samples))
	if err != nil {
		return JobRecord{}, ErrProbeImportCapacity
	}
	if err := s.capacityAdmissionForImportTx(ctx, tx, actor.DeploymentID, now, reserved); err != nil {
		return JobRecord{}, err
	}
	populationHash, err := populationKeyHash(input.Run.PopulationKey)
	if err != nil {
		return JobRecord{}, ErrProbeImportInvalid
	}
	finalizedMS := any(nil)
	if input.Run.FinalizationState != "active" {
		finalizedMS = now
	}
	reservedRecords := len(input.Run.Samples)
	if reservedRecords == 0 {
		reservedRecords = 1
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO request_runs(id,deployment_id,host_id,source_id,target_id,source_kind,verification_state,population_key_sha256,population_key_json,expected_count,submitted_count,completed_count,failed_count,cancelled_count,incomplete_count,finalization_state,reserved_records,reserved_bytes,created_ms,finalized_ms) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`, input.Run.RunID, actor.DeploymentID, input.Run.HostID, input.Run.SourceID, input.Run.TargetID, input.Run.SourceKind, input.Run.VerificationState, populationHash, string(mustJSON(input.Run.PopulationKey)), input.Run.ExpectedCount, input.Run.SubmittedCount, input.Run.CompletedCount, input.Run.FailedCount, input.Run.CancelledCount, input.Run.IncompleteCount, input.Run.FinalizationState, reservedRecords, reserved, now, finalizedMS); err != nil {
		return JobRecord{}, err
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO request_run_metadata(deployment_id,host_id,run_id,target_id,model_id,config_id,decoded_size_bytes,original_artifact_sha256,partial_reason,content_persistence) VALUES(?,?,?,?,?,?,?,?,?,?)`, actor.DeploymentID, input.Run.HostID, input.Run.RunID, input.Run.TargetID, input.Run.ModelID, input.Run.ConfigSnapshotID, input.Run.DecodedSizeBytes, input.OriginalArtifactSHA256, input.Run.PartialReason, input.Run.ContentPersistence); err != nil {
		return JobRecord{}, err
	}
	for _, sample := range input.Run.Samples {
		if err := insertRequestSampleTx(ctx, tx, input.Run, sample, populationHash); err != nil {
			return JobRecord{}, err
		}
	}
	jobID, err := domain.NewUUID()
	if err != nil {
		return JobRecord{}, err
	}
	requestJSON, _ := json.Marshal(struct {
		RunID                  string `json:"run_id"`
		OriginalArtifactSHA256 string `json:"original_artifact_sha256"`
		SampleCount            int    `json:"sample_count"`
	}{input.Run.RunID, input.OriginalArtifactSHA256, len(input.Run.Samples)})
	if len(requestJSON) > comparisonRequestMaximumBytes {
		return JobRecord{}, ErrProbeImportInvalid
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO jobs(id,deployment_id,deployment_generation,type,state,progress,request_json,actor_user_id,result_snapshot_id,error_code,lease_until_ms,created_ms,updated_ms,expires_ms) VALUES(?,?,?,'probe_import','succeeded',1,?,?,NULL,NULL,NULL,?,?,?)`, jobID, actor.DeploymentID, actor.Generation, string(requestJSON), actor.User.ID, now, now, now+int64(24*time.Hour/time.Millisecond)); err != nil {
		return JobRecord{}, err
	}
	if err := persistGenericJobReceiptTx(ctx, tx, actor, idempotencyKey, requestHash, jobID, "probe_import", "succeeded", input.Run.RunID, "probe_run", now); err != nil {
		return JobRecord{}, err
	}
	if err := writeComparisonAuditTx(ctx, tx, actor, "probe.import", input.Run.RunID, now, map[string]any{"artifact_sha256": input.OriginalArtifactSHA256, "sample_count": len(input.Run.Samples)}); err != nil {
		return JobRecord{}, err
	}
	if err := tx.Commit(); err != nil {
		return JobRecord{}, err
	}
	return JobRecord{ID: jobID, DeploymentGeneration: actor.Generation, Type: "probe_import", State: "succeeded", ProgressRatio: 1, CreatedMS: now, UpdatedMS: now, Result: &JobResult{ResourceID: input.Run.RunID, ResourceType: "probe_run"}, CancelState: "not_requested"}, nil
}

func validateImportReferencesTx(ctx context.Context, tx *sql.Tx, run RequestRun) error {
	var count int
	if err := tx.QueryRowContext(ctx, `SELECT count(*) FROM hosts WHERE deployment_id=? AND id=?`, run.DeploymentID, run.HostID).Scan(&count); err != nil || count != 1 {
		return ErrOwnershipMismatch
	}
	if err := tx.QueryRowContext(ctx, `SELECT count(*) FROM sources WHERE deployment_id=? AND host_id=? AND id=? AND kind IN ('runtime','observed_request')`, run.DeploymentID, run.HostID, run.SourceID).Scan(&count); err != nil || count != 1 {
		return ErrOwnershipMismatch
	}
	if err := tx.QueryRowContext(ctx, `SELECT count(*) FROM targets WHERE deployment_id=? AND host_id=? AND id=?`, run.DeploymentID, run.HostID, run.TargetID).Scan(&count); err != nil || count != 1 {
		return ErrOwnershipMismatch
	}
	var digest, configHash string
	if err := tx.QueryRowContext(ctx, `SELECT COALESCE(digest,''),config_hash FROM model_revisions WHERE deployment_id=? AND host_id=? AND target_id=? AND id=?`, run.DeploymentID, run.HostID, run.TargetID, run.ModelID).Scan(&digest, &configHash); err != nil {
		return ErrOwnershipMismatch
	}
	if digest != run.PopulationKey.ModelDigest {
		return ErrOwnershipMismatch
	}
	if err := tx.QueryRowContext(ctx, `SELECT config_hash FROM config_snapshots WHERE deployment_id=? AND host_id=? AND target_id=? AND id=?`, run.DeploymentID, run.HostID, run.TargetID, run.ConfigSnapshotID).Scan(&configHash); err != nil || configHash != run.PopulationKey.ConfigRevision {
		return ErrOwnershipMismatch
	}
	return nil
}

func insertRequestSampleTx(ctx context.Context, tx *sql.Tx, run RequestRun, sample RequestSample, populationHash string) error {
	fields, err := canonicalJSON(sample.FieldProvenance)
	if err != nil || len(fields) > 65536 {
		return ErrProbeImportInvalid
	}
	var headers, firstByte, firstThinking, firstContent any
	if sample.OffsetsNS.Headers != nil {
		headers = *sample.OffsetsNS.Headers
	}
	if sample.OffsetsNS.FirstByte != nil {
		firstByte = *sample.OffsetsNS.FirstByte
	}
	if sample.OffsetsNS.FirstThinking != nil {
		firstThinking = *sample.OffsetsNS.FirstThinking
	}
	if sample.OffsetsNS.FirstContent != nil {
		firstContent = *sample.OffsetsNS.FirstContent
	}
	var status any
	if sample.HTTPStatus != nil {
		status = *sample.HTTPStatus
	}
	var done, safe any
	if sample.DoneReason != nil {
		done = *sample.DoneReason
	}
	if sample.SafeErrorCategory != nil {
		safe = *sample.SafeErrorCategory
	}
	metrics := sample.Metrics
	_, err = tx.ExecContext(ctx, `INSERT INTO request_samples(sample_id,deployment_id,host_id,run_id,source_id,target_id,model_id,config_id,observation_scope,runtime_source_pin_id,terminal_record_observed,population_key_sha256,submitted_at_ms,submit_offset_ns,headers_offset_ns,first_byte_offset_ns,first_thinking_offset_ns,first_content_offset_ns,end_offset_ns,http_status,terminal_status,done_reason,safe_error_category,client_first_byte_ms,client_first_content_ms,client_total_ms,runtime_total_duration_ms,runtime_load_duration_ms,runtime_prompt_eval_duration_ms,runtime_eval_duration_ms,runtime_prompt_tokens,runtime_output_tokens,field_provenance_json) VALUES(
		?,?,?,?,?,?,?,?,?,
		?,?,?,?,?,?,?,?,?,
		?,?,?,?,?,?,?,?,?,
		?,?,?,?,?,?
	)`, sample.SampleID, run.DeploymentID, run.HostID, run.RunID, run.SourceID, run.TargetID, run.ModelID, run.ConfigSnapshotID, sample.ObservationScope, sample.RuntimeSourcePinID, sample.TerminalRecordObserved, populationHash, sample.SubmittedAtMS, sample.OffsetsNS.Submit, headers, firstByte, firstThinking, firstContent, sample.OffsetsNS.End, status, sample.TerminalStatus, done, safe, metrics.ClientFirstByteMS, metrics.ClientFirstContentMS, metrics.ClientTotalMS, metrics.RuntimeTotalDurationMS, metrics.RuntimeLoadDurationMS, metrics.RuntimePromptEvalMS, metrics.RuntimeEvalMS, metrics.RuntimePromptTokens, metrics.RuntimeOutputTokens, string(fields))
	if err != nil {
		return err
	}
	return nil
}

func (s *Store) capacityAdmissionForImportTx(ctx context.Context, tx *sql.Tx, deploymentID string, now, requested int64) error {
	if requested < 0 {
		return ErrProbeImportCapacity
	}
	var state string
	if err := tx.QueryRowContext(ctx, `SELECT storage_state FROM maintenance WHERE deployment_id=?`, deploymentID).Scan(&state); err != nil {
		return ErrProbeImportCapacity
	}
	if state == StorageReadOnlyENOSPC || state == StorageBulkIngestPaused {
		return ErrProbeImportCapacity
	}
	if err := s.capacityAdmissionTx(ctx, tx, deploymentID, now, requested); err != nil {
		return ErrProbeImportCapacity
	}
	return nil
}

func validateRequestComparison(value RequestComparison) error {
	if value.ComparisonKind != "request_run" || !validUUIDText(value.ScopeID) || !validRequestMetricID(value.MetricID) || !validUUIDText(value.BeforeRunID) || !validUUIDText(value.AfterRunID) || value.BeforeRunID == value.AfterRunID {
		return ErrComparisonInvalid
	}
	if value.DeclaredIntervention == nil {
		return nil
	}
	change := value.DeclaredIntervention
	if !validUUIDText(change.DeclarationID) || change.DeclaredTimeMS < 0 || !sha256HexPattern.MatchString(change.BeforeValueSHA256) || !sha256HexPattern.MatchString(change.AfterValueSHA256) {
		return ErrComparisonInvalid
	}
	switch change.Type {
	case "runtime_version":
		if change.Field != "runtime_version" {
			return ErrComparisonInvalid
		}
	case "config_revision":
		if change.Field != "config_revision" {
			return ErrComparisonInvalid
		}
	case "generation_option":
		if !validGenerationOptionField(change.Field) {
			return ErrComparisonInvalid
		}
	default:
		return ErrComparisonInvalid
	}
	return nil
}

func validGenerationOptionField(value string) bool {
	switch value {
	case "num_ctx", "num_predict", "temperature", "seed", "think", "stream", "cold_warm_policy":
		return true
	default:
		return false
	}
}

func (s *Store) PreviewComparison(ctx context.Context, actor SessionRecord, request RequestComparison) (ComparisonResult, error) {
	if err := validateRequestComparison(request); err != nil {
		return ComparisonResult{}, err
	}
	if _, _, err := s.validateAPITokenActorRead(ctx, actor); err != nil {
		return ComparisonResult{}, err
	}
	tx, err := s.db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return ComparisonResult{}, err
	}
	defer tx.Rollback()
	before, err := readImportedRunTx(ctx, tx, actor.DeploymentID, request.BeforeRunID)
	if err != nil {
		return ComparisonResult{}, err
	}
	after, err := readImportedRunTx(ctx, tx, actor.DeploymentID, request.AfterRunID)
	if err != nil {
		return ComparisonResult{}, err
	}
	result := buildRequestComparison(request, before, after, nil, false)
	if err := tx.Commit(); err != nil {
		return ComparisonResult{}, err
	}
	return result, nil
}

func buildRequestComparison(request RequestComparison, before, after RequestRun, resultID *string, persisted bool) ComparisonResult {
	beforeSummary := summarizeRequestRun(before, request.MetricID)
	afterSummary := summarizeRequestRun(after, request.MetricID)
	result := ComparisonResult{
		SchemaVersion: domain.SchemaVersion, ComparisonKind: "request_run", ResultID: resultID, Persisted: persisted,
		Status: "insufficient_evidence", MetricID: request.MetricID, Before: beforeSummary, After: afterSummary,
		DeclaredIntervention: request.DeclaredIntervention, Confounds: []string{"other_ollama_traffic_absent"}, BlockedReasons: []string{}, ClaimScope: "explicit_observed_requests_only_no_causal_claim",
	}
	if before.SourceKind == "imported_test" || after.SourceKind == "imported_test" {
		result.Confounds = append(result.Confounds, "operator_imported_unverified")
	}
	addUnique := func(list *[]string, value string) {
		for _, existing := range *list {
			if existing == value {
				return
			}
		}
		*list = append(*list, value)
	}
	if before.TargetID != request.ScopeID || after.TargetID != request.ScopeID {
		addUnique(&result.BlockedReasons, "scope_mismatch")
	}
	if before.FinalizationState != "finalized" || after.FinalizationState != "finalized" {
		addUnique(&result.BlockedReasons, "run_not_finalized")
	}
	comparePopulationDifferences(before.PopulationKey, after.PopulationKey, request.DeclaredIntervention, &result.BlockedReasons, &result.Confounds)
	if beforeSummary.Summary == nil || afterSummary.Summary == nil {
		addUnique(&result.BlockedReasons, "selected_metric_missing")
	}
	if len(result.BlockedReasons) != 0 {
		return result
	}
	if request.DeclaredIntervention != nil {
		addUnique(&result.Confounds, "declared_intervention")
	}
	delta := afterSummary.Summary.Median - beforeSummary.Summary.Median
	if math.Abs(delta) <= 1e-9 {
		result.Status = "no_clear_observed_change"
	} else if request.DeclaredIntervention != nil {
		result.Status = "observed_change_with_confounds"
	} else {
		result.Status = "observed_change_similar_recorded_conditions"
	}
	return result
}

func comparePopulationDifferences(before, after RequestPopulationKey, change *DeclaredIntervention, blocked, confounds *[]string) {
	type difference struct {
		code    string
		allowed bool
	}
	values := []difference{}
	if before.TargetID != after.TargetID {
		values = append(values, difference{"target_mismatch", false})
	}
	if before.ModelDigest != after.ModelDigest {
		values = append(values, difference{"model_digest_mismatch", false})
	}
	if before.RuntimeVersion != after.RuntimeVersion || !sameStringPointer(before.RuntimeBuild, after.RuntimeBuild) {
		values = append(values, difference{"runtime_version_change", change != nil && change.Type == "runtime_version"})
	}
	if before.ConfigRevision != after.ConfigRevision {
		values = append(values, difference{"config_revision_change", change != nil && change.Type == "config_revision"})
	}
	if before.ProfileID != after.ProfileID {
		values = append(values, difference{"profile_mismatch", false})
	}
	if before.ProfileSHA256 != after.ProfileSHA256 {
		values = append(values, difference{"profile_hash_mismatch", false})
	}
	if before.Concurrency != after.Concurrency {
		values = append(values, difference{"concurrency_mismatch", false})
	}
	if before.VantageID != after.VantageID {
		values = append(values, difference{"vantage_mismatch", false})
	}
	if before.ClockMethod != after.ClockMethod {
		values = append(values, difference{"clock_method_mismatch", false})
	}
	if before.SourceKind != after.SourceKind {
		values = append(values, difference{"source_kind_mismatch", false})
	}
	if before.VerificationState != after.VerificationState {
		values = append(values, difference{"verification_mismatch", false})
	}
	for _, option := range []struct {
		name          string
		before, after any
	}{
		{"num_ctx", before.Options.NumCtx, after.Options.NumCtx},
		{"num_predict", before.Options.NumPredict, after.Options.NumPredict},
		{"temperature", before.Options.Temperature, after.Options.Temperature},
		{"seed", before.Options.Seed, after.Options.Seed},
		{"think", before.Options.Think, after.Options.Think},
		{"stream", before.Options.Stream, after.Options.Stream},
		{"cold_warm_policy", before.Options.ColdWarmPolicy, after.Options.ColdWarmPolicy},
	} {
		if !sameJSONValue(option.before, option.after) {
			values = append(values, difference{"generation_option_" + option.name, change != nil && change.Type == "generation_option" && change.Field == option.name})
		}
	}
	if change != nil {
		beforeValue, beforeOK := declaredPopulationValue(before, *change)
		afterValue, afterOK := declaredPopulationValue(after, *change)
		if !beforeOK || !afterOK || sha256Text(string(mustJSON(beforeValue))) != change.BeforeValueSHA256 || sha256Text(string(mustJSON(afterValue))) != change.AfterValueSHA256 {
			*blocked = append(*blocked, "declared_change_hash_mismatch")
		}
		observed := false
		for _, item := range values {
			if item.allowed {
				observed = true
			}
		}
		if !observed {
			*blocked = append(*blocked, "declared_change_not_observed")
		}
	}
	for _, item := range values {
		if !item.allowed {
			*blocked = append(*blocked, item.code)
		}
	}
	if len(values) > 0 && change != nil {
		allowedCount := 0
		for _, item := range values {
			if item.allowed {
				allowedCount++
			}
		}
		if allowedCount != len(values) {
			*blocked = append(*blocked, "uncontrolled_population_change")
		}
	}
	if change != nil {
		for _, item := range values {
			if item.allowed {
				*confounds = append(*confounds, item.code)
			}
		}
	}
	*blocked = uniqueStrings(*blocked)
	*confounds = uniqueStrings(*confounds)
}

func sameStringPointer(left, right *string) bool {
	if left == nil || right == nil {
		return left == nil && right == nil
	}
	return *left == *right
}

func sameJSONValue(left, right any) bool {
	return bytes.Equal(mustJSON(left), mustJSON(right))
}

func declaredPopulationValue(population RequestPopulationKey, change DeclaredIntervention) (any, bool) {
	switch change.Type {
	case "runtime_version":
		return struct {
			RuntimeVersion string  `json:"runtime_version"`
			RuntimeBuild   *string `json:"runtime_build"`
		}{population.RuntimeVersion, population.RuntimeBuild}, true
	case "config_revision":
		return population.ConfigRevision, true
	case "generation_option":
		switch change.Field {
		case "num_ctx":
			return population.Options.NumCtx, true
		case "num_predict":
			return population.Options.NumPredict, true
		case "temperature":
			return population.Options.Temperature, true
		case "seed":
			return population.Options.Seed, true
		case "think":
			return population.Options.Think, true
		case "stream":
			return population.Options.Stream, true
		case "cold_warm_policy":
			return population.Options.ColdWarmPolicy, true
		}
	}
	return nil, false
}

func uniqueStrings(values []string) []string {
	seen := make(map[string]struct{}, len(values))
	result := make([]string, 0, len(values))
	for _, value := range values {
		if _, ok := seen[value]; !ok {
			seen[value] = struct{}{}
			result = append(result, value)
		}
	}
	return result
}

func summarizeRequestRun(run RequestRun, metricID string) RequestSummary {
	status := "complete"
	if run.FinalizationState != "finalized" {
		status = "partial"
	}
	values := make([]float64, 0, run.CompletedCount)
	for _, sample := range run.Samples {
		if sample.TerminalStatus != "completed" {
			continue
		}
		if value, ok := requestSampleMetric(sample, metricID); ok {
			values = append(values, value)
		}
	}
	sort.Float64s(values)
	var summary *RequestSummaryStats
	if len(values) > 0 {
		median := values[len(values)/2]
		if len(values)%2 == 0 {
			median = (values[len(values)/2-1] + values[len(values)/2]) / 2
		}
		stats := &RequestSummaryStats{ValidN: len(values), Minimum: values[0], Median: median, Maximum: values[len(values)-1], Algorithm: "exact_median_empirical_nearest_rank_p95"}
		if len(values) >= 100 {
			rank := int(math.Ceil(0.95*float64(len(values)))) - 1
			p95 := values[rank]
			stats.P95 = &p95
		}
		summary = stats
	}
	warnings := []string{"explicit_observed_requests_only", "other_ollama_traffic_absent"}
	provenance := map[string]string{"source_kind": run.SourceKind, "verification_state": run.VerificationState, "metric_source": "operator_import"}
	if run.SourceKind == "imported_test" {
		warnings = append(warnings, "operator_imported_unverified")
	}
	if status != "complete" {
		warnings = append(warnings, "population_expired_or_partial")
	}
	return RequestSummary{SchemaVersion: domain.SchemaVersion, AggregationRevision: "exact-field-nearest-rank-1", PopulationKey: run.PopulationKey, PopulationStatus: status, RunIDs: []string{run.RunID}, MetricID: metricID, CompletedCount: run.CompletedCount, ValidCount: len(values), FailedCount: run.FailedCount, CancelledCount: run.CancelledCount, IncompleteCount: run.IncompleteCount, ProvenanceKey: provenance, Summary: summary, Warnings: uniqueStrings(warnings)}
}

func requestSampleMetric(sample RequestSample, metricID string) (float64, bool) {
	switch metricID {
	case "request.client.first_byte_ms":
		if sample.Metrics.ClientFirstByteMS != nil {
			return *sample.Metrics.ClientFirstByteMS, true
		}
	case "request.client.first_content_ms":
		if sample.Metrics.ClientFirstContentMS != nil {
			return *sample.Metrics.ClientFirstContentMS, true
		}
	case "request.client.total_ms":
		if sample.Metrics.ClientTotalMS != nil {
			return *sample.Metrics.ClientTotalMS, true
		}
	case "request.runtime.total_duration_ms":
		if sample.Metrics.RuntimeTotalDurationMS != nil {
			return *sample.Metrics.RuntimeTotalDurationMS, true
		}
	case "request.runtime.load_duration_ms":
		if sample.Metrics.RuntimeLoadDurationMS != nil {
			return *sample.Metrics.RuntimeLoadDurationMS, true
		}
	case "request.runtime.prompt_eval_duration_ms":
		if sample.Metrics.RuntimePromptEvalMS != nil {
			return *sample.Metrics.RuntimePromptEvalMS, true
		}
	case "request.runtime.eval_duration_ms":
		if sample.Metrics.RuntimeEvalMS != nil {
			return *sample.Metrics.RuntimeEvalMS, true
		}
	case "request.runtime.prompt_tokens":
		if sample.Metrics.RuntimePromptTokens != nil {
			return float64(*sample.Metrics.RuntimePromptTokens), true
		}
	case "request.runtime.output_tokens":
		if sample.Metrics.RuntimeOutputTokens != nil {
			return float64(*sample.Metrics.RuntimeOutputTokens), true
		}
	}
	return 0, false
}

func (s *Store) SaveComparison(ctx context.Context, actor SessionRecord, idempotencyKey, requestHash string, request RequestComparison) (JobRecord, error) {
	if err := validateRequestComparison(request); err != nil || !validMutationReceipt(idempotencyKey, requestHash) {
		return JobRecord{}, ErrComparisonInvalid
	}
	release, err := s.acquireWrite(ctx)
	if err != nil {
		return JobRecord{}, err
	}
	defer release()
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return JobRecord{}, err
	}
	defer tx.Rollback()
	role, _, err := validateAPITokenActor(ctx, tx, actor)
	if err != nil {
		return JobRecord{}, err
	}
	if role != "admin" {
		return JobRecord{}, ErrOwnershipMismatch
	}
	now := s.clock.Now().UnixMilli()
	if job, found, err := readGenericJobReceiptTx(ctx, tx, actor, idempotencyKey, requestHash, now); err != nil {
		return JobRecord{}, err
	} else if found {
		return job, nil
	}
	before, err := readImportedRunTx(ctx, tx, actor.DeploymentID, request.BeforeRunID)
	if err != nil {
		return JobRecord{}, err
	}
	after, err := readImportedRunTx(ctx, tx, actor.DeploymentID, request.AfterRunID)
	if err != nil {
		return JobRecord{}, err
	}
	preview := buildRequestComparison(request, before, after, nil, false)
	if len(preview.BlockedReasons) != 0 || preview.Before.Summary == nil || preview.After.Summary == nil {
		return JobRecord{}, ErrComparisonIneligible
	}
	comparisonID, err := domain.NewUUID()
	if err != nil {
		return JobRecord{}, err
	}
	preview.ResultID, preview.Persisted = &comparisonID, true
	resultJSON, err := json.Marshal(preview)
	if err != nil || len(resultJSON) > comparisonResultMaximumBytes {
		return JobRecord{}, ErrComparisonInvalid
	}
	beforeArtifact, _ := importedArtifactHashTx(ctx, tx, actor.DeploymentID, before.RunID)
	afterArtifact, _ := importedArtifactHashTx(ctx, tx, actor.DeploymentID, after.RunID)
	requestJSON, err := json.Marshal(struct {
		Comparison           RequestComparison `json:"comparison"`
		BeforeArtifactSHA256 string            `json:"before_artifact_sha256"`
		AfterArtifactSHA256  string            `json:"after_artifact_sha256"`
	}{request, beforeArtifact, afterArtifact})
	if err != nil || len(requestJSON) > comparisonRequestMaximumBytes {
		return JobRecord{}, ErrComparisonInvalid
	}
	inputHash := sha256Text(string(requestJSON))
	payloadHash := sha256Text(string(resultJSON))
	if err := purgeExpiredComparisonsTx(ctx, tx, actor.DeploymentID, now); err != nil {
		return JobRecord{}, err
	}
	var count int
	if err := tx.QueryRowContext(ctx, `SELECT count(*) FROM comparisons WHERE deployment_id=?`, actor.DeploymentID).Scan(&count); err != nil {
		return JobRecord{}, err
	}
	if count >= comparisonMaximumResults {
		return JobRecord{}, ErrComparisonCapacity
	}
	if err := admitSavedComparisonTx(ctx, tx, actor.DeploymentID, now, int64(len(requestJSON)+len(resultJSON)+4096)); err != nil {
		return JobRecord{}, err
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO comparisons(id,deployment_id,schema_version,comparison_kind,scope_id,metric_id,before_run_id,after_run_id,request_json,result_json,input_sha256,payload_sha256,created_by,created_ms,expires_ms) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`, comparisonID, actor.DeploymentID, domain.SchemaVersion, "request_run", request.ScopeID, request.MetricID, request.BeforeRunID, request.AfterRunID, string(requestJSON), string(resultJSON), inputHash, payloadHash, actor.User.ID, now, now+comparisonRetention.Milliseconds()); err != nil {
		if strings.Contains(strings.ToLower(err.Error()), "unique") {
			return JobRecord{}, ErrComparisonConflict
		}
		return JobRecord{}, err
	}
	jobID, err := domain.NewUUID()
	if err != nil {
		return JobRecord{}, err
	}
	jobRequest, _ := json.Marshal(struct {
		ComparisonID string `json:"comparison_id"`
	}{comparisonID})
	if _, err := tx.ExecContext(ctx, `INSERT INTO jobs(id,deployment_id,deployment_generation,type,state,progress,request_json,actor_user_id,result_snapshot_id,error_code,lease_until_ms,created_ms,updated_ms,expires_ms) VALUES(?,?,?,'comparison','succeeded',1,?,?,NULL,NULL,NULL,?,?,?)`, jobID, actor.DeploymentID, actor.Generation, string(jobRequest), actor.User.ID, now, now, now+int64(24*time.Hour/time.Millisecond)); err != nil {
		return JobRecord{}, err
	}
	if err := persistGenericJobReceiptTx(ctx, tx, actor, idempotencyKey, requestHash, jobID, "comparison", "succeeded", comparisonID, "comparison", now); err != nil {
		return JobRecord{}, err
	}
	if err := writeComparisonAuditTx(ctx, tx, actor, "comparison.save", comparisonID, now, map[string]any{"metric_id": request.MetricID, "before_run_id": request.BeforeRunID, "after_run_id": request.AfterRunID}); err != nil {
		return JobRecord{}, err
	}
	if err := tx.Commit(); err != nil {
		return JobRecord{}, err
	}
	return JobRecord{ID: jobID, DeploymentGeneration: actor.Generation, Type: "comparison", State: "succeeded", ProgressRatio: 1, CreatedMS: now, UpdatedMS: now, Result: &JobResult{ResourceID: comparisonID, ResourceType: "comparison"}, CancelState: "not_requested"}, nil
}

func importedArtifactHashTx(ctx context.Context, tx *sql.Tx, deploymentID, runID string) (string, error) {
	var hash sql.NullString
	err := tx.QueryRowContext(ctx, `SELECT original_artifact_sha256 FROM request_run_metadata WHERE deployment_id=? AND run_id=?`, deploymentID, runID).Scan(&hash)
	if err != nil || !hash.Valid {
		return "", err
	}
	return hash.String, nil
}

func admitSavedComparisonTx(ctx context.Context, tx *sql.Tx, deploymentID string, now, requested int64) error {
	if requested < 0 {
		return ErrComparisonCapacity
	}
	var state string
	if err := tx.QueryRowContext(ctx, `SELECT storage_state FROM maintenance WHERE deployment_id=?`, deploymentID).Scan(&state); err != nil {
		return ErrComparisonCapacity
	}
	if state == StorageOptionalJobsStopped || state == StorageBulkIngestPaused || state == StorageReadOnlyENOSPC {
		return ErrComparisonCapacity
	}
	var limit, current, reserved int64
	if err := tx.QueryRowContext(ctx, `SELECT byte_limit,current_physical_bytes,reserved_physical_bytes FROM quota_classes WHERE deployment_id=? AND class='saved_comparisons'`, deploymentID).Scan(&limit, &current, &reserved); err != nil || requested > limit || current > math.MaxInt64-reserved || current+reserved > math.MaxInt64-requested || current+reserved+requested > limit {
		return ErrComparisonCapacity
	}
	if err := tx.QueryRowContext(ctx, `SELECT byte_limit,current_physical_bytes,reserved_physical_bytes FROM quota_classes WHERE deployment_id=? AND class='live_total'`, deploymentID).Scan(&limit, &current, &reserved); err != nil || requested > limit || current > math.MaxInt64-reserved || current+reserved > math.MaxInt64-requested || current+reserved+requested > limit {
		return ErrComparisonCapacity
	}
	_ = now
	return nil
}

func purgeExpiredComparisonsTx(ctx context.Context, tx *sql.Tx, deploymentID string, now int64) error {
	if _, err := tx.ExecContext(ctx, `DELETE FROM incident_comparisons WHERE deployment_id=? AND comparison_id IN (SELECT id FROM comparisons WHERE deployment_id=? AND expires_ms<=?)`, deploymentID, deploymentID, now); err != nil {
		return err
	}
	_, err := tx.ExecContext(ctx, `DELETE FROM comparisons WHERE deployment_id=? AND expires_ms<=?`, deploymentID, now)
	return err
}

func (s *Store) ReadComparison(ctx context.Context, actor SessionRecord, comparisonID string) (ComparisonResult, error) {
	if !validUUIDText(comparisonID) {
		return ComparisonResult{}, ErrComparisonInvalid
	}
	if _, _, err := s.validateAPITokenActorRead(ctx, actor); err != nil {
		return ComparisonResult{}, err
	}
	var payload string
	var expires int64
	err := s.db.QueryRowContext(ctx, `SELECT result_json,expires_ms FROM comparisons WHERE deployment_id=? AND id=?`, actor.DeploymentID, comparisonID).Scan(&payload, &expires)
	if errors.Is(err, sql.ErrNoRows) {
		return ComparisonResult{}, ErrComparisonNotFound
	}
	if err != nil {
		return ComparisonResult{}, err
	}
	if expires <= s.clock.Now().UnixMilli() {
		return ComparisonResult{}, ErrComparisonExpired
	}
	var result ComparisonResult
	if json.Unmarshal([]byte(payload), &result) != nil || result.ResultID == nil || *result.ResultID != comparisonID || !result.Persisted {
		return ComparisonResult{}, ErrComparisonInvalid
	}
	return result, nil
}

type comparisonAttachmentReceipt struct {
	IncidentID   string `json:"incident_id"`
	ComparisonID string `json:"comparison_id"`
}

func (s *Store) AttachComparison(ctx context.Context, actor SessionRecord, incidentID, comparisonID, idempotencyKey, requestHash string) error {
	if !validUUIDText(incidentID) || !validUUIDText(comparisonID) || !validMutationReceipt(idempotencyKey, requestHash) {
		return ErrComparisonInvalid
	}
	release, err := s.acquireWrite(ctx)
	if err != nil {
		return err
	}
	defer release()
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	role, _, err := validateAPITokenActor(ctx, tx, actor)
	if err != nil {
		return err
	}
	if role != "admin" {
		return ErrOwnershipMismatch
	}
	now := s.clock.Now().UnixMilli()
	var storedHash, encoded string
	var expires int64
	err = tx.QueryRowContext(ctx, `SELECT request_body_sha256,result_json,expires_ms FROM idempotency_receipts WHERE deployment_id=? AND deployment_generation=? AND actor_user_id=? AND idempotency_key=?`, actor.DeploymentID, actor.Generation, actor.User.ID, idempotencyKey).Scan(&storedHash, &encoded, &expires)
	if err == nil && expires > now {
		var receipt comparisonAttachmentReceipt
		if storedHash != requestHash || json.Unmarshal([]byte(encoded), &receipt) != nil || receipt.IncidentID != incidentID || receipt.ComparisonID != comparisonID {
			return ErrComparisonConflict
		}
		return tx.Commit()
	}
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return err
	}
	if err == nil {
		if _, err := tx.ExecContext(ctx, `DELETE FROM idempotency_receipts WHERE deployment_id=? AND deployment_generation=? AND actor_user_id=? AND idempotency_key=?`, actor.DeploymentID, actor.Generation, actor.User.ID, idempotencyKey); err != nil {
			return err
		}
	}
	var count int
	if err := tx.QueryRowContext(ctx, `SELECT count(*) FROM incidents WHERE deployment_id=? AND id=?`, actor.DeploymentID, incidentID).Scan(&count); err != nil || count != 1 {
		return ErrIncidentNotFound
	}
	if err := tx.QueryRowContext(ctx, `SELECT count(*) FROM comparisons WHERE deployment_id=? AND id=? AND expires_ms>?`, actor.DeploymentID, comparisonID, now).Scan(&count); err != nil || count != 1 {
		return ErrComparisonNotFound
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO incident_comparisons(deployment_id,incident_id,comparison_id,attached_by,attached_ms) VALUES(?,?,?,?,?) ON CONFLICT(deployment_id,incident_id,comparison_id) DO NOTHING`, actor.DeploymentID, incidentID, comparisonID, actor.User.ID, now); err != nil {
		return err
	}
	receiptJSON, _ := json.Marshal(comparisonAttachmentReceipt{IncidentID: incidentID, ComparisonID: comparisonID})
	if len(receiptJSON) > 65536 {
		return ErrComparisonInvalid
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO idempotency_receipts(deployment_id,deployment_generation,actor_user_id,idempotency_key,request_body_sha256,result_status,result_json,created_ms,expires_ms) VALUES(?,?,?,?,?,200,?,?,?)`, actor.DeploymentID, actor.Generation, actor.User.ID, idempotencyKey, requestHash, string(receiptJSON), now, now+int64(24*time.Hour/time.Millisecond)); err != nil {
		return err
	}
	if err := writeComparisonAuditTx(ctx, tx, actor, "comparison.attach", incidentID, now, map[string]any{"comparison_id": comparisonID}); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *Store) ListIncidentComparisons(ctx context.Context, actor SessionRecord, incidentID string) ([]ComparisonReference, error) {
	if !validUUIDText(incidentID) {
		return nil, ErrIncidentNotFound
	}
	if _, _, err := s.validateAPITokenActorRead(ctx, actor); err != nil {
		return nil, err
	}
	rows, err := s.db.QueryContext(ctx, `SELECT c.id,c.metric_id,c.result_json,c.before_run_id,c.after_run_id,c.created_ms,c.expires_ms FROM incident_comparisons ic JOIN comparisons c ON c.deployment_id=ic.deployment_id AND c.id=ic.comparison_id WHERE ic.deployment_id=? AND ic.incident_id=? ORDER BY ic.attached_ms,c.id`, actor.DeploymentID, incidentID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	items := []ComparisonReference{}
	now := s.clock.Now().UnixMilli()
	for rows.Next() {
		var item ComparisonReference
		var resultJSON string
		if err := rows.Scan(&item.ComparisonID, &item.MetricID, &resultJSON, &item.BeforeRunID, &item.AfterRunID, &item.CreatedMS, &item.ExpiresMS); err != nil {
			return nil, err
		}
		var result struct {
			Status string `json:"status"`
		}
		if err := json.Unmarshal([]byte(resultJSON), &result); err != nil {
			return nil, err
		}
		item.Status = result.Status
		if item.ExpiresMS <= now {
			item.Status = "expired"
		}
		items = append(items, item)
	}
	return items, rows.Err()
}

type genericJobReceipt struct {
	Job JobRecord `json:"job"`
}

func readGenericJobReceiptTx(ctx context.Context, tx *sql.Tx, actor SessionRecord, key, requestHash string, now int64) (JobRecord, bool, error) {
	var storedHash, encoded string
	var expires int64
	err := tx.QueryRowContext(ctx, `SELECT request_body_sha256,result_json,expires_ms FROM idempotency_receipts WHERE deployment_id=? AND deployment_generation=? AND actor_user_id=? AND idempotency_key=?`, actor.DeploymentID, actor.Generation, actor.User.ID, key).Scan(&storedHash, &encoded, &expires)
	if errors.Is(err, sql.ErrNoRows) {
		return JobRecord{}, false, nil
	}
	if err != nil {
		return JobRecord{}, false, err
	}
	if expires <= now {
		if _, err := tx.ExecContext(ctx, `DELETE FROM idempotency_receipts WHERE deployment_id=? AND deployment_generation=? AND actor_user_id=? AND idempotency_key=?`, actor.DeploymentID, actor.Generation, actor.User.ID, key); err != nil {
			return JobRecord{}, false, err
		}
		return JobRecord{}, false, nil
	}
	var receipt genericJobReceipt
	if storedHash != requestHash || json.Unmarshal([]byte(encoded), &receipt) != nil || !validUUIDText(receipt.Job.ID) {
		return JobRecord{}, false, ErrComparisonConflict
	}
	return receipt.Job, true, nil
}

func persistGenericJobReceiptTx(ctx context.Context, tx *sql.Tx, actor SessionRecord, key, requestHash, jobID, jobType, state, resourceID, resourceType string, now int64) error {
	job := JobRecord{ID: jobID, DeploymentGeneration: actor.Generation, Type: jobType, State: state, ProgressRatio: 1, CreatedMS: now, UpdatedMS: now, Result: &JobResult{ResourceID: resourceID, ResourceType: resourceType}, CancelState: "not_requested"}
	encoded, err := json.Marshal(genericJobReceipt{Job: job})
	if err != nil || len(encoded) > 65536 {
		return ErrComparisonInvalid
	}
	_, err = tx.ExecContext(ctx, `INSERT INTO idempotency_receipts(deployment_id,deployment_generation,actor_user_id,idempotency_key,request_body_sha256,result_status,result_json,created_ms,expires_ms) VALUES(?,?,?,?,?,202,?,?,?)`, actor.DeploymentID, actor.Generation, actor.User.ID, key, requestHash, string(encoded), now, now+int64(24*time.Hour/time.Millisecond))
	return err
}

func writeComparisonAuditTx(ctx context.Context, tx *sql.Tx, actor SessionRecord, action, resourceID string, now int64, detail map[string]any) error {
	auditID, err := domain.NewUUID()
	if err != nil {
		return err
	}
	encoded, err := json.Marshal(detail)
	if err != nil || len(encoded) > 65536 {
		return ErrComparisonInvalid
	}
	_, err = tx.ExecContext(ctx, `INSERT INTO audit(id,deployment_id,actor_user_id,action,resource_id,time_ms,allowlisted_detail_json) VALUES(?,?,?, ?,?,?,?)`, auditID, actor.DeploymentID, actor.User.ID, action, resourceID, now, string(encoded))
	return err
}

func (s *Store) ReadJob(ctx context.Context, actor SessionRecord, jobID string) (JobRecord, error) {
	if !validUUIDText(jobID) {
		return JobRecord{}, ErrComparisonInvalid
	}
	if _, _, err := s.validateAPITokenActorRead(ctx, actor); err != nil {
		return JobRecord{}, err
	}
	var job JobRecord
	var requestJSON string
	var resultSnapshot sql.NullString
	var errorCode sql.NullString
	var expires int64
	err := s.db.QueryRowContext(ctx, `SELECT id,deployment_generation,type,state,progress,request_json,result_snapshot_id,error_code,created_ms,updated_ms,expires_ms FROM jobs WHERE deployment_id=? AND id=? AND type IN ('comparison','probe_import')`, actor.DeploymentID, jobID).Scan(&job.ID, &job.DeploymentGeneration, &job.Type, &job.State, &job.ProgressRatio, &requestJSON, &resultSnapshot, &errorCode, &job.CreatedMS, &job.UpdatedMS, &expires)
	if errors.Is(err, sql.ErrNoRows) {
		return JobRecord{}, ErrComparisonNotFound
	}
	if err != nil {
		return JobRecord{}, err
	}
	job.ErrorCode = nullableStringPointer(errorCode)
	job.CancelState = "not_requested"
	var request struct {
		RunID        string `json:"run_id"`
		ComparisonID string `json:"comparison_id"`
	}
	if json.Unmarshal([]byte(requestJSON), &request) != nil {
		return JobRecord{}, ErrComparisonInvalid
	}
	resourceID, resourceType := request.ComparisonID, "comparison"
	if job.Type == "probe_import" {
		resourceID, resourceType = request.RunID, "probe_run"
	}
	if resourceID == "" {
		return JobRecord{}, ErrComparisonInvalid
	}
	job.Result = &JobResult{ResourceID: resourceID, ResourceType: resourceType}
	if job.State == "succeeded" {
		job.ProgressRatio = 1
	}
	_ = resultSnapshot
	_ = expires
	return job, nil
}

func (s *Store) ReadImportedRun(ctx context.Context, deploymentID, runID string) (RequestRun, error) {
	if !validUUIDText(deploymentID) || !validUUIDText(runID) {
		return RequestRun{}, ErrProbeImportInvalid
	}
	tx, err := s.db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return RequestRun{}, err
	}
	defer tx.Rollback()
	run, err := readImportedRunTx(ctx, tx, deploymentID, runID)
	if err != nil {
		return RequestRun{}, err
	}
	if err := tx.Commit(); err != nil {
		return RequestRun{}, err
	}
	return run, nil
}

func readImportedRunTx(ctx context.Context, tx *sql.Tx, deploymentID, runID string) (RequestRun, error) {
	var run RequestRun
	var populationJSON string
	var created int64
	var finalised sql.NullInt64
	var partial, artifact sql.NullString
	var decoded int64
	err := tx.QueryRowContext(ctx, `SELECT r.id,r.deployment_id,r.host_id,r.source_id,r.target_id,r.source_kind,r.verification_state,r.population_key_json,r.expected_count,r.submitted_count,r.completed_count,r.failed_count,r.cancelled_count,r.incomplete_count,r.finalization_state,r.created_ms,r.finalized_ms,m.model_id,m.config_id,m.decoded_size_bytes,m.original_artifact_sha256,m.partial_reason FROM request_runs r JOIN request_run_metadata m ON m.deployment_id=r.deployment_id AND m.host_id=r.host_id AND m.run_id=r.id WHERE r.deployment_id=? AND r.id=?`, deploymentID, runID).Scan(&run.RunID, &run.DeploymentID, &run.HostID, &run.SourceID, &run.TargetID, &run.SourceKind, &run.VerificationState, &populationJSON, &run.ExpectedCount, &run.SubmittedCount, &run.CompletedCount, &run.FailedCount, &run.CancelledCount, &run.IncompleteCount, &run.FinalizationState, &created, &finalised, &run.ModelID, &run.ConfigSnapshotID, &decoded, &artifact, &partial)
	if errors.Is(err, sql.ErrNoRows) {
		return RequestRun{}, ErrComparisonNotFound
	}
	if err != nil {
		return RequestRun{}, err
	}
	if json.Unmarshal([]byte(populationJSON), &run.PopulationKey) != nil {
		return RequestRun{}, ErrProbeImportInvalid
	}
	run.SchemaVersion = domain.SchemaVersion
	run.DecodedSizeBytes = decoded
	run.PartialReason = nullableStringPointer(partial)
	run.ContentPersistence = "none"
	run.Samples, err = readImportedSamplesTx(ctx, tx, deploymentID, run)
	if err != nil {
		return RequestRun{}, err
	}
	_ = finalised
	_ = created
	_ = artifact
	return run, nil
}

func readImportedSamplesTx(ctx context.Context, tx *sql.Tx, deploymentID string, run RequestRun) ([]RequestSample, error) {
	rows, err := tx.QueryContext(ctx, `SELECT sample_id,host_id,source_id,target_id,model_id,config_id,observation_scope,runtime_source_pin_id,terminal_record_observed,submitted_at_ms,submit_offset_ns,headers_offset_ns,first_byte_offset_ns,first_thinking_offset_ns,first_content_offset_ns,end_offset_ns,http_status,terminal_status,done_reason,safe_error_category,client_first_byte_ms,client_first_content_ms,client_total_ms,runtime_total_duration_ms,runtime_load_duration_ms,runtime_prompt_eval_duration_ms,runtime_eval_duration_ms,runtime_prompt_tokens,runtime_output_tokens,field_provenance_json FROM request_samples WHERE deployment_id=? AND run_id=? ORDER BY submitted_at_ms,sample_id`, deploymentID, run.RunID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	items := []RequestSample{}
	for rows.Next() {
		var sample RequestSample
		var headers, firstByte, firstThinking, firstContent sql.NullString
		var status sql.NullInt64
		var done, safe sql.NullString
		var terminal int
		var fields string
		var metrics RequestMetrics
		var clientFirstByte, clientFirstContent, clientTotal, runtimeTotal, runtimeLoad, runtimePromptEval, runtimeEval sql.NullFloat64
		var runtimePromptTokens, runtimeOutputTokens sql.NullInt64
		if err := rows.Scan(&sample.SampleID, &sample.HostID, &sample.SourceID, &sample.TargetID, &sample.ModelID, &sample.ConfigSnapshotID, &sample.ObservationScope, &sample.RuntimeSourcePinID, &terminal, &sample.SubmittedAtMS, &sample.OffsetsNS.Submit, &headers, &firstByte, &firstThinking, &firstContent, &sample.OffsetsNS.End, &status, &sample.TerminalStatus, &done, &safe, &clientFirstByte, &clientFirstContent, &clientTotal, &runtimeTotal, &runtimeLoad, &runtimePromptEval, &runtimeEval, &runtimePromptTokens, &runtimeOutputTokens, &fields); err != nil {
			return nil, err
		}
		metrics.ClientFirstByteMS, metrics.ClientFirstContentMS, metrics.ClientTotalMS = nullableFloat64Pointer(clientFirstByte), nullableFloat64Pointer(clientFirstContent), nullableFloat64Pointer(clientTotal)
		metrics.RuntimeTotalDurationMS, metrics.RuntimeLoadDurationMS, metrics.RuntimePromptEvalMS, metrics.RuntimeEvalMS = nullableFloat64Pointer(runtimeTotal), nullableFloat64Pointer(runtimeLoad), nullableFloat64Pointer(runtimePromptEval), nullableFloat64Pointer(runtimeEval)
		metrics.RuntimePromptTokens, metrics.RuntimeOutputTokens = nullableInt64Pointer(runtimePromptTokens), nullableInt64Pointer(runtimeOutputTokens)
		sample.Metrics = metrics
		sample.SchemaVersion, sample.RunID, sample.SourceKind, sample.VerificationState = domain.SchemaVersion, run.RunID, run.SourceKind, run.VerificationState
		sample.DeploymentID, sample.PopulationKey, sample.RuntimeOperation, sample.ContentPersistence = run.DeploymentID, run.PopulationKey, "generate", "none"
		sample.TerminalRecordObserved = terminal != 0
		sample.OffsetsNS.Headers, sample.OffsetsNS.FirstByte, sample.OffsetsNS.FirstThinking, sample.OffsetsNS.FirstContent = nullableStringPointer(headers), nullableStringPointer(firstByte), nullableStringPointer(firstThinking), nullableStringPointer(firstContent)
		sample.HTTPStatus, sample.DoneReason, sample.SafeErrorCategory = nullableIntPointer(status), nullableStringPointer(done), nullableStringPointer(safe)
		if json.Unmarshal([]byte(fields), &sample.FieldProvenance) != nil {
			return nil, ErrProbeImportInvalid
		}
		items = append(items, sample)
	}
	return items, rows.Err()
}

func nullableIntPointer(value sql.NullInt64) *int {
	if !value.Valid {
		return nil
	}
	parsed := int(value.Int64)
	return &parsed
}

func nullableFloat64Pointer(value sql.NullFloat64) *float64 {
	if !value.Valid {
		return nil
	}
	parsed := value.Float64
	return &parsed
}
