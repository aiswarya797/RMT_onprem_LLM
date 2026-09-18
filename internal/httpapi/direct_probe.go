package httpapi

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"strconv"
	"strings"
	"time"

	"rmt.local/monitor/internal/adapters/ollama"
	"rmt.local/monitor/internal/domain"
	"rmt.local/monitor/internal/store"
)

const (
	localProbeEndpointDefault = "http://127.0.0.1:11434"
	localProbeProfileID       = "short_text_v1"
	localProbeProfileSHA256   = "2222222222222222222222222222222222222222222222222222222222222222"
	localProbePrompt          = "Reply with one short sentence confirming this local smoke request."
	localProbePromptSHA256    = "f8215ae56bb12e83e57aef3dd1b489a73e5065d5f813acd30bca8d56c8e2ae21"
	localProbeBudgetSHA256    = "dc23909f6bc825f96427ae5072bcc7f4fbf184c1e14b14b07d0e90574883f284"
)

type localProbeRunRequest struct {
	TargetID          string                     `json:"target_id"`
	ProfileID         string                     `json:"profile_id"`
	Count             int                        `json:"count"`
	LoadConfirmation  localProbeLoadConfirmation `json:"load_confirmation"`
	ConfirmDeployment string                     `json:"confirm_deployment_id"`
}

type localProbeLoadConfirmation struct {
	Confirmation       string `json:"confirmation"`
	ProfileSHA256      string `json:"profile_sha256"`
	DisplayedBudgetSHA string `json:"displayed_budget_sha256"`
}

type localProbePreflight struct {
	context store.DirectProbeContext
	runtime ollama.RuntimeVersion
	model   ollama.Model
	modelID string
	loaded  bool
	client  *ollama.Client
}

type localProbeBlock struct {
	code    string
	reasons []string
}

// ConfigureLocalProbeEndpoint follows the reviewed local target manifest. It
// is intentionally not part of ordinary browser input: the executable loads
// the active collector-side target configuration at startup.
func (s *Server) ConfigureLocalProbeEndpoint(endpoint string) error {
	if _, err := ollama.NewClient(endpoint); err != nil {
		return err
	}
	s.localProbeEndpoint = endpoint
	return nil
}

// ConfigureLocalProbeAdmission is reserved for an explicitly launched,
// one-off experiment. The default constructor remains fail-closed.
func (s *Server) ConfigureLocalProbeAdmission(admission func() (bool, string)) {
	if admission == nil {
		s.localProbeAdmission = func() (bool, string) { return false, "inference_policy_unresolved" }
		return
	}
	s.localProbeAdmission = admission
}

func (s *Server) handleLocalProbeRoute(w http.ResponseWriter, r *http.Request, requestID string) bool {
	if r.URL.Path == "/api/v1/probes/run" {
		if r.Method != http.MethodPost {
			s.writeError(w, http.StatusMethodNotAllowed, requestID, "method_not_allowed", "A local probe run is available only as a POST.", "none", 2, false)
			return true
		}
		s.handleLocalProbeRun(w, r, requestID)
		return true
	}
	if strings.HasPrefix(r.URL.Path, "/api/v1/probes/runs/") {
		id := strings.TrimPrefix(r.URL.Path, "/api/v1/probes/runs/")
		if strings.Contains(id, "/") || !validAPIUUID(id) {
			s.writeError(w, http.StatusBadRequest, requestID, "invalid_probe_run", "A valid probe run ID is required.", "fix_input", 2, false)
			return true
		}
		if r.Method != http.MethodGet {
			s.writeError(w, http.StatusMethodNotAllowed, requestID, "method_not_allowed", "Probe run results are read-only after execution.", "none", 2, false)
			return true
		}
		s.handleLocalProbeShow(w, r, requestID, id)
		return true
	}
	return false
}

func (s *Server) handleLocalProbeRun(w http.ResponseWriter, r *http.Request, requestID string) {
	_, actor, key, ok := s.incidentMutationActor(w, r, requestID)
	if !ok {
		return
	}
	var input localProbeRunRequest
	if !s.decodeJSON(w, r, requestID, &input) {
		return
	}
	if err := validateLocalProbeRunRequest(input, actor.DeploymentID); err != nil {
		s.comparisonError(w, requestID, err)
		return
	}
	requestHash := localProbeRequestHash(r.Method, r.URL.Path, input)
	if !s.localProbeMu.TryLock() {
		s.recordLocalProbeBlock(w, r, requestID, actor, key, requestHash, input.TargetID, "probe_busy", []string{"probe_busy"})
		return
	}
	defer s.localProbeMu.Unlock()

	preflight, blocked := s.localProbePreflight(r.Context(), input.TargetID)
	if blocked != nil {
		s.recordLocalProbeBlock(w, r, requestID, actor, key, requestHash, input.TargetID, blocked.code, blocked.reasons)
		return
	}
	receipt, err := s.executeLocalProbe(r.Context(), actor, key, requestHash, preflight)
	if err != nil {
		s.comparisonError(w, requestID, err)
		return
	}
	s.writeJSON(w, http.StatusOK, receipt)
}

func (s *Server) recordLocalProbeBlock(w http.ResponseWriter, r *http.Request, requestID string, actor store.SessionRecord, key, requestHash, targetID, code string, reasons []string) {
	receipt, err := s.store.RecordDirectProbeBlock(r.Context(), actor, key, requestHash, targetID, code, reasons)
	if err != nil {
		s.comparisonError(w, requestID, err)
		return
	}
	s.writeJSON(w, http.StatusOK, receipt)
}

func (s *Server) handleLocalProbeShow(w http.ResponseWriter, r *http.Request, requestID, runID string) {
	session, _, ok := s.requireSession(w, r, requestID)
	if !ok {
		return
	}
	state, err := s.store.DeploymentState(r.Context())
	if err != nil {
		s.internalError(w, requestID)
		return
	}
	if session.User.Role != "admin" {
		s.writeError(w, http.StatusForbidden, requestID, "administrator_required", "Administrator access is required to read direct probe results.", "authenticate", 4, false)
		return
	}
	run, err := s.store.ReadImportedRun(r.Context(), state.DeploymentID, runID)
	if err != nil {
		s.comparisonError(w, requestID, err)
		return
	}
	if run.SourceKind != "deliberate_probe" || run.VerificationState != "direct_capture" {
		s.writeError(w, http.StatusNotFound, requestID, "probe_run_not_found", "The selected direct probe run was not found.", "review_current_state", 7, false)
		return
	}
	s.writeJSON(w, http.StatusOK, run)
}

func validateLocalProbeRunRequest(input localProbeRunRequest, deploymentID string) error {
	if !validAPIUUID(input.TargetID) || input.ProfileID != localProbeProfileID || input.Count != 1 || input.ConfirmDeployment != deploymentID || input.LoadConfirmation.Confirmation != "confirm_load" || input.LoadConfirmation.ProfileSHA256 != localProbeProfileSHA256 || input.LoadConfirmation.DisplayedBudgetSHA != localProbeBudgetSHA256 {
		return store.ErrProbeRunInvalid
	}
	return nil
}

func localProbeRequestHash(method, path string, input localProbeRunRequest) string {
	digest := sha256.Sum256(append([]byte(method+" "+path+"\x00"), mustJSON(input)...))
	return hex.EncodeToString(digest[:])
}

func (s *Server) localProbePreflight(ctx context.Context, targetID string) (localProbePreflight, *localProbeBlock) {
	probeContext, err := s.store.ReadDirectProbeContext(ctx, targetID)
	if err != nil {
		return localProbePreflight{}, &localProbeBlock{code: "target_not_ready", reasons: []string{"target_not_ready"}}
	}
	endpoint := s.localProbeEndpoint
	if endpoint == "" {
		endpoint = localProbeEndpointDefault
	}
	client, err := ollama.NewClient(endpoint)
	if err != nil {
		return localProbePreflight{}, &localProbeBlock{code: "runtime_unreachable", reasons: []string{"runtime_unreachable"}}
	}
	preflightContext, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	runtime, err := client.Version(preflightContext)
	if err != nil {
		return localProbePreflight{}, &localProbeBlock{code: "runtime_unreachable", reasons: []string{"runtime_unreachable"}}
	}
	tags, err := client.Tags(preflightContext)
	if err != nil {
		return localProbePreflight{}, &localProbeBlock{code: "runtime_unreachable", reasons: []string{"runtime_unreachable"}}
	}
	loadedInventory, err := client.LoadedModels(preflightContext)
	if err != nil {
		return localProbePreflight{}, &localProbeBlock{code: "runtime_unreachable", reasons: []string{"runtime_unreachable"}}
	}
	model, modelID, ok := selectLocalProbeModel(tags.Models, probeContext.Models)
	if !ok {
		return localProbePreflight{}, &localProbeBlock{code: "model_not_suitable", reasons: []string{"model_not_suitable", "inference_policy_unresolved"}}
	}
	loaded := modelLoaded(model, loadedInventory.Models)
	if runtime.SourcePinID == "runtime-version-unverified" {
		return localProbePreflight{}, &localProbeBlock{code: "runtime_version_unverified", reasons: []string{"runtime_version_unverified", "inference_policy_unresolved"}}
	}
	admitted, reason := s.localProbeAdmissionDecision()
	if !admitted {
		if reason == "" {
			reason = "inference_policy_unresolved"
		}
		return localProbePreflight{}, &localProbeBlock{code: reason, reasons: []string{reason}}
	}
	model.Loaded = loaded
	return localProbePreflight{context: probeContext, runtime: runtime, model: model, modelID: modelID, loaded: loaded, client: client}, nil
}

func (s *Server) localProbeAdmissionDecision() (bool, string) {
	if s.localProbeAdmission == nil {
		return false, "inference_policy_unresolved"
	}
	return s.localProbeAdmission()
}

func selectLocalProbeModel(runtimeModels []ollama.Model, retained []store.DirectProbeModel) (ollama.Model, string, bool) {
	retainedByDigest := make(map[string]store.DirectProbeModel, len(retained))
	for _, item := range retained {
		if item.Digest != nil {
			retainedByDigest[*item.Digest] = item
		}
	}
	for _, model := range runtimeModels {
		if !model.Local || model.Digest == nil || !smallQuantizedModel(model) {
			continue
		}
		retainedModel, ok := retainedByDigest[*model.Digest]
		if !ok || retainedModel.Digest == nil {
			continue
		}
		return model, retainedModel.ID, true
	}
	return ollama.Model{}, "", false
}

func smallQuantizedModel(model ollama.Model) bool {
	if model.Details.ParameterSize == nil || model.Details.QuantizationLevel == nil || strings.TrimSpace(*model.Details.QuantizationLevel) == "" {
		return false
	}
	parameters, ok := parameterSizeInBillions(*model.Details.ParameterSize)
	return ok && parameters >= 0.5 && parameters <= 1.0
}

func parameterSizeInBillions(value string) (float64, bool) {
	value = strings.TrimSpace(strings.ToUpper(value))
	multiplier := 1.0
	switch {
	case strings.HasSuffix(value, "B"):
		value = strings.TrimSpace(strings.TrimSuffix(value, "B"))
	case strings.HasSuffix(value, "M"):
		value = strings.TrimSpace(strings.TrimSuffix(value, "M"))
		multiplier = 0.001
	default:
		return 0, false
	}
	parameters, err := strconv.ParseFloat(value, 64)
	return parameters * multiplier, err == nil && parameters > 0
}

func modelLoaded(model ollama.Model, loaded []ollama.Model) bool {
	for _, candidate := range loaded {
		if model.Digest != nil && candidate.Digest != nil && *model.Digest == *candidate.Digest {
			return true
		}
	}
	return false
}

func (s *Server) executeLocalProbe(ctx context.Context, actor store.SessionRecord, key, requestHash string, preflight localProbePreflight) (store.DirectProbeReceipt, error) {
	run, err := domain.NewUUID()
	if err != nil {
		return store.DirectProbeReceipt{}, err
	}
	sample, err := domain.NewUUID()
	if err != nil {
		return store.DirectProbeReceipt{}, err
	}
	requestResult, timings, requestErr := preflight.client.Generate(ctx, ollama.GenerateRequest{
		Model: preflight.model.Alias, Prompt: localProbePrompt, NumCtx: 1024, NumPredict: 64,
		Temperature: 0, Seed: 7, Think: false, Stream: true,
	})
	directRun := directProbeRun(actor, preflight, run, sample, requestResult, timings)
	if requestErr != nil && directRun.Samples[0].SafeErrorCategory == nil {
		category := "connection"
		directRun.Samples[0].SafeErrorCategory = &category
		directRun.FailedCount = 1
	}
	return s.store.RecordDirectProbe(ctx, actor, key, requestHash, directRun)
}

func directProbeRun(actor store.SessionRecord, preflight localProbePreflight, runID, sampleID string, result ollama.StreamResult, timings ollama.RequestTimings) store.RequestRun {
	status := string(result.TerminalStatus)
	if status == "" {
		status = "failed"
	}
	think := false
	temperature := float64(0)
	seed := int64(7)
	population := store.RequestPopulationKey{
		TargetID: preflight.context.TargetID, ModelDigest: *preflight.model.Digest, RuntimeVersion: preflight.runtime.Version,
		ConfigRevision: preflight.context.ConfigHash, ProfileID: localProbeProfileID, ProfileSHA256: localProbeProfileSHA256,
		Options:     store.RequestGenerationOptions{NumCtx: 1024, NumPredict: 64, Temperature: &temperature, Seed: &seed, Think: &think, Stream: true, ColdWarmPolicy: coldWarmPolicy(preflight.loaded)},
		Concurrency: 1, VantageID: "mac-local", ClockMethod: "monotonic", SourceKind: "deliberate_probe", VerificationState: "direct_capture",
	}
	metrics := directProbeMetrics(result, timings)
	provenance := directProbeProvenance(metrics, result)
	sample := store.RequestSample{
		SchemaVersion: domain.SchemaVersion, SampleID: sampleID, RunID: runID, SourceKind: "deliberate_probe", VerificationState: "direct_capture", ObservationScope: "explicit_observed_request",
		DeploymentID: actor.DeploymentID, HostID: preflight.context.HostID, SourceID: preflight.context.SourceID, TargetID: preflight.context.TargetID, ModelID: preflight.modelID, ConfigSnapshotID: preflight.context.ConfigSnapshotID,
		PopulationKey: population, RuntimeSourcePinID: preflight.runtime.SourcePinID, RuntimeOperation: "generate", TerminalRecordObserved: result.TerminalRecordObserved,
		SubmittedAtMS: time.Now().UnixMilli(), OffsetsNS: directProbeOffsets(timings), HTTPStatus: result.HTTPStatus, TerminalStatus: status, DoneReason: result.DoneReason, SafeErrorCategory: result.SafeErrorCategory,
		Metrics: metrics, FieldProvenance: provenance, ContentPersistence: "none",
	}
	completed, failed, cancelled, incomplete := 0, 0, 0, 0
	switch status {
	case "completed":
		completed = 1
	case "cancelled":
		cancelled = 1
	case "incomplete":
		incomplete = 1
	default:
		failed = 1
	}
	run := store.RequestRun{
		SchemaVersion: domain.SchemaVersion, RunID: runID, DeploymentID: actor.DeploymentID, HostID: preflight.context.HostID, SourceID: preflight.context.SourceID, TargetID: preflight.context.TargetID, ModelID: preflight.modelID, ConfigSnapshotID: preflight.context.ConfigSnapshotID,
		SourceKind: "deliberate_probe", VerificationState: "direct_capture", PopulationKey: population, ExpectedCount: 1, SubmittedCount: 1, CompletedCount: completed, FailedCount: failed, CancelledCount: cancelled, IncompleteCount: incomplete,
		DecodedSizeBytes: 1024, FinalizationState: "finalized", ContentPersistence: "none", Samples: []store.RequestSample{sample},
	}
	run.DecodedSizeBytes = int64(len(mustJSON(run)))
	return run
}

func coldWarmPolicy(loaded bool) string {
	if loaded {
		return "warm_model_reported_loaded"
	}
	return "cold_model_unloaded"
}

func directProbeOffsets(timings ollama.RequestTimings) store.RequestOffsets {
	return store.RequestOffsets{Submit: "0", Headers: uint64StringPointer(timings.HeadersNS), FirstByte: uint64PointerString(timings.FirstByteNS), FirstThinking: uint64PointerString(timings.FirstThinkingNS), FirstContent: uint64PointerString(timings.FirstContentNS), End: strconv.FormatUint(timings.EndNS, 10)}
}

func directProbeMetrics(result ollama.StreamResult, timings ollama.RequestTimings) store.RequestMetrics {
	return store.RequestMetrics{
		ClientFirstByteMS: nanosecondsMS(timings.FirstByteNS), ClientFirstContentMS: nanosecondsMS(timings.FirstContentNS), ClientTotalMS: nanosecondsMS(&timings.EndNS),
		RuntimeTotalDurationMS: result.Metrics.TotalDurationMS, RuntimeLoadDurationMS: result.Metrics.LoadDurationMS, RuntimePromptEvalMS: result.Metrics.PromptEvalDurationMS, RuntimeEvalMS: result.Metrics.EvalDurationMS,
		RuntimePromptTokens: uint64ToInt64(result.Metrics.PromptTokens), RuntimeOutputTokens: uint64ToInt64(result.Metrics.OutputTokens),
	}
}

func directProbeProvenance(metrics store.RequestMetrics, result ollama.StreamResult) map[string]store.RequestFieldProvenance {
	provenance := make(map[string]store.RequestFieldProvenance, 9)
	for _, metric := range []struct {
		name   string
		value  bool
		source string
	}{
		{"request.client.first_byte_ms", metrics.ClientFirstByteMS != nil, "client_monotonic"},
		{"request.client.first_content_ms", metrics.ClientFirstContentMS != nil, "client_monotonic"},
		{"request.client.total_ms", metrics.ClientTotalMS != nil, "client_monotonic"},
		{"request.runtime.total_duration_ms", metrics.RuntimeTotalDurationMS != nil, "ollama_terminal"},
		{"request.runtime.load_duration_ms", metrics.RuntimeLoadDurationMS != nil, "ollama_terminal"},
		{"request.runtime.prompt_eval_duration_ms", metrics.RuntimePromptEvalMS != nil, "ollama_terminal"},
		{"request.runtime.eval_duration_ms", metrics.RuntimeEvalMS != nil, "ollama_terminal"},
		{"request.runtime.prompt_tokens", metrics.RuntimePromptTokens != nil, "ollama_terminal"},
		{"request.runtime.output_tokens", metrics.RuntimeOutputTokens != nil, "ollama_terminal"},
	} {
		var missing *string
		if !metric.value {
			reason := "field_omitted"
			if result.TerminalStatus == ollama.TerminalCancelled {
				reason = "cancelled"
			} else if result.TerminalStatus == ollama.TerminalFailed {
				reason = "failed"
			} else if result.TerminalStatus == ollama.TerminalIncomplete {
				reason = "incomplete"
			}
			missing = &reason
		}
		provenance[metric.name] = store.RequestFieldProvenance{Source: metric.source, Verification: "direct_capture", MissingReason: missing}
	}
	return provenance
}

func nanosecondsMS(value *uint64) *float64 {
	if value == nil {
		return nil
	}
	converted := float64(*value) / 1_000_000
	return &converted
}

func uint64StringPointer(value uint64) *string {
	if value == 0 {
		return nil
	}
	return uint64PointerString(&value)
}

func uint64PointerString(value *uint64) *string {
	if value == nil {
		return nil
	}
	converted := strconv.FormatUint(*value, 10)
	return &converted
}

func uint64ToInt64(value *uint64) *int64 {
	if value == nil {
		return nil
	}
	converted := int64(*value)
	return &converted
}
