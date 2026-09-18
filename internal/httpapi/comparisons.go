package httpapi

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"

	"rmt.local/monitor/internal/domain"
	"rmt.local/monitor/internal/protocol"
	"rmt.local/monitor/internal/store"
)

const probeImportHTTPMaximumBytes int64 = 8 << 20

// handleComparisonRoute owns the content-free probe import and request-run
// comparison surface. It deliberately keeps imports as one bounded request;
// Store.ImportProbe validates the complete envelope before opening its write
// transaction.
func (s *Server) handleComparisonRoute(w http.ResponseWriter, r *http.Request, requestID string) bool {
	path := r.URL.Path
	switch {
	case path == "/api/v1/probes":
		if r.Method != http.MethodPost {
			s.writeError(w, http.StatusMethodNotAllowed, requestID, "method_not_allowed", "Probe import is available only as a POST.", "none", 2, false)
			return true
		}
		s.handleProbeImport(w, r, requestID)
		return true
	case path == "/api/v1/comparisons/preview":
		if r.Method != http.MethodGet {
			s.writeError(w, http.StatusMethodNotAllowed, requestID, "method_not_allowed", "Comparison preview is available only as a GET.", "none", 2, false)
			return true
		}
		s.handleComparisonPreview(w, r, requestID)
		return true
	case path == "/api/v1/comparisons":
		if r.Method != http.MethodPost {
			s.writeError(w, http.StatusMethodNotAllowed, requestID, "method_not_allowed", "Saving a comparison is available only as a POST.", "none", 2, false)
			return true
		}
		s.handleComparisonSave(w, r, requestID)
		return true
	case strings.HasPrefix(path, "/api/v1/comparisons/"):
		id := strings.TrimPrefix(path, "/api/v1/comparisons/")
		if strings.Contains(id, "/") || !validAPIUUID(id) {
			s.writeError(w, http.StatusBadRequest, requestID, "invalid_comparison", "A valid comparison ID is required.", "fix_input", 2, false)
			return true
		}
		if r.Method != http.MethodGet {
			s.writeError(w, http.StatusMethodNotAllowed, requestID, "method_not_allowed", "Comparison results are read-only after saving.", "none", 2, false)
			return true
		}
		s.handleComparisonShow(w, r, requestID, id)
		return true
	case strings.HasPrefix(path, "/api/v1/incidents/") && strings.HasSuffix(path, "/comparisons"):
		incidentID := strings.TrimSuffix(strings.TrimPrefix(path, "/api/v1/incidents/"), "/comparisons")
		if strings.Contains(incidentID, "/") || !validAPIUUID(incidentID) {
			s.writeError(w, http.StatusBadRequest, requestID, "invalid_incident", "A valid incident ID is required.", "fix_input", 2, false)
			return true
		}
		if r.Method != http.MethodPost {
			s.writeError(w, http.StatusMethodNotAllowed, requestID, "method_not_allowed", "Attaching a comparison is available only as a POST.", "none", 2, false)
			return true
		}
		s.handleComparisonAttach(w, r, requestID, incidentID)
		return true
	default:
		return false
	}
}

func (s *Server) handleProbeImport(w http.ResponseWriter, r *http.Request, requestID string) {
	_, actor, key, ok := s.incidentMutationActor(w, r, requestID)
	if !ok {
		return
	}
	raw, input, ok := s.decodeProbeImport(w, r, requestID)
	if !ok {
		return
	}
	digest := sha256.Sum256(append([]byte(r.Method+" "+r.URL.Path+"\x00"), raw...))
	job, err := s.store.ImportProbe(r.Context(), actor, key, hex.EncodeToString(digest[:]), input)
	if err != nil {
		s.comparisonError(w, requestID, err)
		return
	}
	s.writeJSON(w, http.StatusAccepted, publicComparisonJob(job, actor.Generation))
}

func (s *Server) decodeProbeImport(w http.ResponseWriter, r *http.Request, requestID string) ([]byte, store.ProbeImport, bool) {
	if mediaType := strings.ToLower(strings.TrimSpace(strings.Split(r.Header.Get("Content-Type"), ";")[0])); mediaType != "application/json" {
		s.writeError(w, http.StatusUnsupportedMediaType, requestID, "json_required", "Content-Type must be application/json.", "fix_input", 2, false)
		return nil, store.ProbeImport{}, false
	}
	if r.ContentLength > probeImportHTTPMaximumBytes {
		s.writeError(w, http.StatusRequestEntityTooLarge, requestID, "probe_import_too_large", "The normalized request evidence exceeds the 8 MiB import bound.", "fix_input", 2, false)
		return nil, store.ProbeImport{}, false
	}
	r.Body = http.MaxBytesReader(w, r.Body, probeImportHTTPMaximumBytes+1)
	raw, err := io.ReadAll(io.LimitReader(r.Body, probeImportHTTPMaximumBytes+1))
	if err != nil || int64(len(raw)) > probeImportHTTPMaximumBytes {
		s.writeError(w, http.StatusRequestEntityTooLarge, requestID, "probe_import_too_large", "The normalized request evidence exceeds the 8 MiB import bound.", "fix_input", 2, false)
		return nil, store.ProbeImport{}, false
	}
	var input store.ProbeImport
	if protocol.DecodeStrictJSONWithCeiling(bytes.NewReader(raw), int64(len(raw)), probeImportHTTPMaximumBytes, &input) != nil || !validProbeImportShape(raw) {
		s.writeError(w, http.StatusBadRequest, requestID, "invalid_probe_import", "The request-evidence import is not a complete bounded normalized envelope.", "fix_input", 2, false)
		return nil, store.ProbeImport{}, false
	}
	return raw, input, true
}

func validProbeImportShape(raw []byte) bool {
	var envelope map[string]json.RawMessage
	if json.Unmarshal(raw, &envelope) != nil || len(envelope) != 3 || !hasFields(envelope, "original_artifact_sha256", "normalization_revision", "run") {
		return false
	}
	var run map[string]json.RawMessage
	if json.Unmarshal(envelope["run"], &run) != nil || !hasFields(run, "schema_version", "run_id", "deployment_id", "host_id", "source_id", "target_id", "model_id", "config_snapshot_id", "source_kind", "verification_state", "population_key", "expected_count", "submitted_count", "completed_count", "failed_count", "cancelled_count", "incomplete_count", "decoded_size_bytes", "finalization_state", "partial_reason", "content_persistence", "samples") {
		return false
	}
	var samples []json.RawMessage
	if json.Unmarshal(run["samples"], &samples) != nil {
		return false
	}
	for _, encoded := range samples {
		var sample map[string]json.RawMessage
		if json.Unmarshal(encoded, &sample) != nil || !hasFields(sample, "schema_version", "sample_id", "run_id", "source_kind", "verification_state", "observation_scope", "deployment_id", "host_id", "source_id", "target_id", "model_id", "config_snapshot_id", "population_key", "runtime_source_pin_id", "runtime_operation", "terminal_record_observed", "submitted_at_ms", "offsets_ns", "http_status", "terminal_status", "done_reason", "safe_error_category", "metrics", "field_provenance", "content_persistence") {
			return false
		}
		var offsets, metrics, provenance map[string]json.RawMessage
		if json.Unmarshal(sample["offsets_ns"], &offsets) != nil || len(offsets) != 6 || !hasFields(offsets, "submit", "headers", "first_byte", "first_thinking", "first_content", "end") || json.Unmarshal(sample["metrics"], &metrics) != nil || len(metrics) != len(requestMetricFieldNames) || !hasFields(metrics, requestMetricFieldNames...) || json.Unmarshal(sample["field_provenance"], &provenance) != nil || len(provenance) != len(requestMetricFieldNames) || !hasFields(provenance, requestMetricFieldNames...) {
			return false
		}
	}
	return true
}

var requestMetricFieldNames = []string{
	"request.client.first_byte_ms", "request.client.first_content_ms", "request.client.total_ms",
	"request.runtime.total_duration_ms", "request.runtime.load_duration_ms", "request.runtime.prompt_eval_duration_ms",
	"request.runtime.eval_duration_ms", "request.runtime.prompt_tokens", "request.runtime.output_tokens",
}

func hasFields(value map[string]json.RawMessage, fields ...string) bool {
	for _, field := range fields {
		if _, ok := value[field]; !ok {
			return false
		}
	}
	return true
}

func (s *Server) handleComparisonPreview(w http.ResponseWriter, r *http.Request, requestID string) {
	if !onlyQueryKeys(r, "comparison_kind", "scope_id", "metric_id", "before_run_id", "after_run_id") {
		s.writeError(w, http.StatusBadRequest, requestID, "invalid_query", "Comparison preview requires only the reviewed run and metric parameters.", "fix_input", 2, false)
		return
	}
	session, _, ok := s.requireSession(w, r, requestID)
	if !ok {
		return
	}
	state, err := s.store.DeploymentState(r.Context())
	if err != nil {
		s.internalError(w, requestID)
		return
	}
	request := store.RequestComparison{ComparisonKind: r.URL.Query().Get("comparison_kind"), ScopeID: r.URL.Query().Get("scope_id"), MetricID: r.URL.Query().Get("metric_id"), BeforeRunID: r.URL.Query().Get("before_run_id"), AfterRunID: r.URL.Query().Get("after_run_id")}
	actor := store.SessionRecord{User: session.User, DeploymentID: state.DeploymentID, Generation: state.DeploymentGeneration, ExpiresMS: session.ExpiresMS}
	result, err := s.store.PreviewComparison(r.Context(), actor, request)
	if err != nil {
		s.comparisonError(w, requestID, err)
		return
	}
	s.writeJSON(w, http.StatusOK, result)
}

func (s *Server) handleComparisonSave(w http.ResponseWriter, r *http.Request, requestID string) {
	_, actor, key, ok := s.incidentMutationActor(w, r, requestID)
	if !ok {
		return
	}
	var request store.RequestComparison
	if !s.decodeJSON(w, r, requestID, &request) {
		return
	}
	digest := sha256.Sum256(append([]byte(r.Method+" "+r.URL.Path+"\x00"), mustJSON(request)...))
	job, err := s.store.SaveComparison(r.Context(), actor, key, hex.EncodeToString(digest[:]), request)
	if err != nil {
		s.comparisonError(w, requestID, err)
		return
	}
	s.writeJSON(w, http.StatusAccepted, publicComparisonJob(job, actor.Generation))
}

func (s *Server) handleComparisonShow(w http.ResponseWriter, r *http.Request, requestID, comparisonID string) {
	if r.URL.RawQuery != "" {
		s.writeError(w, http.StatusBadRequest, requestID, "invalid_query", "Comparison results do not accept query parameters.", "fix_input", 2, false)
		return
	}
	session, _, ok := s.requireSession(w, r, requestID)
	if !ok {
		return
	}
	state, err := s.store.DeploymentState(r.Context())
	if err != nil {
		s.internalError(w, requestID)
		return
	}
	actor := store.SessionRecord{User: session.User, DeploymentID: state.DeploymentID, Generation: state.DeploymentGeneration, ExpiresMS: session.ExpiresMS}
	result, err := s.store.ReadComparison(r.Context(), actor, comparisonID)
	if err != nil {
		s.comparisonError(w, requestID, err)
		return
	}
	s.writeJSON(w, http.StatusOK, result)
}

func (s *Server) handleComparisonAttach(w http.ResponseWriter, r *http.Request, requestID, incidentID string) {
	_, actor, key, ok := s.incidentMutationActor(w, r, requestID)
	if !ok {
		return
	}
	var body struct {
		ResourceID string `json:"resource_id"`
	}
	if !s.decodeJSON(w, r, requestID, &body) {
		return
	}
	if !validAPIUUID(body.ResourceID) {
		s.comparisonError(w, requestID, store.ErrComparisonInvalid)
		return
	}
	digest := sha256.Sum256(append([]byte(r.Method+" "+r.URL.Path+"\x00"), []byte(body.ResourceID)...))
	if err := s.store.AttachComparison(r.Context(), actor, incidentID, body.ResourceID, key, hex.EncodeToString(digest[:])); err != nil {
		s.comparisonError(w, requestID, err)
		return
	}
	record, err := s.store.ReadIncident(r.Context(), actor.DeploymentID, incidentID)
	if err != nil {
		s.comparisonError(w, requestID, err)
		return
	}
	response, err := incidentDetail(record)
	if err != nil {
		s.internalError(w, requestID)
		return
	}
	response.Comparisons, err = s.store.ListIncidentComparisons(r.Context(), actor, incidentID)
	if err != nil {
		s.comparisonError(w, requestID, err)
		return
	}
	s.writeJSON(w, http.StatusOK, response)
}

func publicComparisonJob(job store.JobRecord, generation string) map[string]any {
	return map[string]any{
		"schema_version":        domain.SchemaVersion,
		"job_id":                job.ID,
		"deployment_generation": generation,
		"type":                  job.Type,
		"state":                 job.State,
		"progress_ratio":        job.ProgressRatio,
		"created_ms":            job.CreatedMS,
		"updated_ms":            job.UpdatedMS,
		"result":                job.Result,
		"error":                 nil,
		"cancel_state":          job.CancelState,
	}
}

func (s *Server) comparisonError(w http.ResponseWriter, requestID string, err error) {
	switch {
	case errors.Is(err, store.ErrProbeRunInvalid):
		s.writeError(w, http.StatusBadRequest, requestID, "invalid_probe_run", "The bounded local probe request or result is invalid.", "fix_input", 2, false)
	case errors.Is(err, store.ErrProbeTargetUnavailable):
		s.writeError(w, http.StatusConflict, requestID, "local_target_not_ready", "The local Ollama target is not ready for a direct probe.", "review_current_state", 7, false)
	case errors.Is(err, store.ErrProbeRunConflict):
		s.writeError(w, http.StatusConflict, requestID, "idempotency_conflict", "The direct probe retry key or run identity is already associated with different input.", "fix_input", 7, false)
	case errors.Is(err, store.ErrProbeImportInvalid):
		s.writeError(w, http.StatusBadRequest, requestID, "invalid_probe_import", "The normalized request evidence is invalid or incomplete.", "fix_input", 2, false)
	case errors.Is(err, store.ErrComparisonInvalid):
		s.writeError(w, http.StatusBadRequest, requestID, "invalid_comparison", "The comparison request is invalid.", "fix_input", 2, false)
	case errors.Is(err, store.ErrOwnershipMismatch):
		s.writeError(w, http.StatusForbidden, requestID, "administrator_required", "The requested evidence is not owned by this deployment or requires administrator access.", "authenticate", 4, false)
	case errors.Is(err, store.ErrAdmissionFenced), errors.Is(err, store.ErrGenerationConflict):
		s.writeError(w, http.StatusConflict, requestID, "restore_state_changed", "The deployment changed before this operation completed.", "review_current_state", 7, false)
	case errors.Is(err, store.ErrProbeImportConflict), errors.Is(err, store.ErrComparisonConflict):
		s.writeError(w, http.StatusConflict, requestID, "idempotency_conflict", "The retry key or imported identity is already associated with different input.", "fix_input", 7, false)
	case errors.Is(err, store.ErrProbeImportBusy):
		s.writeError(w, http.StatusTooManyRequests, requestID, "probe_import_busy", "Another bounded probe import is still active.", "retry_later", 7, true)
	case errors.Is(err, store.ErrProbeImportRate):
		w.Header().Set("Retry-After", "60")
		s.writeError(w, http.StatusTooManyRequests, requestID, "probe_import_rate_limited", "Wait before importing another request-evidence artifact.", "retry_later", 7, true)
	case errors.Is(err, store.ErrProbeImportCapacity), errors.Is(err, store.ErrComparisonCapacity):
		s.writeError(w, http.StatusInsufficientStorage, requestID, "comparison_capacity_exhausted", "The bounded evidence or comparison retention capacity is full.", "review_current_state", 7, false)
	case errors.Is(err, store.ErrComparisonNotFound):
		s.writeError(w, http.StatusNotFound, requestID, "comparison_not_found", "The selected run or saved comparison was not found.", "review_current_state", 7, false)
	case errors.Is(err, store.ErrIncidentNotFound):
		s.writeError(w, http.StatusNotFound, requestID, "investigation_not_found", "The investigation was not found.", "review_current_state", 7, false)
	case errors.Is(err, store.ErrComparisonExpired):
		s.writeError(w, http.StatusGone, requestID, "comparison_expired", "The saved comparison expired under the bounded retention policy.", "review_current_state", 7, false)
	case errors.Is(err, store.ErrComparisonIneligible):
		s.writeError(w, http.StatusUnprocessableEntity, requestID, "comparison_ineligible", "The selected runs cannot be compared under the recorded population and evidence rules.", "review_current_state", 2, false)
	case errors.Is(err, store.ErrWriterBackpressure), errors.Is(err, context.DeadlineExceeded):
		w.Header().Set("Retry-After", "1")
		s.writeError(w, http.StatusServiceUnavailable, requestID, "comparison_busy", "Comparison storage is busy.", "retry_later", 7, true)
	default:
		s.internalError(w, requestID)
	}
}

func mustJSON(value any) []byte {
	encoded, _ := json.Marshal(value)
	return encoded
}
