package httpapi

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"rmt.local/monitor/internal/domain"
	"rmt.local/monitor/internal/investigation"
	"rmt.local/monitor/internal/store"
)

type manualIncidentCreateRequest struct {
	Title string              `json:"title"`
	Scope investigation.Scope `json:"scope"`
	Start string              `json:"start"`
	End   string              `json:"end"`
}

type annotationCreateRequest struct {
	IncidentID     string `json:"incident_id"`
	DeclaredTimeMS int64  `json:"declared_time_ms"`
	Text           string `json:"text"`
}

type annotationEditRequest struct {
	ExpectedRevision int64  `json:"expected_revision"`
	Text             string `json:"text"`
}

type manualIncidentUpdateRequest struct {
	ExpectedRevision int64   `json:"expected_revision"`
	Title            *string `json:"title,omitempty"`
	WorkflowState    *string `json:"workflow_state,omitempty"`
}

type incidentSummaryResponse struct {
	SchemaVersion  string                    `json:"schema_version"`
	ID             string                    `json:"id"`
	Revision       int64                     `json:"revision"`
	Title          string                    `json:"title"`
	Origin         string                    `json:"origin"`
	Scope          investigation.Scope       `json:"scope"`
	StartMS        int64                     `json:"start_ms"`
	EndMS          *int64                    `json:"end_ms"`
	WorkflowState  string                    `json:"workflow_state"`
	OwnerUserID    *string                   `json:"owner_user_id"`
	EvidenceStatus string                    `json:"evidence_status"`
	CapsuleSHA256  string                    `json:"capsule_sha256"`
	CreatedMS      int64                     `json:"created_ms"`
	UpdatedMS      int64                     `json:"updated_ms"`
	AlertState     *store.AlertIncidentState `json:"alert_state,omitempty"`
}

type incidentDetailResponse struct {
	incidentSummaryResponse
	Capsule               json.RawMessage             `json:"capsule"`
	Annotations           []annotationResponse        `json:"annotations"`
	AnnotationsNextCursor *string                     `json:"annotations_next_cursor"`
	Comparisons           []store.ComparisonReference `json:"comparisons"`
}

type incidentListResponse struct {
	Items      []incidentSummaryResponse `json:"items"`
	NextCursor *string                   `json:"next_cursor"`
}

type annotationResponse struct {
	ID             string `json:"id"`
	Revision       int64  `json:"revision"`
	IncidentID     string `json:"incident_id"`
	DeclaredTimeMS int64  `json:"declared_time_ms"`
	Text           string `json:"text"`
	AuthorUserID   string `json:"author_user_id"`
	EditedMS       *int64 `json:"edited_ms"`
	CreatedMS      int64  `json:"created_ms"`
	Provenance     string `json:"provenance"`
}

type annotationListResponse struct {
	Items      []annotationResponse `json:"items"`
	NextCursor *string              `json:"next_cursor"`
}

// handleInvestigationRoute owns the narrow U06 manual-investigation surface.
// Server.ServeHTTP should dispatch to it before the generic /api/ 404 case:
//
//	case s.handleInvestigationRoute(w, r, requestID):
//
// It returns false without writing when the request is outside this surface.
func (s *Server) handleInvestigationRoute(w http.ResponseWriter, r *http.Request, requestID string) bool {
	path := r.URL.Path
	switch {
	case strings.HasPrefix(path, "/api/v1/incidents/") && (strings.HasSuffix(path, "/acknowledgements") || strings.HasSuffix(path, "/mute")):
		s.handleAlertControl(w, r, requestID)
	case path == "/api/v1/incidents" && r.Method == http.MethodGet:
		s.handleIncidentList(w, r, requestID)
	case path == "/api/v1/incidents" && r.Method == http.MethodPost:
		s.handleIncidentCreate(w, r, requestID)
	case strings.HasPrefix(path, "/api/v1/incidents/") && strings.HasSuffix(path, "/annotations") && r.Method == http.MethodGet:
		incidentID := strings.TrimSuffix(strings.TrimPrefix(path, "/api/v1/incidents/"), "/annotations")
		s.handleIncidentAnnotations(w, r, requestID, incidentID)
	case strings.HasPrefix(path, "/api/v1/incidents/") && r.Method == http.MethodGet:
		s.handleIncidentShow(w, r, requestID, strings.TrimPrefix(path, "/api/v1/incidents/"))
	case strings.HasPrefix(path, "/api/v1/incidents/") && r.Method == http.MethodPatch:
		s.handleIncidentUpdate(w, r, requestID, strings.TrimPrefix(path, "/api/v1/incidents/"))
	case path == "/api/v1/annotations" && r.Method == http.MethodPost:
		s.handleAnnotationCreate(w, r, requestID)
	case strings.HasPrefix(path, "/api/v1/annotations/") && r.Method == http.MethodPatch:
		s.handleAnnotationEdit(w, r, requestID, strings.TrimPrefix(path, "/api/v1/annotations/"))
	case path == "/api/v1/incidents" || strings.HasPrefix(path, "/api/v1/incidents/") || path == "/api/v1/annotations" || strings.HasPrefix(path, "/api/v1/annotations/"):
		s.writeError(w, http.StatusMethodNotAllowed, requestID, "method_not_allowed", "This investigation operation is not available.", "none", 2, false)
	default:
		return false
	}
	return true
}

func (s *Server) handleIncidentList(w http.ResponseWriter, r *http.Request, requestID string) {
	cursor, limit, ok := parseInvestigationPage(r)
	if !ok {
		s.writeError(w, http.StatusBadRequest, requestID, "invalid_query", "Incident pagination accepts one UUID cursor and a limit from 1 to 100.", "fix_input", 2, false)
		return
	}
	if _, _, ok := s.requireSession(w, r, requestID); !ok {
		return
	}
	state, err := s.store.DeploymentState(r.Context())
	if err != nil {
		s.internalError(w, requestID)
		return
	}
	ctx, cancel := interactiveQueryContext(r)
	defer cancel()
	page, err := s.store.ListIncidents(ctx, state.DeploymentID, cursor, limit)
	if err != nil {
		s.incidentError(w, requestID, err)
		return
	}
	response := incidentListResponse{Items: []incidentSummaryResponse{}}
	response.NextCursor = page.NextCursor
	for _, record := range page.Items {
		item, err := incidentSummary(record)
		if err != nil {
			s.internalError(w, requestID)
			return
		}
		if item.Origin == "alert" {
			alertState, err := s.store.ReadAlertIncidentState(ctx, state.DeploymentID, item.ID)
			if err != nil {
				s.incidentError(w, requestID, err)
				return
			}
			item.AlertState = &alertState
		}
		response.Items = append(response.Items, item)
	}
	s.writeJSON(w, http.StatusOK, response)
}

func (s *Server) handleIncidentAnnotations(w http.ResponseWriter, r *http.Request, requestID, incidentID string) {
	cursor, limit, queryOK := parseInvestigationPage(r)
	if !queryOK || !validAPIUUID(incidentID) {
		s.writeError(w, http.StatusBadRequest, requestID, "invalid_query", "Annotation pagination requires a valid incident, one UUID cursor and a limit from 1 to 100.", "fix_input", 2, false)
		return
	}
	if _, _, ok := s.requireSession(w, r, requestID); !ok {
		return
	}
	state, err := s.store.DeploymentState(r.Context())
	if err != nil {
		s.internalError(w, requestID)
		return
	}
	ctx, cancel := interactiveQueryContext(r)
	defer cancel()
	page, err := s.store.ListIncidentAnnotations(ctx, state.DeploymentID, incidentID, cursor, limit)
	if err != nil {
		s.incidentError(w, requestID, err)
		return
	}
	response := annotationListResponse{Items: []annotationResponse{}, NextCursor: page.NextCursor}
	for _, item := range page.Items {
		response.Items = append(response.Items, annotationFromStore(item))
	}
	s.writeJSON(w, http.StatusOK, response)
}

func parseInvestigationPage(r *http.Request) (string, int, bool) {
	query := r.URL.Query()
	for key, values := range query {
		if (key != "cursor" && key != "limit") || len(values) != 1 {
			return "", 0, false
		}
	}
	cursor := query.Get("cursor")
	if cursor != "" && !validAPIUUID(cursor) {
		return "", 0, false
	}
	limit := 100
	if value := query.Get("limit"); value != "" {
		parsed, err := strconv.Atoi(value)
		if err != nil || parsed < 1 || parsed > 100 {
			return "", 0, false
		}
		limit = parsed
	}
	return cursor, limit, true
}

func (s *Server) handleIncidentShow(w http.ResponseWriter, r *http.Request, requestID, incidentID string) {
	if r.URL.RawQuery != "" || !validAPIUUID(incidentID) {
		s.writeError(w, http.StatusBadRequest, requestID, "invalid_incident", "A valid incident ID is required.", "fix_input", 2, false)
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
	ctx, cancel := interactiveQueryContext(r)
	defer cancel()
	record, err := s.store.ReadIncident(ctx, state.DeploymentID, incidentID)
	if err != nil {
		s.incidentError(w, requestID, err)
		return
	}
	response, err := incidentDetail(record)
	if err != nil {
		s.internalError(w, requestID)
		return
	}
	if record.Origin == "alert" {
		alertState, err := s.store.ReadAlertIncidentState(ctx, state.DeploymentID, record.ID)
		if err != nil {
			s.incidentError(w, requestID, err)
			return
		}
		response.AlertState = &alertState
	}
	comparisons, err := s.store.ListIncidentComparisons(ctx, store.SessionRecord{User: session.User, DeploymentID: state.DeploymentID, Generation: state.DeploymentGeneration}, record.ID)
	if err != nil && !errors.Is(err, store.ErrIncidentNotFound) {
		s.comparisonError(w, requestID, err)
		return
	}
	response.Comparisons = comparisons
	s.writeJSON(w, http.StatusOK, response)
}

func (s *Server) handleIncidentCreate(w http.ResponseWriter, r *http.Request, requestID string) {
	_, actor, idempotencyKey, ok := s.incidentMutationActor(w, r, requestID)
	if !ok {
		return
	}
	var body manualIncidentCreateRequest
	if !s.decodeJSON(w, r, requestID, &body) {
		return
	}
	body.Title = strings.TrimSpace(body.Title)
	start, startErr := time.Parse(time.RFC3339, body.Start)
	end, endErr := time.Parse(time.RFC3339, body.End)
	if startErr != nil || endErr != nil || body.Title == "" || utf8.RuneCountInString(body.Title) > 160 || invalidIncidentTitle(body.Title) {
		s.writeError(w, http.StatusBadRequest, requestID, "invalid_incident", "A title, retained scope and valid five-minute to 24-hour absolute range are required.", "fix_input", 2, false)
		return
	}
	body.Start, body.End = start.UTC().Format(time.RFC3339Nano), end.UTC().Format(time.RFC3339Nano)
	canonical, _ := json.Marshal(body)
	digest := sha256.Sum256(canonical)
	requestHash := hex.EncodeToString(digest[:])
	ctx, cancel := interactiveQueryContext(r)
	defer cancel()
	if record, found, err := s.store.ReadManualIncidentRetry(ctx, actor, idempotencyKey, requestHash); err != nil {
		s.incidentError(w, requestID, err)
		return
	} else if found {
		response, err := incidentMutationSummary(record)
		if err != nil {
			s.internalError(w, requestID)
			return
		}
		s.writeJSON(w, http.StatusCreated, response)
		return
	}
	builder := investigation.NewBuilder(s.queries, s.store, func() int64 { return s.clock.Now().UnixMilli() })
	capsule, err := builder.Build(ctx, actor.DeploymentID, body.Scope, investigation.Window{StartMS: start.UnixMilli(), EndMS: end.UnixMilli()})
	if err != nil {
		s.incidentError(w, requestID, err)
		return
	}
	payload, _, err := capsule.Marshal()
	if err != nil {
		s.incidentError(w, requestID, err)
		return
	}
	scopeJSON, _ := json.Marshal(body.Scope)
	record, err := s.store.CreateManualIncident(ctx, actor, idempotencyKey, requestHash, store.ManualIncidentInput{
		Title: body.Title, ScopeJSON: scopeJSON, StartMS: start.UnixMilli(), EndMS: end.UnixMilli(), CapsuleSchemaRevision: investigation.CapsuleSchemaRevision,
		CardRevision: investigation.CardRevision, CapsulePayload: payload, EvidenceState: capsule.EvidenceState,
	})
	if err != nil {
		s.incidentError(w, requestID, err)
		return
	}
	response, err := incidentMutationSummary(record)
	if err != nil {
		s.internalError(w, requestID)
		return
	}
	s.writeJSON(w, http.StatusCreated, response)
}

func (s *Server) handleIncidentUpdate(w http.ResponseWriter, r *http.Request, requestID, incidentID string) {
	_, actor, idempotencyKey, ok := s.incidentMutationActor(w, r, requestID)
	if !ok {
		return
	}
	if r.URL.RawQuery != "" || !validAPIUUID(incidentID) {
		s.writeError(w, http.StatusBadRequest, requestID, "invalid_incident", "A valid incident ID is required.", "fix_input", 2, false)
		return
	}
	var body manualIncidentUpdateRequest
	if !s.decodeJSON(w, r, requestID, &body) {
		return
	}
	if body.Title != nil {
		trimmed := strings.TrimSpace(*body.Title)
		body.Title = &trimmed
	}
	if body.ExpectedRevision < 1 || (body.Title == nil && body.WorkflowState == nil) || (body.Title != nil && (*body.Title == "" || utf8.RuneCountInString(*body.Title) > 160 || invalidIncidentTitle(*body.Title))) || (body.WorkflowState != nil && *body.WorkflowState != "open" && *body.WorkflowState != "closed") {
		s.writeError(w, http.StatusBadRequest, requestID, "invalid_incident", "An expected revision and at least one valid title or manual workflow state are required.", "fix_input", 2, false)
		return
	}
	canonical, _ := json.Marshal(struct {
		IncidentID       string  `json:"incident_id"`
		ExpectedRevision int64   `json:"expected_revision"`
		Title            *string `json:"title,omitempty"`
		WorkflowState    *string `json:"workflow_state,omitempty"`
	}{incidentID, body.ExpectedRevision, body.Title, body.WorkflowState})
	digest := sha256.Sum256(canonical)
	record, err := s.store.UpdateManualIncident(r.Context(), actor, idempotencyKey, hex.EncodeToString(digest[:]), incidentID, store.ManualIncidentUpdate{
		ExpectedRevision: body.ExpectedRevision,
		Title:            body.Title,
		WorkflowState:    body.WorkflowState,
	})
	if err != nil {
		s.incidentError(w, requestID, err)
		return
	}
	response, err := incidentMutationSummary(record)
	if err != nil {
		s.internalError(w, requestID)
		return
	}
	s.writeJSON(w, http.StatusOK, response)
}

func invalidIncidentTitle(value string) bool {
	return strings.ContainsAny(value, "<>") || strings.IndexFunc(value, unicode.IsControl) >= 0
}

func (s *Server) handleAnnotationCreate(w http.ResponseWriter, r *http.Request, requestID string) {
	_, actor, key, ok := s.incidentMutationActor(w, r, requestID)
	if !ok {
		return
	}
	var body annotationCreateRequest
	if !s.decodeJSON(w, r, requestID, &body) {
		return
	}
	body.Text = strings.TrimSpace(body.Text)
	canonical, _ := json.Marshal(body)
	digest := sha256.Sum256(canonical)
	record, err := s.store.CreateIncidentAnnotation(r.Context(), actor, key, hex.EncodeToString(digest[:]), body.IncidentID, body.DeclaredTimeMS, body.Text)
	if err != nil {
		s.incidentError(w, requestID, err)
		return
	}
	s.writeJSON(w, http.StatusCreated, annotationFromStore(record))
}

func (s *Server) handleAnnotationEdit(w http.ResponseWriter, r *http.Request, requestID, annotationID string) {
	_, actor, key, ok := s.incidentMutationActor(w, r, requestID)
	if !ok {
		return
	}
	if !validAPIUUID(annotationID) {
		s.writeError(w, http.StatusBadRequest, requestID, "invalid_annotation", "A valid annotation ID is required.", "fix_input", 2, false)
		return
	}
	var body annotationEditRequest
	if !s.decodeJSON(w, r, requestID, &body) {
		return
	}
	body.Text = strings.TrimSpace(body.Text)
	canonical, _ := json.Marshal(struct {
		AnnotationID     string `json:"annotation_id"`
		ExpectedRevision int64  `json:"expected_revision"`
		Text             string `json:"text"`
	}{annotationID, body.ExpectedRevision, body.Text})
	digest := sha256.Sum256(canonical)
	record, err := s.store.EditIncidentAnnotation(r.Context(), actor, key, hex.EncodeToString(digest[:]), annotationID, body.ExpectedRevision, body.Text)
	if err != nil {
		s.incidentError(w, requestID, err)
		return
	}
	s.writeJSON(w, http.StatusOK, annotationFromStore(record))
}

func (s *Server) incidentMutationActor(w http.ResponseWriter, r *http.Request, requestID string) (domain.Session, store.SessionRecord, string, bool) {
	session, cookieToken, ok := s.requireSession(w, r, requestID)
	if !ok {
		return domain.Session{}, store.SessionRecord{}, "", false
	}
	if session.User.Role != "admin" {
		s.writeError(w, http.StatusForbidden, requestID, "administrator_required", "Administrator access is required to change investigations.", "authenticate", 4, false)
		return domain.Session{}, store.SessionRecord{}, "", false
	}
	if cookieToken != "" && !s.auth.ValidCSRF(cookieToken, r.Header.Get("X-CSRF-Token")) {
		s.writeError(w, http.StatusForbidden, requestID, "csrf_required", "A valid CSRF token is required.", "authenticate", 4, false)
		return domain.Session{}, store.SessionRecord{}, "", false
	}
	state, err := s.store.DeploymentState(r.Context())
	if err != nil {
		s.internalError(w, requestID)
		return domain.Session{}, store.SessionRecord{}, "", false
	}
	if generation := r.Header.Get("If-Deployment-Generation"); generation == "" || generation != state.DeploymentGeneration || !state.MutationsAllowed {
		s.writeError(w, http.StatusConflict, requestID, "restore_state_changed", "Review the current deployment generation before changing investigations.", "review_current_state", 7, false)
		return domain.Session{}, store.SessionRecord{}, "", false
	}
	key := r.Header.Get("Idempotency-Key")
	if len(key) < 16 || len(key) > 128 {
		s.writeError(w, http.StatusBadRequest, requestID, "idempotency_key_required", "A bounded idempotency key is required.", "fix_input", 2, false)
		return domain.Session{}, store.SessionRecord{}, "", false
	}
	actor := store.SessionRecord{User: session.User, DeploymentID: state.DeploymentID, Generation: state.DeploymentGeneration, ExpiresMS: session.ExpiresMS}
	return session, actor, key, true
}

func incidentSummary(record store.IncidentRecord) (incidentSummaryResponse, error) {
	var scope investigation.Scope
	if json.Unmarshal([]byte(record.ScopeJSON), &scope) != nil {
		return incidentSummaryResponse{}, errors.New("invalid stored incident scope")
	}
	evidence := "partial"
	if record.EvidenceExpiryReason != nil || strings.HasPrefix(record.EvidenceState, "evidence_expired_") {
		evidence = "expired"
	} else if record.EvidenceState == "complete" {
		evidence = "available"
	}
	var endMS *int64
	if record.Origin == "manual" || record.EndMSValid {
		endMS = &record.EndMS
	}
	return incidentSummaryResponse{SchemaVersion: domain.SchemaVersion, ID: record.ID, Revision: record.Revision, Title: record.Title, Origin: record.Origin, Scope: scope, StartMS: record.StartMS, EndMS: endMS, WorkflowState: record.WorkflowState, OwnerUserID: record.OwnerUserID, EvidenceStatus: evidence, CapsuleSHA256: record.CapsuleSHA256, CreatedMS: record.CreatedMS, UpdatedMS: record.UpdatedMS}, nil
}

func incidentMutationSummary(record store.IncidentSummaryResult) (incidentSummaryResponse, error) {
	return incidentSummary(store.IncidentRecord{
		ID:                   record.ID,
		Revision:             record.Revision,
		Title:                record.Title,
		ScopeJSON:            record.ScopeJSON,
		Origin:               record.Origin,
		StartMS:              record.StartMS,
		EndMS:                record.EndMS,
		WorkflowState:        record.WorkflowState,
		OwnerUserID:          record.OwnerUserID,
		EvidenceState:        record.EvidenceState,
		EvidenceExpiryReason: record.EvidenceExpiryReason,
		CapsuleSHA256:        record.CapsuleSHA256,
		CreatedMS:            record.CreatedMS,
		UpdatedMS:            record.UpdatedMS,
	})
}

func incidentDetail(record store.IncidentRecord) (incidentDetailResponse, error) {
	summary, err := incidentSummary(record)
	if err != nil {
		return incidentDetailResponse{}, err
	}
	response := incidentDetailResponse{incidentSummaryResponse: summary, Annotations: []annotationResponse{}, AnnotationsNextCursor: record.AnnotationsNextCursor, Comparisons: []store.ComparisonReference{}}
	if len(record.CapsulePayload) > 0 {
		switch record.Origin {
		case "manual":
			var capsule investigation.Capsule
			if json.Unmarshal(record.CapsulePayload, &capsule) != nil || capsule.SchemaRevision != investigation.CapsuleSchemaRevision {
				return incidentDetailResponse{}, errors.New("invalid stored incident capsule")
			}
		case "alert":
			var capsule store.AlertTriggerCapsule
			if json.Unmarshal(record.CapsulePayload, &capsule) != nil || capsule.SchemaRevision != "alert-trigger-capsule-1" || capsule.IncidentID != record.ID {
				return incidentDetailResponse{}, errors.New("invalid stored alert capsule")
			}
		default:
			return incidentDetailResponse{}, errors.New("invalid stored incident origin")
		}
		response.Capsule = append(json.RawMessage(nil), record.CapsulePayload...)
	}
	for _, annotation := range record.Annotations {
		response.Annotations = append(response.Annotations, annotationFromStore(annotation))
	}
	return response, nil
}

func annotationFromStore(record store.AnnotationRecord) annotationResponse {
	return annotationResponse{ID: record.ID, Revision: record.Revision, IncidentID: record.IncidentID, DeclaredTimeMS: record.DeclaredTimeMS, Text: record.Text, AuthorUserID: record.AuthorUserID, EditedMS: record.EditedMS, CreatedMS: record.CreatedMS, Provenance: "operator_declared"}
}

func (s *Server) incidentError(w http.ResponseWriter, requestID string, err error) {
	switch {
	case errors.Is(err, store.ErrIncidentNotFound), errors.Is(err, store.ErrAnnotationNotFound):
		s.writeError(w, http.StatusNotFound, requestID, "investigation_not_found", "The saved investigation or note was not found.", "review_current_state", 7, false)
	case errors.Is(err, store.ErrIncidentRevision):
		s.writeError(w, http.StatusConflict, requestID, "revision_conflict", "The investigation or note changed before this edit was saved.", "review_current_state", 7, false)
	case errors.Is(err, store.ErrIncidentState):
		s.writeError(w, http.StatusConflict, requestID, "investigation_state_conflict", "Only a manual investigation with retained evidence can change this workflow state.", "review_current_state", 7, false)
	case errors.Is(err, store.ErrIncidentConflict):
		s.writeError(w, http.StatusConflict, requestID, "idempotency_conflict", "The idempotency key was already used for different input.", "fix_input", 7, false)
	case errors.Is(err, store.ErrIncidentLimit):
		s.writeError(w, http.StatusConflict, requestID, "open_incident_limit", "The bounded open-investigation limit is reached.", "review_current_state", 7, false)
	case errors.Is(err, store.ErrIncidentCapacity), errors.Is(err, store.ErrAnnotationLimit):
		s.writeError(w, http.StatusInsufficientStorage, requestID, "incident_capacity_exhausted", "Protected investigation storage cannot admit this change.", "review_current_state", 7, false)
	case errors.Is(err, store.ErrIncidentInvalid), errors.Is(err, investigation.ErrInvalidInvestigation):
		s.writeError(w, http.StatusBadRequest, requestID, "invalid_incident", "The investigation scope, window or note is invalid.", "fix_input", 2, false)
	case errors.Is(err, investigation.ErrCapsuleTooLarge):
		s.writeError(w, http.StatusRequestEntityTooLarge, requestID, "incident_capsule_too_large", "The bounded evidence capsule exceeded 64 KiB. Choose a narrower scope or window.", "fix_input", 7, false)
	case errors.Is(err, store.ErrAdmissionFenced), errors.Is(err, store.ErrGenerationConflict):
		s.writeError(w, http.StatusConflict, requestID, "restore_state_changed", "The deployment generation changed before the investigation mutation completed.", "review_current_state", 7, false)
	case errors.Is(err, store.ErrOwnershipMismatch):
		s.writeError(w, http.StatusForbidden, requestID, "administrator_required", "Administrator access is required to change investigations.", "authenticate", 4, false)
	case errors.Is(err, store.ErrWriterBackpressure), errors.Is(err, context.DeadlineExceeded):
		w.Header().Set("Retry-After", "1")
		s.writeError(w, http.StatusServiceUnavailable, requestID, "investigation_busy", "Investigation storage is busy.", "retry_later", 7, true)
	default:
		s.internalError(w, requestID)
	}
}
