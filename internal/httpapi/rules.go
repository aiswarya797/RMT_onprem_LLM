package httpapi

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"strings"

	"rmt.local/monitor/internal/protocol"
	"rmt.local/monitor/internal/store"
)

func (s *Server) handleRuleRoute(w http.ResponseWriter, r *http.Request, requestID string) bool {
	if r.URL.Path != "/api/v1/rules" && !strings.HasPrefix(r.URL.Path, "/api/v1/rules/") {
		return false
	}
	id := strings.TrimPrefix(r.URL.Path, "/api/v1/rules")
	if id != "" {
		id = strings.TrimPrefix(id, "/")
		if !validAPIUUID(id) {
			s.writeError(w, 400, requestID, "invalid_rule", "A valid rule ID is required.", "fix_input", 2, false)
			return true
		}
	}
	if r.URL.RawQuery != "" {
		s.writeError(w, 400, requestID, "invalid_query", "Rule operations do not accept query parameters.", "fix_input", 2, false)
		return true
	}
	mutation := (id == "" && r.Method == http.MethodPost) || (id != "" && r.Method == http.MethodPut)
	if !mutation && r.Method != http.MethodGet {
		s.writeError(w, 405, requestID, "method_not_allowed", "This rule operation is not available.", "none", 2, false)
		return true
	}
	session, cookie, ok := s.requireSession(w, r, requestID)
	if !ok {
		return true
	}
	state, err := s.store.DeploymentState(r.Context())
	if err != nil {
		s.internalError(w, requestID)
		return true
	}
	actor := store.SessionRecord{User: session.User, DeploymentID: state.DeploymentID, Generation: state.DeploymentGeneration, ExpiresMS: session.ExpiresMS}
	ctx, cancel := interactiveQueryContext(r)
	defer cancel()
	if !mutation {
		if id == "" {
			items, err := s.store.ListRules(ctx, actor)
			if err != nil {
				s.ruleError(w, requestID, err)
			} else {
				if items == nil {
					items = []store.RuleRecord{}
				}
				s.writeJSON(w, 200, struct {
					Items []store.RuleRecord `json:"items"`
				}{items})
			}
		} else {
			record, err := s.store.ReadRule(ctx, actor, id)
			if err != nil {
				s.ruleError(w, requestID, err)
			} else {
				s.writeJSON(w, 200, record)
			}
		}
		return true
	}
	if session.User.Role != "admin" {
		s.writeError(w, 403, requestID, "administrator_required", "Administrator access is required to change alert rules.", "request_admin", 4, false)
		return true
	}
	if cookie != "" && !s.auth.ValidCSRF(cookie, r.Header.Get("X-CSRF-Token")) {
		s.writeError(w, 403, requestID, "csrf_required", "A valid CSRF token is required.", "authenticate", 4, false)
		return true
	}
	current, key, ok := s.mutationHeaders(w, r, requestID)
	if !ok {
		return true
	}
	actor.Generation = current.DeploymentGeneration
	var raw json.RawMessage
	if !s.decodeJSON(w, r, requestID, &raw) {
		return true
	}
	var fields map[string]json.RawMessage
	valid := json.Unmarshal(raw, &fields) == nil && fields != nil
	for _, field := range []string{"expected_revision", "evaluator_type", "scope_id", "enabled", "metric_id", "request_population", "aggregation", "threshold", "dwell_ms", "recovery_ms"} {
		_, present := fields[field]
		valid = valid && present
	}
	// Null is allowed only in the five explicit optional-value slots.
	for _, field := range []string{"evaluator_type", "scope_id", "enabled", "dwell_ms", "recovery_ms"} {
		valid = valid && !bytes.Equal(bytes.TrimSpace(fields[field]), []byte("null"))
	}
	var definition store.RuleDefinition
	if !valid || protocol.DecodeStrictJSON(bytes.NewReader(raw), 64<<10, &definition) != nil {
		s.ruleError(w, requestID, store.ErrRuleInvalid)
		return true
	}
	canonical, err := json.Marshal(definition)
	if err != nil {
		s.ruleError(w, requestID, store.ErrRuleInvalid)
		return true
	}
	digest := sha256.Sum256(append([]byte(r.Method+" "+r.URL.Path+"\x00"), canonical...))
	var record store.RuleRecord
	status := http.StatusOK
	if id == "" {
		record, err = s.store.CreateRule(ctx, actor, key, hex.EncodeToString(digest[:]), definition)
		status = http.StatusCreated
	} else {
		record, err = s.store.UpdateRule(ctx, actor, id, key, hex.EncodeToString(digest[:]), definition)
	}
	if err != nil {
		s.ruleError(w, requestID, err)
	} else {
		s.writeJSON(w, status, record)
	}
	return true
}

func (s *Server) ruleError(w http.ResponseWriter, requestID string, err error) {
	switch {
	case errors.Is(err, store.ErrRuleInvalid):
		s.writeError(w, 400, requestID, "invalid_rule", "Use a supported scope, population, threshold and dwell definition.", "fix_input", 2, false)
	case errors.Is(err, store.ErrRuleNotFound):
		s.writeError(w, 404, requestID, "rule_not_found", "The rule was not found.", "review_current_state", 7, false)
	case errors.Is(err, store.ErrRuleRevision):
		s.writeError(w, 409, requestID, "revision_conflict", "The rule changed before this edit was saved.", "review_current_state", 7, false)
	case errors.Is(err, store.ErrRuleConflict):
		s.writeError(w, 409, requestID, "idempotency_conflict", "The retry key already belongs to different input.", "review_current_state", 7, false)
	case errors.Is(err, store.ErrRuleLimit):
		s.writeError(w, 409, requestID, "rule_limit", "The deployment has reached its 64-rule limit.", "review_current_state", 7, false)
	case errors.Is(err, store.ErrOwnershipMismatch):
		s.writeError(w, 403, requestID, "administrator_required", "Current administrator access is required for this change.", "request_admin", 4, false)
	case errors.Is(err, store.ErrGenerationConflict), errors.Is(err, store.ErrAdmissionFenced):
		s.writeError(w, 409, requestID, "restore_state_changed", "Review the current deployment state before changing rules.", "review_current_state", 7, false)
	case errors.Is(err, store.ErrWriterBackpressure), errors.Is(err, context.DeadlineExceeded):
		w.Header().Set("Retry-After", "1")
		s.writeError(w, 503, requestID, "rules_busy", "Rule storage is busy.", "retry_later", 7, true)
	default:
		s.internalError(w, requestID)
	}
}
