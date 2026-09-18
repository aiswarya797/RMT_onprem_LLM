package httpapi

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"

	"rmt.local/monitor/internal/domain"
	"rmt.local/monitor/internal/protocol"
	"rmt.local/monitor/internal/store"
)

type recoveryGrantCreateRequest struct {
	Manifest             protocol.RecoveryManifest `json:"manifest"`
	DeploymentGeneration string                    `json:"deployment_generation"`
}

type recoveryGrantListResponse struct {
	Items []protocol.RecoveryGrant `json:"items"`
}

func (s *Server) handleRecoveryGrantCreate(w http.ResponseWriter, r *http.Request, requestID string) {
	actor, key, state, ok := s.recoveryMutationActor(w, r, requestID)
	if !ok {
		return
	}
	var body recoveryGrantCreateRequest
	if !s.decodeJSON(w, r, requestID, &body) {
		return
	}
	manifestJSON, err := json.Marshal(body.Manifest)
	if err != nil || body.DeploymentGeneration != state.DeploymentGeneration {
		s.writeError(w, http.StatusBadRequest, requestID, "invalid_recovery_manifest", "The recovery manifest or deployment generation is invalid.", "fix_input", 7, false)
		return
	}
	manifest, err := protocol.DecodeRecoveryManifest(bytes.NewReader(manifestJSON))
	if err != nil {
		s.writeError(w, http.StatusBadRequest, requestID, "invalid_recovery_manifest", "The recovery manifest is incomplete, malformed or self-hash inconsistent.", "fix_input", 7, false)
		return
	}
	canonical, _ := json.Marshal(recoveryGrantCreateRequest{Manifest: manifest, DeploymentGeneration: body.DeploymentGeneration})
	digest := sha256.Sum256(canonical)
	grant, err := s.store.CreateRecoveryGrant(r.Context(), actor, key, hex.EncodeToString(digest[:]), manifest)
	if err != nil {
		s.recoveryError(w, requestID, err)
		return
	}
	s.writeJSON(w, http.StatusOK, grant)
}

func (s *Server) handleRecoveryGrantList(w http.ResponseWriter, r *http.Request, requestID string) {
	actor, ok := s.recoveryReadActor(w, r, requestID)
	if !ok {
		return
	}
	if r.URL.RawQuery != "" {
		s.writeError(w, http.StatusBadRequest, requestID, "invalid_query", "Recovery grant list does not accept query parameters.", "fix_input", 2, false)
		return
	}
	items, err := s.store.ListRecoveryGrants(r.Context(), actor)
	if err != nil {
		s.recoveryError(w, requestID, err)
		return
	}
	s.writeJSON(w, http.StatusOK, recoveryGrantListResponse{Items: items})
}

func (s *Server) handleRecoveryGrantShow(w http.ResponseWriter, r *http.Request, requestID, grantID string) {
	actor, ok := s.recoveryReadActor(w, r, requestID)
	if !ok {
		return
	}
	if r.URL.RawQuery != "" || !validAPIUUID(grantID) {
		s.writeError(w, http.StatusBadRequest, requestID, "invalid_recovery_grant", "The recovery grant identifier is invalid.", "fix_input", 2, false)
		return
	}
	grant, err := s.store.ReadRecoveryGrant(r.Context(), actor, grantID)
	if err != nil {
		s.recoveryError(w, requestID, err)
		return
	}
	s.writeJSON(w, http.StatusOK, grant)
}

func (s *Server) handleRecoveryGrantRevoke(w http.ResponseWriter, r *http.Request, requestID, grantID string) {
	actor, key, _, ok := s.recoveryMutationActor(w, r, requestID)
	if !ok {
		return
	}
	if r.URL.RawQuery != "" || !validAPIUUID(grantID) || (r.ContentLength != 0 && r.ContentLength != -1) {
		s.writeError(w, http.StatusBadRequest, requestID, "invalid_recovery_grant", "Recovery grant revocation requires a valid identifier and an empty body.", "fix_input", 2, false)
		return
	}
	canonical, _ := json.Marshal(struct {
		GrantID string `json:"grant_id"`
	}{grantID})
	digest := sha256.Sum256(canonical)
	grant, err := s.store.RevokeRecoveryGrant(r.Context(), actor, grantID, key, hex.EncodeToString(digest[:]))
	if err != nil {
		s.recoveryError(w, requestID, err)
		return
	}
	s.writeJSON(w, http.StatusOK, grant)
}

func (s *Server) recoveryMutationActor(w http.ResponseWriter, r *http.Request, requestID string) (store.SessionRecord, string, domain.DeploymentState, bool) {
	session, cookieToken, ok := s.requireSession(w, r, requestID)
	if !ok {
		return store.SessionRecord{}, "", domain.DeploymentState{}, false
	}
	if session.User.Role != "admin" {
		s.writeError(w, http.StatusForbidden, requestID, "administrator_required", "Administrator access is required for spool recovery.", "authenticate", 4, false)
		return store.SessionRecord{}, "", domain.DeploymentState{}, false
	}
	if cookieToken != "" && !s.auth.ValidCSRF(cookieToken, r.Header.Get("X-CSRF-Token")) {
		s.writeError(w, http.StatusForbidden, requestID, "csrf_required", "A valid CSRF token is required.", "authenticate", 4, false)
		return store.SessionRecord{}, "", domain.DeploymentState{}, false
	}
	state, err := s.store.DeploymentState(r.Context())
	if err != nil {
		s.internalError(w, requestID)
		return store.SessionRecord{}, "", domain.DeploymentState{}, false
	}
	if generation := r.Header.Get("If-Deployment-Generation"); generation == "" || generation != state.DeploymentGeneration || !state.MutationsAllowed {
		s.writeError(w, http.StatusConflict, requestID, "restore_state_changed", "Review the current deployment generation before changing spool recovery grants.", "review_current_state", 7, false)
		return store.SessionRecord{}, "", domain.DeploymentState{}, false
	}
	key := r.Header.Get("Idempotency-Key")
	if len(key) < 16 || len(key) > 128 {
		s.writeError(w, http.StatusBadRequest, requestID, "idempotency_key_required", "A bounded idempotency key is required.", "fix_input", 2, false)
		return store.SessionRecord{}, "", domain.DeploymentState{}, false
	}
	actor := store.SessionRecord{User: session.User, DeploymentID: state.DeploymentID, Generation: state.DeploymentGeneration, ExpiresMS: session.ExpiresMS}
	return actor, key, state, true
}

func (s *Server) recoveryReadActor(w http.ResponseWriter, r *http.Request, requestID string) (store.SessionRecord, bool) {
	session, _, ok := s.requireSession(w, r, requestID)
	if !ok {
		return store.SessionRecord{}, false
	}
	if session.User.Role != "admin" {
		s.writeError(w, http.StatusForbidden, requestID, "administrator_required", "Administrator access is required for spool recovery.", "authenticate", 4, false)
		return store.SessionRecord{}, false
	}
	state, err := s.store.DeploymentState(r.Context())
	if err != nil {
		s.internalError(w, requestID)
		return store.SessionRecord{}, false
	}
	return store.SessionRecord{User: session.User, DeploymentID: state.DeploymentID, Generation: state.DeploymentGeneration, ExpiresMS: session.ExpiresMS}, true
}

func (s *Server) recoveryError(w http.ResponseWriter, requestID string, err error) {
	switch {
	case errors.Is(err, store.ErrOwnershipMismatch):
		s.writeError(w, http.StatusForbidden, requestID, "administrator_required", "Administrator access is required for spool recovery.", "authenticate", 4, false)
	case errors.Is(err, store.ErrRecoveryCapacityBusy):
		w.Header().Set("Retry-After", "5")
		s.writeError(w, http.StatusServiceUnavailable, requestID, "recovery_capacity_busy", "Recovery receipt capacity is unavailable.", "free_capacity", 7, true)
	case errors.Is(err, store.ErrRecoveryGrantExpired):
		s.writeError(w, http.StatusGone, requestID, "recovery_grant_expired", "The recovery grant expired; review a new retained-spool preview.", "review_current_state", 7, false)
	case errors.Is(err, store.ErrRecoveryDefinition):
		s.writeError(w, http.StatusUnprocessableEntity, requestID, "recovery_definition_incompatible", "A historical source, target or model definition cannot be proven compatible.", "review_current_state", 7, false)
	case errors.Is(err, store.ErrRecoveryConflict):
		s.writeError(w, http.StatusConflict, requestID, "recovery_scope_conflict", "The recovery scope conflicts with retained identity, an active grant or prior input.", "review_current_state", 7, false)
	case errors.Is(err, store.ErrAdmissionFenced), errors.Is(err, store.ErrGenerationConflict):
		s.writeError(w, http.StatusConflict, requestID, "restore_state_changed", "The deployment generation changed before the recovery operation completed.", "review_current_state", 7, false)
	case errors.Is(err, store.ErrWriterBackpressure):
		w.Header().Set("Retry-After", "1")
		s.writeError(w, http.StatusServiceUnavailable, requestID, "write_busy", "Recovery storage is busy.", "retry_later", 7, true)
	default:
		s.internalError(w, requestID)
	}
}
