package httpapi

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net/http"
	"strings"

	"rmt.local/monitor/internal/store"
)

type deliveryResponse struct {
	ID                  string  `json:"id"`
	DestinationID       string  `json:"destination_id"`
	DestinationRevision int64   `json:"destination_revision"`
	State               string  `json:"state"`
	Status              string  `json:"status"`
	Attempts            int     `json:"attempts"`
	NextAttemptMS       *int64  `json:"next_attempt_ms"`
	SafeErrorCode       *string `json:"safe_error_code"`
	ReceiverACKMS       *int64  `json:"receiver_ack_ms"`
	AcceptedUnknown     bool    `json:"accepted_unknown"`
}

func publicDelivery(record store.DeliveryRecord) deliveryResponse {
	return deliveryResponse{
		ID: record.ID, DestinationID: record.DestinationID, DestinationRevision: record.DestinationRevision,
		State: record.State, Status: record.Status, Attempts: record.Attempts, NextAttemptMS: record.NextAttemptMS,
		SafeErrorCode: record.LastErrorCode, ReceiverACKMS: record.ReceiverACKMS, AcceptedUnknown: record.AcceptedUnknown,
	}
}

func (s *Server) handleNotificationDeliveryRoute(w http.ResponseWriter, r *http.Request, requestID string) bool {
	if !strings.HasPrefix(r.URL.Path, "/api/v1/deliveries/") {
		return false
	}
	path := strings.TrimPrefix(r.URL.Path, "/api/v1/deliveries/")
	parts := strings.Split(path, "/")
	if len(parts) != 1 && !(len(parts) == 2 && parts[1] == "retry") {
		return false
	}
	deliveryID := parts[0]
	if r.URL.RawQuery != "" || !validAPIUUID(deliveryID) {
		s.writeError(w, http.StatusBadRequest, requestID, "invalid_delivery", "The notification delivery identifier is invalid.", "fix_input", 2, false)
		return true
	}
	if len(parts) == 1 {
		if r.Method != http.MethodGet {
			s.writeError(w, http.StatusMethodNotAllowed, requestID, "method_not_allowed", "This delivery operation is not available.", "none", 2, false)
			return true
		}
		return s.handleNotificationDeliveryShow(w, r, requestID, deliveryID)
	}
	if r.Method != http.MethodPost || r.ContentLength > 0 {
		s.writeError(w, http.StatusMethodNotAllowed, requestID, "method_not_allowed", "This delivery retry operation requires an empty POST body.", "none", 2, false)
		return true
	}
	return s.handleNotificationDeliveryRetry(w, r, requestID, deliveryID)
}

func (s *Server) handleNotificationDeliveryShow(w http.ResponseWriter, r *http.Request, requestID, deliveryID string) bool {
	session, _, ok := s.requireSession(w, r, requestID)
	if !ok {
		return true
	}
	if session.User.Role != "admin" {
		s.writeError(w, http.StatusForbidden, requestID, "administrator_required", "Administrator access is required for notification delivery status.", "request_admin", 4, false)
		return true
	}
	state, err := s.store.DeploymentState(r.Context())
	if err != nil {
		s.internalError(w, requestID)
		return true
	}
	actor := store.SessionRecord{User: session.User, DeploymentID: state.DeploymentID, Generation: state.DeploymentGeneration, ExpiresMS: session.ExpiresMS}
	record, err := s.store.ReadNotificationDelivery(r.Context(), actor, deliveryID)
	if err != nil {
		s.notificationDeliveryError(w, requestID, err)
		return true
	}
	s.writeJSON(w, http.StatusOK, publicDelivery(record))
	return true
}

func (s *Server) handleNotificationDeliveryRetry(w http.ResponseWriter, r *http.Request, requestID, deliveryID string) bool {
	session, cookie, ok := s.requireSession(w, r, requestID)
	if !ok {
		return true
	}
	if session.User.Role != "admin" {
		s.writeError(w, http.StatusForbidden, requestID, "administrator_required", "Administrator access is required to retry notification delivery.", "request_admin", 4, false)
		return true
	}
	if cookie != "" && !s.auth.ValidCSRF(cookie, r.Header.Get("X-CSRF-Token")) {
		s.writeError(w, http.StatusForbidden, requestID, "csrf_required", "A valid CSRF token is required.", "authenticate", 4, false)
		return true
	}
	state, idempotencyKey, ok := s.mutationHeaders(w, r, requestID)
	if !ok {
		return true
	}
	digest := sha256.Sum256([]byte(r.Method + " " + r.URL.Path + "\x00"))
	requestHash := hex.EncodeToString(digest[:])
	actor := store.SessionRecord{User: session.User, DeploymentID: state.DeploymentID, Generation: state.DeploymentGeneration, ExpiresMS: session.ExpiresMS}
	record, err := s.store.RetryNotificationDelivery(r.Context(), actor, deliveryID, idempotencyKey, requestHash)
	if err != nil {
		s.notificationDeliveryError(w, requestID, err)
		return true
	}
	s.writeJSON(w, http.StatusOK, publicDelivery(record))
	return true
}

func (s *Server) notificationDeliveryError(w http.ResponseWriter, requestID string, err error) {
	switch {
	case errors.Is(err, store.ErrDeliveryNotFound):
		s.writeError(w, http.StatusNotFound, requestID, "delivery_not_found", "The notification delivery was not found.", "review_current_state", 7, false)
	case errors.Is(err, store.ErrDeliveryInvalid):
		s.writeError(w, http.StatusBadRequest, requestID, "invalid_delivery", "The notification delivery request is invalid.", "fix_input", 2, false)
	case errors.Is(err, store.ErrDeliveryExpired):
		s.writeError(w, http.StatusConflict, requestID, "delivery_expired", "This notification delivery has expired and cannot be retried.", "review_current_state", 7, false)
	case errors.Is(err, store.ErrDeliveryStale):
		s.writeError(w, http.StatusConflict, requestID, "delivery_stale", "The notification delivery is no longer current for this destination or alert.", "review_current_state", 7, false)
	case errors.Is(err, store.ErrDeliveryConflict):
		s.writeError(w, http.StatusConflict, requestID, "delivery_conflict", "The notification delivery changed before this operation completed.", "review_current_state", 7, false)
	case errors.Is(err, store.ErrAdmissionFenced), errors.Is(err, store.ErrGenerationConflict):
		s.writeError(w, http.StatusConflict, requestID, "restore_state_changed", "The deployment generation changed before notification delivery was updated.", "review_current_state", 7, false)
	case errors.Is(err, store.ErrOwnershipMismatch):
		s.writeError(w, http.StatusForbidden, requestID, "administrator_required", "Administrator access is required for notification delivery.", "request_admin", 4, false)
	case errors.Is(err, store.ErrWriterBackpressure):
		w.Header().Set("Retry-After", "1")
		s.writeError(w, http.StatusServiceUnavailable, requestID, "delivery_busy", "Notification delivery storage is busy.", "retry_later", 7, true)
	default:
		s.internalError(w, requestID)
	}
}
