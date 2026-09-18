package httpapi

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"strings"

	"rmt.local/monitor/internal/domain"
	"rmt.local/monitor/internal/notify"
	"rmt.local/monitor/internal/protocol"
	"rmt.local/monitor/internal/store"
)

func (s *Server) ConfigureNotifications(vault notify.Vault) { s.notificationVault = &vault }

type destinationRequest struct {
	ExpectedRevision *int64                     `json:"expected_revision"`
	Type             string                     `json:"type"`
	DisplayName      string                     `json:"display_name"`
	Webhook          *domain.WebhookDestination `json:"webhook"`
	SMTP             *domain.SMTPDestination    `json:"smtp"`
	SecretInput      *string                    `json:"secret_input"`
}

type destinationResponse struct {
	ID               string                    `json:"id"`
	Revision         int64                     `json:"revision"`
	Type             string                    `json:"type"`
	DisplayName      string                    `json:"display_name"`
	Enabled          bool                      `json:"enabled"`
	SecretConfigured bool                      `json:"secret_configured"`
	Configuration    domain.NotificationConfig `json:"configuration"`
	LastTestMS       *int64                    `json:"last_test_ms"`
	LastTestResult   *string                   `json:"last_test_result"`
	LastTestJobID    *string                   `json:"last_test_job_id"`
}

func publicDestination(d store.DestinationRecord) destinationResponse {
	return destinationResponse{d.ID, d.Version, d.Kind, d.DisplayName, d.DisabledMS == nil, d.SecretConfigured, d.Config, d.LastTestMS, d.LastTestResult, d.LastTestJobID}
}

func (s *Server) handleDestinationTestRoute(w http.ResponseWriter, r *http.Request, requestID string) bool {
	if !strings.HasPrefix(r.URL.Path, "/api/v1/destinations/") || !strings.HasSuffix(r.URL.Path, "/tests") {
		return false
	}
	id := strings.TrimSuffix(strings.TrimPrefix(r.URL.Path, "/api/v1/destinations/"), "/tests")
	if r.Method != http.MethodPost {
		s.writeError(w, http.StatusMethodNotAllowed, requestID, "method_not_allowed", "This destination test operation is not available.", "none", 2, false)
		return true
	}
	if r.URL.RawQuery != "" || !validAPIUUID(id) || r.ContentLength > 0 {
		s.destinationError(w, requestID, store.ErrDestinationInvalid)
		return true
	}
	session, cookie, ok := s.requireSession(w, r, requestID)
	if !ok {
		return true
	}
	if session.User.Role != "admin" {
		s.writeError(w, http.StatusForbidden, requestID, "administrator_required", "Administrator access is required for notification settings.", "request_admin", 4, false)
		return true
	}
	if cookie != "" && !s.auth.ValidCSRF(cookie, r.Header.Get("X-CSRF-Token")) {
		s.writeError(w, http.StatusForbidden, requestID, "csrf_required", "A valid CSRF token is required.", "authenticate", 4, false)
		return true
	}
	state, key, ok := s.mutationHeaders(w, r, requestID)
	if !ok {
		return true
	}
	if s.notificationVault == nil {
		s.writeError(w, http.StatusServiceUnavailable, requestID, "notification_secrets_unavailable", "Notification credential storage is unavailable.", "retry_later", 7, true)
		return true
	}
	revision, err := strconv.ParseInt(r.Header.Get("If-Match"), 10, 64)
	if err != nil || revision < 1 {
		s.destinationError(w, requestID, store.ErrDestinationInvalid)
		return true
	}
	hash, err := s.notificationVault.Fingerprint([]byte(r.Method + " " + r.URL.Path + "\x00" + strconv.FormatInt(revision, 10)))
	if err != nil {
		s.destinationError(w, requestID, err)
		return true
	}
	actor := store.SessionRecord{User: session.User, DeploymentID: state.DeploymentID, Generation: state.DeploymentGeneration, ExpiresMS: session.ExpiresMS}
	job, err := s.store.EnqueueDestinationTest(r.Context(), actor, id, key, hash, revision)
	if err != nil {
		s.destinationError(w, requestID, err)
		return true
	}
	s.writeJSON(w, http.StatusAccepted, publicNotificationJob(job, state.DeploymentGeneration, requestID))
	return true
}

func (s *Server) handleDestinationRoute(w http.ResponseWriter, r *http.Request, requestID string) bool {
	if r.URL.Path != "/api/v1/destinations" && !strings.HasPrefix(r.URL.Path, "/api/v1/destinations/") {
		return false
	}
	id := strings.TrimPrefix(strings.TrimPrefix(r.URL.Path, "/api/v1/destinations"), "/")
	if id != "" && !validAPIUUID(id) {
		return false
	} // child operations have their own exact routes
	if r.URL.RawQuery != "" {
		s.writeError(w, 400, requestID, "invalid_query", "Destination operations do not accept query parameters.", "fix_input", 2, false)
		return true
	}
	mutation := id == "" && r.Method == http.MethodPost || id != "" && (r.Method == http.MethodPut || r.Method == http.MethodDelete)
	if !mutation && r.Method != http.MethodGet {
		s.writeError(w, 405, requestID, "method_not_allowed", "This destination operation is not available.", "none", 2, false)
		return true
	}
	session, cookie, ok := s.requireSession(w, r, requestID)
	if !ok {
		return true
	}
	if session.User.Role != "admin" {
		s.writeError(w, 403, requestID, "administrator_required", "Administrator access is required for notification settings.", "request_admin", 4, false)
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
			records, err := s.store.ListDestinations(ctx, actor, store.DestinationListOptions{Limit: 16})
			if err != nil {
				s.destinationError(w, requestID, err)
				return true
			}
			items := make([]destinationResponse, 0, len(records))
			for _, d := range records {
				items = append(items, publicDestination(d))
			}
			s.writeJSON(w, 200, struct {
				Items []destinationResponse `json:"items"`
			}{items})
		} else {
			d, err := s.store.ReadDestination(ctx, actor, id)
			if err != nil {
				s.destinationError(w, requestID, err)
			} else {
				s.writeJSON(w, 200, publicDestination(d))
			}
		}
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
	if s.notificationVault == nil {
		s.writeError(w, 503, requestID, "notification_secrets_unavailable", "Notification credential storage is unavailable.", "retry_later", 7, true)
		return true
	}
	if r.Method == http.MethodDelete {
		revision, err := strconv.ParseInt(r.Header.Get("If-Match"), 10, 64)
		if err != nil || revision < 1 || r.ContentLength > 0 || (r.Body != nil && r.ContentLength < 0) {
			s.destinationError(w, requestID, store.ErrDestinationInvalid)
			return true
		}
		hash, err := s.notificationVault.Fingerprint([]byte(r.Method + " " + r.URL.Path + "\x00" + strconv.FormatInt(revision, 10)))
		if err != nil {
			s.destinationError(w, requestID, err)
			return true
		}
		_, err = s.store.DisableDestination(ctx, actor, id, key, hash, revision)
		if err != nil {
			s.destinationError(w, requestID, err)
		} else {
			w.WriteHeader(http.StatusNoContent)
		}
		return true
	}
	var raw json.RawMessage
	if !s.decodeJSON(w, r, requestID, &raw) {
		return true
	}
	var fields map[string]json.RawMessage
	var input destinationRequest
	if json.Unmarshal(raw, &fields) != nil || protocol.DecodeStrictJSON(bytes.NewReader(raw), 64<<10, &input) != nil {
		s.destinationError(w, requestID, store.ErrDestinationInvalid)
		return true
	}
	for _, field := range []string{"expected_revision", "type", "display_name", "webhook", "smtp", "secret_input"} {
		if _, ok := fields[field]; !ok {
			s.destinationError(w, requestID, store.ErrDestinationInvalid)
			return true
		}
	}
	c := domain.NotificationConfig{Webhook: input.Webhook, SMTP: input.SMTP}
	if domain.ValidateNotificationConfig(input.Type, c) != nil || len([]rune(input.DisplayName)) < 1 || len([]rune(input.DisplayName)) > 128 || strings.TrimSpace(input.DisplayName) == "" || (id == "" && input.ExpectedRevision != nil) || (id != "" && (input.ExpectedRevision == nil || *input.ExpectedRevision < 1)) || (input.SecretInput != nil && (len(*input.SecretInput) == 0 || len(*input.SecretInput) > 4096)) || (id == "" && c.NeedsSecret() && input.SecretInput == nil) {
		s.destinationError(w, requestID, store.ErrDestinationInvalid)
		return true
	}
	if input.SMTP != nil {
		var smtpFields map[string]json.RawMessage
		_ = json.Unmarshal(fields["smtp"], &smtpFields)
		if _, ok := smtpFields["username"]; !ok {
			s.destinationError(w, requestID, store.ErrDestinationInvalid)
			return true
		}
	}
	if input.Webhook != nil {
		var webhookFields map[string]json.RawMessage
		_ = json.Unmarshal(fields["webhook"], &webhookFields)
		hmacField := bytes.TrimSpace(webhookFields["hmac_enabled"])
		if !bytes.Equal(hmacField, []byte("true")) && !bytes.Equal(hmacField, []byte("false")) {
			s.destinationError(w, requestID, store.ErrDestinationInvalid)
			return true
		}
	}
	canonical, _ := json.Marshal(input)
	hash, err := s.notificationVault.Fingerprint(append([]byte(r.Method+" "+r.URL.Path+"\x00"), canonical...))
	if err != nil {
		s.destinationError(w, requestID, err)
		return true
	}
	ref := ""
	if !c.NeedsSecret() || input.SecretInput != nil {
		secret := ""
		if c.NeedsSecret() {
			secret = *input.SecretInput
		}
		ref, err = s.notificationVault.Put(actor.Generation+"/"+actor.User.ID+"/"+key+"/"+hash, secret)
		if err != nil {
			s.destinationError(w, requestID, err)
			return true
		}
	}
	def := store.DestinationDefinition{ExpectedVersion: input.ExpectedRevision, Kind: input.Type, DisplayName: input.DisplayName, Config: c, SecretRef: ref}
	var d store.DestinationRecord
	status := 200
	if id == "" {
		d, err = s.store.CreateDestination(ctx, actor, key, hash, def)
		status = 201
	} else {
		d, err = s.store.UpdateDestination(ctx, actor, id, key, hash, def)
	}
	if err != nil {
		s.destinationError(w, requestID, err)
	} else {
		s.writeJSON(w, status, publicDestination(d))
	}
	return true
}

func (s *Server) destinationError(w http.ResponseWriter, id string, err error) {
	switch {
	case errors.Is(err, store.ErrDestinationInvalid):
		s.writeError(w, 400, id, "invalid_destination", "Review the receiver, credentials and expected revision.", "fix_input", 2, false)
	case errors.Is(err, store.ErrDestinationNotFound):
		s.writeError(w, 404, id, "destination_not_found", "The notification destination was not found.", "review_current_state", 7, false)
	case errors.Is(err, store.ErrDestinationRevision), errors.Is(err, store.ErrDestinationConflict):
		s.writeError(w, 409, id, "destination_conflict", "The destination or retry identity changed; review its current state.", "review_current_state", 7, false)
	case errors.Is(err, store.ErrDestinationLimit):
		s.writeError(w, 409, id, "destination_limit", "At most 16 notification destinations can be active.", "review_current_state", 7, false)
	case errors.Is(err, store.ErrDestinationTestBusy):
		s.writeError(w, 409, id, "destination_test_busy", "A notification test is already running for this administrator or destination.", "retry_later", 7, true)
	case errors.Is(err, store.ErrGenerationConflict), errors.Is(err, store.ErrAdmissionFenced):
		s.writeError(w, 409, id, "restore_state_changed", "Review the current deployment before changing notification settings.", "review_current_state", 7, false)
	case errors.Is(err, store.ErrOwnershipMismatch):
		s.writeError(w, 403, id, "administrator_required", "Current administrator access is required.", "request_admin", 4, false)
	case errors.Is(err, notify.ErrSecretUnavailable):
		s.writeError(w, 503, id, "notification_secrets_unavailable", "Notification credential storage is unavailable.", "retry_later", 7, true)
	case errors.Is(err, store.ErrWriterBackpressure), errors.Is(err, context.DeadlineExceeded):
		s.writeError(w, 503, id, "notifications_busy", "Notification storage is busy.", "retry_later", 7, true)
	default:
		s.internalError(w, id)
	}
}
