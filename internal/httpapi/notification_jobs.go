package httpapi

import (
	"errors"
	"net/http"
	"strings"

	"rmt.local/monitor/internal/domain"
	"rmt.local/monitor/internal/store"
)

type notificationJobResult struct {
	ResourceID        string `json:"resource_id"`
	ResourceType      string `json:"resource_type"`
	DownloadExpiresMS *int64 `json:"download_expires_ms"`
}

type notificationJobResponse struct {
	SchemaVersion        string                 `json:"schema_version"`
	JobID                string                 `json:"job_id"`
	DeploymentGeneration string                 `json:"deployment_generation"`
	Type                 string                 `json:"type"`
	State                string                 `json:"state"`
	ProgressRatio        float64                `json:"progress_ratio"`
	CreatedMS            int64                  `json:"created_ms"`
	UpdatedMS            int64                  `json:"updated_ms"`
	Result               *notificationJobResult `json:"result"`
	Error                *domain.APIError       `json:"error"`
	CancelState          string                 `json:"cancel_state"`
	ReceiverACKMS        *int64                 `json:"receiver_ack_ms,omitempty"`
}

func publicNotificationJob(job store.NotificationTestJob, generation, requestID string) notificationJobResponse {
	progress := 0.0
	switch job.State {
	case "running":
		progress = 0.5
	case "succeeded", "failed", "cancelled":
		progress = 1
	}
	var apiError *domain.APIError
	if job.ErrorCode != nil {
		code := *job.ErrorCode
		recovery := "retry_later"
		retryable := false
		if code == "notification_tls_verification_failed" || code == "webhook_receiver_rejected" || code == "notification_configuration_invalid" {
			recovery = "fix_input"
		}
		apiError = &domain.APIError{SchemaVersion: domain.SchemaVersion, Code: code, Message: notificationFailureMessage(code), RecoveryAction: recovery, RequestID: requestID, Retryable: retryable, CLIExitCode: 7}
	}
	return notificationJobResponse{
		SchemaVersion:        domain.SchemaVersion,
		JobID:                job.ID,
		DeploymentGeneration: generation,
		Type:                 "destination_test",
		State:                job.State,
		ProgressRatio:        progress,
		CreatedMS:            job.CreatedMS,
		UpdatedMS:            job.UpdatedMS,
		Result:               &notificationJobResult{ResourceID: job.DeliveryID, ResourceType: "notification_delivery"},
		Error:                apiError,
		CancelState:          "not_requested",
		ReceiverACKMS:        job.ReceiverACKMS,
	}
}

func publicStoredJob(job store.JobRecord, generation, requestID string) notificationJobResponse {
	var result *notificationJobResult
	if job.Result != nil {
		result = &notificationJobResult{ResourceID: job.Result.ResourceID, ResourceType: job.Result.ResourceType, DownloadExpiresMS: job.Result.DownloadExpiresMS}
	}
	var apiError *domain.APIError
	if job.ErrorCode != nil {
		apiError = &domain.APIError{SchemaVersion: domain.SchemaVersion, Code: *job.ErrorCode, Message: "The bounded operation failed.", RecoveryAction: "review_current_state", RequestID: requestID, Retryable: false, CLIExitCode: 7}
	}
	return notificationJobResponse{
		SchemaVersion: domain.SchemaVersion, JobID: job.ID, DeploymentGeneration: generation,
		Type: job.Type, State: job.State, ProgressRatio: job.ProgressRatio, CreatedMS: job.CreatedMS,
		UpdatedMS: job.UpdatedMS, Result: result, Error: apiError, CancelState: job.CancelState,
	}
}

func notificationFailureMessage(code string) string {
	switch code {
	case "notification_connection_failed":
		return "The receiver could not be reached. Check its availability and HTTPS URL."
	case "notification_timeout_or_cancelled":
		return "The receiver did not respond before the notification deadline. Check its availability."
	case "notification_tls_verification_failed":
		return "The receiver TLS certificate could not be verified. Check the HTTPS hostname and certificate."
	case "webhook_receiver_rejected":
		return "The receiver rejected the notification. Check its authentication and status."
	case "notification_secret_unavailable":
		return "The stored notification credential is unavailable. Reconfigure the destination."
	case "notification_configuration_invalid":
		return "The saved notification configuration is invalid. Reconfigure the destination."
	default:
		return "The notification receiver did not acknowledge the test. Check its status and retry."
	}
}

func (s *Server) handleNotificationJobRoute(w http.ResponseWriter, r *http.Request, requestID string) bool {
	if !strings.HasPrefix(r.URL.Path, "/api/v1/jobs/") {
		return false
	}
	jobID := strings.TrimPrefix(r.URL.Path, "/api/v1/jobs/")
	if strings.Contains(jobID, "/") {
		return false
	}
	if r.Method != http.MethodGet {
		s.writeError(w, http.StatusMethodNotAllowed, requestID, "method_not_allowed", "This job operation is not available.", "none", 2, false)
		return true
	}
	if r.URL.RawQuery != "" || !validAPIUUID(jobID) {
		s.writeError(w, http.StatusBadRequest, requestID, "invalid_job", "The notification job identifier is invalid.", "fix_input", 2, false)
		return true
	}
	session, _, ok := s.requireSession(w, r, requestID)
	if !ok {
		return true
	}
	if session.User.Role != "admin" {
		s.writeError(w, http.StatusForbidden, requestID, "administrator_required", "Administrator access is required for notification job status.", "request_admin", 4, false)
		return true
	}
	state, err := s.store.DeploymentState(r.Context())
	if err != nil {
		s.internalError(w, requestID)
		return true
	}
	actor := store.SessionRecord{User: session.User, DeploymentID: state.DeploymentID, Generation: state.DeploymentGeneration, ExpiresMS: session.ExpiresMS}
	if job, genericErr := s.store.ReadJob(r.Context(), actor, jobID); genericErr == nil {
		s.writeJSON(w, http.StatusOK, publicStoredJob(job, state.DeploymentGeneration, requestID))
		return true
	} else if !errors.Is(genericErr, store.ErrComparisonNotFound) && !errors.Is(genericErr, store.ErrComparisonInvalid) {
		s.comparisonError(w, requestID, genericErr)
		return true
	}
	job, err := s.store.ReadDestinationTest(r.Context(), actor, jobID)
	if err != nil {
		s.notificationJobError(w, requestID, err)
		return true
	}
	s.writeJSON(w, http.StatusOK, publicNotificationJob(job, state.DeploymentGeneration, requestID))
	return true
}

func (s *Server) notificationJobError(w http.ResponseWriter, requestID string, err error) {
	switch {
	case errors.Is(err, store.ErrDeliveryNotFound):
		s.writeError(w, http.StatusNotFound, requestID, "job_not_found", "The notification test job was not found.", "review_current_state", 7, false)
	case errors.Is(err, store.ErrDestinationInvalid), errors.Is(err, store.ErrDeliveryInvalid):
		s.writeError(w, http.StatusBadRequest, requestID, "invalid_job", "The notification test job is invalid.", "fix_input", 2, false)
	case errors.Is(err, store.ErrOwnershipMismatch):
		s.writeError(w, http.StatusForbidden, requestID, "administrator_required", "Administrator access is required for notification job status.", "request_admin", 4, false)
	default:
		s.internalError(w, requestID)
	}
}
