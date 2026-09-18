package httpapi

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"strings"

	"rmt.local/monitor/internal/store"
)

func (s *Server) handleAlertControl(w http.ResponseWriter, r *http.Request, requestID string) {
	parts := strings.Split(strings.TrimPrefix(r.URL.Path, "/api/v1/incidents/"), "/")
	if len(parts) != 2 || !validAPIUUID(parts[0]) || r.URL.RawQuery != "" {
		s.writeError(w, 400, requestID, "invalid_incident", "A valid alert incident is required, without query parameters.", "fix_input", 2, false)
		return
	}
	action := parts[1]
	if !(action == "acknowledgements" && r.Method == http.MethodPost) && !(action == "mute" && (r.Method == http.MethodPost || r.Method == http.MethodDelete)) {
		s.writeError(w, 405, requestID, "method_not_allowed", "This alert operation is not available.", "none", 2, false)
		return
	}
	_, actor, key, ok := s.incidentMutationActor(w, r, requestID)
	if !ok {
		return
	}
	var acknowledgement struct {
		Sequence int64 `json:"observed_transition_seq"`
	}
	var mute struct {
		Reason    string `json:"reason"`
		ExpiresMS int64  `json:"expires_ms"`
	}
	var canonical []byte
	switch {
	case action == "acknowledgements":
		if !s.decodeJSON(w, r, requestID, &acknowledgement) {
			return
		}
		canonical, _ = json.Marshal(acknowledgement)
	case r.Method == http.MethodPost:
		if !s.decodeJSON(w, r, requestID, &mute) {
			return
		}
		canonical, _ = json.Marshal(mute)
	default:
		if r.ContentLength != 0 {
			s.writeError(w, 400, requestID, "invalid_input", "Unmute does not accept a request body.", "fix_input", 2, false)
			return
		}
	}
	digest := sha256.Sum256(append([]byte(r.Method+" "+r.URL.Path+"\x00"), canonical...))
	hash := hex.EncodeToString(digest[:])
	ctx, cancel := interactiveQueryContext(r)
	defer cancel()
	var result store.AlertControlResult
	var err error
	switch {
	case action == "acknowledgements":
		result, err = s.store.AcknowledgeAlertIncident(ctx, actor, parts[0], key, hash, acknowledgement.Sequence)
	case r.Method == http.MethodPost:
		result, err = s.store.MuteAlertIncident(ctx, actor, parts[0], key, hash, mute.Reason, mute.ExpiresMS)
	default:
		result, err = s.store.UnmuteAlertIncident(ctx, actor, parts[0], key, hash)
	}
	if err != nil {
		switch {
		case errors.Is(err, store.ErrAlertInvalid):
			s.writeError(w, 400, requestID, "invalid_alert_action", "Review the current alert, acknowledgement sequence or mute reason and expiry (within 24 hours).", "fix_input", 2, false)
		case errors.Is(err, store.ErrAlertCursorConflict):
			s.writeError(w, 409, requestID, "alert_state_changed", "The alert state or request identity changed. Refresh it before submitting a new action.", "review_current_state", 7, false)
		case errors.Is(err, store.ErrAlertCapacity), errors.Is(err, store.ErrAlertCapacityUncalibrated):
			s.writeError(w, 507, requestID, "alert_capacity_exhausted", "The alert action could not be saved within the protected storage budget.", "review_current_state", 7, false)
		default:
			s.incidentError(w, requestID, err)
		}
		return
	}
	s.writeJSON(w, http.StatusOK, result)
}
