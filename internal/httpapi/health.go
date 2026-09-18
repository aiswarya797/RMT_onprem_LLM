package httpapi

import (
	"net/http"

	"rmt.local/monitor/internal/alertruntime"
	"rmt.local/monitor/internal/store"
)

// ConfigureAlertEvaluator is called once, before the HTTP server starts.
// The callback reads the runner's synchronized, monotonic health snapshot.
func (s *Server) ConfigureAlertEvaluator(status func() alertruntime.Status) {
	s.evaluatorStatus = status
}

func (s *Server) alertEvaluatorStatus() alertruntime.Status {
	if s.evaluatorStatus == nil {
		return alertruntime.Status{}
	}
	return s.evaluatorStatus()
}

func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request, requestID string) {
	if r.Method != http.MethodGet {
		s.writeError(w, 405, requestID, "method_not_allowed", "Health checks require GET.", "none", 2, false)
		return
	}
	if r.URL.RawQuery != "" {
		s.writeError(w, 400, requestID, "invalid_query", "Health checks do not accept query parameters.", "fix_input", 2, false)
		return
	}
	if r.URL.Path == "/healthz" {
		// Liveness must not wait for a blocked database or collector.
		s.writeJSON(w, 200, map[string]string{"status": "ok"})
		return
	}
	ctx, cancel := interactiveQueryContext(r)
	defer cancel()
	status := s.alertEvaluatorStatus()
	ready := status.Started && status.LastSuccessMS != nil && !status.LastPassFailed && status.LagMS <= 15000
	state, err := s.store.DeploymentState(ctx)
	ready = ready && err == nil && state.MutationsAllowed
	if err == nil {
		capacity, capacityErr := s.store.ReadCapacityState(ctx, state.DeploymentID, s.clock.Now().UnixMilli())
		ready = ready && capacityErr == nil && capacity.State != store.StorageReadOnlyENOSPC && capacity.State != store.StorageBulkIngestPaused
	}
	if !ready {
		s.writeJSON(w, 503, map[string]string{"status": "not_ready"})
		return
	}
	s.writeJSON(w, 200, map[string]string{"status": "ready"})
}
