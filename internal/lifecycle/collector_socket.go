package lifecycle

import (
	"context"
	"errors"
	"net/http"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"rmt.local/monitor/internal/collect/darwin"
	"rmt.local/monitor/internal/collector/pairing"
	"rmt.local/monitor/internal/config"
	"rmt.local/monitor/internal/domain"
	"rmt.local/monitor/internal/protocol"
	"rmt.local/monitor/internal/store"
)

// LocalCollectorHandler is reachable only through the verified owner socket.
// Ownership comes from that socket plus durable local pairing, never envelope
// claims. The remote mTLS listener must supply its own certificate-bound owner.
func LocalCollectorHandler(st *store.Store, paths config.Paths) http.Handler {
	type processIdentity struct {
		PID   int                  `json:"pid"`
		Start domain.Uint64Decimal `json:"process_start_identity"`
	}
	var self atomic.Pointer[processIdentity]
	// At most one native self read. If it stalls or fails, the socket and UI
	// remain available and process association is explicitly absent.
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		observation, err := darwin.NewNativeReader().Process(ctx, os.Getpid())
		if err == nil {
			self.Store(&processIdentity{PID: os.Getpid(), Start: domain.DecimalUint64(observation.Identity.StartAbsolute)})
		}
	}()
	gate := make(chan struct{}, 1)
	limiter := &collectorByteBudget{updated: time.Now(), total: 256 << 10, replay: 128 << 10}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /v1/status", func(w http.ResponseWriter, r *http.Request) {
		status, err := st.FoundationStatus(r.Context())
		if err != nil {
			http.Error(w, "status unavailable", 503)
			return
		}
		collected, err := st.HasCollectedFrames(r.Context(), status.State.DeploymentID)
		if err != nil {
			http.Error(w, "status unavailable", 503)
			return
		}
		writeLocal(w, map[string]any{"schema_version": domain.SchemaVersion, "service": "hub", "state": "running", "deployment_state": status.State, "host_count": status.HostCount, "target_count": status.TargetCount, "collection_started": collected, "inference_started": false, "process_identity": self.Load()})
	})
	mux.HandleFunc("GET /collector/v1/time", func(w http.ResponseWriter, r *http.Request) {
		writeLocal(w, map[string]int64{"hub_time_ms": time.Now().UnixMilli()})
	})
	mux.HandleFunc("POST /collector/v1/", func(w http.ResponseWriter, r *http.Request) {
		if !OwnerPeer(r.Context()) {
			http.Error(w, "verified owner required", 403)
			return
		}
		select {
		case gate <- struct{}{}:
			defer func() { <-gate }()
		default:
			w.Header().Set("Retry-After", "1")
			http.Error(w, "collector admission busy", 503)
			return
		}
		deployment, err := st.DeploymentState(r.Context())
		if err != nil {
			http.Error(w, "deployment unavailable", 503)
			return
		}
		local, err := pairing.Open(paths.Collector, deployment.DeploymentID, deployment.DeploymentGeneration)
		if err != nil {
			http.Error(w, "local pairing requires recovery", 409)
			return
		}
		identity := local.Snapshot()
		if r.Header.Get("Content-Encoding") != "" && r.Header.Get("Content-Encoding") != "identity" {
			http.Error(w, "unsupported transport encoding", 415)
			return
		}
		if r.ContentLength < 0 || r.ContentLength > protocol.MaxBatchBytes {
			http.Error(w, "bounded content length required", 413)
			return
		}
		statusLane := r.URL.Path == "/collector/v1/status"
		if !limiter.take(r.ContentLength, statusLane) {
			w.Header().Set("Retry-After", "1")
			http.Error(w, "collector rate limit", 429)
			return
		}
		r.Body = http.MaxBytesReader(w, r.Body, protocol.MaxBatchBytes)
		matches := func(deploymentID, hostID, generation string) bool {
			return deploymentID == identity.DeploymentID && hostID == identity.HostID && generation == identity.Generation
		}
		var result any
		switch r.URL.Path {
		case "/collector/v1/local-pair":
			var request struct {
				HostID         string `json:"host_id"`
				InstallationID string `json:"installation_id"`
			}
			if err = protocol.DecodeStrictJSON(r.Body, 4096, &request); err != nil || request.HostID != identity.HostID || request.InstallationID != identity.InstallationID {
				http.Error(w, "local identity mismatch", 403)
				return
			}
			err = st.RegisterLocalHost(r.Context(), store.TrustedOwnerContext{DeploymentID: identity.DeploymentID, SecurityGeneration: identity.Generation, VerifiedOSOwner: true, InstallingUID: uint32(os.Getuid())}, store.LocalHostRegistration{HostID: identity.HostID, InstallationUUID: identity.InstallationID, DisplayName: "This Mac", CollectorVersion: protocol.CurrentIdentity().Version, Capabilities: map[string]bool{"darwin": true, "ollama_read_only": true}})
			result = map[string]any{"durable": true, "host_id": identity.HostID}
		case "/collector/v1/sessions":
			var request protocol.SessionActivation
			request, err = protocol.DecodeSessionActivation(r.Body)
			if err == nil && !matches(request.DeploymentID, request.HostID, request.SecurityGeneration) {
				http.Error(w, "ownership mismatch", 403)
				return
			}
			if err == nil {
				result, err = st.ActivateCollectorSession(r.Context(), request)
			}
		case "/collector/v1/inventory":
			var request protocol.CollectorInventory
			request, err = protocol.DecodeCollectorInventory(r.Body)
			if err == nil && !matches(request.DeploymentID, request.HostID, request.SecurityGeneration) {
				http.Error(w, "ownership mismatch", 403)
				return
			}
			if err == nil {
				targets, readErr := pairing.ReadTargets(paths.Collector, identity.Generation)
				if readErr != nil || !localInventoryMatches(request, identity, targets) {
					http.Error(w, "inventory differs from reviewed local configuration", 403)
					return
				}
			}
			if err == nil {
				result, err = st.RegisterCollectorInventory(r.Context(), request)
			}
		case "/collector/v1/batches":
			var request protocol.CollectorBatch
			request, err = protocol.DecodeCollectorBatch(r.Body)
			if err == nil && !matches(request.DeploymentID, request.HostID, request.SecurityGeneration) {
				http.Error(w, "ownership mismatch", 403)
				return
			}
			if err == nil && request.DeliveryMode == "replay" && !limiter.takeReplay(r.ContentLength) {
				w.Header().Set("Retry-After", "1")
				http.Error(w, "replay rate limit", 429)
				return
			}
			if err == nil {
				result, err = st.IngestCollectorBatch(r.Context(), request)
			}
		case "/collector/v1/recovery-replay":
			var request protocol.RecoveryReplay
			request, err = protocol.DecodeRecoveryReplay(r.Body)
			if err == nil && !matches(request.DeploymentID, request.HostID, request.AdmittingSecurityGeneration) {
				http.Error(w, "ownership mismatch", http.StatusForbidden)
				return
			}
			if err == nil && !limiter.takeReplay(r.ContentLength) {
				w.Header().Set("Retry-After", "1")
				http.Error(w, "replay rate limit", http.StatusTooManyRequests)
				return
			}
			if err == nil {
				result, err = st.IngestRecoveryReplay(r.Context(), request)
			}
		case "/collector/v1/status":
			var request protocol.SourceStatus
			request, err = protocol.DecodeSourceStatus(r.Body)
			if err == nil && !matches(request.DeploymentID, request.HostID, request.SecurityGeneration) {
				http.Error(w, "ownership mismatch", 403)
				return
			}
			if err == nil {
				result, err = st.IngestSourceStatus(r.Context(), request)
			}
		default:
			http.NotFound(w, r)
			return
		}
		if err != nil {
			localAdmissionError(w, err)
			return
		}
		writeLocal(w, result)
	})
	return mux
}

func writeLocal(w http.ResponseWriter, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	_ = protocol.WriteJSON(w, value)
}
func localAdmissionError(w http.ResponseWriter, err error) {
	code := http.StatusUnprocessableEntity
	if errors.Is(err, store.ErrOwnershipMismatch) {
		code = 403
	}
	if errors.Is(err, store.ErrGenerationConflict) || errors.Is(err, store.ErrAdmissionFenced) || errors.Is(err, store.ErrRecoveryConflict) || errors.Is(err, store.ErrRecoveryDefinition) {
		code = 409
	}
	if errors.Is(err, store.ErrRecoveryGrantExpired) {
		code = http.StatusGone
	}
	if errors.Is(err, store.ErrStatusObservationExpired) {
		http.Error(w, "status_observation_expired", http.StatusGone)
		return
	}
	if errors.Is(err, store.ErrWriterBackpressure) || errors.Is(err, protocol.ErrDecoderBusy) || errors.Is(err, store.ErrCapacityMeasurementUnavailable) || errors.Is(err, store.ErrBulkIngestPaused) || errors.Is(err, store.ErrRecoveryCapacityBusy) {
		code = 503
		w.Header().Set("Retry-After", "1")
	}
	// No SQL, filesystem paths, or submitted metadata enter the response.
	http.Error(w, "collector admission rejected", code)
}

func localInventoryMatches(inventory protocol.CollectorInventory, state pairing.State, targets pairing.TargetState) bool {
	for _, proposed := range inventory.Targets {
		found := false
		for _, configured := range targets.Targets {
			if !configured.Retired && configured.TargetID == proposed.TargetID && configured.SelectorSHA256 == proposed.LocalSelectorSHA256 {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	for _, proposed := range inventory.Sources {
		if proposed.Kind == "host" && proposed.SourceID == state.HostSourceID && proposed.TargetID == nil && proposed.Active {
			continue
		}
		found := false
		for _, configured := range targets.Targets {
			if configured.SourceID == proposed.SourceID && proposed.Kind == "runtime" && proposed.TargetID != nil && *proposed.TargetID == configured.TargetID && proposed.Active == !configured.Retired {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	return true
}

type collectorByteBudget struct {
	mu            sync.Mutex
	updated       time.Time
	total, replay float64
	controlAt     time.Time
}

func (b *collectorByteBudget) refill() {
	now := time.Now()
	elapsed := now.Sub(b.updated).Seconds()
	b.updated = now
	b.total = min(256<<10, b.total+elapsed*(256<<10))
	b.replay = min(256<<10, b.replay+elapsed*(128<<10))
}
func (b *collectorByteBudget) take(bytes int64, control bool) bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.refill()
	if control {
		if bytes > 4096 || time.Since(b.controlAt) < 5*time.Second {
			return false
		}
		b.controlAt = time.Now()
		return true
	}
	if float64(bytes) > b.total {
		return false
	}
	b.total -= float64(bytes)
	return true
}
func (b *collectorByteBudget) takeReplay(bytes int64) bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.refill()
	if float64(bytes) > b.replay {
		return false
	}
	b.replay -= float64(bytes)
	return true
}
