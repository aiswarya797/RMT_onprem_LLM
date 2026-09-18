package httpapi

import (
	"context"
	"net/http"
	"testing"
	"time"

	"rmt.local/monitor/internal/alertruntime"
	"rmt.local/monitor/internal/config"
	"rmt.local/monitor/internal/store"
)

func TestReadinessRequiresFreshStorageAndSuccessfulEvaluator(t *testing.T) {
	clock := &apiClock{now: time.UnixMilli(1800000000000)}
	st, err := store.Open(config.ForHome(t.TempDir()).Database, clock)
	if err != nil {
		t.Fatal(err)
	}
	closed := false
	defer func() {
		if !closed {
			_ = st.Close()
		}
	}()
	deployment, _, err := st.EnsureDeployment(context.Background(), "Health test")
	if err != nil {
		t.Fatal(err)
	}
	server := New(st, nil, clock, "127.0.0.1:9443", nil)
	check := func(path string, code int) {
		t.Helper()
		response := request(t, server, http.MethodGet, path, "127.0.0.1:9443", "", nil, nil)
		if response.Code != code {
			t.Fatalf("%s=%d %s", path, response.Code, response.Body.String())
		}
	}
	check("/healthz", 200)
	check("/readyz", 503)
	now := clock.Now().UnixMilli()
	status := alertruntime.Status{Started: true, LastAttemptMS: &now, LastSuccessMS: &now}
	server.ConfigureAlertEvaluator(func() alertruntime.Status { return status })
	check("/readyz", 503) // No measured storage observation yet.
	if _, err := st.MeasureAndRecordCapacity(context.Background(), deployment.DeploymentID, now, store.ExternalCapacityUsage{}); err != nil {
		t.Fatal(err)
	}
	check("/readyz", 200)
	status.LastPassFailed = true
	check("/readyz", 503)
	status.LastPassFailed, status.LagMS = false, 15001
	check("/readyz", 503)
	status.LagMS = 0
	clock.now = clock.now.Add(store.CapacityMeasurementMaxAge + time.Second)
	check("/readyz", 503)
	if err := st.Close(); err != nil {
		t.Fatal(err)
	}
	closed = true
	check("/healthz", 200) // Database failure cannot turn liveness into readiness.
	check("/readyz", 503)
}
