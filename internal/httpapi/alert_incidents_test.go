package httpapi

import (
	"context"
	"encoding/json"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"

	"rmt.local/monitor/internal/alerts"
	"rmt.local/monitor/internal/auth"
	"rmt.local/monitor/internal/config"
	"rmt.local/monitor/internal/domain"
	"rmt.local/monitor/internal/store"
)

func TestAlertIncidentHTTPKeepsConditionAndFrozenEvidenceSeparate(t *testing.T) {
	t.Setenv("LLM_MONITOR_EXPERIMENTAL", "1")
	ctx := context.Background()
	clock := &apiClock{now: time.UnixMilli(1_800_000_600_000)}
	paths := config.ForHome(t.TempDir())
	st, err := store.Open(paths.Database, clock)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	deployment, _, err := st.EnsureDeployment(ctx, "Alert incident HTTP")
	if err != nil {
		t.Fatal(err)
	}
	service, err := auth.NewService(st, paths, clock)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, _, err = service.RenewBootstrap(ctx); err != nil {
		t.Fatal(err)
	}
	token, err := os.ReadFile(paths.BootstrapToken)
	if err != nil {
		t.Fatal(err)
	}
	session, raw, err := service.CreateFirstAdmin(ctx, strings.TrimSpace(string(token)), "admin", "a sufficiently long password", "127.0.0.1")
	if err != nil {
		t.Fatal(err)
	}
	actor := store.SessionRecord{User: session.User, DeploymentID: deployment.DeploymentID, Generation: deployment.DeploymentGeneration, ExpiresMS: session.ExpiresMS}
	destination, err := st.CreateDestination(ctx, actor, "80000000-0000-4000-8000-000000000000", strings.Repeat("c", 64), store.DestinationDefinition{
		Kind: "webhook", DisplayName: "Incident status receiver",
		Config: domain.NotificationConfig{Webhook: &domain.WebhookDestination{HTTPSURL: "https://localhost:9444/events"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	rule, err := st.CreateRule(ctx, actor, "80000000-0000-4000-8000-000000000001", strings.Repeat("a", 64), store.RuleDefinition{EvaluatorType: alerts.RuleDiskMonitorHealth, ScopeID: deployment.DeploymentID, Enabled: true, Threshold: json.RawMessage(`15000`), DwellMS: 30000, RecoveryMS: 30000})
	if err != nil {
		t.Fatal(err)
	}
	now := clock.Now().UnixMilli()
	if _, err = st.MeasureAndRecordCapacity(ctx, deployment.DeploymentID, now, store.ExternalCapacityUsage{}); err != nil {
		t.Fatal(err)
	}
	pressure := true
	write := store.AlertEvaluationWrite{DeploymentID: deployment.DeploymentID, DeploymentGeneration: deployment.DeploymentGeneration, RuleID: rule.ID, RuleVersion: rule.Revision, Cursor: store.AlertInputCursor{InputOrdinal: 1, ObservedThroughMS: now, InputSHA256: strings.Repeat("b", 64)}, EventMS: now, CurrentLive: true, Input: alerts.Input{DataState: alerts.DataValid, MonitorHealth: &alerts.MonitorHealthInput{StoragePressure: &pressure}}, Evidence: &store.AlertCapsuleEvidence{MetricID: "monitor.storage_pressure", Unit: "boolean", WindowStartMS: now - 1, WindowEndMS: now + 1, ObservedMS: now, Quality: string(domain.QualityDerived), BooleanValue: &pressure, DefinitionRevision: domain.RegistryRevision, MethodRevision: "fixture-monitor-health-1"}}
	fired, err := st.ApplyAlertEvaluation(ctx, write)
	if err != nil || fired.IncidentID == nil {
		t.Fatalf("fired=%#v err=%v", fired, err)
	}
	server := New(st, service, clock, "127.0.0.1:9443", nil)
	cookie := &http.Cookie{Name: sessionCookie, Value: raw}
	path := "/api/v1/incidents/" + *fired.IncidentID
	detail := request(t, server, http.MethodGet, path, "127.0.0.1:9443", "", nil, cookie)
	if detail.Code != 200 {
		t.Fatalf("detail=%d %s", detail.Code, detail.Body.String())
	}
	var result struct {
		Origin     string                    `json:"origin"`
		EndMS      *int64                    `json:"end_ms"`
		Capsule    store.AlertTriggerCapsule `json:"capsule"`
		AlertState store.AlertIncidentState  `json:"alert_state"`
	}
	if err = json.Unmarshal(detail.Body.Bytes(), &result); err != nil {
		t.Fatal(err)
	}
	if result.Origin != "alert" || result.EndMS != nil || result.Capsule.Evaluation.NewState != alerts.StateFiring || result.AlertState.Condition != alerts.StateFiring || result.AlertState.AcknowledgedMS != nil || result.AlertState.Delivery.Total != 1 || len(result.AlertState.Deliveries) != 1 || result.AlertState.Deliveries[0].DestinationID != destination.ID || result.AlertState.Deliveries[0].Status != "queued" {
		t.Fatalf("wrong independent states: %s", detail.Body.String())
	}
	deliveryID := result.AlertState.Deliveries[0].ID
	delivery := request(t, server, http.MethodGet, "/api/v1/deliveries/"+deliveryID, "127.0.0.1:9443", "", nil, cookie)
	if delivery.Code != http.StatusOK || strings.Contains(delivery.Body.String(), "secret_ref") || !strings.Contains(delivery.Body.String(), `"status":"queued"`) {
		t.Fatalf("delivery status=%d %s", delivery.Code, delivery.Body.String())
	}
	// The verbose test log is an actual serialized fixture for schema validation;
	// it contains only this synthetic monitor-health incident, never credentials.
	t.Logf("ALERT_HTTP_RESPONSE %s", strings.TrimSpace(detail.Body.String()))
	list := request(t, server, http.MethodGet, "/api/v1/incidents", "127.0.0.1:9443", "", nil, cookie)
	if list.Code != 200 || !strings.Contains(list.Body.String(), `"condition":"FIRING"`) {
		t.Fatalf("list=%d %s", list.Code, list.Body.String())
	}
	key := "80000000-0000-4000-8000-000000000002"
	headers := func(r *http.Request) {
		r.Header.Set("X-CSRF-Token", session.CSRFToken)
		r.Header.Set("If-Deployment-Generation", deployment.DeploymentGeneration)
		r.Header.Set("Idempotency-Key", key)
	}
	close := request(t, server, http.MethodPatch, path, "127.0.0.1:9443", "http://127.0.0.1:9443", map[string]any{"expected_revision": 1, "workflow_state": "closed"}, cookie, headers)
	assertError(t, close, http.StatusConflict, "investigation_state_conflict")
	current, err := st.ReadAlertIncidentState(ctx, deployment.DeploymentID, *fired.IncidentID)
	if err != nil || current.Condition != alerts.StateFiring {
		t.Fatalf("manual close changed condition=%#v err=%v", current, err)
	}
	ackBody := map[string]any{"observed_transition_seq": current.TransitionSeq}
	missingCSRF := request(t, server, http.MethodPost, path+"/acknowledgements", "127.0.0.1:9443", "http://127.0.0.1:9443", ackBody, cookie, headers, func(r *http.Request) { r.Header.Del("X-CSRF-Token") })
	assertError(t, missingCSRF, 403, "csrf_required")
	key = "80000000-0000-4000-8000-000000000003"
	ack := request(t, server, http.MethodPost, path+"/acknowledgements", "127.0.0.1:9443", "http://127.0.0.1:9443", ackBody, cookie, headers)
	if ack.Code != 200 {
		t.Fatalf("ack=%d %s", ack.Code, ack.Body.String())
	}
	ackRetry := request(t, server, http.MethodPost, path+"/acknowledgements", "127.0.0.1:9443", "http://127.0.0.1:9443", ackBody, cookie, headers)
	if ackRetry.Code != 200 || ackRetry.Body.String() != ack.Body.String() {
		t.Fatalf("ack retry=%d %s", ackRetry.Code, ackRetry.Body.String())
	}
	key = "80000000-0000-4000-8000-000000000004"
	muteBody := map[string]any{"reason": "Planned fixture maintenance", "expires_ms": now + 3600000}
	muted := request(t, server, http.MethodPost, path+"/mute", "127.0.0.1:9443", "http://127.0.0.1:9443", muteBody, cookie, headers)
	if muted.Code != 200 {
		t.Fatalf("mute=%d %s", muted.Code, muted.Body.String())
	}
	key = "80000000-0000-4000-8000-000000000005"
	unmuted := request(t, server, http.MethodDelete, path+"/mute", "127.0.0.1:9443", "http://127.0.0.1:9443", nil, cookie, headers)
	if unmuted.Code != 200 {
		t.Fatalf("unmute=%d %s", unmuted.Code, unmuted.Body.String())
	}
	key = "80000000-0000-4000-8000-000000000004"
	oldMuteRetry := request(t, server, http.MethodPost, path+"/mute", "127.0.0.1:9443", "http://127.0.0.1:9443", muteBody, cookie, headers)
	if oldMuteRetry.Code != 200 || oldMuteRetry.Body.String() != muted.Body.String() {
		t.Fatalf("old mute retry=%d %s", oldMuteRetry.Code, oldMuteRetry.Body.String())
	}
	current, err = st.ReadAlertIncidentState(ctx, deployment.DeploymentID, *fired.IncidentID)
	if err != nil || current.Condition != alerts.StateFiring || current.AcknowledgedMS == nil || current.MutedUntilMS != nil {
		t.Fatalf("control retry altered independent condition=%#v err=%v", current, err)
	}
}
