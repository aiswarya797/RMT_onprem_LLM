package notify

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"rmt.local/monitor/internal/alerts"
	"rmt.local/monitor/internal/auth"
	"rmt.local/monitor/internal/config"
	"rmt.local/monitor/internal/domain"
	"rmt.local/monitor/internal/store"
)

type dispatcherTestClock struct {
	now time.Time
}

func (c *dispatcherTestClock) Now() time.Time { return c.now }

func TestAutomaticWebhookDispatchPersistsAcknowledgementAndRetry(t *testing.T) {
	ctx := context.Background()
	clock := &dispatcherTestClock{now: time.UnixMilli(1_800_001_000_000)}
	paths := config.ForHome(t.TempDir())
	st, actor, deployment := newAutomaticWebhookStore(t, paths, clock)
	defer st.Close()

	const secret = "dispatcher-secret-canary"
	serverRequests := make([]receiverRequest, 0, 2)
	var receiverMu sync.Mutex
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(io.LimitReader(r.Body, 65537))
		if err != nil {
			t.Errorf("read receiver body: %v", err)
			return
		}
		request := receiverRequest{body: body, idempotencyKey: r.Header.Get("Idempotency-Key"), timestamp: r.Header.Get("X-LLM-Monitor-Timestamp"), signature: r.Header.Get("X-LLM-Monitor-Signature")}
		receiverMu.Lock()
		serverRequests = append(serverRequests, request)
		attempt := len(serverRequests)
		receiverMu.Unlock()
		if attempt == 1 {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	server.TLS = &tls.Config{MinVersion: tls.VersionTLS13}
	server.StartTLS()
	defer server.Close()
	roots := x509.NewCertPool()
	roots.AddCert(server.Certificate())

	vault := Vault{Dir: paths.NotificationSecrets, KeyFile: paths.NotificationKey}
	secretRef, err := vault.Put("automatic-dispatch/receiver", secret)
	if err != nil {
		t.Fatal(err)
	}
	configuration := domain.NotificationConfig{Webhook: &domain.WebhookDestination{HTTPSURL: server.URL, HMACEnabled: true}}
	destination, err := st.CreateDestination(ctx, actor, "a1000000-0000-4000-8000-000000000001", strings.Repeat("a", 64), store.DestinationDefinition{Kind: "webhook", DisplayName: "Automatic receiver", Config: configuration, SecretRef: secretRef})
	if err != nil {
		t.Fatal(err)
	}
	rule, err := st.CreateRule(ctx, actor, "a1000000-0000-4000-8000-000000000002", strings.Repeat("b", 64), store.RuleDefinition{EvaluatorType: alerts.RuleDiskMonitorHealth, ScopeID: deployment.DeploymentID, Enabled: true, Threshold: json.RawMessage(`15000`), DwellMS: 30_000, RecoveryMS: 30_000})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := st.MeasureAndRecordCapacity(ctx, deployment.DeploymentID, clock.Now().UnixMilli(), store.ExternalCapacityUsage{}); err != nil {
		t.Fatal(err)
	}

	pressure := true
	firstEventMS := clock.Now().UnixMilli()
	fired, err := st.ApplyAlertEvaluation(ctx, store.AlertEvaluationWrite{
		DeploymentID: deployment.DeploymentID, DeploymentGeneration: deployment.DeploymentGeneration, RuleID: rule.ID, RuleVersion: rule.Revision,
		Cursor: store.AlertInputCursor{InputOrdinal: 1, ObservedThroughMS: firstEventMS, InputSHA256: strings.Repeat("c", 64)}, EventMS: firstEventMS, CurrentLive: true,
		Input:    alerts.Input{DataState: alerts.DataValid, MonitorHealth: &alerts.MonitorHealthInput{StoragePressure: &pressure}},
		Evidence: &store.AlertCapsuleEvidence{MetricID: "monitor.storage_pressure", Unit: "boolean", WindowStartMS: firstEventMS - 1, WindowEndMS: firstEventMS + 1, ObservedMS: firstEventMS, Quality: string(domain.QualityDerived), BooleanValue: &pressure, DefinitionRevision: domain.RegistryRevision, MethodRevision: "dispatcher-integration-v1"},
	})
	if err != nil || fired.Snapshot.State != alerts.StateFiring || fired.IncidentID == nil || fired.OutboxIntents != 1 {
		t.Fatalf("fired=%#v err=%v", fired, err)
	}
	stateBeforeDispatch, err := st.ReadAlertIncidentState(ctx, deployment.DeploymentID, *fired.IncidentID)
	if err != nil || len(stateBeforeDispatch.Deliveries) != 1 || stateBeforeDispatch.Deliveries[0].DestinationID != destination.ID || stateBeforeDispatch.Deliveries[0].Status != "queued" {
		t.Fatalf("delivery before dispatch=%#v err=%v", stateBeforeDispatch, err)
	}
	deliveryID := stateBeforeDispatch.Deliveries[0].ID

	dispatcher := NewDispatcherWithTransport(st, vault, Transport{Roots: roots, Now: clock.Now}, func(err error) { t.Errorf("dispatcher: %v", err) })
	dispatcher.dispatch(ctx)
	retrying, err := st.ReadNotificationDelivery(ctx, actor, deliveryID)
	if err != nil || retrying.State != "failed" || retrying.Status != "retrying" || retrying.Attempts != 1 || retrying.NextAttemptMS == nil || retrying.LastErrorCode == nil || *retrying.LastErrorCode != "webhook_transient_failure" {
		t.Fatalf("retrying=%#v err=%v", retrying, err)
	}
	receiverMu.Lock()
	if len(serverRequests) != 1 {
		t.Fatalf("receiver requests=%d want=1", len(serverRequests))
	}
	firstRequest := serverRequests[0]
	receiverMu.Unlock()
	assertAutomaticReceiverRequest(t, firstRequest, secret, retrying.IdempotencyKey, fired.InstanceID)

	clock.now = time.UnixMilli(*retrying.NextAttemptMS)
	dispatcher.dispatch(ctx)
	acknowledged, err := st.ReadNotificationDelivery(ctx, actor, deliveryID)
	if err != nil || acknowledged.State != "sent" || acknowledged.Status != "acknowledged" || acknowledged.Attempts != 2 || acknowledged.ReceiverACKMS == nil || acknowledged.AcceptedUnknown {
		t.Fatalf("acknowledged=%#v err=%v", acknowledged, err)
	}
	receiverMu.Lock()
	if len(serverRequests) != 2 {
		t.Fatalf("receiver requests=%d want=2", len(serverRequests))
	}
	secondRequest := serverRequests[1]
	receiverMu.Unlock()
	assertAutomaticReceiverRequest(t, secondRequest, secret, acknowledged.IdempotencyKey, fired.InstanceID)
	if string(secondRequest.body) != string(firstRequest.body) || secondRequest.idempotencyKey != firstRequest.idempotencyKey {
		t.Fatal("retry changed the bounded payload or idempotency key")
	}
	if strings.Contains(string(firstRequest.body), secret) || strings.Contains(string(secondRequest.body), secret) {
		t.Fatal("receiver payload exposed the webhook secret")
	}

	state, err := st.ReadAlertIncidentState(ctx, deployment.DeploymentID, *fired.IncidentID)
	if err != nil || len(state.Deliveries) != 1 || state.Deliveries[0].Status != "acknowledged" || state.Deliveries[0].ReceiverACKMS == nil || state.Condition != alerts.StateFiring {
		t.Fatalf("incident delivery state=%#v err=%v", state, err)
	}
}

func TestAutomaticWebhookPermanentFailurePersistsTerminalHealth(t *testing.T) {
	ctx := context.Background()
	clock := &dispatcherTestClock{now: time.UnixMilli(1_800_001_100_000)}
	paths := config.ForHome(t.TempDir())
	st, actor, deployment := newAutomaticWebhookStore(t, paths, clock)
	defer st.Close()

	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.Copy(io.Discard, io.LimitReader(r.Body, 65537))
		w.WriteHeader(http.StatusUnauthorized)
	}))
	server.TLS = &tls.Config{MinVersion: tls.VersionTLS13}
	server.StartTLS()
	defer server.Close()
	roots := x509.NewCertPool()
	roots.AddCert(server.Certificate())
	vault := Vault{Dir: paths.NotificationSecrets, KeyFile: paths.NotificationKey}
	secretRef, err := vault.Put("automatic-terminal/receiver", "terminal-secret-canary")
	if err != nil {
		t.Fatal(err)
	}
	destination, err := st.CreateDestination(ctx, actor, "a1000000-0000-4000-8000-000000000011", strings.Repeat("e", 64), store.DestinationDefinition{Kind: "webhook", DisplayName: "Terminal receiver", Config: domain.NotificationConfig{Webhook: &domain.WebhookDestination{HTTPSURL: server.URL, HMACEnabled: true}}, SecretRef: secretRef})
	if err != nil {
		t.Fatal(err)
	}
	rule, err := st.CreateRule(ctx, actor, "a1000000-0000-4000-8000-000000000012", strings.Repeat("f", 64), store.RuleDefinition{EvaluatorType: alerts.RuleDiskMonitorHealth, ScopeID: deployment.DeploymentID, Enabled: true, Threshold: json.RawMessage(`15000`), DwellMS: 30_000, RecoveryMS: 30_000})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := st.MeasureAndRecordCapacity(ctx, deployment.DeploymentID, clock.Now().UnixMilli(), store.ExternalCapacityUsage{}); err != nil {
		t.Fatal(err)
	}
	pressure := true
	eventMS := clock.Now().UnixMilli()
	write := store.AlertEvaluationWrite{DeploymentID: deployment.DeploymentID, DeploymentGeneration: deployment.DeploymentGeneration, RuleID: rule.ID, RuleVersion: rule.Revision, Cursor: store.AlertInputCursor{InputOrdinal: 1, ObservedThroughMS: eventMS, InputSHA256: strings.Repeat("1", 64)}, EventMS: eventMS, CurrentLive: true, Input: alerts.Input{DataState: alerts.DataValid, MonitorHealth: &alerts.MonitorHealthInput{StoragePressure: &pressure}}, Evidence: &store.AlertCapsuleEvidence{MetricID: "monitor.storage_pressure", Unit: "boolean", WindowStartMS: eventMS - 1, WindowEndMS: eventMS + 1, ObservedMS: eventMS, Quality: string(domain.QualityDerived), BooleanValue: &pressure, DefinitionRevision: domain.RegistryRevision, MethodRevision: "dispatcher-terminal-v1"}}
	fired, err := st.ApplyAlertEvaluation(ctx, write)
	if err != nil || fired.IncidentID == nil || fired.OutboxIntents != 1 {
		t.Fatalf("fired=%#v err=%v", fired, err)
	}
	stateBeforeDispatch, err := st.ReadAlertIncidentState(ctx, deployment.DeploymentID, *fired.IncidentID)
	if err != nil || len(stateBeforeDispatch.Deliveries) != 1 || stateBeforeDispatch.Deliveries[0].DestinationID != destination.ID || stateBeforeDispatch.Deliveries[0].Status != "queued" {
		t.Fatalf("delivery before dispatch=%#v err=%v", stateBeforeDispatch, err)
	}
	deliveryID := stateBeforeDispatch.Deliveries[0].ID
	NewDispatcherWithTransport(st, vault, Transport{Roots: roots, Now: clock.Now}, func(err error) { t.Errorf("dispatcher: %v", err) }).dispatch(ctx)
	record, err := st.ReadNotificationDelivery(ctx, actor, deliveryID)
	if err != nil || record.State != "failed" || record.Status != "terminal_failure" || record.NextAttemptMS != nil || record.LastErrorCode == nil || *record.LastErrorCode != "webhook_receiver_rejected" {
		t.Fatalf("terminal=%#v err=%v", record, err)
	}
	plan, err := st.ReadAlertRuntimePlan(ctx, deployment.DeploymentID, deployment.DeploymentGeneration)
	if err != nil || !plan.Monitor.FinalDeliveryFailed {
		t.Fatalf("monitor plan=%#v err=%v", plan.Monitor, err)
	}
}

type receiverRequest struct {
	body           []byte
	idempotencyKey string
	timestamp      string
	signature      string
}

func assertAutomaticReceiverRequest(t *testing.T, request receiverRequest, secret, idempotencyKey, instanceID string) {
	t.Helper()
	if len(request.body) == 0 || len(request.body) > 65536 || request.idempotencyKey != idempotencyKey || request.timestamp == "" {
		t.Fatalf("bounded receiver request=%#v", request)
	}
	var payload struct {
		SchemaVersion string `json:"schema_version"`
		InstanceID    string `json:"instance_id"`
		State         string `json:"state"`
	}
	if err := json.Unmarshal(request.body, &payload); err != nil || payload.SchemaVersion != "alert-notification-1" || payload.InstanceID != instanceID || payload.State != "FIRING" {
		t.Fatalf("payload=%s err=%v", request.body, err)
	}
	mac := hmac.New(sha256.New, []byte(secret))
	_, _ = mac.Write([]byte(request.timestamp + "."))
	_, _ = mac.Write(request.body)
	if request.signature != "sha256="+hex.EncodeToString(mac.Sum(nil)) {
		t.Fatalf("invalid receiver signature=%q", request.signature)
	}
}

func newAutomaticWebhookStore(t *testing.T, paths config.Paths, clock *dispatcherTestClock) (*store.Store, store.SessionRecord, domain.DeploymentState) {
	t.Helper()
	ctx := context.Background()
	st, err := store.Open(paths.Database, clock)
	if err != nil {
		t.Fatal(err)
	}
	deployment, _, err := st.EnsureDeployment(ctx, "Automatic webhook integration")
	if err != nil {
		st.Close()
		t.Fatal(err)
	}
	service, err := auth.NewService(st, paths, clock)
	if err != nil {
		st.Close()
		t.Fatal(err)
	}
	if _, _, _, err := service.RenewBootstrap(ctx); err != nil {
		st.Close()
		t.Fatal(err)
	}
	bootstrap, err := os.ReadFile(paths.BootstrapToken)
	if err != nil {
		st.Close()
		t.Fatal(err)
	}
	session, _, err := service.CreateFirstAdmin(ctx, strings.TrimSpace(string(bootstrap)), "admin", "a sufficiently long password", "127.0.0.1")
	if err != nil {
		st.Close()
		t.Fatal(err)
	}
	actor := store.SessionRecord{User: session.User, DeploymentID: deployment.DeploymentID, Generation: deployment.DeploymentGeneration, ExpiresMS: session.ExpiresMS}
	return st, actor, deployment
}
