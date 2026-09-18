package httpapi

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"

	"rmt.local/monitor/internal/auth"
	"rmt.local/monitor/internal/config"
	"rmt.local/monitor/internal/investigation"
	"rmt.local/monitor/internal/store"
)

func TestIncidentCreateRetryReturnsImmutableCapsuleWithoutSourceHistory(t *testing.T) {
	clock := &apiClock{now: time.UnixMilli(1_800_000_600_000)}
	paths := config.ForHome(t.TempDir())
	st, err := store.Open(paths.Database, clock)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	state, _, err := st.EnsureDeployment(context.Background(), "Investigation retry")
	if err != nil {
		t.Fatal(err)
	}
	authService, err := auth.NewService(st, paths, clock)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, _, err := authService.RenewBootstrap(context.Background()); err != nil {
		t.Fatal(err)
	}
	bootstrap, err := os.ReadFile(paths.BootstrapToken)
	if err != nil {
		t.Fatal(err)
	}
	session, rawSession, err := authService.CreateFirstAdmin(context.Background(), strings.TrimSpace(string(bootstrap)), "admin", "a sufficiently long password", "127.0.0.1")
	if err != nil {
		t.Fatal(err)
	}
	actor := store.SessionRecord{User: session.User, DeploymentID: state.DeploymentID, Generation: state.DeploymentGeneration, ExpiresMS: session.ExpiresMS}
	body := manualIncidentCreateRequest{
		Title: "Retained manual investigation",
		Scope: investigation.Scope{Kind: "host", ID: "10000000-0000-4000-8000-000000000099"},
		Start: time.UnixMilli(1_800_000_000_000).UTC().Format(time.RFC3339Nano),
		End:   time.UnixMilli(1_800_000_300_000).UTC().Format(time.RFC3339Nano),
	}
	if err := st.RegisterLocalHost(context.Background(), store.TrustedOwnerContext{DeploymentID: state.DeploymentID, SecurityGeneration: state.DeploymentGeneration, InstallingUID: uint32(os.Getuid()), VerifiedOSOwner: true}, store.LocalHostRegistration{HostID: body.Scope.ID, InstallationUUID: "10000000-0000-4000-8000-000000000088", DisplayName: "Fixture Mac", CollectorVersion: "test", Capabilities: map[string]bool{}}); err != nil {
		t.Fatal(err)
	}

	if _, err := st.MeasureAndRecordCapacity(context.Background(), state.DeploymentID, clock.Now().UnixMilli(), store.ExternalCapacityUsage{}); err != nil {
		t.Fatal(err)
	}
	canonical, _ := json.Marshal(body)
	digest := sha256.Sum256(canonical)
	requestHash := hex.EncodeToString(digest[:])
	key := "10000000-0000-4000-8000-000000000098"
	scopeJSON, _ := json.Marshal(body.Scope)
	created, err := st.CreateManualIncident(context.Background(), actor, key, requestHash, store.ManualIncidentInput{
		Title: body.Title, ScopeJSON: scopeJSON, StartMS: 1_800_000_000_000, EndMS: 1_800_000_300_000,
		CapsuleSchemaRevision: investigation.CapsuleSchemaRevision, CardRevision: investigation.CardRevision,
		CapsulePayload: []byte(`{"schema_revision":"incident-capsule-1","catalogue_revision":"ec01-ec07-mac-1","generated_ms":1800000300000,"scope":{"kind":"host","id":"10000000-0000-4000-8000-000000000099"},"focus_window":{"start_ms":1800000000000,"end_ms":1800000300000},"baseline_window":{"start_ms":1799999700000,"end_ms":1800000000000},"evidence_state":"partial","cards":[],"collapsed_card_count":0}`),
		EvidenceState:  "partial",
	})
	if err != nil {
		t.Fatal(err)
	}
	server := New(st, authService, clock, "127.0.0.1:9443", nil)
	mutatingHeaders := func(request *http.Request) {
		request.Header.Set("X-CSRF-Token", session.CSRFToken)
		request.Header.Set("If-Deployment-Generation", state.DeploymentGeneration)
		request.Header.Set("Idempotency-Key", key)
	}
	cookie := &http.Cookie{Name: sessionCookie, Value: rawSession}
	retry := request(t, server, http.MethodPost, "/api/v1/incidents", "127.0.0.1:9443", "http://127.0.0.1:9443", body, cookie, mutatingHeaders)
	if retry.Code != http.StatusCreated || !strings.Contains(retry.Body.String(), `"id":"`+created.ID+`"`) || strings.Contains(retry.Body.String(), `"capsule":`) || strings.Contains(retry.Body.String(), `"annotations":`) {
		t.Fatalf("retry code=%d body=%s", retry.Code, retry.Body.String())
	}
	body.Title = "Changed retry"
	changed := request(t, server, http.MethodPost, "/api/v1/incidents", "127.0.0.1:9443", "http://127.0.0.1:9443", body, cookie, mutatingHeaders)
	assertError(t, changed, http.StatusConflict, "idempotency_conflict")

	key = "10000000-0000-4000-8000-000000000097"
	closedState, renamed := "closed", "Reviewed retained evidence"
	update := manualIncidentUpdateRequest{ExpectedRevision: 1, Title: &renamed, WorkflowState: &closedState}
	closed := request(t, server, http.MethodPatch, "/api/v1/incidents/"+created.ID, "127.0.0.1:9443", "http://127.0.0.1:9443", update, cookie, mutatingHeaders)
	if closed.Code != http.StatusOK || !strings.Contains(closed.Body.String(), `"revision":2`) || !strings.Contains(closed.Body.String(), `"workflow_state":"closed"`) || !strings.Contains(closed.Body.String(), `"capsule_sha256":"`+created.CapsuleSHA256+`"`) {
		t.Fatalf("close code=%d body=%s", closed.Code, closed.Body.String())
	}
	retriedClose := request(t, server, http.MethodPatch, "/api/v1/incidents/"+created.ID, "127.0.0.1:9443", "http://127.0.0.1:9443", update, cookie, mutatingHeaders)
	if retriedClose.Code != http.StatusOK || retriedClose.Body.String() != closed.Body.String() {
		t.Fatalf("retry close code=%d body=%s", retriedClose.Code, retriedClose.Body.String())
	}
	changedTitle := "Conflicting retry"
	update.Title = &changedTitle
	conflict := request(t, server, http.MethodPatch, "/api/v1/incidents/"+created.ID, "127.0.0.1:9443", "http://127.0.0.1:9443", update, cookie, mutatingHeaders)
	assertError(t, conflict, http.StatusConflict, "idempotency_conflict")

	key = "10000000-0000-4000-8000-000000000096"
	openState := "open"
	update.ExpectedRevision, update.Title, update.WorkflowState = 2, nil, &openState
	reopened := request(t, server, http.MethodPatch, "/api/v1/incidents/"+created.ID, "127.0.0.1:9443", "http://127.0.0.1:9443", update, cookie, mutatingHeaders)
	if reopened.Code != http.StatusOK || !strings.Contains(reopened.Body.String(), `"revision":3`) || !strings.Contains(reopened.Body.String(), `"workflow_state":"open"`) {
		t.Fatalf("reopen code=%d body=%s", reopened.Code, reopened.Body.String())
	}
	key = "10000000-0000-4000-8000-000000000097"
	update.ExpectedRevision, update.Title, update.WorkflowState = 1, &renamed, &closedState
	retriedAfterReopen := request(t, server, http.MethodPatch, "/api/v1/incidents/"+created.ID, "127.0.0.1:9443", "http://127.0.0.1:9443", update, cookie, mutatingHeaders)
	if retriedAfterReopen.Code != http.StatusOK || retriedAfterReopen.Body.String() != closed.Body.String() {
		t.Fatalf("old retry after reopen code=%d body=%s", retriedAfterReopen.Code, retriedAfterReopen.Body.String())
	}
	current := request(t, server, http.MethodGet, "/api/v1/incidents/"+created.ID, "127.0.0.1:9443", "http://127.0.0.1:9443", nil, cookie)
	if current.Code != http.StatusOK || !strings.Contains(current.Body.String(), `"revision":3`) || !strings.Contains(current.Body.String(), `"workflow_state":"open"`) {
		t.Fatalf("current after old retry code=%d body=%s", current.Code, current.Body.String())
	}
	key = "10000000-0000-4000-8000-000000000098"
	body.Title = "Retained manual investigation"
	createRetryAfterMutations := request(t, server, http.MethodPost, "/api/v1/incidents", "127.0.0.1:9443", "http://127.0.0.1:9443", body, cookie, mutatingHeaders)
	if createRetryAfterMutations.Code != http.StatusCreated || createRetryAfterMutations.Body.String() != retry.Body.String() {
		t.Fatalf("create retry after mutations code=%d body=%s", createRetryAfterMutations.Code, createRetryAfterMutations.Body.String())
	}

	key = "10000000-0000-4000-8000-000000000095"
	update.Title, update.WorkflowState = nil, nil
	invalid := request(t, server, http.MethodPatch, "/api/v1/incidents/"+created.ID, "127.0.0.1:9443", "http://127.0.0.1:9443", update, cookie, mutatingHeaders)
	assertError(t, invalid, http.StatusBadRequest, "invalid_incident")
	update.ExpectedRevision, update.WorkflowState = 2, &openState
	stale := request(t, server, http.MethodPatch, "/api/v1/incidents/"+created.ID, "127.0.0.1:9443", "http://127.0.0.1:9443", update, cookie, mutatingHeaders)
	assertError(t, stale, http.StatusConflict, "revision_conflict")
}
