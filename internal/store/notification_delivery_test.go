package store

import (
	"context"
	"database/sql"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"rmt.local/monitor/internal/alerts"
)

type alertDeliveryFixture struct {
	store         *Store
	clock         *enrollmentTestClock
	admin         SessionRecord
	rule          RuleRecord
	fired         AlertEvaluationResult
	destinationID string
	secretRef     string
}

func newAlertDeliveryFixture(t *testing.T) alertDeliveryFixture {
	t.Helper()
	st, clock, admin := newEnrollmentStore(t)
	rule, fired := createAlertControlFixture(t, st, clock, admin, 1)
	clock.now = time.UnixMilli(fired.Snapshot.LastEvalMS)
	measureAlertTestCapacity(t, st, admin, clock.Now().UnixMilli())
	var destinationID string
	if err := st.db.QueryRow(`SELECT id FROM destinations WHERE deployment_id=? LIMIT 1`, admin.DeploymentID).Scan(&destinationID); err != nil {
		t.Fatal(err)
	}
	secretRef := strings.Repeat("a", 64)
	configuration := `{"webhook":{"https_url":"https://127.0.0.1:9443/events","hmac_enabled":true},"smtp":null}`
	if _, err := st.db.Exec(`UPDATE destinations SET secret_ref=?,configuration_json=? WHERE deployment_id=? AND id=?`, secretRef, configuration, admin.DeploymentID, destinationID); err != nil {
		t.Fatal(err)
	}
	if _, err := st.db.Exec(`UPDATE outbox SET destination_secret_ref=? WHERE deployment_id=? AND instance_id=?`, secretRef, admin.DeploymentID, fired.InstanceID); err != nil {
		t.Fatal(err)
	}
	return alertDeliveryFixture{store: st, clock: clock, admin: admin, rule: rule, fired: fired, destinationID: destinationID, secretRef: secretRef}
}

func claimAlertDelivery(t *testing.T, fixture alertDeliveryFixture) *DeliveryLease {
	t.Helper()
	lease, err := fixture.store.ClaimNotificationDelivery(context.Background(), fixture.admin.DeploymentID, fixture.admin.Generation)
	if err != nil || lease == nil {
		t.Fatalf("claim lease=%#v err=%v", lease, err)
	}
	return lease
}

func readAlertDelivery(t *testing.T, fixture alertDeliveryFixture, deliveryID string) DeliveryRecord {
	t.Helper()
	record, err := fixture.store.ReadNotificationDelivery(context.Background(), fixture.admin, deliveryID)
	if err != nil {
		t.Fatal(err)
	}
	return record
}

func completeAlertRetry(t *testing.T, fixture alertDeliveryFixture, lease *DeliveryLease) DeliveryRecord {
	t.Helper()
	record, err := fixture.store.CompleteNotificationDelivery(context.Background(), DeliveryCompletion{
		ID: lease.ID, ExpectedAttempt: lease.Attempts, LeaseToken: lease.LeaseToken, SafeCode: "notification_connection_failed",
	})
	if err != nil {
		t.Fatal(err)
	}
	return record
}

func TestAutomaticDeliveryRetryRevalidatesMuteDestinationTransitionAndMaintenance(t *testing.T) {
	t.Run("mute suppresses retry while condition remains firing", func(t *testing.T) {
		fixture := newAlertDeliveryFixture(t)
		lease := claimAlertDelivery(t, fixture)
		expires := fixture.clock.Now().Add(time.Hour).UnixMilli()
		muted, err := fixture.store.MuteAlertIncident(context.Background(), fixture.admin, *fixture.fired.IncidentID, "81000000-0000-4000-8000-000000000001", strings.Repeat("1", 64), "receiver maintenance", expires)
		if err != nil || !muted.NotificationMayBeInFlight {
			t.Fatalf("mute=%#v err=%v", muted, err)
		}
		record := completeAlertRetry(t, fixture, lease)
		if record.State != "muted" || record.Status != "suppressed" || record.NextAttemptMS == nil || *record.NextAttemptMS != expires || !record.AcceptedUnknown {
			t.Fatalf("muted completion=%#v", record)
		}
		state, err := fixture.store.ReadAlertIncidentState(context.Background(), fixture.admin.DeploymentID, *fixture.fired.IncidentID)
		if err != nil || state.Condition != alerts.StateFiring || state.Delivery.Muted != 1 || len(state.Deliveries) != 1 || state.Deliveries[0].Status != "suppressed" {
			t.Fatalf("alert state=%#v err=%v", state, err)
		}
	})

	t.Run("destination edit suppresses the old revision", func(t *testing.T) {
		fixture := newAlertDeliveryFixture(t)
		lease := claimAlertDelivery(t, fixture)
		if _, err := fixture.store.db.Exec(`UPDATE destinations SET version=2,secret_ref=? WHERE deployment_id=? AND id=?`, strings.Repeat("b", 64), fixture.admin.DeploymentID, fixture.destinationID); err != nil {
			t.Fatal(err)
		}
		record := completeAlertRetry(t, fixture, lease)
		if record.State != "superseded_before_delivery" || record.Status != "suppressed" || record.NextAttemptMS != nil || record.LastErrorCode == nil || *record.LastErrorCode != "destination_superseded" {
			t.Fatalf("destination edit completion=%#v", record)
		}
		state, err := fixture.store.ReadAlertIncidentState(context.Background(), fixture.admin.DeploymentID, *fixture.fired.IncidentID)
		if err != nil || state.Condition != alerts.StateFiring {
			t.Fatalf("destination edit alert state=%#v err=%v", state, err)
		}
	})

	t.Run("newer transition suppresses the old retry", func(t *testing.T) {
		fixture := newAlertDeliveryFixture(t)
		lease := claimAlertDelivery(t, fixture)
		if _, err := fixture.store.db.Exec(`UPDATE alert_instances SET state='RESOLVED',transition_seq=transition_seq+1,resolved_ms=? WHERE deployment_id=? AND id=?`, fixture.clock.Now().UnixMilli(), fixture.admin.DeploymentID, fixture.fired.InstanceID); err != nil {
			t.Fatal(err)
		}
		record := completeAlertRetry(t, fixture, lease)
		if record.State != "superseded_before_delivery" || record.Status != "suppressed" || record.LastErrorCode == nil || *record.LastErrorCode != "newer_alert_state" {
			t.Fatalf("newer transition completion=%#v", record)
		}
	})

	t.Run("maintenance suppresses the retry until the window ends", func(t *testing.T) {
		fixture := newAlertDeliveryFixture(t)
		lease := claimAlertDelivery(t, fixture)
		expires := fixture.clock.Now().Add(time.Hour).UnixMilli()
		windowID := "82000000-0000-4000-8000-000000000001"
		if _, err := fixture.store.db.Exec(`INSERT INTO maintenance_windows(id,deployment_id,scope_json,reason,starts_ms,expires_ms,created_by,created_ms) VALUES(?,?,?,'receiver maintenance',?,?,?,?)`, windowID, fixture.admin.DeploymentID, `{"scope_kind":"host","scope_id":"`+fixture.rule.Definition.ScopeID+`"}`, fixture.clock.Now().Add(-time.Second).UnixMilli(), expires, fixture.admin.User.ID, fixture.clock.Now().UnixMilli()); err != nil {
			t.Fatal(err)
		}
		record := completeAlertRetry(t, fixture, lease)
		if record.State != "muted" || record.Status != "suppressed" || record.NextAttemptMS == nil || *record.NextAttemptMS != expires || record.LastErrorCode == nil || *record.LastErrorCode != "maintenance_suppressed" {
			t.Fatalf("maintenance completion=%#v", record)
		}
	})
}

func TestAutomaticDeliveryTerminalFailureAndExpiryAffectMonitorHealth(t *testing.T) {
	t.Run("permanent receiver failure is terminal", func(t *testing.T) {
		fixture := newAlertDeliveryFixture(t)
		lease := claimAlertDelivery(t, fixture)
		record, err := fixture.store.CompleteNotificationDelivery(context.Background(), DeliveryCompletion{ID: lease.ID, ExpectedAttempt: lease.Attempts, LeaseToken: lease.LeaseToken, Permanent: true, SafeCode: "webhook_receiver_rejected"})
		if err != nil || record.State != "failed" || record.Status != "terminal_failure" || record.NextAttemptMS != nil {
			t.Fatalf("terminal completion=%#v err=%v", record, err)
		}
		plan, err := fixture.store.ReadAlertRuntimePlan(context.Background(), fixture.admin.DeploymentID, fixture.admin.Generation)
		if err != nil || !plan.Monitor.FinalDeliveryFailed {
			t.Fatalf("monitor plan=%#v err=%v", plan.Monitor, err)
		}
	})

	t.Run("expired delivery is terminal and contributes to health", func(t *testing.T) {
		fixture := newAlertDeliveryFixture(t)
		expires := fixture.clock.Now().Add(time.Second).UnixMilli()
		if _, err := fixture.store.db.Exec(`UPDATE outbox SET expires_ms=? WHERE deployment_id=? AND instance_id=?`, expires, fixture.admin.DeploymentID, fixture.fired.InstanceID); err != nil {
			t.Fatal(err)
		}
		fixture.clock.now = time.UnixMilli(expires + 1)
		lease, err := fixture.store.ClaimNotificationDelivery(context.Background(), fixture.admin.DeploymentID, fixture.admin.Generation)
		if err != nil || lease != nil {
			t.Fatalf("expired claim=%#v err=%v", lease, err)
		}
		record := readAlertDelivery(t, fixture, mustOutboxID(t, fixture))
		if record.State != "expired" || record.Status != "terminal_failure" || record.LastErrorCode == nil || *record.LastErrorCode != "delivery_expired" {
			t.Fatalf("expired record=%#v", record)
		}
		plan, err := fixture.store.ReadAlertRuntimePlan(context.Background(), fixture.admin.DeploymentID, fixture.admin.Generation)
		if err != nil || !plan.Monitor.FinalDeliveryFailed {
			t.Fatalf("expired monitor plan=%#v err=%v", plan.Monitor, err)
		}
	})
}

func TestAutomaticDeliveryRetryEventuallySucceedsAndPreservesIdempotency(t *testing.T) {
	fixture := newAlertDeliveryFixture(t)
	lease := claimAlertDelivery(t, fixture)
	first := completeAlertRetry(t, fixture, lease)
	if first.State != "failed" || first.Status != "retrying" || first.NextAttemptMS == nil {
		t.Fatalf("first retry=%#v", first)
	}
	key := first.IdempotencyKey
	fixture.clock.now = time.UnixMilli(*first.NextAttemptMS)
	second := claimAlertDelivery(t, fixture)
	if second.IdempotencyKey != key || second.Attempts != 2 || second.State != "leased" {
		t.Fatalf("second lease=%#v", second)
	}
	ack := fixture.clock.Now().UnixMilli()
	final, err := fixture.store.CompleteNotificationDelivery(context.Background(), DeliveryCompletion{ID: second.ID, ExpectedAttempt: second.Attempts, LeaseToken: second.LeaseToken, Succeeded: true, ReceiverACKMS: &ack})
	if err != nil || final.State != "sent" || final.Status != "acknowledged" || final.ReceiverACKMS == nil || *final.ReceiverACKMS != ack || final.IdempotencyKey != key {
		t.Fatalf("final delivery=%#v err=%v", final, err)
	}
}

func TestAutomaticDeliveryLeaseContentionAndRestartRecoveryAreBounded(t *testing.T) {
	t.Run("already leased incident destination is deferred", func(t *testing.T) {
		fixture := newAlertDeliveryFixture(t)
		first := claimAlertDelivery(t, fixture)
		secondID := mustTestUUID(t)
		payload := `{"schema_version":"alert-notification-1","state":"firing"}`
		if _, err := fixture.store.db.Exec(`INSERT INTO outbox(id,deployment_id,instance_id,transition_seq,destination_id,destination_revision,destination_secret_ref,rule_revision,incident_generation,idempotency_key,payload_json,state,attempts,next_attempt_ms,expires_ms,created_ms) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,0,?,?,?)`, secondID, fixture.admin.DeploymentID, fixture.fired.InstanceID, fixture.fired.Snapshot.TransitionSeq, fixture.destinationID, 1, fixture.secretRef, fixture.rule.Revision, 1, "contention-"+secondID, payload, "pending", fixture.clock.Now().UnixMilli(), fixture.clock.Now().Add(time.Hour).UnixMilli(), fixture.clock.Now().UnixMilli()+1); err != nil {
			t.Fatal(err)
		}
		deferred, err := fixture.store.ClaimNotificationDelivery(context.Background(), fixture.admin.DeploymentID, fixture.admin.Generation)
		if err != nil || deferred != nil {
			t.Fatalf("contention claim=%#v err=%v", deferred, err)
		}
		record := readAlertDelivery(t, fixture, secondID)
		if record.State != "pending" || record.LastErrorCode == nil || *record.LastErrorCode != "delivery_in_flight" || record.NextAttemptMS == nil || *record.NextAttemptMS <= fixture.clock.Now().UnixMilli() || first.State != "leased" {
			t.Fatalf("contention record=%#v first=%#v", record, first)
		}
	})

	t.Run("expired lease is recovered after reopening the store", func(t *testing.T) {
		fixture := newAlertDeliveryFixture(t)
		first := claimAlertDelivery(t, fixture)
		var sequence int
		var databaseName, databasePath string
		if err := fixture.store.db.QueryRow(`PRAGMA database_list`).Scan(&sequence, &databaseName, &databasePath); err != nil {
			t.Fatal(err)
		}
		if err := fixture.store.Close(); err != nil {
			t.Fatal(err)
		}
		fixture.clock.now = time.UnixMilli(*first.LeaseUntilMS + 1)
		restarted, err := OpenExisting(filepath.Clean(databasePath), fixture.clock)
		if err != nil {
			t.Fatal(err)
		}
		defer restarted.Close()
		recovered, err := restarted.ClaimNotificationDelivery(context.Background(), fixture.admin.DeploymentID, fixture.admin.Generation)
		if err != nil || recovered == nil || recovered.Attempts != 2 || !recovered.AcceptedUnknown {
			t.Fatalf("recovered=%#v err=%v", recovered, err)
		}
		ack := fixture.clock.Now().UnixMilli()
		final, err := restarted.CompleteNotificationDelivery(context.Background(), DeliveryCompletion{ID: recovered.ID, ExpectedAttempt: recovered.Attempts, LeaseToken: recovered.LeaseToken, Succeeded: true, ReceiverACKMS: &ack})
		if err != nil || final.Status != "acknowledged" || final.State != "sent" {
			t.Fatalf("recovered completion=%#v err=%v", final, err)
		}
	})
}

func TestLegacyNotificationOutboxMigrationNeverGuessesEditedSecrets(t *testing.T) {
	databasePath := filepath.Join(t.TempDir(), "legacy.sqlite3")
	db, err := sql.Open("sqlite3", databasePath)
	if err != nil {
		t.Fatal(err)
	}
	db.SetMaxOpenConns(1)
	defer db.Close()
	legacySchema := []string{
		`CREATE TABLE destinations(id TEXT, deployment_id TEXT, type TEXT, display_name TEXT, secret_ref TEXT, configuration_json TEXT, version INTEGER, disabled_ms INTEGER)`,
		`CREATE TABLE outbox(id TEXT, deployment_id TEXT, instance_id TEXT, transition_seq INTEGER, destination_id TEXT, destination_revision INTEGER, rule_revision INTEGER, incident_generation INTEGER, idempotency_key TEXT, payload_json TEXT, state TEXT, attempts INTEGER, lease_until_ms INTEGER, next_attempt_ms INTEGER, last_error_code TEXT, expires_ms INTEGER, created_ms INTEGER)`,
	}
	for _, statement := range legacySchema {
		if _, err := db.Exec(statement); err != nil {
			t.Fatal(err)
		}
	}
	deploymentID := "83000000-0000-4000-8000-000000000001"
	exactDestination := "83000000-0000-4000-8000-000000000002"
	editedDestination := "83000000-0000-4000-8000-000000000003"
	missingDestination := "83000000-0000-4000-8000-000000000004"
	exactSecret := strings.Repeat("a", 64)
	if _, err := db.Exec(`INSERT INTO destinations(id,deployment_id,type,display_name,secret_ref,configuration_json,version) VALUES(?,?, 'webhook','Exact',?,'{}',1),(?,?, 'webhook','Edited',?,'{}',2)`, exactDestination, deploymentID, exactSecret, editedDestination, deploymentID, strings.Repeat("b", 64)); err != nil {
		t.Fatal(err)
	}
	now := int64(1_800_000_000_000)
	rows := []struct {
		id, destination string
		revision        int
		state           string
	}{
		{"83000000-0000-4000-8000-000000000011", exactDestination, 1, "pending"},
		{"83000000-0000-4000-8000-000000000012", editedDestination, 1, "pending"},
		{"83000000-0000-4000-8000-000000000013", missingDestination, 1, "pending"},
		{"83000000-0000-4000-8000-000000000014", exactDestination, 1, "leased"},
	}
	for _, row := range rows {
		leaseUntil := any(nil)
		if row.state == "leased" {
			leaseUntil = now + 30_000
		}
		if _, err := db.Exec(`INSERT INTO outbox(id,deployment_id,instance_id,transition_seq,destination_id,destination_revision,rule_revision,incident_generation,idempotency_key,payload_json,state,attempts,lease_until_ms,next_attempt_ms,expires_ms,created_ms) VALUES(?,?,NULL,NULL,?,?,NULL,1,?,'{}',?,?,?,NULL,?,?)`, row.id, deploymentID, row.destination, row.revision, row.id+"-key", row.state, 0, leaseUntil, now+86_400_000, now); err != nil {
			t.Fatal(err)
		}
	}
	legacy := &Store{db: db, clock: &testClock{now: time.UnixMilli(now)}}
	if err := legacy.ensureNotificationStorage(); err != nil {
		t.Fatal(err)
	}
	var ref, state, errorCode string
	if err := db.QueryRow(`SELECT COALESCE(destination_secret_ref,''),state,COALESCE(last_error_code,'') FROM outbox WHERE id=?`, rows[0].id).Scan(&ref, &state, &errorCode); err != nil {
		t.Fatal(err)
	}
	if ref != exactSecret || state != "pending" || errorCode != "" {
		t.Fatalf("exact legacy row ref=%q state=%q error=%q", ref, state, errorCode)
	}
	for _, id := range []string{rows[1].id, rows[2].id} {
		if err := db.QueryRow(`SELECT state,COALESCE(destination_secret_ref,''),COALESCE(last_error_code,'') FROM outbox WHERE id=?`, id).Scan(&state, &ref, &errorCode); err != nil {
			t.Fatal(err)
		}
		if state != "superseded_before_delivery" || ref != "" || errorCode != "legacy_secret_reference_unavailable" {
			t.Fatalf("unrecoverable legacy row id=%s ref=%q state=%q error=%q", id, ref, state, errorCode)
		}
	}
	if err := db.QueryRow(`SELECT state,COALESCE(destination_secret_ref,''),COALESCE(last_error_code,''),accepted_unknown FROM outbox WHERE id=?`, rows[3].id).Scan(&state, &ref, &errorCode, new(int)); err != nil {
		t.Fatal(err)
	}
	if state != "failed" || ref != exactSecret || errorCode != "receiver_ack_unknown" {
		t.Fatalf("leased legacy row ref=%q state=%q error=%q", ref, state, errorCode)
	}
}

func mustOutboxID(t *testing.T, fixture alertDeliveryFixture) string {
	t.Helper()
	var id string
	if err := fixture.store.db.QueryRow(`SELECT id FROM outbox WHERE deployment_id=? AND instance_id=? LIMIT 1`, fixture.admin.DeploymentID, fixture.fired.InstanceID).Scan(&id); err != nil {
		t.Fatal(err)
	}
	return id
}
