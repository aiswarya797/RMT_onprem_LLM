package store

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"rmt.local/monitor/internal/alerts"
	"rmt.local/monitor/internal/domain"
)

func TestAlertAcknowledgeMuteUnmuteAreDurableAndDoNotChangeCondition(t *testing.T) {
	st, clock, admin := newEnrollmentStore(t)
	rule, fired := createAlertControlFixture(t, st, clock, admin, 2)
	incidentID := *fired.IncidentID

	ackKey := "74000000-0000-4000-8000-000000000001"
	ackHash := strings.Repeat("1", 64)
	ack, err := st.AcknowledgeAlertIncident(context.Background(), admin, incidentID, ackKey, ackHash, fired.Snapshot.TransitionSeq)
	if err != nil || ack.AlertState.Condition != alerts.StateFiring || ack.AlertState.AcknowledgedBy == nil || *ack.AlertState.AcknowledgedBy != admin.User.ID || ack.AlertState.AcknowledgedMS == nil {
		t.Fatalf("ack=%#v err=%v", ack, err)
	}
	ackRetry, err := st.AcknowledgeAlertIncident(context.Background(), admin, incidentID, ackKey, ackHash, fired.Snapshot.TransitionSeq)
	if err != nil || ackRetry.AlertState.AcknowledgedMS == nil || *ackRetry.AlertState.AcknowledgedMS != *ack.AlertState.AcknowledgedMS {
		t.Fatalf("ack retry=%#v err=%v", ackRetry, err)
	}
	if _, err := st.AcknowledgeAlertIncident(context.Background(), admin, incidentID, "74000000-0000-4000-8000-000000000002", strings.Repeat("2", 64), fired.Snapshot.TransitionSeq+1); !errors.Is(err, ErrAlertCursorConflict) {
		t.Fatalf("stale acknowledgement err=%v", err)
	}

	leaseUntil := clock.Now().Add(30 * time.Second).UnixMilli()
	if _, err := st.db.Exec(`UPDATE outbox SET state='leased',lease_until_ms=? WHERE id=(SELECT id FROM outbox WHERE deployment_id=? AND instance_id=? ORDER BY destination_id LIMIT 1)`, leaseUntil, admin.DeploymentID, fired.InstanceID); err != nil {
		t.Fatal(err)
	}
	muteKey := "74000000-0000-4000-8000-000000000003"
	muteHash := strings.Repeat("3", 64)
	expiresMS := clock.Now().Add(time.Hour).UnixMilli()
	muted, err := st.MuteAlertIncident(context.Background(), admin, incidentID, muteKey, muteHash, "planned receiver maintenance", expiresMS)
	if err != nil || !muted.NotificationMayBeInFlight || muted.AlertState.Condition != alerts.StateFiring || muted.AlertState.MutedUntilMS == nil || *muted.AlertState.MutedUntilMS != expiresMS || muted.AlertState.Delivery.Leased != 1 || muted.AlertState.Delivery.Muted != 1 {
		t.Fatalf("muted=%#v err=%v", muted, err)
	}
	var muteAudit string
	if err := st.db.QueryRow(`SELECT allowlisted_detail_json FROM audit WHERE deployment_id=? AND action='alert.mute' AND resource_id=?`, admin.DeploymentID, incidentID).Scan(&muteAudit); err != nil || !strings.Contains(muteAudit, `"reason":"planned receiver maintenance"`) {
		t.Fatalf("mute audit=%q err=%v", muteAudit, err)
	}

	clear := 0.5
	recoveringWrite := alertTestWrite(admin, rule, 3, fired.Snapshot.LastEvalMS+1_000, alerts.Input{DataState: alerts.DataValid, CPU: &alerts.CPUInput{BusyRatio: &clear}})
	recovering, err := st.ApplyAlertEvaluation(context.Background(), recoveringWrite)
	if err != nil || recovering.Snapshot.State != alerts.StateRecovering || recovering.Snapshot.AcknowledgedBy == nil || recovering.Snapshot.MutedUntilMS == nil {
		t.Fatalf("recovering=%#v err=%v", recovering, err)
	}

	unmuteKey := "74000000-0000-4000-8000-000000000004"
	unmuteHash := strings.Repeat("4", 64)
	unmuted, err := st.UnmuteAlertIncident(context.Background(), admin, incidentID, unmuteKey, unmuteHash)
	if err != nil || !unmuted.NotificationMayBeInFlight || unmuted.AlertState.Condition != alerts.StateRecovering || unmuted.AlertState.MutedUntilMS != nil || unmuted.AlertState.AcknowledgedBy == nil || unmuted.AlertState.Delivery.Leased != 1 || unmuted.AlertState.Delivery.Pending != 2 || unmuted.AlertState.Delivery.SupersededBeforeDelivery != 1 || unmuted.AlertState.Delivery.Muted != 0 {
		t.Fatalf("unmuted=%#v err=%v", unmuted, err)
	}
	unmuteRetry, err := st.UnmuteAlertIncident(context.Background(), admin, incidentID, unmuteKey, unmuteHash)
	if err != nil || unmuteRetry.AlertState.TransitionSeq != unmuted.AlertState.TransitionSeq || unmuteRetry.AlertState.Delivery != unmuted.AlertState.Delivery {
		t.Fatalf("unmute retry=%#v err=%v", unmuteRetry, err)
	}
	if _, err := st.UnmuteAlertIncident(context.Background(), admin, incidentID, "74000000-0000-4000-8000-000000000005", strings.Repeat("5", 64)); !errors.Is(err, ErrAlertCursorConflict) {
		t.Fatalf("second unmute err=%v", err)
	}
	var currentSummaries, controlAudits, receipts int
	if err := st.db.QueryRow(`SELECT count(*) FROM outbox WHERE deployment_id=? AND instance_id=? AND transition_seq=?`, admin.DeploymentID, fired.InstanceID, recovering.Snapshot.TransitionSeq).Scan(&currentSummaries); err != nil {
		t.Fatal(err)
	}
	if err := st.db.QueryRow(`SELECT count(*) FROM audit WHERE deployment_id=? AND resource_id=? AND action IN ('alert.acknowledge','alert.mute','alert.unmute')`, admin.DeploymentID, incidentID).Scan(&controlAudits); err != nil {
		t.Fatal(err)
	}
	if err := st.db.QueryRow(`SELECT count(*) FROM idempotency_receipts WHERE deployment_id=? AND actor_user_id=? AND idempotency_key IN (?,?,?)`, admin.DeploymentID, admin.User.ID, ackKey, muteKey, unmuteKey).Scan(&receipts); err != nil {
		t.Fatal(err)
	}
	if currentSummaries != 2 || controlAudits != 3 || receipts != 3 {
		t.Fatalf("summaries=%d audits=%d receipts=%d", currentSummaries, controlAudits, receipts)
	}
}

func TestAlertControlsFenceRoleGenerationAndInvalidMute(t *testing.T) {
	st, clock, admin := newEnrollmentStore(t)
	_, fired := createAlertControlFixture(t, st, clock, admin, 0)
	incidentID := *fired.IncidentID

	if _, err := st.MuteAlertIncident(context.Background(), admin, incidentID, "75000000-0000-4000-8000-000000000001", strings.Repeat("6", 64), "bad\nreason", clock.Now().Add(time.Hour).UnixMilli()); !errors.Is(err, ErrAlertInvalid) {
		t.Fatalf("control-character reason err=%v", err)
	}
	if _, err := st.MuteAlertIncident(context.Background(), admin, incidentID, "75000000-0000-4000-8000-000000000002", strings.Repeat("7", 64), "too long", clock.Now().Add(alertMuteMaximum+time.Millisecond).UnixMilli()); !errors.Is(err, ErrAlertInvalid) {
		t.Fatalf("long mute err=%v", err)
	}
	wrongGeneration := admin
	wrongGeneration.Generation = "76000000-0000-4000-8000-000000000001"
	if _, err := st.AcknowledgeAlertIncident(context.Background(), wrongGeneration, incidentID, "75000000-0000-4000-8000-000000000003", strings.Repeat("8", 64), fired.Snapshot.TransitionSeq); !errors.Is(err, ErrAdmissionFenced) {
		t.Fatalf("wrong generation err=%v", err)
	}
	viewerID, _ := domain.NewUUID()
	now := clock.Now().UnixMilli()
	if _, err := st.db.Exec(`INSERT INTO users(id,deployment_id,name,argon2_hash,role,disabled,trust_generation,historical_restored,version,created_ms,updated_ms) VALUES(?,?,?,'00000000000000000000000000000000','viewer',0,?,0,1,?,?)`, viewerID, admin.DeploymentID, "viewer", admin.Generation, now, now); err != nil {
		t.Fatal(err)
	}
	viewer := admin
	viewer.User = domain.User{ID: viewerID, Revision: 1, Name: "viewer", Role: "viewer", TrustGeneration: admin.Generation}
	if _, err := st.AcknowledgeAlertIncident(context.Background(), viewer, incidentID, "75000000-0000-4000-8000-000000000004", strings.Repeat("9", 64), fired.Snapshot.TransitionSeq); !errors.Is(err, ErrOwnershipMismatch) {
		t.Fatalf("viewer acknowledgement err=%v", err)
	}
	if _, err := st.UnmuteAlertIncident(context.Background(), admin, incidentID, "75000000-0000-4000-8000-000000000005", strings.Repeat("a", 64)); !errors.Is(err, ErrAlertCursorConflict) {
		t.Fatalf("unmute without mute err=%v", err)
	}
	var controls int
	if err := st.db.QueryRow(`SELECT count(*) FROM audit WHERE deployment_id=? AND resource_id=? AND action LIKE 'alert.%'`, admin.DeploymentID, incidentID).Scan(&controls); err != nil || controls != 0 {
		t.Fatalf("unexpected control audits=%d err=%v", controls, err)
	}
}

func TestAlertUnmuteSummarizesSentCurrentStateAndNeverRevivesSupersededRule(t *testing.T) {
	t.Run("sent firing state gets one fresh summary", func(t *testing.T) {
		st, clock, admin := newEnrollmentStore(t)
		_, fired := createAlertControlFixture(t, st, clock, admin, 1)
		incidentID := *fired.IncidentID
		if _, err := st.db.Exec(`UPDATE outbox SET state='sent',next_attempt_ms=NULL WHERE deployment_id=? AND instance_id=?`, admin.DeploymentID, fired.InstanceID); err != nil {
			t.Fatal(err)
		}
		expiresMS := clock.Now().Add(time.Hour).UnixMilli()
		if _, err := st.MuteAlertIncident(context.Background(), admin, incidentID, "78000000-0000-4000-8000-000000000001", strings.Repeat("c", 64), "pause repeats", expiresMS); err != nil {
			t.Fatal(err)
		}
		key := "78000000-0000-4000-8000-000000000002"
		result, err := st.UnmuteAlertIncident(context.Background(), admin, incidentID, key, strings.Repeat("d", 64))
		if err != nil || result.AlertState.Condition != alerts.StateFiring || result.AlertState.Delivery.Sent != 1 || result.AlertState.Delivery.Pending != 1 || result.AlertState.Delivery.Total != 2 {
			t.Fatalf("unmute sent=%#v err=%v", result, err)
		}
		if _, err := st.UnmuteAlertIncident(context.Background(), admin, incidentID, key, strings.Repeat("d", 64)); err != nil {
			t.Fatal(err)
		}
		var summaries int
		if err := st.db.QueryRow(`SELECT count(*) FROM outbox WHERE deployment_id=? AND instance_id=?`, admin.DeploymentID, fired.InstanceID).Scan(&summaries); err != nil || summaries != 2 {
			t.Fatalf("outbox=%d err=%v", summaries, err)
		}
	})

	t.Run("superseded rule keeps every muted delivery terminal", func(t *testing.T) {
		st, clock, admin := newEnrollmentStore(t)
		rule, fired := createAlertControlFixture(t, st, clock, admin, 1)
		incidentID := *fired.IncidentID
		if _, err := st.MuteAlertIncident(context.Background(), admin, incidentID, "78000000-0000-4000-8000-000000000003", strings.Repeat("e", 64), "rule review", clock.Now().Add(time.Hour).UnixMilli()); err != nil {
			t.Fatal(err)
		}
		expected := rule.Revision
		definition := rule.Definition
		definition.ExpectedRevision = &expected
		definition.Enabled = false
		if _, err := st.UpdateRule(context.Background(), admin, rule.ID, "78000000-0000-4000-8000-000000000004", strings.Repeat("f", 64), definition); err != nil {
			t.Fatal(err)
		}
		var startMS, endMS, resolvedMS int64
		if err := st.db.QueryRow(`SELECT i.start_ms,i.end_ms,c.resolved_ms FROM incidents i JOIN incident_capsules c ON c.deployment_id=i.deployment_id AND c.incident_id=i.id WHERE i.deployment_id=? AND i.id=?`, admin.DeploymentID, incidentID).Scan(&startMS, &endMS, &resolvedMS); err != nil || endMS <= startMS || resolvedMS != endMS {
			t.Fatalf("superseded interval start=%d end=%d capsule_resolved=%d err=%v", startMS, endMS, resolvedMS, err)
		}
		result, err := st.UnmuteAlertIncident(context.Background(), admin, incidentID, "78000000-0000-4000-8000-000000000005", strings.Repeat("0", 64))
		if err != nil || result.AlertState.Condition != alerts.StateSuperseded || result.AlertState.Delivery.Pending != 0 || result.AlertState.Delivery.Muted != 0 || result.AlertState.Delivery.SupersededBeforeDelivery != 1 {
			t.Fatalf("unmute superseded=%#v err=%v", result, err)
		}
	})
}

func createAlertControlFixture(t *testing.T, st *Store, clock *enrollmentTestClock, admin SessionRecord, destinations int) (RuleRecord, AlertEvaluationResult) {
	t.Helper()
	hostID := insertAlertTestHost(t, st, admin)
	insertAlertTestCurrentFrame(t, st, admin, hostID, 1)
	for ordinal := 1; ordinal <= destinations; ordinal++ {
		insertAlertTestDestination(t, st, admin, ordinal)
	}
	rule, err := st.CreateRule(context.Background(), admin, "77000000-0000-4000-8000-000000000001", strings.Repeat("b", 64), fixedRuleDefinition(alerts.RuleHeavyCPU, hostID, []byte(`0.9`), 60_000, 60_000))
	if err != nil {
		t.Fatal(err)
	}
	measureAlertTestCapacity(t, st, admin, clock.Now().UnixMilli())
	busy := 0.95
	pendingWrite := alertTestWrite(admin, rule, 1, clock.Now().UnixMilli(), alerts.Input{DataState: alerts.DataValid, CPU: &alerts.CPUInput{BusyRatio: &busy}})
	if pending, err := st.ApplyAlertEvaluation(context.Background(), pendingWrite); err != nil || pending.Snapshot.State != alerts.StatePending {
		t.Fatalf("pending=%#v err=%v", pending, err)
	}
	firingWrite := alertTestWrite(admin, rule, 2, pendingWrite.EventMS+60_000, pendingWrite.Input)
	firingWrite.ElapsedMS, firingWrite.ObservedDwellMS = 60_000, 60_000
	firingWrite.Evidence = alertTestEvidence("host.cpu.busy_ratio", "ratio", firingWrite.EventMS, &busy, nil, nil)
	fired, err := st.ApplyAlertEvaluation(context.Background(), firingWrite)
	if err != nil || fired.IncidentID == nil || fired.Snapshot.State != alerts.StateFiring || fired.OutboxIntents != destinations {
		t.Fatalf("fired=%#v err=%v", fired, err)
	}
	return rule, fired
}
