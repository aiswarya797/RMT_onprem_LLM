package store

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"
)

func TestManualIncidentReceiptSurvivesSourceExpiryAndCapsulePersists(t *testing.T) {
	st, clock, admin := newEnrollmentStore(t)
	ctx := context.Background()
	input := testManualIncidentInput()
	key := "10000000-0000-4000-8000-000000000101"
	hash := strings.Repeat("a", 64)
	created, err := st.CreateManualIncident(ctx, admin, key, hash, input)
	if err != nil {
		t.Fatal(err)
	}
	createdDetail, err := st.ReadIncident(ctx, admin.DeploymentID, created.ID)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := st.db.Exec(`DELETE FROM source_frames WHERE deployment_id=?`, admin.DeploymentID); err != nil {
		t.Fatal(err)
	}
	retry, found, err := st.ReadManualIncidentRetry(ctx, admin, key, hash)
	if err != nil || !found || retry != created {
		t.Fatalf("immutable retry=%#v found=%v err=%v", retry, found, err)
	}
	if _, _, err := st.ReadManualIncidentRetry(ctx, admin, key, strings.Repeat("b", 64)); !errors.Is(err, ErrIncidentConflict) {
		t.Fatalf("changed retry err=%v", err)
	}
	var databaseSequence int
	var databaseName, dbPath string
	if err := st.db.QueryRow(`PRAGMA database_list`).Scan(&databaseSequence, &databaseName, &dbPath); err != nil || dbPath == "" {
		t.Fatalf("database path=%q err=%v", dbPath, err)
	}
	if err := st.Close(); err != nil {
		t.Fatal(err)
	}
	// The new handle opens the same private database to prove the capsule is a
	// durable artifact rather than process memory. The fixture cleanup tolerates
	// the already-closed first handle.
	reopened, err := OpenExisting(dbPath, clock)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = reopened.Close() })
	persisted, err := reopened.ReadIncident(ctx, admin.DeploymentID, created.ID)
	if err != nil || persisted.CapsuleSHA256 != created.CapsuleSHA256 || string(persisted.CapsulePayload) != string(createdDetail.CapsulePayload) {
		t.Fatalf("persisted incident=%#v err=%v", persisted, err)
	}
}

func TestIncidentAndAnnotationPagesAreBoundedStableAndAudited(t *testing.T) {
	st, _, admin := newEnrollmentStore(t)
	ctx := context.Background()
	input := testManualIncidentInput()
	created := make([]IncidentSummaryResult, 0, 3)
	for index := 0; index < 3; index++ {
		input.Title = "Investigation " + string(rune('A'+index))
		item, err := st.CreateManualIncident(ctx, admin, "10000000-0000-4000-8000-00000000011"+string(rune('0'+index)), strings.Repeat(string(rune('c'+index)), 64), input)
		if err != nil {
			t.Fatal(err)
		}
		created = append(created, item)
	}
	first, err := st.ListIncidents(ctx, admin.DeploymentID, "", 2)
	if err != nil || len(first.Items) != 2 || first.NextCursor == nil {
		t.Fatalf("first incident page=%#v err=%v", first, err)
	}
	second, err := st.ListIncidents(ctx, admin.DeploymentID, *first.NextCursor, 2)
	if err != nil || len(second.Items) != 1 || second.NextCursor != nil {
		t.Fatalf("second incident page=%#v err=%v", second, err)
	}

	incidentID := created[0].ID
	notes := make([]AnnotationRecord, 0, 3)
	for index := 0; index < 3; index++ {
		text := "operator note " + string(rune('A'+index))
		note, err := st.CreateIncidentAnnotation(ctx, admin, "20000000-0000-4000-8000-00000000011"+string(rune('0'+index)), strings.Repeat(string(rune('1'+index)), 64), incidentID, input.EndMS+int64(index), text)
		if err != nil {
			t.Fatal(err)
		}
		notes = append(notes, note)
	}
	notePage, err := st.ListIncidentAnnotations(ctx, admin.DeploymentID, incidentID, "", 2)
	if err != nil || len(notePage.Items) != 2 || notePage.NextCursor == nil {
		t.Fatalf("first annotation page=%#v err=%v", notePage, err)
	}
	noteTail, err := st.ListIncidentAnnotations(ctx, admin.DeploymentID, incidentID, *notePage.NextCursor, 2)
	if err != nil || len(noteTail.Items) != 1 || noteTail.NextCursor != nil {
		t.Fatalf("second annotation page=%#v err=%v", noteTail, err)
	}
	edited, err := st.EditIncidentAnnotation(ctx, admin, "30000000-0000-4000-8000-000000000111", strings.Repeat("9", 64), notes[0].ID, 1, "corrected operator note")
	if err != nil || edited.Revision != 2 || edited.EditedMS == nil {
		t.Fatalf("edited=%#v err=%v", edited, err)
	}
	if _, err := st.EditIncidentAnnotation(ctx, admin, "30000000-0000-4000-8000-000000000112", strings.Repeat("8", 64), notes[0].ID, 1, "lost update"); !errors.Is(err, ErrIncidentRevision) {
		t.Fatalf("stale edit err=%v", err)
	}
	createRetry, err := st.CreateIncidentAnnotation(ctx, admin, "20000000-0000-4000-8000-000000000110", strings.Repeat("1", 64), incidentID, input.EndMS, "operator note A")
	if err != nil || createRetry != notes[0] {
		t.Fatalf("annotation create retry=%#v want=%#v err=%v", createRetry, notes[0], err)
	}
	later, err := st.EditIncidentAnnotation(ctx, admin, "30000000-0000-4000-8000-000000000113", strings.Repeat("7", 64), notes[0].ID, 2, "later operator correction")
	if err != nil || later.Revision != 3 {
		t.Fatalf("later annotation edit=%#v err=%v", later, err)
	}
	editRetry, err := st.EditIncidentAnnotation(ctx, admin, "30000000-0000-4000-8000-000000000111", strings.Repeat("9", 64), notes[0].ID, 1, "corrected operator note")
	if err != nil || editRetry.Revision != 2 || editRetry.Text != "corrected operator note" {
		t.Fatalf("annotation edit retry=%#v err=%v", editRetry, err)
	}
	readTx, err := st.db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	current, err := readAnnotationTx(ctx, readTx, admin.DeploymentID, notes[0].ID)
	if commitErr := readTx.Commit(); err == nil && commitErr != nil {
		err = commitErr
	}
	if err != nil || current.Revision != 3 || current.Text != "later operator correction" {
		t.Fatalf("current annotation changed by old retry=%#v err=%v", current, err)
	}
	var auditDetail string
	if err := st.db.QueryRow(`SELECT allowlisted_detail_json FROM audit WHERE deployment_id=? AND action='annotation.edit' AND resource_id=?`, admin.DeploymentID, notes[0].ID).Scan(&auditDetail); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(auditDetail, notes[0].Text) || strings.Contains(auditDetail, edited.Text) || !strings.Contains(auditDetail, "previous_text_sha256") || !strings.Contains(auditDetail, "text_sha256") {
		t.Fatalf("annotation audit detail=%s", auditDetail)
	}
}

func TestManualIncidentAdmissionHonorsProtectedPhysicalLimit(t *testing.T) {
	st, _, admin := newEnrollmentStore(t)
	if _, err := st.db.Exec(`UPDATE quota_classes SET current_physical_bytes=byte_limit WHERE deployment_id=? AND class='incident_ledger'`, admin.DeploymentID); err != nil {
		t.Fatal(err)
	}
	_, err := st.CreateManualIncident(context.Background(), admin, "40000000-0000-4000-8000-000000000111", strings.Repeat("f", 64), testManualIncidentInput())
	if !errors.Is(err, ErrIncidentCapacity) {
		t.Fatalf("capacity admission err=%v", err)
	}
}

func TestIncidentAdmissionExpiresAgedThenOldestResolvedAndKeepsOpenCapsules(t *testing.T) {
	st, clock, admin := newEnrollmentStore(t)
	ctx := context.Background()
	maximum := testManualIncidentInput()
	maximum.CapsulePayload = []byte(`"` + strings.Repeat("x", int(incidentCapsulePayloadLimitBytes)-2) + `"`)

	aged, err := st.CreateManualIncident(ctx, admin, "41000000-0000-4000-8000-000000000101", strings.Repeat("1", 64), maximum)
	if err != nil {
		t.Fatal(err)
	}
	closedState := "closed"
	if _, err := st.UpdateManualIncident(ctx, admin, "41000000-0000-4000-8000-000000000102", strings.Repeat("2", 64), aged.ID, ManualIncidentUpdate{ExpectedRevision: 1, WorkflowState: &closedState}); err != nil {
		t.Fatal(err)
	}
	clock.now = clock.now.Add(incidentResolvedRetention + time.Second)
	// Capacity observations expire independently of evidence retention. Refresh
	// the exact physical snapshot after the synthetic 90-day clock jump before
	// asking the admission path to prune and admit another protected capsule.
	if _, err := st.MeasureAndRecordCapacity(ctx, admin.DeploymentID, clock.Now().UnixMilli(), ExternalCapacityUsage{}); err != nil {
		t.Fatal(err)
	}
	protected := testManualIncidentInput()
	protected.Title = "Protected open investigation"
	protectedRecord, err := st.CreateManualIncident(ctx, admin, "41000000-0000-4000-8000-000000000103", strings.Repeat("3", 64), protected)
	if err != nil {
		t.Fatal(err)
	}
	assertIncidentEvidenceExpired(t, st, admin.DeploymentID, aged.ID, "evidence_expired_age")

	quotaCandidate := maximum
	quotaCandidate.Title = "Oldest resolved quota candidate"
	resolved, err := st.CreateManualIncident(ctx, admin, "41000000-0000-4000-8000-000000000104", strings.Repeat("4", 64), quotaCandidate)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := st.UpdateManualIncident(ctx, admin, "41000000-0000-4000-8000-000000000105", strings.Repeat("5", 64), resolved.ID, ManualIncidentUpdate{ExpectedRevision: 1, WorkflowState: &closedState}); err != nil {
		t.Fatal(err)
	}
	// Use the same atomic physical measurement that production uses. A raw
	// dbstat read cannot clear the conservative pending-write ledger.
	if _, err := st.MeasureAndRecordCapacity(ctx, admin.DeploymentID, clock.Now().UnixMilli(), ExternalCapacityUsage{}); err != nil {
		t.Fatal(err)
	}
	var measured int64
	if err := st.db.QueryRow(`SELECT current_physical_bytes FROM quota_classes WHERE deployment_id=? AND class='incident_ledger'`, admin.DeploymentID).Scan(&measured); err != nil {
		t.Fatal(err)
	}
	current := measured
	minimumLimit := 2 * int64(incidentManualCapsuleAdmissionReservationBytes)
	if current+incidentManualCapsuleAdmissionReservationBytes-1 < minimumLimit {
		current += minimumLimit - (current + incidentManualCapsuleAdmissionReservationBytes - 1)
	}
	limit := current + incidentManualCapsuleAdmissionReservationBytes - 1
	if _, err := st.db.Exec(`UPDATE quota_classes SET byte_limit=?,current_physical_bytes=? WHERE deployment_id=? AND class='incident_ledger'`, limit, current, admin.DeploymentID); err != nil {
		t.Fatal(err)
	}
	incoming := testManualIncidentInput()
	incoming.Title = "Admission after measured prune"
	if _, err := st.CreateManualIncident(ctx, admin, "41000000-0000-4000-8000-000000000106", strings.Repeat("6", 64), incoming); err != nil {
		t.Fatalf("measured prune should make admission fit: %v", err)
	}
	assertIncidentEvidenceExpired(t, st, admin.DeploymentID, resolved.ID, "evidence_expired_quota")
	var protectedPayload int64
	if err := st.db.QueryRow(`SELECT length(payload) FROM incident_capsules WHERE deployment_id=? AND incident_id=?`, admin.DeploymentID, protectedRecord.ID).Scan(&protectedPayload); err != nil || protectedPayload <= 0 {
		t.Fatalf("protected open capsule bytes=%d err=%v", protectedPayload, err)
	}
	for _, reason := range []string{"evidence_expired_age", "evidence_expired_quota"} {
		var losses, audits int64
		if err := st.db.QueryRow(`SELECT loss_count FROM retention_loss_ledger WHERE deployment_id=? AND class='incident_capsule' AND reason=?`, admin.DeploymentID, reason).Scan(&losses); err != nil || losses != 1 {
			t.Fatalf("loss ledger %s count=%d err=%v", reason, losses, err)
		}
		if err := st.db.QueryRow(`SELECT count(*) FROM audit WHERE deployment_id=? AND action='incident.evidence.expire' AND allowlisted_detail_json LIKE ?`, admin.DeploymentID, "%"+reason+"%").Scan(&audits); err != nil || audits != 1 {
			t.Fatalf("expiry audit %s count=%d err=%v", reason, audits, err)
		}
	}
}

func TestIncidentAdmissionChargesCalibratedManualReservationAcrossUnmeasuredBurst(t *testing.T) {
	st, _, admin := newEnrollmentStore(t)
	ctx := context.Background()
	limit := 2 * int64(incidentManualCapsuleAdmissionReservationBytes)
	if _, err := st.db.Exec(`UPDATE quota_classes SET byte_limit=?,current_physical_bytes=0,reserved_physical_bytes=0 WHERE deployment_id=? AND class='incident_ledger'`, limit, admin.DeploymentID); err != nil {
		t.Fatal(err)
	}
	for index := 0; index < 2; index++ {
		input := testManualIncidentInput()
		input.Title = "Calibrated burst " + string(rune('A'+index))
		key := "41500000-0000-4000-8000-00000000010" + string(rune('1'+index))
		if _, err := st.CreateManualIncident(ctx, admin, key, strings.Repeat(string(rune('a'+index)), 64), input); err != nil {
			t.Fatalf("burst admission %d: %v", index, err)
		}
	}
	if _, err := st.CreateManualIncident(ctx, admin, "41500000-0000-4000-8000-000000000103", strings.Repeat("c", 64), testManualIncidentInput()); !errors.Is(err, ErrIncidentCapacity) {
		t.Fatalf("third unmeasured admission err=%v", err)
	}
	tx, err := st.db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	usage, err := readIncidentCapsuleUsageTx(ctx, tx, admin.DeploymentID)
	if rollbackErr := tx.Rollback(); err == nil && rollbackErr != nil {
		err = rollbackErr
	}
	if err != nil || usage.Retained != 2 || usage.Reservations != limit {
		t.Fatalf("calibrated usage=%#v err=%v", usage, err)
	}
	var payloadReservations int64
	if err := st.db.QueryRow(`SELECT sum(physical_reservation_bytes) FROM incident_capsules WHERE deployment_id=?`, admin.DeploymentID).Scan(&payloadReservations); err != nil || payloadReservations != 2*incidentCapsulePayloadReservationBytes {
		t.Fatalf("payload-only row reservations=%d err=%v", payloadReservations, err)
	}
}

func TestIncidentResolutionEnforcesResolvedCapsuleLimit(t *testing.T) {
	st, clock, admin := newEnrollmentStore(t)
	ctx := context.Background()
	now := clock.Now().UnixMilli()
	if _, err := st.db.Exec(`WITH RECURSIVE n(value) AS (SELECT 1 UNION ALL SELECT value+1 FROM n WHERE value<=?) INSERT INTO incidents(id,deployment_id,target_scope_json,title,origin,start_ms,end_ms,workflow_state,version,created_ms,updated_ms) SELECT printf('42000000-0000-4000-8000-%012d',value),?,json_object('kind','host','id',printf('43000000-0000-4000-8000-%012d',value)),'resolved fixture','manual',value,value+300000,'closed',1,?,? FROM n`, incidentResolvedCapsuleLimit, admin.DeploymentID, now, now); err != nil {
		t.Fatal(err)
	}
	if _, err := st.db.Exec(`INSERT INTO incident_capsules(deployment_id,incident_id,schema_revision,card_revision,payload,payload_sha256,physical_reservation_bytes,evidence_state,expires_ms,resolved_ms) SELECT deployment_id,id,'incident-capsule-1','ec01-ec07-mac-1',CAST('{}' AS BLOB),? ,1,'partial',?,start_ms FROM incidents WHERE deployment_id=? AND title='resolved fixture'`, strings.Repeat("f", 64), now+incidentResolvedRetention.Milliseconds(), admin.DeploymentID); err != nil {
		t.Fatal(err)
	}
	countOnlyLimit := (incidentResolvedCapsuleLimit + 1) * int64(incidentManualCapsuleAdmissionReservationBytes)
	if _, err := st.db.Exec(`UPDATE quota_classes SET byte_limit=?,current_physical_bytes=0,reserved_physical_bytes=0 WHERE deployment_id=? AND class='incident_ledger'`, countOnlyLimit, admin.DeploymentID); err != nil {
		t.Fatal(err)
	}
	tx, err := st.db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := pruneResolvedIncidentCapsulesTx(ctx, tx, admin.DeploymentID, admin.User.ID, now, 0, false); err != nil {
		tx.Rollback()
		t.Fatal(err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
	var retained, expired int64
	if err := st.db.QueryRow(`SELECT count(*) FROM incident_capsules WHERE deployment_id=? AND payload IS NOT NULL`, admin.DeploymentID).Scan(&retained); err != nil || retained != incidentResolvedCapsuleLimit {
		t.Fatalf("retained resolved capsules=%d err=%v", retained, err)
	}
	if err := st.db.QueryRow(`SELECT count(*) FROM incidents WHERE deployment_id=? AND evidence_expiry_reason='evidence_expired_quota'`, admin.DeploymentID).Scan(&expired); err != nil || expired != 1 {
		t.Fatalf("quota-expired resolved capsules=%d err=%v", expired, err)
	}
}

func TestManualIncidentMetadataUpdateIsCASAuditedIdempotentAndKeepsCapsuleImmutable(t *testing.T) {
	st, clock, admin := newEnrollmentStore(t)
	ctx := context.Background()
	created, err := st.CreateManualIncident(ctx, admin, "50000000-0000-4000-8000-000000000101", strings.Repeat("a", 64), testManualIncidentInput())
	if err != nil {
		t.Fatal(err)
	}
	createdDetail, err := st.ReadIncident(ctx, admin.DeploymentID, created.ID)
	if err != nil {
		t.Fatal(err)
	}
	originalPayload, originalHash := string(createdDetail.CapsulePayload), created.CapsuleSHA256
	closedState := "closed"
	clock.now = clock.now.Add(time.Second)
	closed, err := st.UpdateManualIncident(ctx, admin, "50000000-0000-4000-8000-000000000102", strings.Repeat("b", 64), created.ID, ManualIncidentUpdate{ExpectedRevision: 1, WorkflowState: &closedState})
	if err != nil || closed.Revision != 2 || closed.WorkflowState != "closed" || closed.CapsuleSHA256 != originalHash {
		t.Fatalf("closed=%#v err=%v", closed, err)
	}
	retry, err := st.UpdateManualIncident(ctx, admin, "50000000-0000-4000-8000-000000000102", strings.Repeat("b", 64), created.ID, ManualIncidentUpdate{ExpectedRevision: 1, WorkflowState: &closedState})
	if err != nil || retry.Revision != 2 || retry.WorkflowState != "closed" {
		t.Fatalf("retry=%#v err=%v", retry, err)
	}
	if _, err := st.UpdateManualIncident(ctx, admin, "50000000-0000-4000-8000-000000000102", strings.Repeat("c", 64), created.ID, ManualIncidentUpdate{ExpectedRevision: 1, WorkflowState: &closedState}); !errors.Is(err, ErrIncidentConflict) {
		t.Fatalf("changed idempotency input err=%v", err)
	}
	if _, err := st.UpdateManualIncident(ctx, admin, "50000000-0000-4000-8000-000000000103", strings.Repeat("d", 64), created.ID, ManualIncidentUpdate{ExpectedRevision: 1, Title: stringPointer("stale rename")}); !errors.Is(err, ErrIncidentRevision) {
		t.Fatalf("stale revision err=%v", err)
	}
	openState, renamed := "open", "Reviewed pressure episode"
	clock.now = clock.now.Add(time.Second)
	reopened, err := st.UpdateManualIncident(ctx, admin, "50000000-0000-4000-8000-000000000104", strings.Repeat("e", 64), created.ID, ManualIncidentUpdate{ExpectedRevision: 2, Title: &renamed, WorkflowState: &openState})
	if err != nil || reopened.Revision != 3 || reopened.WorkflowState != "open" || reopened.Title != renamed || reopened.CapsuleSHA256 != originalHash {
		t.Fatalf("reopened=%#v err=%v", reopened, err)
	}
	oldRetry, err := st.UpdateManualIncident(ctx, admin, "50000000-0000-4000-8000-000000000102", strings.Repeat("b", 64), created.ID, ManualIncidentUpdate{ExpectedRevision: 1, WorkflowState: &closedState})
	if err != nil || oldRetry != closed {
		t.Fatalf("retry after later mutation=%#v want=%#v err=%v", oldRetry, closed, err)
	}
	persisted, err := st.ReadIncident(ctx, admin.DeploymentID, created.ID)
	if err != nil || persisted.Revision != 3 || persisted.WorkflowState != "open" || persisted.Title != renamed || string(persisted.CapsulePayload) != originalPayload || persisted.CapsuleSHA256 != originalHash {
		t.Fatalf("current incident changed by old retry=%#v err=%v", persisted, err)
	}
	var resolvedMS *int64
	if err := st.db.QueryRow(`SELECT resolved_ms FROM incident_capsules WHERE deployment_id=? AND incident_id=?`, admin.DeploymentID, created.ID).Scan(&resolvedMS); err != nil || resolvedMS != nil {
		t.Fatalf("resolved_ms=%v err=%v", resolvedMS, err)
	}
	var auditCount, transitionCount int
	if err := st.db.QueryRow(`SELECT count(*) FROM audit WHERE deployment_id=? AND resource_id=? AND action='incident.manual.update'`, admin.DeploymentID, created.ID).Scan(&auditCount); err != nil || auditCount != 2 {
		t.Fatalf("audit count=%d err=%v", auditCount, err)
	}
	if err := st.db.QueryRow(`SELECT count(*) FROM alert_transitions WHERE deployment_id=?`, admin.DeploymentID).Scan(&transitionCount); err != nil || transitionCount != 0 {
		t.Fatalf("alert transitions=%d err=%v", transitionCount, err)
	}
}

func TestManualIncidentReopenRequiresCapacityAndRetainedProtectedCapsule(t *testing.T) {
	st, _, admin := newEnrollmentStore(t)
	ctx := context.Background()
	created, err := st.CreateManualIncident(ctx, admin, "60000000-0000-4000-8000-000000000101", strings.Repeat("1", 64), testManualIncidentInput())
	if err != nil {
		t.Fatal(err)
	}
	closedState := "closed"
	if _, err := st.UpdateManualIncident(ctx, admin, "60000000-0000-4000-8000-000000000102", strings.Repeat("2", 64), created.ID, ManualIncidentUpdate{ExpectedRevision: 1, WorkflowState: &closedState}); err != nil {
		t.Fatal(err)
	}
	if _, err := st.db.Exec(`WITH RECURSIVE n(value) AS (SELECT 1 UNION ALL SELECT value+1 FROM n WHERE value<1000) INSERT INTO incidents(id,deployment_id,target_scope_json,title,origin,start_ms,end_ms,workflow_state,version,created_ms,updated_ms) SELECT printf('20000000-0000-4000-8000-%012d',value),?,json_object('kind','host','id',printf('30000000-0000-4000-8000-%012d',value)),'open fixture','manual',1000,2000,'open',1,1000,1000 FROM n`, admin.DeploymentID); err != nil {
		t.Fatal(err)
	}
	openState := "open"
	if _, err := st.UpdateManualIncident(ctx, admin, "60000000-0000-4000-8000-000000000103", strings.Repeat("3", 64), created.ID, ManualIncidentUpdate{ExpectedRevision: 2, WorkflowState: &openState}); !errors.Is(err, ErrIncidentLimit) {
		t.Fatalf("open-cap reopen err=%v", err)
	}
	if _, err := st.db.Exec(`DELETE FROM incidents WHERE deployment_id=? AND id<>?`, admin.DeploymentID, created.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := st.db.Exec(`UPDATE incidents SET evidence_expiry_reason='evidence_expired_quota' WHERE deployment_id=? AND id=?`, admin.DeploymentID, created.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := st.db.Exec(`UPDATE incident_capsules SET payload=NULL,physical_reservation_bytes=0,evidence_state='evidence_expired_quota' WHERE deployment_id=? AND incident_id=?`, admin.DeploymentID, created.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := st.UpdateManualIncident(ctx, admin, "60000000-0000-4000-8000-000000000104", strings.Repeat("4", 64), created.ID, ManualIncidentUpdate{ExpectedRevision: 2, WorkflowState: &openState}); !errors.Is(err, ErrIncidentState) {
		t.Fatalf("expired-capsule reopen err=%v", err)
	}
	persisted, err := st.ReadIncident(ctx, admin.DeploymentID, created.ID)
	if err != nil || persisted.WorkflowState != "closed" || persisted.Revision != 2 || persisted.CapsulePayload != nil {
		t.Fatalf("persisted=%#v err=%v", persisted, err)
	}
}

func stringPointer(value string) *string { return &value }

func assertIncidentEvidenceExpired(t *testing.T, st *Store, deploymentID, incidentID, reason string) {
	t.Helper()
	var payload []byte
	var evidenceState, expiryReason string
	var reservation int64
	if err := st.db.QueryRow(`SELECT c.payload,c.physical_reservation_bytes,c.evidence_state,i.evidence_expiry_reason FROM incident_capsules c JOIN incidents i ON i.deployment_id=c.deployment_id AND i.id=c.incident_id WHERE c.deployment_id=? AND c.incident_id=?`, deploymentID, incidentID).Scan(&payload, &reservation, &evidenceState, &expiryReason); err != nil {
		t.Fatal(err)
	}
	if payload != nil || reservation != 0 || evidenceState != reason || expiryReason != reason {
		t.Fatalf("expired evidence payload=%v reservation=%d state=%q reason=%q", payload, reservation, evidenceState, expiryReason)
	}
}

func testManualIncidentInput() ManualIncidentInput {
	return ManualIncidentInput{
		Title:                 "Pressure review",
		ScopeJSON:             []byte(`{"kind":"host","id":"10000000-0000-4000-8000-000000000001"}`),
		StartMS:               1_800_000_000_000,
		EndMS:                 1_800_000_300_000,
		CapsuleSchemaRevision: "incident-capsule-1",
		CardRevision:          "ec01-ec07-mac-1",
		CapsulePayload:        []byte(`{"schema_revision":"incident-capsule-1","cards":[]}`),
		EvidenceState:         "partial",
	}
}
