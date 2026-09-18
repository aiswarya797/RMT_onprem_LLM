//go:build sqlite_dbstat

package store

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"testing"
)

// TestCalibrateAlertLedgerDBStat is an opt-in bounded witness for the three
// alert write envelopes. It does not enable production admission or guess a
// reservation: the logged, page-rounded class deltas are pinned separately
// after review of the SQLite version/source ID.
func TestCalibrateAlertLedgerDBStat(t *testing.T) {
	if os.Getenv("RMT_RUN_ALERT_CALIBRATION") != "1" {
		t.Skip("set RMT_RUN_ALERT_CALIBRATION=1 for the bounded alert dbstat witness")
	}
	t.Run("transition_churn_1000", calibrateAlertTransitionChurn)
	t.Run("snapshot_cursor_64_rules_single_transaction_peak", calibrateAlertSnapshotCursor)
	t.Run("firing_and_resolution_256_by_16", calibrateAlertFiringResolution)
}

func calibrateAlertSnapshotCursor(t *testing.T) {
	st, clock, admin := newEnrollmentStore(t)
	_, instanceID := insertAlertCalibrationFoundation(t, st, admin, 0)
	now := clock.Now().UnixMilli()
	checkpointAlertCalibration(t, st)
	before := alertCalibrationAllocation(t, context.Background(), st)
	cursors := make(map[string]persistedAlertCursor, ruleLimit)
	for index := 1; index <= ruleLimit; index++ {
		ruleID := fmt.Sprintf("65000000-0000-4000-8000-%012x", index)
		cursors[ruleID] = persistedAlertCursor{
			RuleVersion:       1,
			ScopeFingerprint:  strings.Repeat("b", 64),
			InputOrdinal:      1,
			ObservedThroughMS: now,
			InputSHA256:       strings.Repeat("c", 64),
			InstanceID:        instanceID,
		}
	}
	raw, err := json.Marshal(cursors)
	if err != nil {
		t.Fatal(err)
	}
	tx, err := st.db.Begin()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec(`UPDATE alert_instances SET last_eval_ms=?,data_state='valid' WHERE deployment_id=? AND id=?`, now+1, admin.DeploymentID, instanceID); err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec(`UPDATE maintenance SET evaluator_cursor_json=json_set(evaluator_cursor_json,'$.alerts_v1',json(?)),updated_ms=? WHERE deployment_id=?`, string(raw), now+1, admin.DeploymentID); err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
	checkpointAlertCalibration(t, st)
	after := alertCalibrationAllocation(t, context.Background(), st)
	logAlertCalibrationDelta(t, st, "snapshot_cursor_initial_64_rules", 1, before, after)
	maxIncident, maxMetadata, maxFile := after.Incident-before.Incident, after.Metadata-before.Metadata, after.File-before.File

	for iteration := int64(2); iteration <= 65; iteration++ {
		first := "65000000-0000-4000-8000-000000000001"
		cursor := cursors[first]
		cursor.InputOrdinal = iteration
		cursor.ObservedThroughMS = now + iteration
		cursor.InputSHA256 = fmt.Sprintf("%064x", iteration)
		cursors[first] = cursor
		raw, err = json.Marshal(cursors)
		if err != nil {
			t.Fatal(err)
		}
		before = after
		tx, err = st.db.Begin()
		if err != nil {
			t.Fatal(err)
		}
		if _, err := tx.Exec(`UPDATE alert_instances SET last_eval_ms=?,data_state='valid' WHERE deployment_id=? AND id=?`, now+iteration, admin.DeploymentID, instanceID); err != nil {
			tx.Rollback()
			t.Fatal(err)
		}
		if _, err := tx.Exec(`UPDATE maintenance SET evaluator_cursor_json=json_set(evaluator_cursor_json,'$.alerts_v1',json(?)),updated_ms=? WHERE deployment_id=?`, string(raw), now+iteration, admin.DeploymentID); err != nil {
			tx.Rollback()
			t.Fatal(err)
		}
		if err := tx.Commit(); err != nil {
			t.Fatal(err)
		}
		checkpointAlertCalibration(t, st)
		after = alertCalibrationAllocation(t, context.Background(), st)
		if delta := after.Incident - before.Incident; delta > maxIncident {
			maxIncident = delta
		}
		if delta := after.Metadata - before.Metadata; delta > maxMetadata {
			maxMetadata = delta
		}
		if delta := after.File - before.File; delta > maxFile {
			maxFile = delta
		}
	}
	t.Logf("ALERT_DBSTAT_SINGLE_TX_PEAK name=snapshot_cursor_64_rules transactions=65 incident_delta=%d metadata_delta=%d file_delta=%d incident_reservation=%d metadata_reservation=%d live_reservation=%d", maxIncident, maxMetadata, maxFile, pageCeiling(maxIncident, 4096), pageCeiling(maxMetadata, 4096), pageCeiling(maxFile, 4096))
}

func calibrateAlertTransitionChurn(t *testing.T) {
	st, clock, admin := newEnrollmentStore(t)
	ctx := context.Background()
	ruleID, instanceID := insertAlertCalibrationFoundation(t, st, admin, 0)
	checkpointAlertCalibration(t, st)
	before := alertCalibrationAllocation(t, ctx, st)
	now := clock.Now().UnixMilli()
	tx, err := st.db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	statement, err := tx.Prepare(`INSERT INTO alert_transitions(deployment_id,instance_id,transition_seq,previous_state,new_state,event_ms,evidence_hash) VALUES(?,?,?,?,?,?,?)`)
	if err != nil {
		t.Fatal(err)
	}
	states := []string{"PENDING", "FIRING", "RECOVERING", "FIRING"}
	previous := "OK"
	for sequence := 1; sequence <= 1000; sequence++ {
		next := states[(sequence-1)%len(states)]
		if _, err := statement.Exec(admin.DeploymentID, instanceID, sequence, previous, next, now+int64(sequence), strings.Repeat("a", 64)); err != nil {
			statement.Close()
			tx.Rollback()
			t.Fatal(err)
		}
		previous = next
	}
	if err := statement.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec(`UPDATE alert_instances SET state=?,last_eval_ms=?,transition_seq=1000 WHERE deployment_id=? AND id=?`, previous, now+1000, admin.DeploymentID, instanceID); err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec(`UPDATE maintenance SET evaluator_cursor_json=json_set(evaluator_cursor_json,'$.alerts_v1',json_object(? ,json_object('rule_version',1,'scope_fingerprint',?,'input_ordinal',1000,'observed_through_ms',?,'input_sha256',?,'instance_id',?,'transition_seq',1000))) WHERE deployment_id=?`, ruleID, strings.Repeat("b", 64), now+1000, strings.Repeat("c", 64), instanceID, admin.DeploymentID); err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
	checkpointAlertCalibration(t, st)
	after := alertCalibrationAllocation(t, ctx, st)
	logAlertCalibrationDelta(t, st, "transition_churn", 1000, before, after)
}

func calibrateAlertFiringResolution(t *testing.T) {
	st, clock, admin := newEnrollmentStore(t)
	ctx := context.Background()
	ruleID, _ := insertAlertCalibrationFoundation(t, st, admin, 16)
	checkpointAlertCalibration(t, st)
	before := alertCalibrationAllocation(t, ctx, st)
	now := clock.Now().UnixMilli()
	payload := []byte(`{"schema_revision":"alert-trigger-capsule-1","padding":"` + strings.Repeat("p", 65536-len(`{"schema_revision":"alert-trigger-capsule-1","padding":""}`)) + `"}`)
	if len(payload) != 65536 {
		t.Fatalf("payload bytes=%d", len(payload))
	}
	notificationPayload := `{"schema_version":"alert-notification-1","padding":"` + strings.Repeat("n", 65536-len(`{"schema_version":"alert-notification-1","padding":""}`)) + `"}`
	if len(notificationPayload) != 65536 {
		t.Fatalf("notification payload bytes=%d", len(notificationPayload))
	}
	tx, err := st.db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	for index := 1; index <= 256; index++ {
		instanceID := fmt.Sprintf("61000000-0000-4000-8000-%012x", index)
		incidentID := fmt.Sprintf("62000000-0000-4000-8000-%012x", index)
		if _, err := tx.Exec(`INSERT INTO alert_instances(id,deployment_id,rule_id,rule_version,scope_fingerprint,active_generation,state,data_state,dwell_ms,last_eval_ms,last_valid_ms,opened_ms,transition_seq) VALUES(?,?,?,?,?,?,'FIRING','valid',0,?,?,?,1)`, instanceID, admin.DeploymentID, ruleID, 1, strings.Repeat("b", 64), index, now+int64(index), now+int64(index), now+int64(index)); err != nil {
			t.Fatal(err)
		}
		if _, err := tx.Exec(`INSERT INTO alert_transitions(deployment_id,instance_id,transition_seq,previous_state,new_state,event_ms,evidence_hash) VALUES(?,?,1,'PENDING','FIRING',?,?)`, admin.DeploymentID, instanceID, now+int64(index), strings.Repeat("c", 64)); err != nil {
			t.Fatal(err)
		}
		if _, err := tx.Exec(`INSERT INTO incidents(id,deployment_id,target_scope_json,title,origin,start_ms,alert_instance_id,workflow_state,version,created_ms,updated_ms) VALUES(?,?,?,'Alert calibration','alert',?,?,'open',1,?,?)`, incidentID, admin.DeploymentID, `{"scope_id":"`+admin.DeploymentID+`"}`, now+int64(index), instanceID, now, now); err != nil {
			t.Fatal(err)
		}
		if _, err := tx.Exec(`INSERT INTO incident_capsules(deployment_id,incident_id,schema_revision,card_revision,rule_revision,payload,payload_sha256,physical_reservation_bytes,evidence_state) VALUES(?,?, 'alert-trigger-capsule-1','ec01-ec07-mac-1',1,?,?,65536,'complete')`, admin.DeploymentID, incidentID, payload, strings.Repeat("d", 64)); err != nil {
			t.Fatal(err)
		}
		for destination := 1; destination <= 16; destination++ {
			outboxID := fmt.Sprintf("63000000-%04x-4000-8000-%012x", destination, index)
			destinationID := fmt.Sprintf("60000000-0000-4000-8000-%012x", destination)
			if _, err := tx.Exec(`INSERT INTO outbox(id,deployment_id,instance_id,transition_seq,destination_id,destination_revision,rule_revision,incident_generation,idempotency_key,payload_json,state,attempts,next_attempt_ms,expires_ms,created_ms) VALUES(?,?,?,?,?,1,1,?,?,?,'pending',0,?,?,?)`, outboxID, admin.DeploymentID, instanceID, 1, destinationID, index, fmt.Sprintf("alert:%s:1:%s", instanceID, destinationID), notificationPayload, now, now+86400000, now); err != nil {
				t.Fatal(err)
			}
		}
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
	checkpointAlertCalibration(t, st)
	fired := alertCalibrationAllocation(t, ctx, st)
	logAlertCalibrationDelta(t, st, "firing_16_destinations", 256, before, fired)

	tx, err = st.db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	for index := 1; index <= 256; index++ {
		instanceID := fmt.Sprintf("61000000-0000-4000-8000-%012x", index)
		incidentID := fmt.Sprintf("62000000-0000-4000-8000-%012x", index)
		if _, err := tx.Exec(`UPDATE alert_instances SET state='RESOLVED',last_eval_ms=?,resolved_ms=?,transition_seq=2 WHERE deployment_id=? AND id=?`, now+1000+int64(index), now+1000+int64(index), admin.DeploymentID, instanceID); err != nil {
			t.Fatal(err)
		}
		if _, err := tx.Exec(`INSERT INTO alert_transitions(deployment_id,instance_id,transition_seq,previous_state,new_state,event_ms,evidence_hash) VALUES(?,?,2,'RECOVERING','RESOLVED',?,?)`, admin.DeploymentID, instanceID, now+1000+int64(index), strings.Repeat("e", 64)); err != nil {
			t.Fatal(err)
		}
		if _, err := tx.Exec(`UPDATE incidents SET workflow_state='closed',end_ms=?,updated_ms=? WHERE deployment_id=? AND id=?`, now+1000+int64(index), now+1000+int64(index), admin.DeploymentID, incidentID); err != nil {
			t.Fatal(err)
		}
		if _, err := tx.Exec(`UPDATE incident_capsules SET resolved_ms=?,expires_ms=? WHERE deployment_id=? AND incident_id=?`, now+1000+int64(index), now+int64(90*24*60*60*1000), admin.DeploymentID, incidentID); err != nil {
			t.Fatal(err)
		}
		for destination := 1; destination <= 16; destination++ {
			outboxID := fmt.Sprintf("64000000-%04x-4000-8000-%012x", destination, index)
			destinationID := fmt.Sprintf("60000000-0000-4000-8000-%012x", destination)
			if _, err := tx.Exec(`INSERT INTO outbox(id,deployment_id,instance_id,transition_seq,destination_id,destination_revision,rule_revision,incident_generation,idempotency_key,payload_json,state,attempts,next_attempt_ms,expires_ms,created_ms) VALUES(?,?,?,?,?,1,1,?,?,?,'pending',0,?,?,?)`, outboxID, admin.DeploymentID, instanceID, 2, destinationID, index, fmt.Sprintf("alert:%s:2:%s", instanceID, destinationID), notificationPayload, now, now+86400000, now); err != nil {
				t.Fatal(err)
			}
		}
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
	checkpointAlertCalibration(t, st)
	resolved := alertCalibrationAllocation(t, ctx, st)
	logAlertCalibrationDelta(t, st, "resolution_16_destinations", 256, fired, resolved)
}

type alertAllocation struct {
	Incident int64
	Metadata int64
	File     int64
}

func alertCalibrationAllocation(t *testing.T, ctx context.Context, st *Store) alertAllocation {
	t.Helper()
	tx, err := st.db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	classes, _, err := sqliteClassPages(ctx, tx)
	if err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
	physical, err := st.PhysicalDatabaseAllocation(ctx)
	if err != nil {
		t.Fatal(err)
	}
	return alertAllocation{Incident: classes["incident_ledger"], Metadata: classes["metadata"], File: physical.TotalBytes}
}

func logAlertCalibrationDelta(t *testing.T, st *Store, name string, population int64, before, after alertAllocation) {
	t.Helper()
	var version, sourceID string
	var pageSize int64
	if err := st.db.QueryRow(`SELECT sqlite_version(),sqlite_source_id()`).Scan(&version, &sourceID); err != nil {
		t.Fatal(err)
	}
	if err := st.db.QueryRow(`PRAGMA page_size`).Scan(&pageSize); err != nil {
		t.Fatal(err)
	}
	incidentDelta, metadataDelta, fileDelta := after.Incident-before.Incident, after.Metadata-before.Metadata, after.File-before.File
	incidentPer := pageCeiling((incidentDelta+population-1)/population, pageSize)
	metadataPer := pageCeiling((metadataDelta+population-1)/population, pageSize)
	t.Logf("ALERT_DBSTAT_CALIBRATION name=%s sqlite_version=%s sqlite_source_id=%q page_size=%d population=%d incident_delta=%d metadata_delta=%d file_delta=%d incident_per_envelope=%d metadata_per_envelope=%d", name, version, sourceID, pageSize, population, incidentDelta, metadataDelta, fileDelta, incidentPer, metadataPer)
}

func pageCeiling(value, pageSize int64) int64 {
	if value <= 0 {
		return pageSize
	}
	return ((value + pageSize - 1) / pageSize) * pageSize
}

func checkpointAlertCalibration(t *testing.T, st *Store) {
	t.Helper()
	if _, err := st.db.Exec(`PRAGMA wal_checkpoint(TRUNCATE)`); err != nil {
		t.Fatal(err)
	}
}

func insertAlertCalibrationFoundation(t *testing.T, st *Store, admin SessionRecord, destinations int) (string, string) {
	t.Helper()
	now := st.clock.Now().UnixMilli()
	ruleID := "65000000-0000-4000-8000-000000000001"
	if _, err := st.db.Exec(`INSERT INTO rule_revisions(deployment_id,rule_id,version,scope_json,evaluator_type,threshold_json,enabled,updated_by,created_ms) VALUES(?,?,1,?,'memory_pressure',?,1,?,?)`, admin.DeploymentID, ruleID, `{"scope_id":"`+admin.DeploymentID+`","scope_kind":"deployment","incarnation_policy":"stable_scope"}`, `{"metric_id":null,"request_population":null,"aggregation":null,"threshold":"warning","dwell_ms":30000,"recovery_ms":60000}`, admin.User.ID, now); err != nil {
		t.Fatal(err)
	}
	if _, err := st.db.Exec(`INSERT INTO rules(id,deployment_id,current_version,created_ms,updated_ms) VALUES(?,?,1,?,?)`, ruleID, admin.DeploymentID, now, now); err != nil {
		t.Fatal(err)
	}
	for index := 1; index <= destinations; index++ {
		id := fmt.Sprintf("60000000-0000-4000-8000-%012x", index)
		if _, err := st.db.Exec(`INSERT INTO destinations(id,deployment_id,type,display_name,secret_ref,configuration_json,version,created_ms,updated_ms) VALUES(?,?,'webhook',?,'secret-ref','{}',1,?,?)`, id, admin.DeploymentID, fmt.Sprintf("Destination %d", index), now, now); err != nil {
			t.Fatal(err)
		}
	}
	instanceID := "66000000-0000-4000-8000-000000000001"
	if destinations == 0 {
		if _, err := st.db.Exec(`INSERT INTO alert_instances(id,deployment_id,rule_id,rule_version,scope_fingerprint,active_generation,state,data_state,dwell_ms,last_eval_ms,transition_seq) VALUES(?,?,?,?,?,1,'OK','valid',0,?,0)`, instanceID, admin.DeploymentID, ruleID, 1, strings.Repeat("b", 64), now); err != nil {
			t.Fatal(err)
		}
	}
	return ruleID, instanceID
}
