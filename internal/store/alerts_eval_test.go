package store

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"strings"
	"testing"
	"time"

	"rmt.local/monitor/internal/alerts"
	"rmt.local/monitor/internal/domain"
)

const (
	alertTestBootID   = "71000000-0000-4000-8000-000000000001"
	alertTestSourceID = "71000000-0000-4000-8000-000000000002"
)

func TestAlertEvaluationFiringIsAtomicExactAndCurrentOnly(t *testing.T) {
	st, clock, admin := newEnrollmentStore(t)
	hostID := insertAlertTestHost(t, st, admin)
	insertAlertTestCurrentFrame(t, st, admin, hostID, 1)
	insertAlertTestDestination(t, st, admin, 1)
	definition := fixedRuleDefinition(alerts.RuleHeavyCPU, hostID, json.RawMessage(`0.9`), 60_000, 60_000)
	rule, err := st.CreateRule(context.Background(), admin, "72000000-0000-4000-8000-000000000001", strings.Repeat("a", 64), definition)
	if err != nil {
		t.Fatal(err)
	}
	measureAlertTestCapacity(t, st, admin, clock.Now().UnixMilli())
	ratio := 0.95
	first := alertTestWrite(admin, rule, 1, clock.Now().UnixMilli(), alerts.Input{DataState: alerts.DataValid, CPU: &alerts.CPUInput{BusyRatio: &ratio}})
	first.ObservedDwellMS = 0
	pending, err := st.ApplyAlertEvaluation(context.Background(), first)
	if err != nil || pending.Snapshot.State != alerts.StatePending || pending.Transition == nil {
		t.Fatalf("pending=%#v err=%v", pending, err)
	}
	second := alertTestWrite(admin, rule, 2, first.EventMS+60_000, first.Input)
	second.ElapsedMS, second.ObservedDwellMS = 60_000, 60_000
	second.Evidence = alertTestEvidence("host.cpu.busy_ratio", "ratio", second.EventMS, &ratio, nil, nil)
	second.Evidence.SourceSamples[0].ConfigIDs = nil
	second.Evidence.RequestSampleIDs = nil
	second.Evidence.Gaps = nil
	second.Evidence.UnavailableReasons = nil
	fired, err := st.ApplyAlertEvaluation(context.Background(), second)
	if err != nil || fired.Snapshot.State != alerts.StateFiring || fired.IncidentID == nil || fired.OutboxIntents != 1 {
		t.Fatalf("fired=%#v err=%v", fired, err)
	}
	retry, err := st.ApplyAlertEvaluation(context.Background(), second)
	if err != nil || !retry.Duplicate || retry.IncidentID == nil || *retry.IncidentID != *fired.IncidentID || retry.OutboxIntents != 1 {
		t.Fatalf("retry=%#v err=%v", retry, err)
	}
	var incidents, transitions, outbox int
	if err := st.db.QueryRow(`SELECT count(*) FROM incidents WHERE deployment_id=? AND alert_instance_id=?`, admin.DeploymentID, fired.InstanceID).Scan(&incidents); err != nil {
		t.Fatal(err)
	}
	if err := st.db.QueryRow(`SELECT count(*) FROM alert_transitions WHERE deployment_id=? AND instance_id=?`, admin.DeploymentID, fired.InstanceID).Scan(&transitions); err != nil {
		t.Fatal(err)
	}
	if err := st.db.QueryRow(`SELECT count(*) FROM outbox WHERE deployment_id=? AND instance_id=?`, admin.DeploymentID, fired.InstanceID).Scan(&outbox); err != nil {
		t.Fatal(err)
	}
	if incidents != 1 || transitions != 2 || outbox != 1 {
		t.Fatalf("incidents=%d transitions=%d outbox=%d", incidents, transitions, outbox)
	}
	incident, err := st.ReadIncident(context.Background(), admin.DeploymentID, *fired.IncidentID)
	if err != nil || incident.EndMSValid || incident.Origin != "alert" {
		t.Fatalf("incident=%#v err=%v", incident, err)
	}
	var capsule AlertTriggerCapsule
	if err := json.Unmarshal(incident.CapsulePayload, &capsule); err != nil || capsule.Evaluation.ObservedDwellMS != 60_000 || capsule.Rule.ScopeID != hostID || capsule.Evidence.Unit != "ratio" {
		t.Fatalf("capsule=%#v err=%v", capsule, err)
	}
	assertAlertCapsuleArrays(t, incident.CapsulePayload)
	state, err := st.ReadAlertIncidentState(context.Background(), admin.DeploymentID, *fired.IncidentID)
	if err != nil || state.Condition != alerts.StateFiring || state.DataState != alerts.DataValid || state.Delivery.Pending != 1 || state.Delivery.Total != 1 {
		t.Fatalf("state=%#v err=%v", state, err)
	}
	historical := alertTestWrite(admin, rule, 3, second.EventMS+1, second.Input)
	historical.CurrentLive = false
	if _, err := st.ApplyAlertEvaluation(context.Background(), historical); !errors.Is(err, ErrAlertInvalid) {
		t.Fatalf("historical input err=%v", err)
	}
	var encoded string
	if err := st.db.QueryRow(`SELECT evaluator_cursor_json FROM maintenance WHERE deployment_id=?`, admin.DeploymentID).Scan(&encoded); err != nil {
		t.Fatal(err)
	}
	incidentPending, metadataPending, livePending, err := readPendingAlertCapacity(encoded)
	if err != nil || incidentPending == 0 || metadataPending == 0 || livePending == 0 {
		t.Fatalf("pending capacity incident=%d metadata=%d live=%d err=%v", incidentPending, metadataPending, livePending, err)
	}
	measureAlertTestCapacity(t, st, admin, clock.Now().UnixMilli())
	if err := st.db.QueryRow(`SELECT evaluator_cursor_json FROM maintenance WHERE deployment_id=?`, admin.DeploymentID).Scan(&encoded); err != nil {
		t.Fatal(err)
	}
	incidentPending, metadataPending, livePending, err = readPendingAlertCapacity(encoded)
	if err != nil || incidentPending != 0 || metadataPending != 0 || livePending != 0 {
		t.Fatalf("uncleared capacity incident=%d metadata=%d live=%d err=%v", incidentPending, metadataPending, livePending, err)
	}
}

func TestAlertEvaluationGapRecoveryAndResolutionStayDurable(t *testing.T) {
	st, clock, admin := newEnrollmentStore(t)
	hostID := insertAlertTestHost(t, st, admin)
	insertAlertTestCurrentFrame(t, st, admin, hostID, 1)
	definition := fixedRuleDefinition(alerts.RuleMemoryPressure, hostID, json.RawMessage(`"warning"`), 30_000, 60_000)
	rule, err := st.CreateRule(context.Background(), admin, "72000000-0000-4000-8000-000000000002", strings.Repeat("b", 64), definition)
	if err != nil {
		t.Fatal(err)
	}
	measureAlertTestCapacity(t, st, admin, clock.Now().UnixMilli())
	warning := alerts.Input{DataState: alerts.DataValid, MemoryPressure: &alerts.MemoryPressureInput{Level: "warning", Certified: true}}
	unknown := alerts.Input{DataState: alerts.DataUnknown}
	normal := alerts.Input{DataState: alerts.DataValid, MemoryPressure: &alerts.MemoryPressureInput{Level: "normal", Certified: true}}
	writes := []AlertEvaluationWrite{
		alertTestWrite(admin, rule, 1, clock.Now().UnixMilli(), warning),
		alertTestWrite(admin, rule, 2, clock.Now().UnixMilli()+5_000, unknown),
		alertTestWrite(admin, rule, 3, clock.Now().UnixMilli()+10_000, warning),
	}
	for index, write := range writes {
		result, err := st.ApplyAlertEvaluation(context.Background(), write)
		if err != nil {
			t.Fatalf("write %d err=%v", index, err)
		}
		want := []alerts.State{alerts.StatePending, alerts.StateOK, alerts.StatePending}[index]
		if result.Snapshot.State != want {
			t.Fatalf("write %d state=%s want=%s", index, result.Snapshot.State, want)
		}
	}
	firing := alertTestWrite(admin, rule, 4, clock.Now().UnixMilli()+40_000, warning)
	firing.ElapsedMS, firing.ObservedDwellMS = 30_000, 30_000
	level := "warning"
	firing.Evidence = alertTestEvidence("host.memory.pressure_level", "state", firing.EventMS, nil, &level, nil)
	fired, err := st.ApplyAlertEvaluation(context.Background(), firing)
	if err != nil || fired.Snapshot.State != alerts.StateFiring || fired.IncidentID == nil {
		t.Fatalf("fired=%#v err=%v", fired, err)
	}
	recovering := alertTestWrite(admin, rule, 5, firing.EventMS+1_000, normal)
	if result, err := st.ApplyAlertEvaluation(context.Background(), recovering); err != nil || result.Snapshot.State != alerts.StateRecovering {
		t.Fatalf("recovering=%#v err=%v", result, err)
	}
	resolvedWrite := alertTestWrite(admin, rule, 6, recovering.EventMS+60_000, normal)
	resolvedWrite.ElapsedMS = 60_000
	resolved, err := st.ApplyAlertEvaluation(context.Background(), resolvedWrite)
	if err != nil || resolved.Snapshot.State != alerts.StateResolved || resolved.IncidentID == nil {
		t.Fatalf("resolved=%#v err=%v", resolved, err)
	}
	incident, err := st.ReadIncident(context.Background(), admin.DeploymentID, *resolved.IncidentID)
	if err != nil || !incident.EndMSValid || incident.EndMS != resolvedWrite.EventMS || incident.WorkflowState != "closed" {
		t.Fatalf("resolved incident=%#v err=%v", incident, err)
	}
}

func TestAlertEvaluationRefusesStaleCapacityAndAlteredEvidenceAtomically(t *testing.T) {
	st, clock, admin := newEnrollmentStore(t)
	hostID := insertAlertTestHost(t, st, admin)
	insertAlertTestCurrentFrame(t, st, admin, hostID, 1)
	rule, err := st.CreateRule(context.Background(), admin, "72000000-0000-4000-8000-000000000003", strings.Repeat("c", 64), fixedRuleDefinition(alerts.RuleHeavyCPU, hostID, json.RawMessage(`0.9`), 60_000, 60_000))
	if err != nil {
		t.Fatal(err)
	}
	ratio := 0.95
	stale := CapacityObservation{ObservedMS: clock.Now().Add(-CapacityMeasurementMaxAge - time.Second).UnixMilli(), FreeBytes: 8 << 30, Usage: []QuotaUsage{{Class: "live_total", PhysicalBytes: 1}, {Class: "bulk_database", PhysicalBytes: 1}, {Class: "incident_ledger", PhysicalBytes: 1}, {Class: "metadata", PhysicalBytes: 1}}}
	if _, err := st.RecordCapacityObservation(context.Background(), admin.DeploymentID, stale); err != nil {
		t.Fatal(err)
	}
	first := alertTestWrite(admin, rule, 1, clock.Now().UnixMilli(), alerts.Input{DataState: alerts.DataValid, CPU: &alerts.CPUInput{BusyRatio: &ratio}})
	if _, err := st.ApplyAlertEvaluation(context.Background(), first); !errors.Is(err, ErrAlertCapacity) {
		t.Fatalf("stale capacity err=%v", err)
	}
	var instances int
	if err := st.db.QueryRow(`SELECT count(*) FROM alert_instances WHERE deployment_id=? AND rule_id=?`, admin.DeploymentID, rule.ID).Scan(&instances); err != nil || instances != 0 {
		t.Fatalf("instances=%d err=%v", instances, err)
	}
	measureAlertTestCapacity(t, st, admin, clock.Now().UnixMilli())
	if _, err := st.ApplyAlertEvaluation(context.Background(), first); err != nil {
		t.Fatal(err)
	}
	second := alertTestWrite(admin, rule, 2, first.EventMS+60_000, first.Input)
	second.ElapsedMS, second.ObservedDwellMS = 60_000, 60_000
	second.Evidence = alertTestEvidence("host.cpu.busy_ratio", "ratio", second.EventMS, &ratio, nil, nil)
	second.Evidence.SourceSamples[0].Sequence = 99
	if _, err := st.ApplyAlertEvaluation(context.Background(), second); !errors.Is(err, ErrAlertInvalid) {
		t.Fatalf("altered evidence err=%v", err)
	}
	var state string
	var cursorOrdinal int64
	if err := st.db.QueryRow(`SELECT state FROM alert_instances WHERE deployment_id=? AND rule_id=?`, admin.DeploymentID, rule.ID).Scan(&state); err != nil {
		t.Fatal(err)
	}
	var cursorJSON string
	if err := st.db.QueryRow(`SELECT evaluator_cursor_json FROM maintenance WHERE deployment_id=?`, admin.DeploymentID).Scan(&cursorJSON); err != nil {
		t.Fatal(err)
	}
	cursors, err := decodeAlertTestCursors(cursorJSON)
	if err != nil {
		t.Fatal(err)
	}
	cursorOrdinal = cursors[rule.ID].InputOrdinal
	if state != "PENDING" || cursorOrdinal != 1 {
		t.Fatalf("state=%s cursor=%d", state, cursorOrdinal)
	}
}

func TestPinnedAlertCapacityFixtureMatchesProductionEnvelopes(t *testing.T) {
	data, err := os.ReadFile("alert_capacity_calibration.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixture struct {
		WitnessMeasurementStatus string `json:"witness_measurement_status"`
		SQLiteVersion            string `json:"sqlite_version"`
		PageSize                 int64  `json:"page_size"`
		Envelopes                map[string]struct {
			Incident int64 `json:"incident_reservation_bytes"`
			Metadata int64 `json:"metadata_reservation_bytes"`
			Live     int64 `json:"live_reservation_bytes"`
		} `json:"envelopes"`
	}
	if err := json.Unmarshal(data, &fixture); err != nil || fixture.WitnessMeasurementStatus != "measured_pending_independent_review" || fixture.SQLiteVersion != "3.53.4" || fixture.PageSize != 4096 {
		t.Fatalf("fixture=%#v err=%v", fixture, err)
	}
	for name, envelope := range map[string]alertEnvelope{"snapshot_cursor": alertEnvelopeCursor, "transition": alertEnvelopeTransition, "firing_16_destinations": alertEnvelopeFiring, "resolution_16_destinations": alertEnvelopeResolution} {
		want := fixture.Envelopes[name]
		incident, metadata, live, calibrated := alertEnvelopeReservation(envelope)
		if !calibrated || incident != want.Incident || metadata != want.Metadata || live != want.Live {
			t.Fatalf("%s fixture=%#v production=%d/%d/%d calibrated=%v", name, want, incident, metadata, live, calibrated)
		}
	}
}

func TestAlertIncidentEndIsStrictlyAfterStartAtSameObservedMillisecond(t *testing.T) {
	endMS, err := alertIncidentEndMS(42, 42)
	if err != nil || endMS != 43 {
		t.Fatalf("end=%d err=%v", endMS, err)
	}
	endMS, err = alertIncidentEndMS(42, 50)
	if err != nil || endMS != 50 {
		t.Fatalf("later end=%d err=%v", endMS, err)
	}
}

func alertTestWrite(admin SessionRecord, rule RuleRecord, ordinal, eventMS int64, input alerts.Input) AlertEvaluationWrite {
	write := AlertEvaluationWrite{DeploymentID: admin.DeploymentID, DeploymentGeneration: admin.Generation, RuleID: rule.ID, RuleVersion: rule.Revision, Cursor: AlertInputCursor{InputOrdinal: ordinal, ObservedThroughMS: eventMS, InputSHA256: strings.Repeat(string(rune('a'+ordinal%6)), 64)}, EventMS: eventMS, CurrentLive: true, Input: input}
	switch rule.Definition.EvaluatorType {
	case alerts.RuleHostNotReporting, alerts.RuleMemoryPressure, alerts.RuleHeavyCPU:
		boot := alertTestBootID
		write.Fence.Host = &AlertRuntimeHostFence{HostID: rule.Definition.ScopeID, CreatedMS: rule.CreatedMS, SessionGeneration: 1, CollectorBootID: &boot}
	}
	return write
}

func alertTestEvidence(metric, unit string, observedMS int64, number *float64, state *string, boolean *bool) *AlertCapsuleEvidence {
	return &AlertCapsuleEvidence{MetricID: metric, Unit: unit, WindowStartMS: observedMS - 5_000, WindowEndMS: observedMS + 1, ObservedMS: observedMS, Quality: string(domain.QualityMeasured), NumberValue: number, StateValue: state, BooleanValue: boolean, SourceSamples: []AlertSourceSample{{CollectorBootID: alertTestBootID, SourceID: alertTestSourceID, Sequence: 1, ConfigIDs: []string{strings.Repeat("d", 64)}}}, SourceSampleCount: 1, DefinitionRevision: domain.RegistryRevision, MethodRevision: "alert-test-v1", Gaps: []AlertEvidenceGap{}, UnavailableReasons: []string{}, RequestSampleIDs: []string{}}
}

func insertAlertTestCurrentFrame(t *testing.T, st *Store, admin SessionRecord, hostID string, sequence int64) {
	t.Helper()
	now := st.clock.Now().UnixMilli()
	if _, err := st.db.Exec(`INSERT INTO collector_sessions(deployment_id,host_id,session_generation,security_generation,activation_request_id,collector_boot_id,predecessor_generation,activated_ms,activation_result_json) VALUES(?,?,1,?,?,?,0,?,'{}')`, admin.DeploymentID, hostID, admin.Generation, "71000000-0000-4000-8000-000000000003", alertTestBootID, now); err != nil {
		t.Fatal(err)
	}
	if _, err := st.db.Exec(`UPDATE hosts SET current_session_generation=1,last_boot_id=?,updated_ms=? WHERE deployment_id=? AND id=?`, alertTestBootID, now, admin.DeploymentID, hostID); err != nil {
		t.Fatal(err)
	}
	if _, err := st.db.Exec(`INSERT INTO sources(id,deployment_id,host_id,kind,target_id,admitted_capability_revision,created_ms,updated_ms) VALUES(?,?,?,'host',NULL,'mac-ollama-1',?,?)`, alertTestSourceID, admin.DeploymentID, hostID, now, now); err != nil {
		t.Fatal(err)
	}
	if _, err := st.db.Exec(`INSERT INTO source_frames(deployment_id,host_id,security_generation,session_generation,collector_boot_id,source_id,sequence,delivery_mode,incarnation_id,original_wall_ms,aligned_ms,uncertainty_ms,duration_ms,quality,definition_revision,codec,payload,payload_sha256,original_security_generation,original_collector_boot_id,original_source_id,original_sequence,original_payload_sha256,recovery_grant_id,recovery_grant_hash,admitted_ms) VALUES(?,?,?,1,?,?,?,'current',NULL,?,NULL,NULL,1,'measured','mac-ollama-1','cbor-zstd-v1',?,?,?, ?,?,?,?,NULL,NULL,?)`, admin.DeploymentID, hostID, admin.Generation, alertTestBootID, alertTestSourceID, sequence, now, []byte{1}, strings.Repeat("e", 64), admin.Generation, alertTestBootID, alertTestSourceID, sequence, strings.Repeat("e", 64), now); err != nil {
		t.Fatal(err)
	}
}

func insertAlertTestDestination(t *testing.T, st *Store, admin SessionRecord, ordinal int) {
	t.Helper()
	now := st.clock.Now().UnixMilli()
	id := "73000000-0000-4000-8000-" + strings.Repeat("0", 11) + string(rune('0'+ordinal))
	if _, err := st.db.Exec(`INSERT INTO destinations(id,deployment_id,type,display_name,secret_ref,configuration_json,version,created_ms,updated_ms) VALUES(?,?,'webhook','Alert sink',NULL,'{}',1,?,?)`, id, admin.DeploymentID, now, now); err != nil {
		t.Fatal(err)
	}
}

func measureAlertTestCapacity(t *testing.T, st *Store, admin SessionRecord, now int64) {
	t.Helper()
	if _, err := st.MeasureAndRecordCapacity(context.Background(), admin.DeploymentID, now, ExternalCapacityUsage{}); err != nil {
		t.Fatal(err)
	}
}

func decodeAlertTestCursors(encoded string) (map[string]persistedAlertCursor, error) {
	var root map[string]json.RawMessage
	if err := json.Unmarshal([]byte(encoded), &root); err != nil {
		return nil, err
	}
	var cursors map[string]persistedAlertCursor
	err := json.Unmarshal(root[alertCursorKey], &cursors)
	return cursors, err
}

func assertAlertCapsuleArrays(t *testing.T, encoded []byte) {
	t.Helper()
	var root map[string]json.RawMessage
	if err := json.Unmarshal(encoded, &root); err != nil {
		t.Fatal(err)
	}
	var evidence map[string]json.RawMessage
	if err := json.Unmarshal(root["evidence"], &evidence); err != nil {
		t.Fatal(err)
	}
	for _, field := range []string{"source_samples", "request_sample_ids", "gaps", "unavailable_reasons"} {
		if raw := evidence[field]; len(raw) == 0 || raw[0] != '[' {
			t.Fatalf("capsule field %s is not an array: %s", field, raw)
		}
	}
	var sources []map[string]json.RawMessage
	if err := json.Unmarshal(evidence["source_samples"], &sources); err != nil || len(sources) != 1 || len(sources[0]["config_ids"]) == 0 || sources[0]["config_ids"][0] != '[' {
		t.Fatalf("source config_ids is not an array: sources=%s err=%v", evidence["source_samples"], err)
	}
}
